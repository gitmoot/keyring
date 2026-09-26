// Package server is the keyring's proxy: it checks each request against the
// rules, adds the service's key, forwards the request, hides the key if the
// service echoes it, and writes one audit line.
package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const (
	// TokenHeader carries the caller's role token. It is never forwarded.
	TokenHeader = "X-Keyring-Token"
	HealthPath  = "/_keyring/health"
)

// Handler serves proxied API calls.
type Handler struct {
	config *policy.Config
	keys   map[string]string
	audit  io.Writer
	client *http.Client
	now    func() time.Time

	mu     sync.Mutex
	day    string
	counts map[[2]string]int

	auditMu sync.Mutex
}

// New builds a handler. keys maps key names to values; audit receives one JSON
// line per call.
func New(config *policy.Config, keys map[string]string, audit io.Writer) *Handler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Never send keys through an environment-configured proxy.
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 5 * time.Minute
	return &Handler{
		config: config,
		keys:   keys,
		audit:  audit,
		client: &http.Client{
			Transport: transport,
			// A redirect could point anywhere; hand it back to the caller.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:    time.Now,
		counts: map[[2]string]int{},
	}
}

type auditRecord struct {
	Time    string `json:"time"`
	Source  string `json:"source"`
	Role    string `json:"role,omitempty"`
	Service string `json:"service,omitempty"`
	Method  string `json:"method"`
	Path    string `json:"path,omitempty"`
	Status  int    `json:"status"`
	Bytes   int64  `json:"bytes"`
	Ms      int64  `json:"ms"`
	Note    string `json:"note,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := h.now()
	addr, ok := remoteAddr(r.RemoteAddr)
	if !ok || !h.config.SourceAllowed(addr) {
		// Not logged: a stranger could otherwise fill the audit log.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path == HealthPath {
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	rec := auditRecord{Time: start.UTC().Format(time.RFC3339), Source: addr.String(), Method: r.Method}
	defer func() {
		rec.Ms = h.now().Sub(start).Milliseconds()
		h.writeAudit(rec)
	}()
	fail := func(status int, note string) {
		rec.Status, rec.Note = status, note
		http.Error(w, http.StatusText(status)+": "+note, status)
	}

	roleName, role, ok := h.config.RoleForToken(r.Header.Get(TokenHeader))
	if !ok {
		fail(http.StatusUnauthorized, "unknown role token")
		return
	}
	rec.Role = roleName
	if role.Expired(start) {
		fail(http.StatusUnauthorized, "role expired")
		return
	}
	service, restEscaped, rest, ok := splitPath(r.URL)
	rec.Service, rec.Path = service, rest
	if !ok {
		fail(http.StatusBadRequest, "path must be /<service>/<path> without .. or encoded / or .")
		return
	}
	svc, known := h.config.Services[service]
	access, allowed := role.Access[service]
	if !known || !allowed {
		fail(http.StatusForbidden, "role may not use this service")
		return
	}
	if !access.AllowsMethod(r.Method) {
		fail(http.StatusForbidden, "method not allowed for this role")
		return
	}
	if !access.AllowsPath(rest) {
		fail(http.StatusForbidden, "path not allowed for this role")
		return
	}
	key := h.keys[svc.Key]
	if key == "" {
		fail(http.StatusServiceUnavailable, "key not loaded")
		return
	}
	if !h.take(roleName, service, access.DailyRequests, start) {
		fail(http.StatusTooManyRequests, "daily limit reached")
		return
	}

	target := svc.BaseURL()
	basePath := strings.TrimSuffix(target.Path, "/")
	baseEscaped := strings.TrimSuffix(target.EscapedPath(), "/")
	target.Path = basePath + rest
	target.RawPath = baseEscaped + restEscaped
	target.RawQuery = r.URL.RawQuery
	header := outboundHeader(r.Header, svc)
	switch svc.Auth {
	case policy.AuthBearer:
		header.Set("Authorization", "Bearer "+key)
	case policy.AuthHeader:
		header.Set(svc.Header, key)
	case policy.AuthQuery:
		q := target.Query()
		q.Set(svc.Param, key)
		target.RawQuery = q.Encode()
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		fail(http.StatusBadGateway, "could not build upstream request")
		return
	}
	out.Header = header
	out.ContentLength = r.ContentLength
	resp, err := h.client.Do(out)
	if err != nil {
		// The error text can include the URL, and so a query-string key.
		fail(http.StatusBadGateway, "upstream unreachable")
		return
	}
	defer resp.Body.Close()

	secret := []byte(key)
	for name, values := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(name)] || strings.EqualFold(name, "Content-Length") {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, strings.ReplaceAll(v, key, Mask))
		}
	}
	w.WriteHeader(resp.StatusCode)
	rec.Status = resp.StatusCode
	flusher, _ := w.(http.Flusher)
	sink := &countingWriter{w: w}
	red := newRedactor(sink, secret)
	buf := make([]byte, 32<<10)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := red.Write(buf[:n]); err != nil {
				rec.Note = "client went away"
				break
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				rec.Note = "upstream read failed"
			}
			break
		}
	}
	_ = red.Close()
	if flusher != nil {
		flusher.Flush()
	}
	rec.Bytes = sink.n
}

// splitPath takes "/<service>/<rest>" and returns the service, the rest as
// sent (escaped) and decoded. It refuses dot segments and encoded dots,
// slashes and backslashes, so the rules see the same path the service will.
func splitPath(u *url.URL) (service, restEscaped, rest string, ok bool) {
	escaped := u.EscapedPath()
	lower := strings.ToLower(escaped)
	if !strings.HasPrefix(escaped, "/") || strings.Contains(escaped, `\`) ||
		strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", "", "", false
	}
	trimmed := strings.TrimPrefix(escaped, "/")
	service, tail, _ := strings.Cut(trimmed, "/")
	if service == "" {
		return "", "", "", false
	}
	restEscaped = "/" + tail
	for _, seg := range strings.Split(tail, "/") {
		if seg == "." || seg == ".." {
			return service, "", "", false
		}
	}
	rest, err := url.PathUnescape(restEscaped)
	if err != nil {
		return service, "", "", false
	}
	return service, restEscaped, rest, true
}

var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

// outboundHeader copies the caller's headers without hop-by-hop headers, the
// role token, and anything that could carry or replace a credential.
func outboundHeader(in http.Header, svc policy.Service) http.Header {
	out := in.Clone()
	for _, field := range in.Values("Connection") {
		for _, name := range strings.Split(field, ",") {
			out.Del(strings.TrimSpace(name))
		}
	}
	for name := range hopByHop {
		out.Del(name)
	}
	out.Del(TokenHeader)
	out.Del("Authorization")
	out.Del("Cookie")
	// Let the transport negotiate compression and decode it, so the
	// redactor sees plain text.
	out.Del("Accept-Encoding")
	if svc.Auth == policy.AuthHeader {
		out.Del(svc.Header)
	}
	return out
}

// take counts one call and reports whether it is within the daily limit.
func (h *Handler) take(role, service string, limit int, now time.Time) bool {
	if limit <= 0 {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	day := now.UTC().Format("2006-01-02")
	if day != h.day {
		h.day, h.counts = day, map[[2]string]int{}
	}
	k := [2]string{role, service}
	if h.counts[k] >= limit {
		return false
	}
	h.counts[k]++
	return true
}

func (h *Handler) writeAudit(rec auditRecord) {
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	_, _ = h.audit.Write(append(line, '\n'))
}

func remoteAddr(hostport string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
