// Package server is the keyring's proxy: it checks each request against the
// rules, adds the service's key, forwards the request, hides the key if the
// service echoes it, and writes one audit line.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
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
	// snap holds the rules, access list and keys in use. Each request reads
	// it once, so a reload never mixes old and new settings in one request.
	snap   atomic.Pointer[snapshot]
	audit  io.Writer
	client *http.Client
	now    func() time.Time

	mu     sync.Mutex
	day    string
	counts map[[2]string]int

	usage usageBook

	auditMu sync.Mutex
}

type snapshot struct {
	config *policy.Config
	keys   map[string]string
}

// New builds a handler. keys maps key names to values; audit receives one JSON
// line per call.
func New(config *policy.Config, keys map[string]string, audit io.Writer) *Handler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Never send keys through an environment-configured proxy.
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 5 * time.Minute
	h := &Handler{
		audit: audit,
		client: &http.Client{
			Transport: transport,
			// A redirect could point anywhere; hand it back to the caller.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:    time.Now,
		counts: map[[2]string]int{},
	}
	h.Swap(config, keys)
	return h
}

// Config returns the settings in use.
func (h *Handler) Config() *policy.Config { return h.snap.Load().config }

// Swap replaces the settings and keys for every later request. config must be
// validated. Requests already running keep what they started with; daily
// counts carry over.
func (h *Handler) Swap(config *policy.Config, keys map[string]string) {
	h.snap.Store(&snapshot{config: config, keys: keys})
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
	snap := h.snap.Load()
	addr, ok := remoteAddr(r.RemoteAddr)
	if !ok || !snap.config.SourceAllowed(addr) {
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
		if _, known := snap.config.Services[rec.Service]; known && rec.Role != "" {
			h.usage.record(rec.Role, rec.Service, rec.Status, start)
		}
	}()
	fail := func(status int, note string) {
		rec.Status, rec.Note = status, note
		http.Error(w, http.StatusText(status)+": "+note, status)
	}

	roleName, role, ok := snap.config.RoleForToken(r.Header.Get(TokenHeader))
	if !ok {
		fail(http.StatusUnauthorized, "unknown role token")
		return
	}
	rec.Role = roleName
	if role.Expired(start) {
		fail(http.StatusUnauthorized, "role expired")
		return
	}
	service, rest, ok := splitPath(r.URL)
	rec.Service, rec.Path = service, rest
	if !ok {
		fail(http.StatusBadRequest, "path must be /<service>/<path> in plain printable ASCII, without .., ;, % after decoding, or encoded / . \\")
		return
	}
	svc, known := snap.config.Services[service]
	access, allowed := role.Access[service]
	if !known || !allowed {
		fail(http.StatusForbidden, "role may not use this service")
		return
	}
	if access.Expired(start) {
		fail(http.StatusForbidden, "access to this service expired")
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
	key := snap.keys[svc.Key]
	if key == "" {
		fail(http.StatusServiceUnavailable, "key not loaded")
		return
	}
	if !h.take(roleName, service, access.DailyRequests, start) {
		fail(http.StatusTooManyRequests, "daily limit reached")
		return
	}

	out, err := buildOutbound(r.Context(), svc, key, r.Method, rest, r.URL.RawQuery, outboundHeader(r.Header, svc), r.Body, r.ContentLength)
	if errors.Is(err, errBadQuery) {
		h.refund(roleName, service, access.DailyRequests, start)
		fail(http.StatusBadRequest, "malformed query string")
		return
	}
	if err != nil {
		fail(http.StatusBadGateway, "could not build upstream request")
		return
	}
	resp, err := h.client.Do(out)
	if err != nil {
		// The call never reached the service: do not charge the limit. The
		// error text can include the URL, and so a query-string key.
		h.refund(roleName, service, access.DailyRequests, start)
		fail(http.StatusBadGateway, "upstream unreachable")
		return
	}
	defer resp.Body.Close()
	// The transport already decoded gzip. Any other encoding would hide an
	// echoed key from the redactor, so such a reply is not passed on.
	if ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		fail(http.StatusBadGateway, "upstream used an encoding the keyring cannot check")
		return
	}

	forms := secretForms(key)
	for name, values := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(name)] || strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Content-Encoding") {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, maskString(v, forms))
		}
	}
	w.WriteHeader(resp.StatusCode)
	rec.Status = resp.StatusCode
	flusher, _ := w.(http.Flusher)
	sink := &countingWriter{w: w}
	red := newRedactor(sink, forms)
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

var errBadQuery = errors.New("malformed query string")

// buildOutbound makes the request sent to the service: the checked path below
// the service base (escaped again by net/url, never the caller's raw text),
// the query, and the key placed the way the service expects. The proxy and
// the key test both use it.
func buildOutbound(ctx context.Context, svc policy.Service, key, method, rest, rawQuery string, header http.Header, body io.Reader, length int64) (*http.Request, error) {
	target := svc.BaseURL()
	target.Path = strings.TrimSuffix(target.Path, "/") + rest
	target.RawPath = ""
	target.RawQuery = rawQuery
	switch svc.Auth {
	case policy.AuthBearer:
		header.Set("Authorization", "Bearer "+key)
	case policy.AuthHeader:
		header.Set(svc.Header, key)
	case policy.AuthQuery:
		q, err := url.ParseQuery(rawQuery)
		if err != nil {
			return nil, errBadQuery
		}
		for name := range q {
			if strings.EqualFold(name, svc.Param) {
				delete(q, name)
			}
		}
		q.Set(svc.Param, key)
		target.RawQuery = q.Encode()
	}
	out, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}
	out.Header = header
	out.ContentLength = length
	return out, nil
}

// TestKey sends the service's test request with key and returns the status
// code. It never returns the reply body, which could echo the key.
func (h *Handler) TestKey(ctx context.Context, svc policy.Service, key string) (int, error) {
	if svc.TestPath == "" {
		return 0, errors.New("the service has no test request")
	}
	method := svc.TestMethod
	if method == "" {
		method = http.MethodGet
	}
	path, query, _ := strings.Cut(svc.TestPath, "?")
	header := http.Header{"User-Agent": {"keyring-test"}}
	out, err := buildOutbound(ctx, svc, key, method, path, query, header, http.NoBody, 0)
	if err != nil {
		return 0, err
	}
	resp, err := h.client.Do(out)
	if err != nil {
		// The error text can include the URL, and so a query-string key.
		return 0, errors.New("service unreachable")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	return resp.StatusCode, nil
}

// splitPath takes "/<service>/<rest>" and returns the service and the
// decoded rest. The rest is accepted only in a plain form that every server
// reads the same way: printable ASCII after one decode, no "%" left (double
// encoding), no ";" (path parameters such as "..;"), no backslash, no "." or
// ".." segment, and no encoded "/", "." or "\" in the request.
func splitPath(u *url.URL) (service, rest string, ok bool) {
	escaped := u.EscapedPath()
	lower := strings.ToLower(escaped)
	if !strings.HasPrefix(escaped, "/") || strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", "", false
	}
	service, tail, _ := strings.Cut(strings.TrimPrefix(escaped, "/"), "/")
	if service == "" {
		return "", "", false
	}
	rest, err := url.PathUnescape("/" + tail)
	if err != nil {
		return service, "", false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c < 0x21 || c > 0x7e || c == '%' || c == ';' || c == '\\' {
			return service, "", false
		}
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == "." || seg == ".." {
			return service, "", false
		}
	}
	return service, rest, true
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

// refund gives back a call that never reached the service.
func (h *Handler) refund(role, service string, limit int, now time.Time) {
	if limit <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	k := [2]string{role, service}
	if now.UTC().Format("2006-01-02") == h.day && h.counts[k] > 0 {
		h.counts[k]--
	}
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
