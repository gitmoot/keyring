// Package server is the keyring's proxy: it checks each request against the
// rules, adds the service's key, forwards the request, hides the key if the
// service echoes it, and writes one audit line.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/requests"
)

const (
	// TokenHeader carries the caller's role token. It is never forwarded.
	TokenHeader = "X-Keyring-Token"
	HealthPath  = "/_keyring/health"
	// RequestsPath takes access requests from the allowed sources (POST, JSON
	// {"role","fingerprint","services","note"}). The owner approves them in
	// the dashboard; filing one grants nothing.
	RequestsPath = "/_keyring/requests"
)

// Handler serves proxied API calls.
type Handler struct {
	// snap holds the rules, access list and keys in use. Each request reads
	// it once, so a reload never mixes old and new settings in one request.
	snap atomic.Pointer[snapshot]
	// requests, when set, takes access requests at RequestsPath.
	requests *requests.Store
	audit    io.Writer
	client   *http.Client
	// pinned holds one client per tls_pin_sha256 value (see clientFor).
	pinned sync.Map
	now    func() time.Time

	mu     sync.Mutex
	day    string
	counts map[[2]string]int
	// bytes counts tunnel bytes per role and service on day.
	bytes map[[2]string]int64

	// dialProxy reaches a person's proxy (dialPublic outside tests).
	dialProxy proxyDialer

	usage usageBook

	oauth  oauthCache
	google googleCache

	auditMu sync.Mutex
}

type snapshot struct {
	config             *policy.Config
	keys               map[string]string
	appleAdsKey        *ecdsa.PrivateKey
	appStoreConnectKey *ecdsa.PrivateKey
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
		now:       time.Now,
		counts:    map[[2]string]int{},
		bytes:     map[[2]string]int64{},
		dialProxy: dialPublic,
	}
	h.Swap(config, keys)
	return h
}

// errTLSPin is the handshake error for a certificate that does not match the
// service's tls_pin_sha256.
var errTLSPin = errors.New("upstream certificate does not match tls_pin_sha256")

// pinnedTLSConfig trusts exactly the leaf certificate whose DER SHA-256 is
// want; a nil want trusts nothing.
func pinnedTLSConfig(want []byte) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Chain and hostname checks are replaced by the exact pin below.
		InsecureSkipVerify: true,
		// VerifyConnection runs on every handshake, resumed ones included.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(want) != sha256.Size || len(cs.PeerCertificates) == 0 {
				return errTLSPin
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(sum[:], want) != 1 {
				return errTLSPin
			}
			return nil
		},
	}
}

// clientFor returns the client for svc: the shared one (system CA roots) for
// an unpinned service, or one that trusts exactly the pinned certificate.
func (h *Handler) clientFor(svc policy.Service) *http.Client {
	if svc.TLSPinSHA256 == "" {
		return h.client
	}
	if c, ok := h.pinned.Load(svc.TLSPinSHA256); ok {
		return c.(*http.Client)
	}
	// validate() refuses malformed pins; one that slipped through trusts
	// nothing rather than falling back to no check.
	want, _ := hex.DecodeString(svc.TLSPinSHA256)
	transport := h.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = pinnedTLSConfig(want)
	c, _ := h.pinned.LoadOrStore(svc.TLSPinSHA256, &http.Client{Transport: transport, CheckRedirect: h.client.CheckRedirect})
	return c.(*http.Client)
}

// Config returns the settings in use.
func (h *Handler) Config() *policy.Config { return h.snap.Load().config }

// Swap replaces the settings and keys for every later request. config must be
// validated. Requests already running keep what they started with; daily
// counts carry over.
func (h *Handler) Swap(config *policy.Config, keys map[string]string) {
	snap := &snapshot{config: config, keys: keys}
	if svc, ok := config.Services["apple-ads"]; ok && svc.Auth == policy.AuthAppleAdsSign {
		snap.appleAdsKey = parseAppleSigningKey(keys[svc.Key])
	}
	if svc, ok := config.Services["appstoreconnect"]; ok && svc.Auth == policy.AuthAppStoreConnectSign {
		snap.appStoreConnectKey = parseAppleSigningKey(keys[svc.Key])
	}
	h.snap.Store(snap)
	h.retainOAuth(config, keys)
	h.retainGoogle(config)
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

// SetRequests turns on RequestsPath, filing into store. Call before serving.
func (h *Handler) SetRequests(store *requests.Store) { h.requests = store }

func (h *Handler) fileRequest(w http.ResponseWriter, r *http.Request, snap *snapshot, from string, now time.Time) {
	rec := auditRecord{Time: now.UTC().Format(time.RFC3339), Source: from, Method: r.Method, Path: RequestsPath}
	defer func() { h.writeAudit(rec) }()
	fail := func(status int, msg string) {
		rec.Status, rec.Note = status, msg
		http.Error(w, http.StatusText(status)+": "+msg, status)
	}
	if h.requests == nil {
		fail(http.StatusNotFound, "access requests are off")
		return
	}
	if r.Method != http.MethodPost {
		fail(http.StatusMethodNotAllowed, "POST a JSON request")
		return
	}
	var req requests.Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	err := dec.Decode(&req)
	if err == nil {
		if _, extra := dec.Token(); extra != io.EOF {
			err = errors.New("data after the request")
		}
	}
	if err != nil {
		fail(http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	req.Fingerprint = strings.ToLower(req.Fingerprint)
	filed, err := h.requests.File(req, snap.config.AccessList, from, now)
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	rec.Status, rec.Role, rec.Note = http.StatusAccepted, filed.Role, "request "+filed.ID+" filed: "+strings.Join(filed.Services, ",")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"id": filed.ID, "status": "waiting for the owner to approve it in the dashboard"})
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
	if r.URL.Path == RequestsPath {
		h.fileRequest(w, r, snap, addr.String(), start)
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
	service, rest, ok := splitPath(r.URL, snap.config.Services, role.Access)
	var signingKey *ecdsa.PrivateKey
	var signMessage []byte
	var signingAuth string
	switch r.URL.Path {
	case appleAdsSignPath:
		service, rest, ok = "apple-ads", "/", true
		signingAuth, signingKey = policy.AuthAppleAdsSign, snap.appleAdsKey
	case appStoreConnectSignPath:
		service, rest, ok = "appstoreconnect", "/", true
		signingAuth, signingKey = policy.AuthAppStoreConnectSign, snap.appStoreConnectKey
	}
	if signService := ed25519SignService(r.URL.Path); signService != "" && signingAuth == "" {
		service, rest, ok = signService, "/", true
		signingAuth = policy.AuthEd25519Sign
	}
	signing := signingAuth != ""
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
	if signing {
		if r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" || r.URL.ForceQuery {
			fail(http.StatusBadRequest, "signing requires the exact path without a query")
			return
		}
		if r.Method != http.MethodPost {
			fail(http.StatusMethodNotAllowed, "signing requires POST")
			return
		}
		if svc.Auth != signingAuth {
			fail(http.StatusForbidden, "service is not configured for signing")
			return
		}
		if signingAuth == policy.AuthEd25519Sign {
			var reqErr error
			signMessage, reqErr = decodeEd25519Request(r.Body)
			if reqErr != nil {
				fail(http.StatusBadRequest, reqErr.Error())
				return
			}
		} else {
			var probe [1]byte
			if n, err := io.ReadFull(r.Body, probe[:]); n != 0 || err != io.EOF {
				fail(http.StatusBadRequest, "signing requires an empty body")
				return
			}
		}
	} else if svc.SignOnly() {
		fail(http.StatusForbidden, "sign-only service cannot proxy requests")
		return
	}
	// Other services keep forwarding every path, /_tunnel included.
	tunnel := svc.Auth == policy.AuthEgressProxy
	if tunnel && rest != TunnelPath {
		fail(http.StatusNotFound, "an egress-proxy service only opens tunnels at /<service>/_tunnel")
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
	if key == "" && svc.Auth != policy.AuthGcloud {
		fail(http.StatusServiceUnavailable, "key not loaded")
		return
	}
	if !h.take(roleName, service, access.DailyRequests, start) {
		fail(http.StatusTooManyRequests, "daily limit reached")
		return
	}
	if tunnel {
		h.openTunnel(w, r, svc, key, roleName, service, access, start, &rec, fail)
		return
	}
	if signingAuth == policy.AuthEd25519Sign {
		signKey, keyErr := parseEd25519Key(key)
		if keyErr != nil {
			h.refund(roleName, service, access.DailyRequests, start)
			fail(http.StatusServiceUnavailable, "Ed25519 signing unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		rec.Status = http.StatusOK
		sink := &countingWriter{w: w}
		_ = json.NewEncoder(sink).Encode(signEd25519(signKey, signMessage))
		rec.Bytes = sink.n
		return
	}
	if signing {
		token, expires, err := signAppleToken(signingKey, svc, role, access, start)
		if err != nil {
			h.refund(roleName, service, access.DailyRequests, start)
			fail(http.StatusServiceUnavailable, "Apple signing unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		rec.Status = http.StatusOK
		sink := &countingWriter{w: w}
		_ = json.NewEncoder(sink).Encode(struct {
			Token     string `json:"token"`
			ExpiresAt string `json:"expires_at"`
		}{token, expires.UTC().Format(time.RFC3339)})
		rec.Bytes = sink.n
		return
	}

	upstreamKey, alsoRedact := key, []string(nil)
	if svc.Auth == policy.AuthOAuth2 {
		refresh, secret := oauthSecrets(svc, snap.keys)
		token, err := h.accessToken(r.Context(), svc, refresh, secret)
		if err != nil {
			h.refund(roleName, service, access.DailyRequests, start)
			switch {
			case errors.Is(err, errOAuthRejected):
				fail(http.StatusServiceUnavailable, err.Error())
			case r.Context().Err() != nil:
				fail(http.StatusBadGateway, "client went away")
			default:
				fail(http.StatusBadGateway, err.Error())
			}
			return
		}
		// The refresh token and client secret never go upstream; they are
		// masked too in case a service mirrors something unexpected.
		upstreamKey, alsoRedact = token, []string{refresh, secret}
	}
	header := outboundHeader(r.Header, svc)
	if svc.Auth == policy.AuthGcloud {
		account := snap.config.GoogleAccounts[svc.GoogleAccount]
		token, err := h.googleToken(r.Context(), account)
		if err != nil {
			h.refund(roleName, service, access.DailyRequests, start)
			fail(http.StatusBadGateway, err.Error())
			return
		}
		upstreamKey = token
		if account.QuotaProject != "" {
			header.Set("X-Goog-User-Project", account.QuotaProject)
		}
	}
	if snap.config.ContainerMode {
		// The supervisor removes it; never pass the router's proof on even
		// if one slipped through.
		header.Del(policy.CallerHeader)
	}
	out, err := buildOutbound(r.Context(), svc, upstreamKey, r.Method, rest, r.URL.RawQuery, header, r.Body, r.ContentLength)
	if errors.Is(err, errBadQuery) {
		h.refund(roleName, service, access.DailyRequests, start)
		fail(http.StatusBadRequest, "malformed query string")
		return
	}
	if err != nil {
		fail(http.StatusBadGateway, "could not build upstream request")
		return
	}
	resp, err := h.clientFor(svc).Do(out)
	if err != nil {
		// The call never reached the service: do not charge the limit. The
		// error text can include the URL, and so a query-string key.
		h.refund(roleName, service, access.DailyRequests, start)
		if errors.Is(err, errTLSPin) {
			fail(http.StatusBadGateway, "upstream certificate does not match the pinned certificate")
			return
		}
		fail(http.StatusBadGateway, "upstream unreachable")
		return
	}
	defer resp.Body.Close()
	if svc.Auth == policy.AuthOAuth2 && resp.StatusCode == http.StatusUnauthorized {
		// The token may have been revoked before it expired: mint a new
		// one on the next call.
		refresh, secret := oauthSecrets(svc, snap.keys)
		h.dropAccessToken(svc, refresh, secret, upstreamKey)
	}
	if svc.Auth == policy.AuthGcloud && resp.StatusCode == http.StatusUnauthorized {
		// Invalidate only the token used; never replay an ambiguous write.
		h.dropGoogleToken(snap.config.GoogleAccounts[svc.GoogleAccount], upstreamKey)
	}
	// The transport already decoded gzip. Any other encoding would hide an
	// echoed key from the redactor, so such a reply is not passed on.
	if ce := strings.TrimSpace(resp.Header.Get("Content-Encoding")); ce != "" && !strings.EqualFold(ce, "identity") {
		fail(http.StatusBadGateway, "upstream used an encoding the keyring cannot check")
		return
	}

	forms := secretForms(append([]string{upstreamKey}, alsoRedact...)...)
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
	if svc.SignOnly() {
		return nil, errors.New("sign-only service cannot proxy requests")
	}
	target := svc.BaseURL()
	target.Path = strings.TrimSuffix(target.Path, "/") + rest
	target.RawPath = ""
	target.RawQuery = rawQuery
	if svc.Auth == policy.AuthGcloud {
		q, err := url.ParseQuery(rawQuery)
		if err != nil {
			return nil, errBadQuery
		}
		for name := range q {
			switch strings.ToLower(name) {
			case "access_token", "oauth_token", "key", "userproject":
				delete(q, name)
			}
		}
		target.RawQuery = q.Encode()
	}
	switch svc.Auth {
	case policy.AuthBearer, policy.AuthOAuth2, policy.AuthGcloud:
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
// code. It never returns the reply body, which could echo the key. For an
// oauth2 service, key is the refresh token: the test mints an access token
// with it and the client secret in use.
func (h *Handler) TestKey(ctx context.Context, svc policy.Service, key string) (int, error) {
	if svc.SignOnly() {
		return 0, errors.New("sign-only service has no upstream test")
	}
	if svc.TestPath == "" {
		return 0, errors.New("the service has no test request")
	}
	if svc.Auth == policy.AuthOAuth2 {
		_, secret := oauthSecrets(svc, h.snap.Load().keys)
		token, err := h.accessToken(ctx, svc, key, secret)
		if err != nil {
			return 0, err
		}
		key = token
	}
	method := svc.TestMethod
	if method == "" {
		method = http.MethodGet
	}
	path, query, _ := strings.Cut(svc.TestPath, "?")
	header := http.Header{"User-Agent": {"keyring-test"}}
	var googleAccount policy.GoogleAccount
	if svc.Auth == policy.AuthGcloud {
		googleAccount = h.snap.Load().config.GoogleAccounts[svc.GoogleAccount]
		token, err := h.googleToken(ctx, googleAccount)
		if err != nil {
			return 0, err
		}
		key = token
		if googleAccount.QuotaProject != "" {
			header.Set("X-Goog-User-Project", googleAccount.QuotaProject)
		}
	}
	out, err := buildOutbound(ctx, svc, key, method, path, query, header, http.NoBody, 0)
	if err != nil {
		return 0, err
	}
	resp, err := h.clientFor(svc).Do(out)
	if err != nil {
		// The error text can include the URL, and so a query-string key.
		if errors.Is(err, errTLSPin) {
			return 0, errors.New("service certificate does not match the pinned certificate")
		}
		return 0, errors.New("service unreachable")
	}
	if svc.Auth == policy.AuthGcloud && resp.StatusCode == http.StatusUnauthorized {
		h.dropGoogleToken(googleAccount, key)
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
// Google account services also accept spaces (Sheets A1 tab names); other
// services retain their existing no-whitespace rule. buildOutbound re-escapes
// the decoded path before sending it upstream.
func splitPath(u *url.URL, services map[string]policy.Service, grants map[string]policy.Access) (service, rest string, ok bool) {
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
	// Ungranted names must not reveal their auth kind through a space probe.
	_, granted := grants[service]
	allowSpace := granted && services[service].Auth == policy.AuthGcloud
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c < 0x20 || (c == 0x20 && !allowSpace) || c > 0x7e || c == '%' || c == ';' || c == '\\' {
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
	if svc.Auth == policy.AuthGcloud {
		out.Del("X-Goog-Api-Key")
	}
	// Let the transport negotiate compression and decode it, so the
	// redactor sees plain text.
	out.Del("Accept-Encoding")
	if svc.Auth == policy.AuthHeader {
		out.Del(svc.Header)
	}
	return out
}

// openTunnel connects through the person's proxy and, once connected,
// upgrades the request to a WebSocket that carries the TCP bytes. A failure
// before the upgrade is an HTTP status and is not charged.
func (h *Handler) openTunnel(w http.ResponseWriter, r *http.Request, svc policy.Service, credential, role, service string, access policy.Access, start time.Time, rec *auditRecord, fail func(int, string)) {
	e := svc.EgressProxy
	host, port, status, msg := tunnelTarget(r, e)
	if status == 0 && !isWebSocketUpgrade(r) {
		status, msg = http.StatusBadRequest, "a tunnel needs a WebSocket upgrade"
	}
	if status == 0 && access.DailyBytes > 0 && !h.addBytes(role, service, 0, access.DailyBytes, start) {
		status, msg = http.StatusTooManyRequests, "daily byte limit reached"
	}
	if status != 0 {
		h.refund(role, service, access.DailyRequests, start)
		fail(status, msg)
		return
	}
	rec.Note = "tunnel " + net.JoinHostPort(host, strconv.Itoa(port))
	proxy, cred, err := e.Resolve(credential)
	if err != nil {
		h.refund(role, service, access.DailyRequests, start)
		fail(http.StatusServiceUnavailable, "proxy not connected: "+err.Error()+"; connect it again")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	upstream, err := dialThroughProxy(ctx, h.dialProxy, &proxy, cred, host, port)
	cancel()
	if err != nil {
		h.refund(role, service, access.DailyRequests, start)
		// The error text names no credential, but keep it generic.
		if errors.Is(err, errProxyRefused) {
			fail(http.StatusBadGateway, "the proxy refused the tunnel (check the proxy credential and destination)")
		} else {
			fail(http.StatusBadGateway, "the proxy is unreachable")
		}
		return
	}
	var st tunnelStats
	allow := func(n int64) bool {
		return access.DailyBytes <= 0 || h.addBytes(role, service, n, access.DailyBytes, h.now())
	}
	rec.Status = http.StatusSwitchingProtocols
	if hijacked, err := pipeTunnel(w, r, upstream, e, allow, &st); err != nil {
		// The tunnel never carried a byte: not charged.
		upstream.Close()
		h.refund(role, service, access.DailyRequests, start)
		if !hijacked {
			fail(http.StatusInternalServerError, "could not upgrade")
		} else {
			rec.Status, rec.Note = 499, rec.Note+" client went away during the upgrade"
		}
		return
	}
	rec.Bytes = st.up.Load() + st.down.Load()
	rec.Note += fmt.Sprintf(" closed %d, up %d down %d", st.close, st.up.Load(), st.down.Load())
}

// addBytes counts n tunnel bytes and reports whether the total stays within
// limit (n = 0 asks whether any bytes are left).
func (h *Handler) addBytes(role, service string, n, limit int64, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	day := now.UTC().Format("2006-01-02")
	if day != h.day {
		h.day, h.counts, h.bytes = day, map[[2]string]int{}, map[[2]string]int64{}
	}
	k := [2]string{role, service}
	if h.bytes[k]+n > limit || (n == 0 && h.bytes[k] >= limit) {
		return false
	}
	h.bytes[k] += n
	return true
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
		h.day, h.counts, h.bytes = day, map[[2]string]int{}, map[[2]string]int64{}
	}
	k := [2]string{role, service}
	if h.counts[k] >= limit {
		return false
	}
	h.counts[k]++
	return true
}

// DailyCount is one role's calls to one service on one UTC day, as counted
// against its daily limit.
type DailyCount struct {
	Role    string `json:"role"`
	Service string `json:"service"`
	Count   int    `json:"count"`
	// Bytes is tunnel bytes, for egress-proxy services.
	Bytes int64 `json:"bytes,omitempty"`
}

// DailyCounts returns today's counts (UTC day "2006-01-02"), so a supervisor
// can keep them while the process is stopped.
func (h *Handler) DailyCounts(now time.Time) (string, []DailyCount) {
	day := now.UTC().Format("2006-01-02")
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []DailyCount{}
	if h.day != day {
		return day, out
	}
	keys := map[[2]string]bool{}
	for k, n := range h.counts {
		keys[k] = keys[k] || n > 0
	}
	for k, n := range h.bytes {
		keys[k] = keys[k] || n > 0
	}
	for k, used := range keys {
		if used {
			out = append(out, DailyCount{Role: k[0], Service: k[1], Count: h.counts[k], Bytes: h.bytes[k]})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Service < out[j].Service
	})
	return day, out
}

// RestoreDailyCounts adds back counts kept by a supervisor. Counts for
// another day than today are ignored; for each pair the higher of the kept
// and current count wins, so a restore never gives a role more calls.
func (h *Handler) RestoreDailyCounts(day string, counts []DailyCount, now time.Time) {
	today := now.UTC().Format("2006-01-02")
	if day != today {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.day != today {
		h.day, h.counts, h.bytes = today, map[[2]string]int{}, map[[2]string]int64{}
	}
	for _, c := range counts {
		k := [2]string{c.Role, c.Service}
		if c.Count > h.counts[k] {
			h.counts[k] = c.Count
		}
		if c.Bytes > h.bytes[k] {
			h.bytes[k] = c.Bytes
		}
	}
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
