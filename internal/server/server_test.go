package server

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/requests"
)

const (
	testKey   = "sk-live-0123456789abcdefghij"
	testToken = "role-token-phobos"
	caller    = "100.64.0.20"
)

type seen struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
}

func (s *seen) last(t *testing.T) *http.Request {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		t.Fatal("upstream was never called")
	}
	return s.requests[len(s.requests)-1]
}

func (s *seen) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// upstream records every request and answers by path.
func upstream(t *testing.T) (*httptest.Server, *seen) {
	t.Helper()
	s := &seen{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, r.Clone(r.Context()))
		s.bodies = append(s.bodies, string(body))
		s.mu.Unlock()
		switch r.URL.Path {
		case "/v1/echo":
			// A careless API that echoes the key, split across two flushes.
			w.Header().Set("X-Debug", "key="+testKey)
			half := len(testKey) / 2
			_, _ = io.WriteString(w, "before "+testKey[:half])
			w.(http.Flusher).Flush()
			time.Sleep(10 * time.Millisecond)
			_, _ = io.WriteString(w, testKey[half:]+" after")
		case "/v1/reflect":
			// Echo the query (and so a query key) URL-encoded, in a header
			// and the body, with upper- and lowercase hex.
			q := r.URL.RawQuery
			w.Header().Set("Location", "https://evil.example/cb?"+q)
			lower := regexp.MustCompile(`%[0-9A-F]{2}`).ReplaceAllStringFunc(q, strings.ToLower)
			_, _ = io.WriteString(w, "q="+q+" lower="+lower)
		case "/v1/deflate":
			w.Header().Set("Content-Encoding", "deflate")
			zw := zlib.NewWriter(w)
			_, _ = io.WriteString(zw, "zl:"+r.Header.Get("Authorization"))
			_ = zw.Close()
		case "/v1/redirect":
			http.Redirect(w, r, "https://elsewhere.example/steal", http.StatusFound)
		default:
			_, _ = io.WriteString(w, "ok "+r.Method+" "+r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, s
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newHandler(t *testing.T, base string, auth policy.Service, access policy.Access) (*Handler, *bytes.Buffer) {
	t.Helper()
	return newHandlerKey(t, base, auth, access, testKey)
}

func newHandlerKey(t *testing.T, base string, auth policy.Service, access policy.Access, key string) (*Handler, *bytes.Buffer) {
	t.Helper()
	auth.Base, auth.Key = base, "API_KEY"
	cfg := &policy.Config{
		Rules: policy.Rules{
			Listen:       "127.0.0.1:7701",
			AllowSources: []string{caller},
			AuditLog:     "audit.log",
		},
		AccessList: policy.AccessList{
			Services: map[string]policy.Service{"api": auth},
			Roles: map[string]policy.Role{
				"phobos": {TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"api": access}},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	audit := &bytes.Buffer{}
	return New(cfg, map[string]string{"API_KEY": key}, audit), audit
}

func call(h http.Handler, method, target, token string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader("payload"))
	r.RemoteAddr = caller + ":51000"
	if token != "" {
		r.Header.Set(TokenHeader, token)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var bearer = policy.Service{Auth: policy.AuthBearer}
var allowAll = policy.Access{Paths: []string{"/"}, Methods: []string{"GET", "POST"}}

func TestFixedHeadersPreserveBytesAndCredentials(t *testing.T) {
	const primary, extra = "private-primary-credential", "private-extra-credential"
	payload := []byte("\x00default\xff eu\n" + primary + " " + extra)
	want := []byte("\x00default\xff eu\n[REDACTED] [REDACTED]")
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Values("CF-R2-Jurisdiction"); len(got) != 1 || got[0] != "default" {
			t.Errorf("jurisdiction not pinned: %q", got)
			http.Error(w, "wrong jurisdiction", 400)
			return
		}
		if r.Header.Get("CF-Access-Client-Id") != primary || r.Header.Get("CF-Access-Client-Secret") != extra {
			t.Error("stored credential pair changed")
		}
		w.Header().Set("X-Public-Value", "default")
		w.Header().Set("X-Secret-Echo", extra)
		w.Write(payload)
	}))
	defer up.Close()
	var svc policy.Service
	if err := json.Unmarshal([]byte(`{"auth":"header","header":"CF-Access-Client-Id","test_path":"/objects/probe","extra_headers":{"CF-Access-Client-Secret":"SECONDARY"},"fixed_headers":{"cf-r2-jurisdiction":"default"}}`), &svc); err != nil {
		t.Fatal(err)
	}
	h, _ := newHandlerKey(t, up.URL, svc, policy.Access{Paths: []string{"/objects"}, Methods: []string{"GET"}}, primary)
	keys := map[string]string{"API_KEY": primary, "SECONDARY": extra}
	h.Swap(h.Config(), keys)
	for _, headers := range []http.Header{
		{},
		{"cf-r2-jurisdiction": {"eu", "us"}, "CF-R2-JURISDICTION": {"fedramp"}, "Connection": {"cf-r2-jurisdiction"}},
	} {
		r := httptest.NewRequest("GET", "/api/objects/probe", nil)
		r.RemoteAddr = caller + ":51000"
		r.Header = headers
		r.Header.Set(TokenHeader, testToken)
		r.Header.Set("CF-Access-Client-Id", "forged")
		r.Header.Set("CF-Access-Client-Secret", "forged")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), want) || w.Header().Get("X-Public-Value") != "default" || w.Header().Get("X-Secret-Echo") != "[REDACTED]" {
			t.Fatalf("fixed values altered bytes or credential redaction: %d %q %v", w.Code, w.Body.Bytes(), w.Header())
		}
	}
	if status, err := h.TestKey(context.Background(), h.Config().Services["api"], primary); err != nil || status != 200 {
		t.Fatalf("test request lost fixed header: %d %v", status, err)
	}
	before := calls.Load()
	if call(h, "DELETE", "/api/objects/probe", testToken, nil).Code != 403 ||
		call(h, "GET", "/api/settings", testToken, nil).Code != 403 {
		t.Fatal("fixed headers widened method/path access")
	}
	h.Swap(h.Config(), map[string]string{"API_KEY": primary})
	if call(h, "GET", "/api/objects/probe", testToken, nil).Code != 503 || calls.Load() != before {
		t.Fatal("missing credential or denied call reached upstream")
	}
}

func TestExtraHeaderProxy(t *testing.T) {
	const primary, extra = "primary-sensitive-value", "secondary-sensitive-value"
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("CF-Access-Client-Id") != primary || r.Header.Get("CF-Access-Client-Secret") != extra {
			t.Error("upstream did not receive the complete stored credentials")
		}
		w.Header().Set("X-Echo", extra)
		fmt.Fprintf(w, "%s %s", primary, extra)
	}))
	defer up.Close()
	var svc policy.Service
	if err := json.Unmarshal([]byte(`{"auth":"header","header":"CF-Access-Client-Id","test_path":"/check","extra_headers":{"CF-Access-Client-Secret":"EXTRA_KEY"}}`), &svc); err != nil {
		t.Fatal(err)
	}
	h, audit := newHandlerKey(t, up.URL, svc, allowAll, primary)
	if got := call(h, "GET", "/api/check", testToken, nil).Code; got != 503 || calls.Load() != 0 {
		t.Fatal("partial credential bundle was dispatched")
	}
	h.Swap(h.Config(), map[string]string{"API_KEY": primary, "EXTRA_KEY": extra})
	w := call(h, "GET", "/api/check", testToken, map[string]string{
		"CF-Access-Client-Id": "forged-primary", "CF-Access-Client-Secret": "forged-extra",
		"Connection": "CF-Access-Client-Secret",
	})
	if w.Code != 200 || calls.Load() != 1 {
		t.Fatalf("complete bundle failed: status=%d calls=%d", w.Code, calls.Load())
	}
	for _, secret := range []string{primary, extra} {
		if strings.Contains(w.Body.String()+w.Header().Get("X-Echo")+audit.String(), secret) {
			t.Fatal("upstream echoed credential escaped redaction")
		}
	}
	if status, err := h.TestKey(context.Background(), h.Config().Services["api"], primary); err != nil || status != 200 {
		t.Fatalf("dashboard test omitted extra credentials: %d %v", status, err)
	}
	h.Swap(h.Config(), map[string]string{"API_KEY": primary})
	if got := call(h, "GET", "/api/check", testToken, nil).Code; got != 503 || calls.Load() != 2 {
		t.Fatal("removing an extra credential did not stop dispatch")
	}
}

func TestProxyDropsEdgeHeaders(t *testing.T) {
	edgeHeaders := []string{
		"CF-Connecting-IP", "CF-Connecting-IPv6", "CF-IPCountry", "CF-Ray",
		"CF-Visitor", "CF-EW-Via", "CF-Pseudo-IPv4", "CDN-Loop",
		"True-Client-IP", "X-Forwarded-For", "X-Forwarded-Proto", "X-Real-IP",
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Cloudflare rejects a request carrying another edge's client IP.
		if r.Header.Get("CF-Connecting-IP") != "" {
			http.Error(w, "error code: 1000", http.StatusForbidden)
			return
		}
		for _, name := range edgeHeaders {
			if len(r.Header.Values(name)) != 0 {
				t.Errorf("edge metadata reached upstream: %s", name)
			}
		}
		if r.Header.Get("CF-Access-Client-Id") != "stored-client-id" ||
			r.Header.Get("CF-Access-Client-Secret") != "stored-client-secret" {
			http.Error(w, "missing service credentials", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("CF-Custom-Service") != "keep-cf" || r.Header.Get("X-Request-Id") != "keep-request" {
			t.Error("non-edge application headers were stripped")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	svc := policy.Service{
		Auth: policy.AuthHeader, Header: "CF-Access-Client-Id",
		ExtraHeaders: map[string]string{"CF-Access-Client-Secret": "ACCESS_SECRET"},
	}
	h, _ := newHandlerKey(t, up.URL, svc, allowAll, "stored-client-id")
	h.Swap(h.Config(), map[string]string{"API_KEY": "stored-client-id", "ACCESS_SECRET": "stored-client-secret"})
	headers := map[string]string{
		"CF-Access-Client-Id": "forged-id", "CF-Access-Client-Secret": "forged-secret",
		"CF-Custom-Service": "keep-cf", "X-Request-Id": "keep-request",
	}
	for _, name := range edgeHeaders {
		headers[strings.ToLower(name)] = "edge-metadata"
	}
	w := call(h, "GET", "/api/health", testToken, headers)
	if w.Code != http.StatusNoContent {
		t.Fatalf("header-auth upstream rejected proxied request: %d %s", w.Code, w.Body)
	}
}

func TestProxyAddsKeyAndDropsCallerCredentials(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	w := call(h, "POST", "/api/v1/chat?stream=1", testToken, map[string]string{
		"Authorization": "Bearer caller-supplied", "Cookie": "c=1", "X-Other": "kept",
	})
	if w.Code != 200 || w.Body.String() != "ok POST /v1/chat" {
		t.Fatalf("response %d %q", w.Code, w.Body.String())
	}
	r := got.last(t)
	if r.Header.Get("Authorization") != "Bearer "+testKey {
		t.Fatalf("upstream Authorization = %q", r.Header.Get("Authorization"))
	}
	if r.Header.Get(TokenHeader) != "" || r.Header.Get("Cookie") != "" {
		t.Fatal("role token or cookie forwarded upstream")
	}
	if r.Header.Get("X-Other") != "kept" || r.URL.RawQuery != "stream=1" || got.bodies[0] != "payload" {
		t.Fatalf("request not forwarded intact: %v %q %q", r.Header, r.URL.RawQuery, got.bodies[0])
	}
}

func TestHeaderAndQueryAuth(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, policy.Service{Auth: policy.AuthHeader, Header: "X-Api-Key"}, allowAll)
	call(h, "GET", "/api/v1/x", testToken, map[string]string{"X-Api-Key": "caller-supplied", "Authorization": "Bearer caller"})
	if v := got.last(t).Header.Values("X-Api-Key"); len(v) != 1 || v[0] != testKey {
		t.Fatalf("X-Api-Key = %v", v)
	}
	if a := got.last(t).Header.Get("Authorization"); a != "" {
		t.Fatalf("caller's Authorization forwarded with header auth: %q", a)
	}
	h, audit := newHandler(t, up.URL, policy.Service{Auth: policy.AuthQuery, Param: "api_key"}, allowAll)
	call(h, "GET", "/api/v1/x?api_key=caller&q=1", testToken, nil)
	q := got.last(t).URL.Query()
	if q.Get("api_key") != testKey || len(q["api_key"]) != 1 || q.Get("q") != "1" {
		t.Fatalf("query = %v", q)
	}
	if strings.Contains(audit.String(), testKey) || strings.Contains(audit.String(), "q=1") {
		t.Fatalf("audit holds the key or the query: %s", audit.String())
	}
}

func TestRefusalsNeverReachTheService(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, policy.Access{Paths: []string{"/v1/allowed"}, Methods: []string{"GET"}})
	cases := []struct {
		name, method, target, token, source string
		want                                int
	}{
		{"wrong source", "GET", "/api/v1/allowed", testToken, "100.64.0.21", 403},
		{"no token", "GET", "/api/v1/allowed", "", caller, 401},
		{"wrong token", "GET", "/api/v1/allowed", "guess", caller, 401},
		{"unknown service", "GET", "/other/v1/allowed", testToken, caller, 403},
		{"path outside prefix", "GET", "/api/v1/allowedx", testToken, caller, 403},
		{"method not allowed", "POST", "/api/v1/allowed", testToken, caller, 403},
		{"dot-dot", "GET", "/api/v1/allowed/../../admin", testToken, caller, 400},
		{"encoded dot-dot", "GET", "/api/v1/allowed/%2e%2e/%2E%2E/admin", testToken, caller, 400},
		{"encoded slash", "GET", "/api/v1/allowed%2f..%2fadmin", testToken, caller, 400},
		{"double-encoded dot-dot", "GET", "/api/v1/allowed/%252e%252e/admin", testToken, caller, 400},
		{"dot-dot-semicolon", "GET", "/api/v1/allowed/..;/admin", testToken, caller, 400},
		{"NUL byte", "GET", "/api/v1/allowed/%00/admin", testToken, caller, 400},
		{"fullwidth dots", "GET", "/api/v1/allowed/%ef%bc%8e%ef%bc%8e/admin", testToken, caller, 400},
		{"overlong UTF-8 dots", "GET", "/api/v1/allowed/%c0%ae%c0%ae/admin", testToken, caller, 400},
	}
	for _, tc := range cases {
		// Parse the target the way net/http parses a request line: dot
		// segments are kept, not resolved.
		u, err := url.ParseRequestURI(tc.target)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(tc.method, "/", nil)
		r.URL, r.RequestURI = u, tc.target
		r.RemoteAddr = tc.source + ":51000"
		if tc.token != "" {
			r.Header.Set(TokenHeader, tc.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, w.Code, tc.want)
		}
	}
	if n := got.count(); n != 0 {
		t.Fatalf("upstream called %d times for refused requests", n)
	}
	if w := call(h, "GET", "/api/v1/allowed/sub", testToken, nil); w.Code != 200 {
		t.Fatalf("allowed request refused: %d %s", w.Code, w.Body.String())
	}
}

func TestEchoedKeyIsHiddenEvenWhenSplit(t *testing.T) {
	up, _ := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	w := call(h, "GET", "/api/v1/echo", testToken, nil)
	if body := w.Body.String(); body != "before "+Mask+" after" {
		t.Fatalf("body = %q", body)
	}
	if strings.Contains(w.Header().Get("X-Debug"), testKey) {
		t.Fatal("key echoed in a response header")
	}
}

func TestRedirectIsReturnedNotFollowed(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	w := call(h, "GET", "/api/v1/redirect", testToken, nil)
	if w.Code != http.StatusFound || got.count() != 1 {
		t.Fatalf("status %d after %d upstream calls", w.Code, got.count())
	}
}

func TestDailyLimitAndAudit(t *testing.T) {
	up, got := upstream(t)
	limited := allowAll
	limited.DailyRequests = 1
	h, audit := newHandler(t, up.URL, bearer, limited)
	day := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return day }
	if w := call(h, "GET", "/api/v1/a?secret-looking=1", testToken, nil); w.Code != 200 {
		t.Fatalf("first call %d", w.Code)
	}
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second call %d, want 429", w.Code)
	}
	day = day.Add(24 * time.Hour)
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != 200 {
		t.Fatalf("next day %d", w.Code)
	}
	if got.count() != 2 {
		t.Fatalf("upstream calls = %d, want 2", got.count())
	}
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("audit lines = %d, want 3:\n%s", len(lines), audit.String())
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if first["role"] != "phobos" || first["service"] != "api" || first["path"] != "/v1/a" || first["status"] != float64(200) {
		t.Fatalf("audit line = %v", first)
	}
	if strings.Contains(audit.String(), "secret-looking") || strings.Contains(audit.String(), testKey) || strings.Contains(audit.String(), testToken) {
		t.Fatalf("audit leaks query, key or token:\n%s", audit.String())
	}
}

func TestMissingKeyAnswers503(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	h.Swap(h.snap.Load().config, map[string]string{})
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != http.StatusServiceUnavailable || got.count() != 0 {
		t.Fatalf("status %d, upstream calls %d", w.Code, got.count())
	}
}

func TestExpiredRoleRefused(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	past := time.Now().Add(-time.Hour)
	cfg := h.snap.Load().config
	role := cfg.Roles["phobos"]
	role.Expires = &past
	cfg.Roles["phobos"] = role
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != http.StatusUnauthorized || got.count() != 0 {
		t.Fatalf("status %d, upstream calls %d", w.Code, got.count())
	}
}

func TestExpiredAccessRefusedOnlyForThatService(t *testing.T) {
	up, got := upstream(t)
	past, later := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	h, _ := newHandler(t, up.URL, bearer, policy.Access{Paths: []string{"/"}, Expires: &past})
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != http.StatusForbidden || got.count() != 0 {
		t.Fatalf("expired access: status %d, upstream calls %d", w.Code, got.count())
	}
	h.Swap(withAccess(t, h, policy.Access{Paths: []string{"/"}, Expires: &later}), map[string]string{"API_KEY": testKey})
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != 200 {
		t.Fatalf("access ending later: %d, want 200", w.Code)
	}
}

func TestRedactorHoldsBackOnlyAPossiblePrefix(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor(&out, secretForms("SECRET"))
	_, _ = r.Write([]byte("data: hello\n\n"))
	if out.String() != "data: hello\n\n" {
		t.Fatalf("unrelated bytes held back: %q", out.String())
	}
	_, _ = r.Write([]byte("xSEC"))
	_, _ = r.Write([]byte("RETy SE"))
	_ = r.Close()
	if out.String() != "data: hello\n\nx"+Mask+"y SE" {
		t.Fatalf("out = %q", out.String())
	}
}

func TestEncodedEchoOfAQueryKeyIsHidden(t *testing.T) {
	const awkward = "sk_test+weird/key=="
	up, _ := upstream(t)
	h, _ := newHandlerKey(t, up.URL, policy.Service{Auth: policy.AuthQuery, Param: "api_key"}, allowAll, awkward)
	w := call(h, "GET", "/api/v1/reflect?x=1", testToken, nil)
	seenByCaller := w.Body.String() + " " + w.Header().Get("Location")
	// Listed here, not taken from secretForms, so the test checks the code.
	forms := []string{awkward, "sk_test%2Bweird%2Fkey%3D%3D", "sk_test%2bweird%2fkey%3d%3d"}
	for _, form := range forms {
		if strings.Contains(seenByCaller, form) {
			t.Fatalf("caller saw key form %q in %q", form, seenByCaller)
		}
	}
	if !strings.Contains(seenByCaller, Mask) {
		t.Fatalf("nothing was masked: %q", seenByCaller)
	}
}

func TestReplyInAnUncheckableEncodingIsRefused(t *testing.T) {
	up, _ := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	w := call(h, "GET", "/api/v1/deflate", testToken, nil)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", w.Code)
	}
	if w.Header().Get("Content-Encoding") != "" {
		t.Fatal("compressed body passed to the caller")
	}
}

func TestPathIsForwardedAsChecked(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	if w := call(h, "GET", "/api/v1/a%3Ab", testToken, nil); w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	// The raw request line, not the decoded path: the service must receive
	// the path the rules checked, escaped by the keyring, not the caller's
	// own escaping.
	if r := got.last(t); r.RequestURI != "/v1/a:b" {
		t.Fatalf("upstream request URI %q, want /v1/a:b", r.RequestURI)
	}
}

func TestQueryKeyReplacesEveryCasingOfTheParam(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, policy.Service{Auth: policy.AuthQuery, Param: "api_key"}, allowAll)
	call(h, "GET", "/api/v1/x?API_KEY=caller&Api_Key=caller2&q=1", testToken, nil)
	q := got.last(t).URL.Query()
	for name, values := range q {
		if strings.EqualFold(name, "api_key") && (name != "api_key" || len(values) != 1 || values[0] != testKey) {
			t.Fatalf("query still carries %s=%v", name, values)
		}
	}
	if w := call(h, "GET", "/api/v1/x?a=%zz", testToken, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("malformed query: status %d, want 400", w.Code)
	}
}

func TestUnreachableServiceDoesNotUseTheDailyLimit(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	base := dead.URL
	dead.Close()
	limited := allowAll
	limited.DailyRequests = 1
	h, _ := newHandler(t, base, bearer, limited)
	for i := 0; i < 2; i++ {
		if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != http.StatusBadGateway {
			t.Fatalf("call %d: status %d, want 502 (not 429)", i+1, w.Code)
		}
	}
}

func withAccess(t *testing.T, h *Handler, access policy.Access) *policy.Config {
	t.Helper()
	old := h.snap.Load().config
	cfg := &policy.Config{Rules: old.Rules, AccessList: policy.AccessList{
		Services: old.Services,
		Roles: map[string]policy.Role{"phobos": {TokenSHA256: tokenHash(testToken),
			Access: map[string]policy.Access{"api": access}}},
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestSwapAppliesToTheNextRequest(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, policy.Access{Paths: []string{"/v1/a"}, Methods: []string{"GET"}})
	if w := call(h, "GET", "/api/v1/b", testToken, nil); w.Code != http.StatusForbidden {
		t.Fatalf("before swap: %d, want 403", w.Code)
	}
	h.Swap(withAccess(t, h, policy.Access{Paths: []string{"/v1/b"}, Methods: []string{"GET"}}), map[string]string{"API_KEY": "sk-new-key-0123456789"})
	if w := call(h, "GET", "/api/v1/b", testToken, nil); w.Code != 200 {
		t.Fatalf("after swap: %d, want 200", w.Code)
	}
	if a := got.last(t).Header.Get("Authorization"); a != "Bearer sk-new-key-0123456789" {
		t.Fatalf("after swap the service got %q, want the new key", a)
	}
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != http.StatusForbidden {
		t.Fatalf("old path after swap: %d, want 403", w.Code)
	}
}

func TestDailyCountSurvivesASwap(t *testing.T) {
	up, _ := upstream(t)
	limited := allowAll
	limited.DailyRequests = 1
	h, _ := newHandler(t, up.URL, bearer, limited)
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != 200 {
		t.Fatalf("first call %d", w.Code)
	}
	h.Swap(withAccess(t, h, limited), map[string]string{"API_KEY": testKey})
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("after swap %d, want 429: a reload must not reset the limit", w.Code)
	}
}

func TestSwapDuringRequestsIsRaceFree(t *testing.T) {
	up, _ := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	next := withAccess(t, h, allowAll)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != 200 {
					t.Errorf("status %d", w.Code)
					return
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		h.Swap(next, map[string]string{"API_KEY": testKey})
	}
	wg.Wait()
}

func TestAccessRequestsAreFiledNotGranted(t *testing.T) {
	up, got := upstream(t)
	h, audit := newHandler(t, up.URL, bearer, allowAll)
	post := func(from, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", RequestsPath, strings.NewReader(body))
		r.RemoteAddr = from + ":51000"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	tok, fp, err := policy.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	body := `{"role":"adstudio","fingerprint":"` + strings.ToUpper(fp) + `","services":["api"],"note":"voiceovers"}`
	if w := post(caller, body); w.Code != http.StatusNotFound {
		t.Fatalf("requests off: %d, want 404", w.Code)
	}
	store := requests.Open(filepath.Join(t.TempDir(), "requests.json"))
	h.SetRequests(store)
	if w := post("192.0.2.99", body); w.Code != http.StatusForbidden {
		t.Fatalf("from a source not allowed: %d, want 403", w.Code)
	}
	for name, bad := range map[string]string{
		"unknown field":   `{"role":"x","fingerprint":"` + fp + `","services":["api"],"grant":"all"}`,
		"unknown service": `{"role":"x","fingerprint":"` + fp + `","services":["nope"]}`,
		"not json":        `role=x`,
		"trailing data":   `{"role":"x","fingerprint":"` + fp + `","services":["api"]} {}`,
	} {
		if w := post(caller, bad); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, w.Code)
		}
	}
	w := post(caller, body)
	if w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"id"`) {
		t.Fatalf("file: %d %s", w.Code, w.Body.String())
	}
	list, _ := store.Pending()
	if len(list) != 1 || list[0].Fingerprint != fp || list[0].From != caller {
		t.Fatalf("stored: %+v", list)
	}
	// Filing grants nothing: the new agent's token is still unknown.
	if w := call(h, "GET", "/api/v1/x", tok, nil); w.Code != http.StatusUnauthorized || got.count() != 0 {
		t.Fatalf("after filing, a call: %d (upstream %d)", w.Code, got.count())
	}
	if !strings.Contains(audit.String(), "request "+list[0].ID+" filed") {
		t.Fatalf("audit: %s", audit.String())
	}
}

func TestContainerModeNeverForwardsTheCallerProof(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	cfg := *h.Config()
	cfg.ContainerMode, cfg.Listen, cfg.AllowSources = true, "0.0.0.0:8080", nil
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h.Swap(&cfg, map[string]string{"API_KEY": testKey})
	r := httptest.NewRequest("GET", "/api/v1/x", nil)
	r.RemoteAddr = "172.16.0.9:4000" // the supervisor's side, any address
	r.Header.Set(TokenHeader, testToken)
	r.Header.Set(policy.CallerHeader, "router-proof")
	r.Header.Set("X-Other", "kept")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("container-mode call: %d %s", w.Code, w.Body)
	}
	out := got.last(t)
	if v := out.Header.Get(policy.CallerHeader); v != "" {
		t.Fatalf("caller proof forwarded upstream: %q", v)
	}
	if out.Header.Get("X-Other") != "kept" {
		t.Fatal("other headers dropped")
	}
}

func TestRestoreDailyCountsNeverGivesMoreCalls(t *testing.T) {
	up, _ := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, policy.Access{Paths: []string{"/"}, DailyRequests: 3})
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	for range 2 {
		call(h, "GET", "/api/v1/x", testToken, nil)
	}
	// A lower kept count (an older checkpoint) does not undo calls made.
	h.RestoreDailyCounts("2026-10-14", []DailyCount{{Role: "phobos", Service: "api", Count: 1}}, now)
	if day, counts := h.DailyCounts(now); day != "2026-10-14" || len(counts) != 1 || counts[0].Count != 2 {
		t.Fatalf("after a lower restore: %s %v", day, counts)
	}
	h.RestoreDailyCounts("2026-10-14", []DailyCount{{Role: "phobos", Service: "api", Count: 3}}, now)
	if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("after restoring a full count: %d", w.Code)
	}
	// The next day starts fresh, and a kept count from another day is ignored.
	next := now.Add(24 * time.Hour)
	h.now = func() time.Time { return next }
	h.RestoreDailyCounts("2026-10-14", []DailyCount{{Role: "phobos", Service: "api", Count: 3}}, next)
	if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK {
		t.Fatalf("next day: %d", w.Code)
	}
}
