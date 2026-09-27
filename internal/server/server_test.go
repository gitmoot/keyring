package server

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const (
	testKey   = "sk-live-0123456789abcdefghij"
	testToken = "role-token-phobos"
	caller    = "100.106.218.88"
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
		{"wrong source", "GET", "/api/v1/allowed", testToken, "100.106.218.89", 403},
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
