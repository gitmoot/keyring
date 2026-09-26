package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	auth.Base, auth.Key = base, "API_KEY"
	cfg := &policy.Config{
		Listen:       "127.0.0.1:7701",
		AllowSources: []string{caller},
		AuditLog:     "audit.log",
		Services:     map[string]policy.Service{"api": auth},
		Roles: map[string]policy.Role{
			"phobos": {TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"api": access}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	audit := &bytes.Buffer{}
	return New(cfg, map[string]string{"API_KEY": testKey}, audit), audit
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
	call(h, "GET", "/api/v1/x", testToken, map[string]string{"X-Api-Key": "caller-supplied"})
	if v := got.last(t).Header.Values("X-Api-Key"); len(v) != 1 || v[0] != testKey {
		t.Fatalf("X-Api-Key = %v", v)
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
	h.keys = map[string]string{}
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != http.StatusServiceUnavailable || got.count() != 0 {
		t.Fatalf("status %d, upstream calls %d", w.Code, got.count())
	}
}

func TestExpiredRoleRefused(t *testing.T) {
	up, got := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	past := time.Now().Add(-time.Hour)
	role := h.config.Roles["phobos"]
	role.Expires = &past
	h.config.Roles["phobos"] = role
	if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != http.StatusUnauthorized || got.count() != 0 {
		t.Fatalf("status %d, upstream calls %d", w.Code, got.count())
	}
}

func TestRedactorHoldsBackOnlyAPossiblePrefix(t *testing.T) {
	var out bytes.Buffer
	r := newRedactor(&out, []byte("SECRET"))
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
