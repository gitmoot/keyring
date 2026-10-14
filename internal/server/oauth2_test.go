package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const (
	testRefresh = "1//refresh-token-0123456789"
	testSecret  = "client-secret-abcdefghij"
)

// tokenEndpoint is a fake OAuth token endpoint. It hands out access-1,
// access-2, ... and records the forms it got. reply, when set, answers
// instead.
type tokenEndpoint struct {
	srv   *httptest.Server
	calls atomic.Int32
	mu    sync.Mutex
	forms []map[string]string
	// gate, when set, holds every refresh until it is closed.
	gate  chan struct{}
	reply func(w http.ResponseWriter)
}

func newTokenEndpoint(t *testing.T, expiresIn int) *tokenEndpoint {
	t.Helper()
	te := &tokenEndpoint{}
	te.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := te.calls.Add(1)
		if err := r.ParseForm(); err != nil || r.Method != http.MethodPost {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		te.mu.Lock()
		te.forms = append(te.forms, form)
		gate, reply := te.gate, te.reply
		te.mu.Unlock()
		if gate != nil {
			<-gate
		}
		if reply != nil {
			reply(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"ya29.access-%d","token_type":"Bearer","expires_in":%d}`, n, expiresIn)
	}))
	t.Cleanup(te.srv.Close)
	return te
}

// newOAuthHandler builds a handler with one oauth2 service "api" (refresh
// token API_KEY, client secret CLIENT_SECRET) and a clock the test moves.
func newOAuthHandler(t *testing.T, base, tokenURL string, access policy.Access) (*Handler, *bytes.Buffer, *time.Time) {
	t.Helper()
	svc := policy.Service{
		Auth:     policy.AuthOAuth2,
		TestPath: "/v1/test",
		OAuth2:   &policy.OAuth2{TokenURL: tokenURL, ClientID: "client-id.apps", ClientSecretKey: "CLIENT_SECRET"},
	}
	h, audit := newHandlerKey(t, base, svc, access, testRefresh)
	cfg := h.Config()
	h.Swap(cfg, map[string]string{"API_KEY": testRefresh, "CLIENT_SECRET": testSecret})
	clock := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return clock }
	return h, audit, &clock
}

func authOf(r *http.Request) string { return r.Header.Get("Authorization") }

func TestOAuthRefreshesBeforeExpiry(t *testing.T) {
	up, got := upstream(t)
	te := newTokenEndpoint(t, 3600)
	h, _, clock := newOAuthHandler(t, up.URL, te.srv.URL, policy.Access{Paths: []string{"/"}})

	if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK {
		t.Fatalf("first call: %d %s", w.Code, w.Body)
	}
	if a := authOf(got.last(t)); a != "Bearer ya29.access-1" {
		t.Fatalf("upstream Authorization = %q", a)
	}
	te.mu.Lock()
	form := te.forms[0]
	te.mu.Unlock()
	if form["grant_type"] != "refresh_token" || form["refresh_token"] != testRefresh || form["client_id"] != "client-id.apps" || form["client_secret"] != testSecret {
		t.Fatalf("token request form = %v", form)
	}

	// Still valid for more than a minute: reused.
	*clock = clock.Add(58 * time.Minute)
	call(h, "GET", "/api/v1/x", testToken, nil)
	if a := authOf(got.last(t)); a != "Bearer ya29.access-1" || te.calls.Load() != 1 {
		t.Fatalf("at 58m: Authorization %q after %d refreshes; want the cached token", a, te.calls.Load())
	}
	// Less than a minute left: replaced before it expires.
	*clock = clock.Add(90 * time.Second)
	call(h, "GET", "/api/v1/x", testToken, nil)
	if a := authOf(got.last(t)); a != "Bearer ya29.access-2" || te.calls.Load() != 2 {
		t.Fatalf("at 59m30s: Authorization %q after %d refreshes; want a new token", a, te.calls.Load())
	}

	// The refresh token and client secret never reach the API.
	got.mu.Lock()
	defer got.mu.Unlock()
	for i, r := range got.requests {
		blob := fmt.Sprint(r.URL, r.Header) + got.bodies[i]
		if strings.Contains(blob, testRefresh) || strings.Contains(blob, testSecret) {
			t.Fatalf("upstream request %d carried the refresh token or client secret: %s", i, blob)
		}
	}
}

func TestOAuthConcurrentCallsShareOneRefresh(t *testing.T) {
	up, got := upstream(t)
	te := newTokenEndpoint(t, 3600)
	te.gate = make(chan struct{})
	h, _, _ := newOAuthHandler(t, up.URL, te.srv.URL, policy.Access{Paths: []string{"/"}})

	const n = 20
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- call(h, "GET", "/api/v1/x", testToken, nil).Code
		}()
	}
	// Let every caller reach the refresh before the endpoint answers.
	deadline := time.Now().Add(5 * time.Second)
	for te.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(te.gate)
	wg.Wait()
	close(codes)
	for code := range codes {
		if code != http.StatusOK {
			t.Fatalf("a concurrent call got %d", code)
		}
	}
	if c := te.calls.Load(); c != 1 {
		t.Fatalf("%d refreshes for %d concurrent calls; want 1", c, n)
	}
	got.mu.Lock()
	defer got.mu.Unlock()
	for _, r := range got.requests {
		if a := authOf(r); a != "Bearer ya29.access-1" {
			t.Fatalf("upstream Authorization = %q", a)
		}
	}
}

func TestOAuthRevokedRefreshTokenFailsClosed(t *testing.T) {
	up, got := upstream(t)
	te := newTokenEndpoint(t, 3600)
	te.reply = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		// The description is the provider's free text; it must not be passed on.
		io.WriteString(w, `{"error":"invalid_grant","error_description":"Token has been expired or revoked. `+testRefresh+`"}`)
	}
	h, audit, clock := newOAuthHandler(t, up.URL, te.srv.URL, policy.Access{Paths: []string{"/"}, DailyRequests: 1})

	w := call(h, "GET", "/api/v1/x", testToken, nil)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "invalid_grant") || !strings.Contains(w.Body.String(), "connect the account again") {
		t.Fatalf("revoked: %d %q; want 503 naming invalid_grant", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "revoked. ") {
		t.Fatalf("provider description passed to the caller: %q", w.Body)
	}
	if got.count() != 0 {
		t.Fatal("the API was called without a valid access token")
	}
	if f := h.OAuthFailure("API_KEY"); !strings.Contains(f, "invalid_grant") {
		t.Fatalf("OAuthFailure = %q; want the refresh failure for the dashboard", f)
	}
	// A failed refresh is not retried on every call...
	call(h, "GET", "/api/v1/x", testToken, nil)
	if c := te.calls.Load(); c != 1 {
		t.Fatalf("%d refreshes within the retry delay; want 1", c)
	}
	// ...and did not use up the daily limit, which allows only 1.
	te.mu.Lock()
	te.reply = nil
	te.mu.Unlock()
	*clock = clock.Add(oauthRetry)
	if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK {
		t.Fatalf("after the account is fixed: %d %s", w.Code, w.Body)
	}
	if f := h.OAuthFailure("API_KEY"); f != "" {
		t.Fatalf("OAuthFailure after success = %q", f)
	}
	if strings.Contains(audit.String(), testRefresh) {
		t.Fatal("audit log holds the refresh token")
	}
}

func TestOAuthTransientFailureIsBadGateway(t *testing.T) {
	up, got := upstream(t)
	te := newTokenEndpoint(t, 3600)
	te.reply = func(w http.ResponseWriter) { http.Error(w, "down", http.StatusInternalServerError) }
	h, _, _ := newOAuthHandler(t, up.URL, te.srv.URL, policy.Access{Paths: []string{"/"}})
	w := call(h, "GET", "/api/v1/x", testToken, nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "answered 500") {
		t.Fatalf("token endpoint down: %d %q; want 502", w.Code, w.Body)
	}
	if got.count() != 0 {
		t.Fatal("the API was called without an access token")
	}
}

func TestOAuthTokensNeverLogged(t *testing.T) {
	up, _ := upstream(t)
	te := newTokenEndpoint(t, 3600)
	h, audit, _ := newOAuthHandler(t, up.URL, te.srv.URL, policy.Access{Paths: []string{"/"}})
	// /v1/deflate is refused (502) after reaching the API; /v1/x succeeds.
	for _, p := range []string{"/api/v1/x", "/api/v1/deflate", "/api/v1/x?access_token=ya29.access-1"} {
		call(h, "GET", p, testToken, nil)
	}
	log := audit.String()
	if strings.Count(log, "\n") != 3 {
		t.Fatalf("want 3 audit lines, got:\n%s", log)
	}
	for _, secret := range []string{"ya29.access-1", testRefresh, testSecret} {
		if strings.Contains(log, secret) {
			t.Fatalf("audit log holds %q:\n%s", secret, log)
		}
	}
}

func TestOAuthEchoedSecretsRedacted(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		io.WriteString(w, r.Header.Get("Authorization")+" "+testRefresh+" "+testSecret)
	}))
	t.Cleanup(echo.Close)
	te := newTokenEndpoint(t, 3600)
	h, _, _ := newOAuthHandler(t, echo.URL, te.srv.URL, policy.Access{Paths: []string{"/"}})
	w := call(h, "GET", "/api/v1/x", testToken, nil)
	out := fmt.Sprint(w.Header()) + w.Body.String()
	for _, secret := range []string{"ya29.access-1", testRefresh, testSecret} {
		if strings.Contains(out, secret) {
			t.Fatalf("reply to the caller holds %q: %s", secret, out)
		}
	}
}

func TestOAuthUpstream401MintsNewToken(t *testing.T) {
	var rejectFirst atomic.Bool
	rejectFirst.Store(true)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rejectFirst.Swap(false) {
			http.Error(w, "revoked", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "ok "+r.Header.Get("X-Seen"))
	}))
	t.Cleanup(api.Close)
	te := newTokenEndpoint(t, 3600)
	h, _, _ := newOAuthHandler(t, api.URL, te.srv.URL, policy.Access{Paths: []string{"/"}})
	if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("first call: %d", w.Code)
	}
	if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK {
		t.Fatalf("second call: %d", w.Code)
	}
	if c := te.calls.Load(); c != 2 {
		t.Fatalf("%d refreshes; want a new token after the API refused the first", c)
	}
}

func TestOAuthReplacedRefreshTokenNotReused(t *testing.T) {
	up, got := upstream(t)
	te := newTokenEndpoint(t, 3600)
	h, _, _ := newOAuthHandler(t, up.URL, te.srv.URL, policy.Access{Paths: []string{"/"}})
	call(h, "GET", "/api/v1/x", testToken, nil)
	h.Swap(h.Config(), map[string]string{"API_KEY": "1//another-account", "CLIENT_SECRET": testSecret})
	call(h, "GET", "/api/v1/x", testToken, nil)
	if a := authOf(got.last(t)); a != "Bearer ya29.access-2" {
		t.Fatalf("after replacing the refresh token, Authorization = %q; want a token minted from the new one", a)
	}
	te.mu.Lock()
	defer te.mu.Unlock()
	if te.forms[1]["refresh_token"] != "1//another-account" {
		t.Fatalf("second refresh used %q", te.forms[1]["refresh_token"])
	}
}

func TestOAuthTestKeyMintsWithGivenRefreshToken(t *testing.T) {
	up, got := upstream(t)
	te := newTokenEndpoint(t, 3600)
	h, _, _ := newOAuthHandler(t, up.URL, te.srv.URL, policy.Access{Paths: []string{"/"}})
	status, err := h.TestKey(t.Context(), h.Config().Services["api"], testRefresh)
	if err != nil || status != http.StatusOK {
		t.Fatalf("TestKey = %d, %v", status, err)
	}
	if r := got.last(t); r.URL.Path != "/v1/test" || authOf(r) != "Bearer ya29.access-1" {
		t.Fatalf("test request %s with %q", r.URL.Path, authOf(r))
	}
}
