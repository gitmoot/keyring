package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testListen   = "127.0.0.1:7702"
	testOrigin   = "http://127.0.0.1:7702"
	testPassword = "correct horse battery"
)

func newTestServer(t *testing.T) (*Server, *bytes.Buffer, *time.Time) {
	t.Helper()
	line, err := NewPasswordHash(testPassword, 1000)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := ParsePasswordHash(line)
	if err != nil {
		t.Fatal(err)
	}
	audit := &bytes.Buffer{}
	s := New(testListen, hash, audit)
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return s, audit, &now
}

type req struct {
	method, path, host, origin, cookie, csrf string
	form                                     url.Values
}

func (s *Server) do(r req) *httptest.ResponseRecorder {
	var body *strings.Reader
	if r.form != nil {
		body = strings.NewReader(r.form.Encode())
	} else {
		body = strings.NewReader("")
	}
	h := httptest.NewRequest(r.method, r.path, body)
	h.Host = testListen
	if r.host != "" {
		h.Host = r.host
	}
	if r.form != nil {
		h.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if r.origin != "" {
		h.Header.Set("Origin", r.origin)
	}
	if r.cookie != "" {
		h.AddCookie(&http.Cookie{Name: cookieName, Value: r.cookie})
	}
	if r.csrf != "" {
		h.Header.Set(csrfHeader, r.csrf)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, h)
	return w
}

func login(t *testing.T, s *Server) (sid, csrf string) {
	t.Helper()
	w := s.do(req{method: "POST", path: "/login", origin: testOrigin, form: url.Values{"password": {testPassword}}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("login status %d: %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == cookieName {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Fatalf("cookie attributes %+v", c)
			}
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no session cookie")
	}
	s.mu.Lock()
	csrf = s.sessions[sid].csrf
	s.mu.Unlock()
	return sid, csrf
}

func TestHostMustNameTheListener(t *testing.T) {
	s, _, _ := newTestServer(t)
	for _, host := range []string{"evil.example:7702", "127.0.0.1", "127.0.0.1:80", "localhost:9999", "keys.example.com"} {
		if w := s.do(req{method: "GET", path: "/login", host: host}); w.Code != http.StatusMisdirectedRequest {
			t.Errorf("Host %q: status %d, want 421", host, w.Code)
		}
	}
	for _, host := range []string{testListen, "localhost:7702"} {
		if w := s.do(req{method: "GET", path: "/login", host: host}); w.Code != http.StatusOK {
			t.Errorf("Host %q: status %d, want 200", host, w.Code)
		}
	}
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s, _, _ := newTestServer(t)
	for _, w := range []*httptest.ResponseRecorder{
		s.do(req{method: "GET", path: "/login"}),
		s.do(req{method: "GET", path: "/login", host: "evil.example:7702"}),
		s.do(req{method: "POST", path: "/login"}),
	} {
		h := w.Header()
		if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("Referrer-Policy") != "same-origin" || h.Get("Cache-Control") != "no-store" {
			t.Fatalf("status %d headers %v", w.Code, h)
		}
	}
}

func TestChangesNeedSameOrigin(t *testing.T) {
	s, _, _ := newTestServer(t)
	for _, origin := range []string{"", "http://evil.example", "http://localhost:7702.evil.example", "null"} {
		w := s.do(req{method: "POST", path: "/login", origin: origin, form: url.Values{"password": {testPassword}}})
		if w.Code != http.StatusForbidden {
			t.Errorf("Origin %q: status %d, want 403", origin, w.Code)
		}
	}
	s.mu.Lock()
	n := len(s.sessions)
	s.mu.Unlock()
	if n != 0 {
		t.Fatal("a cross-origin login created a session")
	}
}

func TestLoginLogoutAndCSRF(t *testing.T) {
	s, audit, _ := newTestServer(t)
	if w := s.do(req{method: "GET", path: "/"}); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("home without session: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := s.do(req{method: "GET", path: "/api/session"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("api without session: %d", w.Code)
	}
	sid, csrf := login(t, s)
	if w := s.do(req{method: "GET", path: "/", cookie: sid}); w.Code != 200 {
		t.Fatalf("home with session: %d", w.Code)
	}
	if w := s.do(req{method: "POST", path: "/logout", origin: testOrigin, cookie: sid}); w.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF token: %d, want 403", w.Code)
	}
	if w := s.do(req{method: "POST", path: "/logout", origin: testOrigin, cookie: sid, csrf: "wrong"}); w.Code != http.StatusForbidden {
		t.Fatalf("logout with wrong CSRF token: %d, want 403", w.Code)
	}
	if w := s.do(req{method: "POST", path: "/logout", origin: testOrigin, cookie: sid, csrf: csrf}); w.Code != http.StatusSeeOther {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := s.do(req{method: "GET", path: "/api/session", cookie: sid}); w.Code != http.StatusUnauthorized {
		t.Fatalf("session after logout: %d, want 401", w.Code)
	}
	if strings.Contains(audit.String(), testPassword) || strings.Contains(audit.String(), sid) || strings.Contains(audit.String(), csrf) {
		t.Fatalf("audit leaks the password, session or CSRF token:\n%s", audit.String())
	}
	if !strings.Contains(audit.String(), `"admin":"login"`) || !strings.Contains(audit.String(), `"admin":"logout"`) {
		t.Fatalf("audit misses login/logout:\n%s", audit.String())
	}
}

func TestWrongPasswordNeverLogsIn(t *testing.T) {
	s, audit, _ := newTestServer(t)
	w := s.do(req{method: "POST", path: "/login", origin: testOrigin, form: url.Values{"password": {"wrong password!!"}}})
	if w.Code != http.StatusUnauthorized || len(w.Result().Cookies()) != 0 {
		t.Fatalf("wrong password: %d cookies %v", w.Code, w.Result().Cookies())
	}
	if strings.Contains(w.Body.String(), "wrong password!!") || strings.Contains(audit.String(), "wrong password!!") {
		t.Fatal("the attempted password was echoed or logged")
	}
}

func TestSessionsExpire(t *testing.T) {
	s, _, now := newTestServer(t)
	sid, _ := login(t, s)
	*now = now.Add(IdleTimeout - time.Minute)
	if w := s.do(req{method: "GET", path: "/api/session", cookie: sid}); w.Code != 200 {
		t.Fatalf("before idle timeout: %d", w.Code)
	}
	*now = now.Add(IdleTimeout)
	if w := s.do(req{method: "GET", path: "/api/session", cookie: sid}); w.Code != http.StatusUnauthorized {
		t.Fatalf("after idle timeout: %d, want 401", w.Code)
	}
	sid, _ = login(t, s)
	for elapsed := time.Duration(0); elapsed < MaxLifetime; elapsed += 20 * time.Minute {
		*now = now.Add(20 * time.Minute)
		s.do(req{method: "GET", path: "/api/session", cookie: sid})
	}
	if w := s.do(req{method: "GET", path: "/api/session", cookie: sid}); w.Code != http.StatusUnauthorized {
		t.Fatalf("after max lifetime while active: %d, want 401", w.Code)
	}
}

func TestConfirmNeedsThePasswordEveryTime(t *testing.T) {
	s, audit, _ := newTestServer(t)
	sid, _ := login(t, s)
	// Right after login, a stolen session alone must not be enough.
	if s.Confirm(sid, "") {
		t.Fatal("confirmed without a password right after login")
	}
	if s.Confirm(sid, "nope nope nope") {
		t.Fatal("confirmed with a wrong password")
	}
	if !s.Confirm(sid, testPassword) {
		t.Fatal("right password refused")
	}
	if s.Confirm(sid, "") {
		t.Fatal("a confirmed change made the next one free")
	}
	if !strings.Contains(audit.String(), `"admin":"confirm_failed"`) {
		t.Fatalf("failed confirm not audited: %s", audit.String())
	}
	// Wrong passwords given to Confirm count toward the login limits.
	for i := 0; i < lockFailures; i++ {
		s.Confirm(sid, "nope nope nope")
	}
	if s.Confirm(sid, testPassword) {
		t.Fatal("confirm guesses are not limited")
	}
}

func TestLoginLimitsHoldForRequestsSentAtOnce(t *testing.T) {
	s, _, _ := newTestServer(t)
	// A slow hash widens the gap between the limit check and the result.
	line, _ := NewPasswordHash(testPassword, 100000)
	hash, _ := ParsePasswordHash(line)
	s.SetPassword(hash)
	const burst = 60
	var checked atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := s.do(req{method: "POST", path: "/login", origin: testOrigin, form: url.Values{"password": {"not the password"}}})
			if w.Code == http.StatusUnauthorized {
				checked.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if n := checked.Load(); n > freeFailures+1 {
		t.Fatalf("%d of %d simultaneous guesses were checked; the limit allows %d", n, burst, freeFailures+1)
	}
}

func TestLoginLimits(t *testing.T) {
	s, _, now := newTestServer(t)
	bad := url.Values{"password": {"not the password"}}
	for i := 0; i < freeFailures; i++ {
		if w := s.do(req{method: "POST", path: "/login", origin: testOrigin, form: bad}); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d, want 401", i+1, w.Code)
		}
	}
	s.do(req{method: "POST", path: "/login", origin: testOrigin, form: bad}) // sixth failure starts the delay
	w := s.do(req{method: "POST", path: "/login", origin: testOrigin, form: url.Values{"password": {testPassword}}})
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("during the delay even the right password: %d, want 429", w.Code)
	}
	*now = now.Add(time.Minute)
	if w := s.do(req{method: "POST", path: "/login", origin: testOrigin, form: url.Values{"password": {testPassword}}}); w.Code != http.StatusSeeOther {
		t.Fatalf("after the delay: %d", w.Code)
	}
	for i := 0; i < lockFailures; i++ {
		s.do(req{method: "POST", path: "/login", origin: testOrigin, form: bad})
		*now = now.Add(70 * time.Second)
	}
	*now = now.Add(30 * time.Minute)
	if w := s.do(req{method: "POST", path: "/login", origin: testOrigin, form: url.Values{"password": {testPassword}}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("locked: %d, want 429", w.Code)
	}
}

func TestPasswordChangeEndsSessions(t *testing.T) {
	s, _, _ := newTestServer(t)
	sid, _ := login(t, s)
	line, _ := NewPasswordHash("a different password", 1000)
	next, _ := ParsePasswordHash(line)
	if !s.SetPassword(next) {
		t.Fatal("change not detected")
	}
	if w := s.do(req{method: "GET", path: "/api/session", cookie: sid}); w.Code != http.StatusUnauthorized {
		t.Fatalf("session after password change: %d", w.Code)
	}
	if s.SetPassword(next) {
		t.Fatal("same hash reported as a change")
	}
}

func TestPasswordHashAndFile(t *testing.T) {
	if _, err := NewPasswordHash("short", 1000); err == nil {
		t.Fatal("short password accepted")
	}
	line, err := NewPasswordHash(testPassword, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(line, testPassword) {
		t.Fatal("hash line contains the password")
	}
	other, _ := NewPasswordHash(testPassword, 1000)
	if line == other {
		t.Fatal("two hashes of one password are equal: salt not random")
	}
	h, _ := ParsePasswordHash(line)
	if !h.Matches(testPassword) || h.Matches(testPassword+"x") || h.Matches("") {
		t.Fatal("Matches wrong")
	}
	if (PasswordHash{}).Matches("") {
		t.Fatal("empty hash matched")
	}
	path := filepath.Join(t.TempDir(), "admin.pw")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadPasswordFile(path); err != nil || !got.Equal(h) {
		t.Fatalf("load: %v", err)
	}
	for _, mode := range []os.FileMode{0o644, 0o660} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPasswordFile(path); err == nil {
			t.Fatalf("mode %04o accepted", mode)
		}
	}
}
