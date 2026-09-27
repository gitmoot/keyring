package dashboard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
)

func (e *env) call(method, path, tok string) int {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set(server.TokenHeader, tok)
	w := httptest.NewRecorder()
	e.proxy.ServeHTTP(w, r)
	return w.Code
}

func (e *env) saveCell(role, service string, form url.Values) *httptest.ResponseRecorder {
	if !form.Has("password") {
		form.Set("password", password)
	}
	return e.request("POST", "/access/"+role+"/"+service, form)
}

var tokenInPage = regexp.MustCompile(`id="token" readonly autocomplete="off" value="([^"]+)"`)

func tokenFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	m := tokenInPage.FindStringSubmatch(w.Body.String())
	if w.Code != 200 || m == nil {
		t.Fatalf("no token shown: %d\n%s", w.Code, w.Body.String())
	}
	return m[1]
}

func TestGridChangesApplyToTheNextCall(t *testing.T) {
	e := newEnv(t)
	if code := e.call("GET", "/api/v1/x", token); code != 200 {
		t.Fatalf("before: %d", code)
	}
	if w := e.saveCell("phobos", "api", url.Values{"on": {"yes"}, "mode": {"read"}, "paths": {"/v2\n"}, "daily": {"2"}}); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatalf("save: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if code := e.call("GET", "/api/v1/x", token); code != http.StatusForbidden {
		t.Fatalf("old path after change: %d, want 403", code)
	}
	if code := e.call("POST", "/api/v2/x", token); code != http.StatusForbidden {
		t.Fatalf("POST on read only: %d, want 403", code)
	}
	for i := 0; i < 2; i++ {
		if code := e.call("GET", "/api/v2/x", token); code != 200 {
			t.Fatalf("new path call %d: %d", i, code)
		}
	}
	if code := e.call("GET", "/api/v2/x", token); code != http.StatusTooManyRequests {
		t.Fatalf("third call over a limit of 2: %d, want 429", code)
	}
	page := e.request("GET", "/access", nil).Body.String()
	if !strings.Contains(page, "Read only") || !strings.Contains(page, "6 calls today · limit 2") {
		t.Fatalf("grid does not show the new cell:\n%s", page)
	}
	e.saveCell("phobos", "api", url.Values{"mode": {"read"}, "paths": {"/"}}) // box unticked: off
	if code := e.call("GET", "/api/v2/x", token); code != http.StatusForbidden {
		t.Fatalf("after switching off: %d, want 403", code)
	}
	if page := e.request("GET", "/access", nil).Body.String(); strings.Contains(page, `href="/access/phobos/api"`) || !strings.Contains(page, "<option>api</option>") {
		t.Fatal("the agents page still shows api as granted, or does not offer to add it")
	}
}

func TestInvalidCellIsRefusedAndTheOldStateStays(t *testing.T) {
	e := newEnv(t)
	before, _ := os.ReadFile(e.proxy.Config().AccessFile)
	for name, form := range map[string]url.Values{
		"relative path":     {"on": {"yes"}, "mode": {"read"}, "paths": {"v1"}},
		"dot-dot path":      {"on": {"yes"}, "mode": {"read"}, "paths": {"/v1/../admin"}},
		"no path":           {"on": {"yes"}, "mode": {"read"}, "paths": {"  \n"}},
		"negative limit":    {"on": {"yes"}, "mode": {"read"}, "paths": {"/"}, "daily": {"-3"}},
		"word limit":        {"on": {"yes"}, "mode": {"read"}, "paths": {"/"}, "daily": {"lots"}},
		"end date passed":   {"on": {"yes"}, "mode": {"read"}, "paths": {"/"}, "expires": {"2020-01-01"}},
		"bad end date":      {"on": {"yes"}, "mode": {"read"}, "paths": {"/"}, "expires": {"soon"}},
		"no custom methods": {"on": {"yes"}, "mode": {"custom"}, "paths": {"/"}},
		"unknown method":    {"on": {"yes"}, "mode": {"custom"}, "method": {"GET", "TRACE"}, "paths": {"/"}},
	} {
		if w := e.saveCell("phobos", "api", form); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, w.Code)
		}
	}
	if after, _ := os.ReadFile(e.proxy.Config().AccessFile); !bytes.Equal(before, after) {
		t.Fatal("a refused change was written")
	}
	if code := e.call("GET", "/api/v1/x", token); code != 200 {
		t.Fatalf("old access no longer works: %d", code)
	}
	if !strings.Contains(e.request("GET", "/access", nil).Body.String(), "GET, HEAD, POST") {
		t.Fatal("grid no longer shows the old state")
	}
	if w := e.saveCell("nobody", "api", url.Values{"on": {"yes"}, "mode": {"read"}, "paths": {"/"}}); w.Code != http.StatusNotFound {
		t.Fatalf("unknown agent: %d, want 404", w.Code)
	}
}

func TestAddAgentShowsItsTokenInOneResponseOnly(t *testing.T) {
	e := newEnv(t)
	w := e.request("POST", "/agents", url.Values{"name": {"deimos"}, "password": {password}})
	tok := tokenFrom(t, w)
	if !strings.Contains(w.Body.String(), "/etc/keyring/tokens/deimos.token") {
		t.Fatal("token page does not say where the token goes")
	}
	if code := e.call("GET", "/api/v1/x", tok); code != http.StatusForbidden {
		t.Fatalf("new agent with no access: %d, want 403", code)
	}
	e.saveCell("deimos", "api", url.Values{"on": {"yes"}, "mode": {"read"}, "paths": {"/"}})
	if code := e.call("GET", "/api/v1/x", tok); code != 200 {
		t.Fatalf("new agent after grant: %d", code)
	}
	raw, _ := os.ReadFile(e.proxy.Config().AccessFile)
	for where, text := range map[string]string{
		"a page":      e.everyPage("/access", "/agents/deimos", "/access/deimos/api", "/new/agent"),
		"the audit":   e.audit.String(),
		"access file": string(raw),
	} {
		if strings.Contains(text, tok) {
			t.Fatalf("the token appears in %s", where)
		}
	}
	w = e.request("POST", "/agents", url.Values{"name": {"deimos"}, "password": {password}})
	if w.Code != http.StatusConflict || tokenInPage.MatchString(w.Body.String()) {
		t.Fatalf("second add of the same name: %d", w.Code)
	}
	if w := e.request("POST", "/agents", url.Values{"name": {"-bad name"}, "password": {password}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad name: %d, want 400", w.Code)
	}
}

func currentFrom(t *testing.T, e *env, role string) string {
	t.Helper()
	m := regexp.MustCompile(`name="current" value="([0-9a-f]{12})"`).FindStringSubmatch(e.request("GET", "/agents/"+role, nil).Body.String())
	if m == nil {
		t.Fatal("agent page has no current-token field")
	}
	return m[1]
}

func TestNewTokenReplacesTheOldOneOnce(t *testing.T) {
	e := newEnv(t)
	form := url.Values{"current": {currentFrom(t, e, "phobos")}, "password": {password}}
	fresh := tokenFrom(t, e.request("POST", "/agents/phobos/token", form))
	if code := e.call("GET", "/api/v1/x", token); code != http.StatusUnauthorized {
		t.Fatalf("old token after a new one: %d, want 401", code)
	}
	if code := e.call("GET", "/api/v1/x", fresh); code != 200 {
		t.Fatalf("new token: %d", code)
	}
	// The same form again, as a reload of the result page would send it.
	w := e.request("POST", "/agents/phobos/token", url.Values{"current": form["current"], "password": {password}})
	if !strings.Contains(w.Header().Get("Location"), "error=stale") || tokenInPage.MatchString(w.Body.String()) {
		t.Fatalf("form sent twice: %d %s", w.Code, w.Header().Get("Location"))
	}
	if code := e.call("GET", "/api/v1/x", fresh); code != 200 {
		t.Fatalf("the token just shown stopped working: %d", code)
	}
	if !strings.Contains(e.audit.String(), `"admin":"token_replaced"`) || strings.Contains(e.audit.String(), fresh) {
		t.Fatal("audit missing the change or holding the token")
	}
}

func TestRevokeEndsTheAgentAtOnce(t *testing.T) {
	e := newEnv(t)
	if w := e.request("POST", "/agents/phobos/revoke", url.Values{"password": {password}}); !strings.Contains(w.Header().Get("Location"), "error=confirm") {
		t.Fatalf("revoke without the tick: %s", w.Header().Get("Location"))
	}
	if code := e.call("GET", "/api/v1/x", token); code != 200 {
		t.Fatalf("revoked without the tick: %d", code)
	}
	if w := e.request("POST", "/agents/phobos/revoke", url.Values{"confirm": {"yes"}, "password": {password}}); w.Header().Get("Location") != "/access?done=revoked" {
		t.Fatalf("revoke: %d %s", w.Code, w.Header().Get("Location"))
	}
	if code := e.call("GET", "/api/v1/x", token); code != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d, want 401", code)
	}
	if strings.Contains(e.request("GET", "/access", nil).Body.String(), `href="/agents/phobos"`) {
		t.Fatal("grid still lists the revoked agent")
	}
}

func TestAccessChangesNeedThePassword(t *testing.T) {
	e := newEnv(t)
	before, _ := os.ReadFile(e.proxy.Config().AccessFile)
	if w := e.saveCell("phobos", "api", url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}, "password": {""}}); w.Code != http.StatusForbidden {
		t.Fatalf("grant without password: %d, want 403", w.Code)
	}
	if w := e.request("POST", "/agents", url.Values{"name": {"deimos"}}); w.Code != http.StatusForbidden || tokenInPage.MatchString(w.Body.String()) {
		t.Fatalf("add agent without password: %d", w.Code)
	}
	cur := currentFrom(t, e, "phobos")
	if w := e.request("POST", "/agents/phobos/token", url.Values{"current": {cur}, "password": {"wrong password!!"}}); !strings.Contains(w.Header().Get("Location"), "error=password") {
		t.Fatalf("new token with a wrong password: %s", w.Header().Get("Location"))
	}
	if w := e.request("POST", "/agents/phobos/revoke", url.Values{"confirm": {"yes"}}); !strings.Contains(w.Header().Get("Location"), "error=password") {
		t.Fatalf("revoke without password: %s", w.Header().Get("Location"))
	}
	if after, _ := os.ReadFile(e.proxy.Config().AccessFile); !bytes.Equal(before, after) {
		t.Fatal("a change without the password was written")
	}
	if code := e.call("GET", "/api/v1/x", token); code != 200 {
		t.Fatalf("token changed without the password: %d", code)
	}
}

func TestCellEndDateAndEditorRoundTrip(t *testing.T) {
	e := newEnv(t)
	end := time.Now().UTC().AddDate(0, 0, 3).Format(time.DateOnly)
	e.saveCell("phobos", "api", url.Values{"on": {"yes"}, "mode": {"custom"}, "method": {"GET", "DELETE"}, "paths": {"/v1\n/v3"}, "daily": {"50"}, "expires": {end}})
	page := e.request("GET", "/access/phobos/api", nil).Body.String()
	for _, want := range []string{`value="custom" checked`, `value="DELETE" checked`, "/v1\n/v3", `value="50"`, `value="` + end + `"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("editor does not show %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `value="POST" checked`) {
		t.Fatal("editor ticks a method that was not granted")
	}
	if code := e.call("DELETE", "/api/v3/x", token); code != 200 {
		t.Fatalf("granted custom method: %d", code)
	}
	if !strings.Contains(e.request("GET", "/access", nil).Body.String(), "GET, DELETE") {
		t.Fatal("grid label for custom methods")
	}
}

func TestChangesKeepHandEditsNotYetReloaded(t *testing.T) {
	e := newEnv(t)
	access, err := policy.LoadAccess(e.proxy.Config().AccessFile)
	if err != nil {
		t.Fatal(err)
	}
	access.Roles["manual"] = policy.Role{TokenSHA256: strings.Repeat("ab", 32), Access: map[string]policy.Access{"api": {Paths: []string{"/"}}}}
	if _, err := policy.SaveAccess(e.proxy.Config().Rules, access); err != nil { // by hand, no SIGHUP
		t.Fatal(err)
	}
	e.addAndConnect("OTHER_KEY", "sk-other-0123456789", url.Values{"service": {"other"}, "base": {"https://other.example.com"}, "auth": {"bearer"}})
	e.saveCell("phobos", "other", url.Values{"on": {"yes"}, "mode": {"read"}, "paths": {"/"}})
	after, err := policy.LoadAccess(e.proxy.Config().AccessFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Roles["manual"]; !ok {
		t.Fatal("a dashboard change dropped a hand edit")
	}
	if _, ok := after.Roles["phobos"].Access["other"]; !ok || after.Services["other"].Key != "OTHER_KEY" {
		t.Fatalf("the dashboard changes are missing: %+v", after)
	}
	if !strings.Contains(e.request("GET", "/access", nil).Body.String(), `href="/agents/manual"`) {
		t.Fatal("the hand edit was not applied with the change")
	}
}

func TestFailedChangeLeavesFileAndRunningConfigAlike(t *testing.T) {
	e := newEnv(t)
	cur := currentFrom(t, e, "phobos")
	before, _ := os.ReadFile(e.proxy.Config().AccessFile)
	// The store cannot be read: a change must fail before it writes anything.
	if err := os.WriteFile(e.backend.StorePath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := e.request("POST", "/agents/phobos/token", url.Values{"current": {cur}, "password": {password}})
	if tokenInPage.MatchString(w.Body.String()) {
		t.Fatal("a token was shown although the change failed")
	}
	e.saveCell("phobos", "api", url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}})
	if after, _ := os.ReadFile(e.proxy.Config().AccessFile); !bytes.Equal(before, after) {
		t.Fatal("the access file changed although the change failed")
	}
	if code := e.call("GET", "/api/v1/x", token); code != 200 {
		t.Fatalf("the old token stopped working: %d", code)
	}
}

func TestAgentNamedNewHasAPage(t *testing.T) {
	e := newEnv(t)
	tokenFrom(t, e.request("POST", "/agents", url.Values{"name": {"new"}, "password": {password}}))
	if body := e.request("GET", "/agents/new", nil).Body.String(); !strings.Contains(body, `action="/agents/new/revoke"`) {
		t.Fatalf("/agents/new is not the agent's page:\n%s", body)
	}
}

func TestChangesWorkWhenTheAccessFileLeavesAListOut(t *testing.T) {
	e := newEnv(t)
	path := e.proxy.Config().AccessFile
	if err := os.WriteFile(path, []byte(`{"services":{"api":{"base":"https://api.example.com","key":"API_KEY","auth":"bearer"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFrom(t, e.request("POST", "/agents", url.Values{"name": {"deimos"}, "password": {password}}))
	if err := os.WriteFile(path, []byte(`{"roles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, w := e.addAndConnect("NEW_KEY", "sk-new-0123456789", url.Values{"service": {"newsvc"}, "base": {"https://new.example.com"}, "auth": {"bearer"}})
	if !strings.Contains(w.Header().Get("Location"), "done=connected") {
		t.Fatalf("connect with no services list: %d %s", w.Code, w.Body.String())
	}
}
