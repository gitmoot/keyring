package dashboard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
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

	"github.com/gitmoot/keyring/internal/admin"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

const (
	listen   = "127.0.0.1:7702"
	origin   = "http://127.0.0.1:7702"
	password = "dashboard test password"
	token    = "role-token-phobos-0123456789"
	oldValue = "sk-dash-old-VALUE-0123456789"
	newValue = "sk-dash-new-VALUE-9876543210"
)

type env struct {
	t        *testing.T
	backend  *Backend
	admin    *admin.Server
	proxy    *server.Handler
	audit    *bytes.Buffer
	now      *time.Time
	cookie   string
	csrf     string
	seenAuth atomic.Value // last Authorization the fake service got
	status   atomic.Int32 // what the fake service answers
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t}
	e.status.Store(200)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.seenAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(int(e.status.Load()))
		// Echo the key, as a careless API might.
		_, _ = io.WriteString(w, "echo "+r.Header.Get("Authorization"))
	}))
	t.Cleanup(api.Close)
	dir := t.TempDir()
	rules := policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{"127.0.0.1"}, AuditLog: filepath.Join(dir, "audit.log"), AccessFile: filepath.Join(dir, "access.json")}
	sum := sha256.Sum256([]byte(token))
	access := policy.AccessList{
		Services: map[string]policy.Service{"api": {Base: api.URL, Key: "API_KEY", Auth: policy.AuthBearer, TestPath: "/v1/check"}},
		Roles:    map[string]policy.Role{"phobos": {TokenSHA256: hex.EncodeToString(sum[:]), Access: map[string]policy.Access{"api": {Paths: []string{"/v1"}}}}},
	}
	cfg, err := policy.SaveAccess(rules, access)
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(dir, "keys.json")
	if err := store.Set(storePath, "API_KEY", oldValue); err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(storePath)
	e.audit = &bytes.Buffer{}
	e.proxy = server.New(cfg, keys, e.audit)
	line, _ := admin.NewPasswordHash(password, 1000)
	hash, _ := admin.ParsePasswordHash(line)
	e.admin = admin.New(listen, hash, e.audit)
	now := time.Now().UTC()
	e.now = &now
	clock := func() time.Time { return *e.now }
	e.admin.SetClock(clock)
	e.backend = &Backend{Mu: &sync.Mutex{}, StorePath: storePath, MetaPath: filepath.Join(dir, "keymeta.json"), Proxy: e.proxy, Admin: e.admin, Now: clock}
	Register(e.backend)
	e.login()
	return e
}

func (e *env) request(method, path string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader = http.NoBody
	if form != nil {
		form.Set("csrf", e.csrf)
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	r.Host = listen
	if method != "GET" {
		r.Header.Set("Origin", origin)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if e.cookie != "" {
		r.AddCookie(&http.Cookie{Name: "keyring_session", Value: e.cookie})
	}
	w := httptest.NewRecorder()
	e.admin.ServeHTTP(w, r)
	return w
}

func (e *env) login() {
	w := e.request("POST", "/login", url.Values{"password": {password}})
	for _, c := range w.Result().Cookies() {
		if c.Name == "keyring_session" {
			e.cookie = c.Value
		}
	}
	if e.cookie == "" {
		e.t.Fatalf("login failed: %d", w.Code)
	}
	e.csrf = e.admin.CSRF(e.cookie)
}

// everyPage fetches every page a user can see and returns the combined HTML.
func (e *env) everyPage(names ...string) string {
	var all strings.Builder
	for _, p := range append([]string{"/keys", "/keys?q=api", "/new/key"}, names...) {
		w := e.request("GET", p, nil)
		all.WriteString(w.Body.String())
	}
	return all.String()
}

func (e *env) proxyCall() int {
	r := httptest.NewRequest("GET", "/api/v1/x", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set(server.TokenHeader, token)
	w := httptest.NewRecorder()
	e.proxy.ServeHTTP(w, r)
	return w.Code
}

func TestKeysPageListsWithoutValues(t *testing.T) {
	e := newEnv(t)
	e.proxyCall()
	w := e.request("GET", "/keys", nil)
	body := w.Body.String()
	if w.Code != 200 || !strings.Contains(body, "API_KEY") || !strings.Contains(body, "phobos") || !strings.Contains(body, "just now") {
		t.Fatalf("keys page %d:\n%s", w.Code, body)
	}
	if strings.Contains(e.everyPage("/keys/API_KEY"), oldValue) {
		t.Fatal("a page shows the key value")
	}
	if w := e.request("GET", "/", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/keys" {
		t.Fatalf("home: %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestAddKeyWithNewServiceNeverEchoesTheValue(t *testing.T) {
	e := newEnv(t)
	const value = "sk-added-VALUE-abcdef012345"
	w := e.request("POST", "/keys", url.Values{"name": {"TAVILY_API_KEY"}, "value": {value}, "mode": {"new"}, "password": {password},
		"svc_name": {"tavily"}, "base": {"https://api.tavily.com"}, "auth": {"bearer"}, "test_method": {"GET"}, "test_path": {"/usage"}})
	if w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), value) {
		t.Fatalf("add: %d %s", w.Code, w.Body.String())
	}
	keys, _ := store.Load(e.backend.StorePath)
	if keys["TAVILY_API_KEY"] != value {
		t.Fatal("value not stored")
	}
	if svc, ok := e.proxy.Config().Services["tavily"]; !ok || svc.Key != "TAVILY_API_KEY" {
		t.Fatalf("service not added to the running proxy: %+v", e.proxy.Config().Services)
	}
	if strings.Contains(e.everyPage("/keys/TAVILY_API_KEY"), value) || strings.Contains(e.audit.String(), value) {
		t.Fatal("the value appears in a page or the audit log")
	}
	if !strings.Contains(e.audit.String(), `"admin":"key_added"`) {
		t.Fatalf("audit: %s", e.audit.String())
	}
}

func TestRefusedAddLeavesNothingBehind(t *testing.T) {
	e := newEnv(t)
	before, _ := os.ReadFile(e.proxy.Config().AccessFile)
	w := e.request("POST", "/keys", url.Values{"name": {"BAD_KEY"}, "value": {"sk-bad-VALUE-0123456789"}, "mode": {"new"}, "password": {password},
		"svc_name": {"bad"}, "base": {"http://example.com"}, "auth": {"bearer"}})
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "sk-bad-VALUE") {
		t.Fatalf("plain-http service: %d", w.Code)
	}
	if keys, _ := store.Load(e.backend.StorePath); keys["BAD_KEY"] != "" {
		t.Fatal("value stored although the service was refused")
	}
	if after, _ := os.ReadFile(e.proxy.Config().AccessFile); !bytes.Equal(before, after) {
		t.Fatal("access file changed")
	}
	if w := e.request("POST", "/keys", url.Values{"name": {"API_KEY"}, "value": {"x"}, "mode": {"none"}, "password": {password}}); w.Code != http.StatusConflict {
		t.Fatalf("existing name: %d, want 409", w.Code)
	}
	if w := e.request("POST", "/keys", url.Values{"name": {"1bad"}, "value": {"x"}, "mode": {"none"}, "password": {password}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad name: %d", w.Code)
	}
}

func TestSensitiveChangesNeedThePasswordEveryTime(t *testing.T) {
	e := newEnv(t) // just logged in: that alone must not be enough
	if w := e.request("POST", "/keys", url.Values{"name": {"NEW_KEY"}, "value": {"v-0123456789"}, "mode": {"none"}}); w.Code != http.StatusForbidden {
		t.Fatalf("add without password: %d, want 403", w.Code)
	}
	w := e.request("POST", "/keys/API_KEY/replace", url.Values{"value": {newValue}})
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "error=password") {
		t.Fatalf("replace without password: %d %s", w.Code, loc)
	}
	if keys, _ := store.Load(e.backend.StorePath); keys["API_KEY"] != oldValue {
		t.Fatal("replaced without the password")
	}
	if w := e.request("POST", "/keys/API_KEY/replace", url.Values{"value": {newValue}, "password": {"wrong password here"}}); !strings.Contains(w.Header().Get("Location"), "error=password") {
		t.Fatal("wrong password accepted")
	}
	if w := e.request("POST", "/keys/API_KEY/replace", url.Values{"value": {newValue}, "password": {password}}); !strings.Contains(w.Header().Get("Location"), "done=replaced") {
		t.Fatalf("with password: %s", w.Header().Get("Location"))
	}
	if w := e.request("POST", "/keys/API_KEY/delete", url.Values{"confirm_in_use": {"yes"}}); !strings.Contains(w.Header().Get("Location"), "error=password") {
		t.Fatalf("delete right after a confirmed change, without password: %s", w.Header().Get("Location"))
	}
}

func TestReplaceTakesEffectAndClearsLeaked(t *testing.T) {
	e := newEnv(t)
	if code := e.proxyCall(); code != 200 || e.seenAuth.Load() != "Bearer "+oldValue {
		t.Fatalf("before: %d %v", code, e.seenAuth.Load())
	}
	if w := e.request("POST", "/keys/API_KEY/leaked", url.Values{}); !strings.Contains(w.Header().Get("Location"), "error=password") {
		t.Fatalf("marked leaked without the password: %s", w.Header().Get("Location"))
	}
	e.request("POST", "/keys/API_KEY/leaked", url.Values{"password": {password}})
	if !strings.Contains(e.request("GET", "/keys", nil).Body.String(), "Leaked") {
		t.Fatal("leaked flag not shown")
	}
	e.request("POST", "/keys/API_KEY/replace", url.Values{"value": {newValue}, "password": {password}})
	if code := e.proxyCall(); code != 200 || e.seenAuth.Load() != "Bearer "+newValue {
		t.Fatalf("after replace the proxy sent %v", e.seenAuth.Load())
	}
	page := e.request("GET", "/keys", nil).Body.String()
	if strings.Contains(page, "Leaked") || !strings.Contains(page, "Not tested") {
		t.Fatal("replace did not clear the leaked flag")
	}
	if strings.Contains(e.everyPage("/keys/API_KEY"), newValue) {
		t.Fatal("new value shown")
	}
}

func TestTestButtonStoresStatusWithoutTheBody(t *testing.T) {
	e := newEnv(t)
	e.status.Store(401)
	w := e.request("POST", "/keys/API_KEY/test", url.Values{})
	if !strings.Contains(w.Header().Get("Location"), "done=tested") {
		t.Fatalf("test: %d %s", w.Code, w.Header().Get("Location"))
	}
	page := e.request("GET", "/keys/API_KEY", nil).Body.String()
	if !strings.Contains(page, "Failing: 401 Unauthorized") || strings.Contains(page, oldValue) || strings.Contains(page, "echo") {
		t.Fatalf("after failing test:\n%s", page)
	}
	e.status.Store(200)
	e.request("POST", "/keys/API_KEY/test", url.Values{})
	if !strings.Contains(e.request("GET", "/keys", nil).Body.String(), "Working") {
		t.Fatal("working status not stored")
	}
	if e.seenAuth.Load() != "Bearer "+oldValue {
		t.Fatal("test did not send the key the way the proxy does")
	}
}

func TestDeleteInUseNeedsConfirmation(t *testing.T) {
	e := newEnv(t)
	if w := e.request("POST", "/keys/API_KEY/delete", url.Values{"password": {password}}); !strings.Contains(w.Header().Get("Location"), "error=in-use") {
		t.Fatalf("delete in use: %s", w.Header().Get("Location"))
	}
	if keys, _ := store.Load(e.backend.StorePath); keys["API_KEY"] == "" {
		t.Fatal("deleted without confirmation")
	}
	if w := e.request("POST", "/keys/API_KEY/delete", url.Values{"confirm_in_use": {"yes"}, "password": {password}}); !strings.Contains(w.Header().Get("Location"), "done=deleted") {
		t.Fatalf("confirmed delete: %s", w.Header().Get("Location"))
	}
	if code := e.proxyCall(); code != http.StatusServiceUnavailable {
		t.Fatalf("proxy after delete: %d, want 503", code)
	}
	if !strings.Contains(e.request("GET", "/keys", nil).Body.String(), "No value stored") {
		t.Fatal("deleted key not shown as missing")
	}
}

func TestPagesNeedALoggedInSession(t *testing.T) {
	e := newEnv(t)
	e.cookie = ""
	if w := e.request("GET", "/keys", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("keys without session: %d", w.Code)
	}
	if w := e.request("POST", "/keys/API_KEY/replace", url.Values{"value": {newValue}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("replace without session: %d", w.Code)
	}
	if keys, _ := store.Load(e.backend.StorePath); keys["API_KEY"] != oldValue {
		t.Fatal("changed without a session")
	}
}

func TestChangesKeepRulesReloadedSinceStart(t *testing.T) {
	e := newEnv(t)
	// A SIGHUP reload narrowed allow_sources after the dashboard started.
	cfg := e.proxy.Config()
	narrowed := *cfg
	narrowed.AllowSources = []string{"127.0.0.9"}
	if err := narrowed.Validate(); err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(&narrowed, keys)
	if code := e.proxyCall(); code != http.StatusForbidden {
		t.Fatalf("after the reload: %d, want 403", code)
	}
	e.request("POST", "/keys/API_KEY/replace", url.Values{"value": {newValue}, "password": {password}})
	if code := e.proxyCall(); code != http.StatusForbidden {
		t.Fatalf("a dashboard change reopened the reloaded source list: %d", code)
	}
}

func TestTestResultOfAReplacedValueIsDropped(t *testing.T) {
	e := newEnv(t)
	started, release := make(chan struct{}), make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
	}))
	defer slow.Close()
	access, _ := policy.LoadAccess(e.proxy.Config().AccessFile)
	svc := access.Services["api"]
	svc.Base = slow.URL
	access.Services["api"] = svc
	if _, err := policy.SaveAccess(e.proxy.Config().Rules, access); err != nil {
		t.Fatal(err)
	}
	e.backend.Mu.Lock()
	if err := e.backend.apply(); err != nil {
		t.Fatal(err)
	}
	e.backend.Mu.Unlock()
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- e.request("POST", "/keys/API_KEY/test", url.Values{}) }()
	<-started
	e.request("POST", "/keys/API_KEY/replace", url.Values{"value": {newValue}, "password": {password}})
	close(release)
	if w := <-done; !strings.Contains(w.Header().Get("Location"), "error=changed") {
		t.Fatalf("test finishing after a replace: %s", w.Header().Get("Location"))
	}
	if !strings.Contains(e.request("GET", "/keys", nil).Body.String(), "Not tested") {
		t.Fatal("the replaced value shows a result it never had")
	}
}

func TestChangesToUnknownKeysAreRefused(t *testing.T) {
	e := newEnv(t)
	before, _ := os.ReadFile(e.backend.StorePath)
	for _, action := range []string{"leaked", "replace", "delete"} {
		w := e.request("POST", "/keys/GHOST_KEY/"+action, url.Values{"value": {newValue}, "password": {password}, "confirm_in_use": {"yes"}})
		if w.Code != http.StatusNotFound && !strings.Contains(w.Header().Get("Location"), "error=no-value") {
			t.Errorf("%s on an unknown key: %d %s", action, w.Code, w.Header().Get("Location"))
		}
	}
	if after, _ := os.ReadFile(e.backend.StorePath); !bytes.Equal(before, after) {
		t.Fatal("the store changed")
	}
	if _, err := os.Stat(e.backend.MetaPath); err == nil {
		if raw, _ := os.ReadFile(e.backend.MetaPath); strings.Contains(string(raw), "GHOST_KEY") {
			t.Fatal("keymeta.json holds an unknown key")
		}
	}
}

func TestKeyNamedNewHasADetailPage(t *testing.T) {
	e := newEnv(t)
	if err := store.Set(e.backend.StorePath, "new", "sk-named-new-0123456789"); err != nil {
		t.Fatal(err)
	}
	if body := e.request("GET", "/keys/new", nil).Body.String(); !strings.Contains(body, "<h2>new") && !strings.Contains(body, ">new<") {
		t.Fatalf("/keys/new is not the key's page:\n%s", body)
	}
	if w := e.request("GET", "/new/key", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Add a key") {
		t.Fatalf("add form: %d", w.Code)
	}
}
