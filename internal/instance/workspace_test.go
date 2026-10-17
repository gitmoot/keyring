package instance

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const accountGenerationHeader = "X-Keyring-Binding-Generation"

var workspaceScopes = []string{"https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/calendar.events", "https://www.googleapis.com/auth/calendar.calendarlist.readonly", "https://www.googleapis.com/auth/calendar.events.freebusy"}

type workspaceProvider struct {
	mu           sync.Mutex
	events       []string
	holdRefresh  string
	entered      chan struct{}
	release      <-chan struct{}
	rejectRevoke bool
}

func (p *workspaceProvider) log(event string) {
	p.mu.Lock()
	p.events = append(p.events, event)
	p.mu.Unlock()
}
func (p *workspaceProvider) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.events...)
}

func (p *workspaceProvider) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(accountGenerationHeader) != "" || r.Header.Get("X-Keyring-Token") != "" {
		http.Error(w, "credential control header leaked", 500)
		p.log("header_leak")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		name := ""
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			name = r.Form.Get("code")
		case "refresh_token":
			name = strings.TrimPrefix(r.Form.Get("refresh_token"), "refresh-")
		}
		if (name != "personal" && name != "work" && name != "other") || r.Form.Get("client_id") != "fixture-client" || r.Form.Get("client_secret") != "fixture-secret" {
			p.log("token_rejected")
			http.Error(w, `{"error":"invalid_grant"}`, 400)
			return
		}
		p.log("token:" + name)
		p.mu.Lock()
		held, entered, release := p.holdRefresh == name && r.Form.Get("grant_type") == "refresh_token", p.entered, p.release
		p.mu.Unlock()
		if held {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-" + name, "refresh_token": "refresh-" + name, "token_type": "Bearer", "expires_in": 3600, "scope": strings.Join(workspaceScopes, " ")})
		return
	}
	if r.URL.Path == "/revoke" {
		_ = r.ParseForm()
		p.log("revoke:" + r.Form.Get("token"))
		p.mu.Lock()
		reject := p.rejectRevoke
		p.mu.Unlock()
		if reject {
			http.Error(w, "provider unavailable", 503)
			return
		}
		_, _ = io.WriteString(w, `{}`)
		return
	}
	identities := map[string]string{"Bearer access-personal": "personal@example.test", "Bearer access-work": "work@example.test", "Bearer access-other": "other@example.test"}
	email, ok := identities[r.Header.Get("Authorization")]
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	if r.URL.Path == "/gmail/v1/users/me/profile" && r.Method == "GET" {
		p.log("profile:" + email)
		_ = json.NewEncoder(w).Encode(map[string]string{"emailAddress": email})
		return
	}
	if r.URL.Path == "/gmail/v1/users/me/messages/send" && r.Method == "POST" {
		p.log("write:" + email)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "message-from-" + email})
		return
	}
	if r.URL.Path == "/calendar/v3/users/me/calendarList" && r.Method == "GET" {
		p.log("calendar:" + email)
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []map[string]any{{"id": email, "primary": true}}})
		return
	}
	http.NotFound(w, r)
}

type workspaceFixture struct {
	t                         *testing.T
	in                        *Instance
	admin                     http.Handler
	listen, pages, key, token string
	options                   Options
	audit                     *syncBuffer
	provider                  *workspaceProvider
}

func newWorkspaceFixture(t *testing.T, daily int) *workspaceFixture {
	t.Helper()
	provider := &workspaceProvider{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(provider.serve))
	t.Cleanup(upstream.Close)
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Synthetic loopback provider only.
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch addr {
		case "oauth2.googleapis.com:443", "gmail.googleapis.com:443", "www.googleapis.com:443":
			addr = upstream.Listener.Addr().String()
		default:
			if !strings.HasPrefix(addr, "127.0.0.1:") {
				return nil, fmt.Errorf("unexpected external destination %s", addr)
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	audit := &syncBuffer{}
	options := Options{AdminListen: freeAddr(t), AdminTokenSHA256: sha(adminToken), StatePath: filepath.Join(t.TempDir(), "sealed"), Container: true, Audit: audit, AuditName: "test"}
	in, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f := &workspaceFixture{t: t, in: in, admin: in.AdminHandler(), listen: freeAddr(t), pages: freeAddr(t), key: newKey(t), options: options, provider: provider, audit: audit}
	t.Cleanup(func() { f.in.Close() })
	f.must("POST", "/create", map[string]any{"id": "person", "data_key": f.key, "listen": f.listen}, "")
	oauth := map[string]any{"token_url": "https://oauth2.googleapis.com/token", "auth_url": "https://accounts.google.com/o/oauth2/v2/auth", "revoke_url": "https://oauth2.googleapis.com/revoke", "client_id": "fixture-client", "client_secret_key": "WORKSPACE_CLIENT_SECRET", "scopes": workspaceScopes, "auth_params": map[string]string{"access_type": "offline", "prompt": "consent"}}
	for service, base := range map[string]string{"gmail": "https://gmail.googleapis.com", "calendar": "https://www.googleapis.com/calendar/v3"} {
		f.must("PUT", "/services/"+service, map[string]any{"base": base, "auth": "oauth2", "key": "GOOGLE_WORKSPACE_REFRESH_TOKEN", "oauth2": oauth}, "")
	}
	f.must("PUT", "/keys/WORKSPACE_CLIENT_SECRET", map[string]string{"value": "fixture-secret"}, "")
	f.must("PUT", "/keys/GOOGLE_WORKSPACE_REFRESH_TOKEN", map[string]string{"value": "refresh-personal"}, "")
	grants := map[string]any{}
	for _, service := range []string{"gmail", "calendar"} {
		grants[service] = map[string]any{"paths": []string{"/"}, "methods": []string{"GET", "POST"}, "daily_requests": daily}
	}
	role := f.must("PUT", "/roles/router", map[string]any{"access": grants}, "")
	f.token = role["token"].(string)
	f.must("PUT", "/consent", map[string]any{"listen": f.pages, "public_url": "http://" + f.pages + "/connect", "api_listen": freeAddr(t), "api_token_sha256": sha("consent-fixture")}, "")
	f.must("POST", "/google-drive", map[string]any{}, "")
	return f
}

func (f *workspaceFixture) call(method, path string, body any, generation string) (int, map[string]any) {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "http://admin"+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set(accountGenerationHeader, generation)
	rec := httptest.NewRecorder()
	f.admin.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}
func (f *workspaceFixture) must(method, path string, body any, generation string) map[string]any {
	f.t.Helper()
	code, out := f.call(method, path, body, generation)
	if code < 200 || code >= 300 {
		f.t.Fatalf("%s %s: %d %v", method, path, code, out)
	}
	return out
}
func accountField(account map[string]any, name string) string { return account[name].(string) }
func (f *workspaceFixture) migrate() map[string]any {
	return f.must("POST", "/accounts/migrate", map[string]any{}, "")["account"].(map[string]any)
}
func (f *workspaceFixture) hydrate(a map[string]any) map[string]any {
	return f.must("POST", "/accounts/"+accountField(a, "account_id")+"/identity", map[string]any{}, accountField(a, "binding_generation"))["account"].(map[string]any)
}
func (f *workspaceFixture) listed(id string) map[string]any {
	f.t.Helper()
	for _, raw := range f.must("GET", "/accounts", nil, "")["accounts"].([]any) {
		a := raw.(map[string]any)
		if a["account_id"] == id {
			return a
		}
	}
	f.t.Fatalf("account %s missing", id)
	return nil
}

type workspaceSignIn struct {
	client   *http.Client
	callback string
}

func (f *workspaceFixture) start(a map[string]any) workspaceSignIn {
	f.t.Helper()
	id, generation := accountField(a, "account_id"), accountField(a, "binding_generation")
	link := f.must("POST", "/accounts/"+id+"/links", map[string]any{"service": "gmail", "ttl_seconds": 900}, generation)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 5 * time.Second}
	response, err := client.Get(link["url"].(string))
	if err != nil {
		f.t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		f.t.Fatalf("link page: %d", response.StatusCode)
	}
	req, _ := http.NewRequest("POST", link["url"].(string), strings.NewReader("action=connect"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+f.pages)
	response, err = client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther {
		f.t.Fatalf("consent start: %d", response.StatusCode)
	}
	target, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		f.t.Fatal(err)
	}
	callback := target.Query().Get("redirect_uri") + "?state=" + url.QueryEscape(target.Query().Get("state"))
	return workspaceSignIn{client, callback}
}
func (f *workspaceFixture) finish(flow workspaceSignIn, name string) int {
	f.t.Helper()
	response, err := flow.client.Get(flow.callback + "&code=" + name)
	if err != nil {
		f.t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}
func (f *workspaceFixture) connect(a map[string]any, name string) map[string]any {
	f.t.Helper()
	if status := f.finish(f.start(a), name); status != 200 {
		f.t.Fatalf("consent callback: %d", status)
	}
	return f.listed(accountField(a, "account_id"))
}
func (f *workspaceFixture) proxy(method, path, generation string) (int, map[string]any, error) {
	req, err := http.NewRequest(method, "http://"+f.listen+path, strings.NewReader(`{"raw":"fixture"}`))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("X-Keyring-Token", f.token)
	req.Header.Set(accountGenerationHeader, generation)
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(response.Body).Decode(&out)
	return response.StatusCode, out, nil
}
func qualified(a map[string]any, path string) string {
	return "/_accounts/" + accountField(a, "account_id") + path
}
func (f *workspaceFixture) expectIdentity(a map[string]any, email string) {
	f.t.Helper()
	code, out, err := f.proxy("GET", qualified(a, "/gmail/gmail/v1/users/me/profile"), accountField(a, "binding_generation"))
	if err != nil || code != 200 || out["emailAddress"] != email {
		f.t.Fatalf("account identity: %d %v %v", code, out, err)
	}
}

func TestWorkspaceAccountsPreserveDefaultAndIsolateCredentials(t *testing.T) {
	f := newWorkspaceFixture(t, 0)
	initial := f.must("GET", "/accounts", nil, "")
	if initial["migration_required"] != true {
		t.Fatalf("migration status: %v", initial)
	}
	before := f.must("GET", "/status", nil, "")
	personal := f.migrate()
	id := accountField(personal, "account_id")
	generation := accountField(personal, "binding_generation")
	again := f.migrate()
	if again["account_id"] != id || again["binding_generation"] != generation || personal["email"] != nil || personal["identity_state"] != "unknown" {
		t.Fatalf("default migration: %v / %v", personal, again)
	}
	after := f.must("GET", "/status", nil, "")
	if !reflect.DeepEqual(before["services"], after["services"]) || !reflect.DeepEqual(before["roles"], after["roles"]) {
		t.Fatal("migration changed service or role grants")
	}
	if len(f.provider.snapshot()) != 0 {
		t.Fatal("metadata migration contacted provider")
	}
	if code, _, err := f.proxy("GET", "/google-me-drive/about", ""); err != nil || code != 503 {
		t.Fatalf("migration changed the independent disconnected Drive path: %d %v", code, err)
	}
	for _, bad := range []struct {
		gen    string
		status int
	}{{"", 428}, {strings.Repeat("0", 32), 409}} {
		code, _ := f.call("POST", "/accounts/"+id+"/identity", map[string]any{}, bad.gen)
		if code != bad.status {
			t.Fatalf("hydration generation: %d", code)
		}
	}
	if code, _ := f.call("POST", "/accounts", map[string]string{"alias": "work"}, ""); code != 409 {
		t.Fatalf("unknown default identity allowed adding account: %d", code)
	}
	personal = f.hydrate(personal)
	if personal["email"] != "personal@example.test" || personal["binding_generation"] != generation {
		t.Fatalf("hydrated default: %v", personal)
	}
	positive := f.provider.snapshot()
	if !reflect.DeepEqual(positive, []string{"token:personal", "profile:personal@example.test"}) {
		t.Fatalf("hydration did not exercise provider: %v", positive)
	}
	f.hydrate(personal)
	f.must("GET", "/accounts", nil, "")
	if !reflect.DeepEqual(positive, f.provider.snapshot()) {
		t.Fatal("cached identity/list repeated provider work")
	}
	work := f.must("POST", "/accounts", map[string]string{"alias": "work"}, "")["account"].(map[string]any)
	work = f.connect(work, "work")
	if work["email"] != "work@example.test" {
		t.Fatalf("verified work identity: %v", work)
	}
	f.expectIdentity(personal, "personal@example.test")
	f.expectIdentity(work, "work@example.test")
	code, out, err := f.proxy("GET", "/gmail/gmail/v1/users/me/profile", accountField(work, "binding_generation"))
	if err != nil || code != 200 || out["emailAddress"] != "personal@example.test" {
		t.Fatalf("legacy route was retargeted: %d %v %v", code, out, err)
	}
	calendarCode, calendar, err := f.proxy("GET", qualified(work, "/calendar/users/me/calendarList"), accountField(work, "binding_generation"))
	if err != nil || calendarCode != 200 || calendar["items"].([]any)[0].(map[string]any)["id"] != "work@example.test" {
		t.Fatalf("shared Calendar credential: %d %v %v", calendarCode, calendar, err)
	}
	duplicate := f.must("POST", "/accounts", map[string]string{"alias": "duplicate"}, "")["account"].(map[string]any)
	if code := f.finish(f.start(duplicate), "personal"); code == 200 {
		t.Fatal("duplicate Google identity was accepted")
	}
	if f.listed(accountField(duplicate, "account_id"))["connected"] != false {
		t.Fatal("rejected duplicate was published")
	}
	for _, event := range f.provider.snapshot() {
		if strings.HasPrefix(event, "revoke:") {
			t.Fatal("rejected duplicate revoked an active grant")
		}
	}
	if code := f.finish(f.start(work), "other"); code == 200 {
		t.Fatal("active account silently replaced with another identity")
	}
	if got := f.listed(accountField(work, "account_id")); got["binding_generation"] != work["binding_generation"] || got["email"] != work["email"] {
		t.Fatalf("failed reconnect replaced binding: %v", got)
	}
	oldFlow := f.start(personal)
	disconnected := f.must("DELETE", "/accounts/"+id, nil, generation)
	if disconnected["provider_revoked"] != true {
		t.Fatalf("provider revoke: %v", disconnected)
	}
	staleEvents := f.provider.snapshot()
	if code := f.finish(oldFlow, "personal"); code == 200 {
		t.Fatal("disconnected browser capability survived")
	}
	if !reflect.DeepEqual(staleEvents, f.provider.snapshot()) {
		t.Fatal("stale callback contacted provider")
	}
	code, _, err = f.proxy("GET", "/gmail/gmail/v1/users/me/profile", "")
	if err != nil || code != 409 {
		t.Fatalf("legacy disconnected default: %d %v", code, err)
	}
	if !reflect.DeepEqual(staleEvents, f.provider.snapshot()) {
		t.Fatal("legacy route fell through to remaining work account")
	}
	f.expectIdentity(work, "work@example.test")
	sealed := f.must("GET", "/state", nil, "")
	f.in.Close()
	f.in, err = New(f.options)
	if err != nil {
		t.Fatal(err)
	}
	f.admin = f.in.AdminHandler()
	f.must("POST", "/unlock", map[string]any{"data_key": f.key, "state": sealed["state"]}, "")
	preserved := f.listed(accountField(work, "account_id"))
	if preserved["binding_generation"] != work["binding_generation"] || preserved["email"] != "work@example.test" {
		t.Fatalf("sealed identity lost: %v", preserved)
	}
	f.expectIdentity(preserved, "work@example.test")
	code, _, err = f.proxy("GET", "/gmail/gmail/v1/users/me/profile", "")
	if err != nil || code != 409 {
		t.Fatalf("restart changed legacy default binding: %d %v", code, err)
	}
}

func TestWorkspaceAccountGenerationGatesDispatchAndGroupDisconnect(t *testing.T) {
	f := newWorkspaceFixture(t, 0)
	personal := f.hydrate(f.migrate())
	work := f.connect(f.must("POST", "/accounts", map[string]string{"alias": "work"}, "")["account"].(map[string]any), "work")
	generation := accountField(work, "binding_generation")
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	entered := make(chan struct{})
	f.provider.mu.Lock()
	f.provider.holdRefresh = "work"
	f.provider.entered = entered
	f.provider.release = release
	f.provider.rejectRevoke = true
	f.provider.mu.Unlock()
	type result struct {
		status int
		body   map[string]any
		err    error
	}
	writeDone := make(chan result, 1)
	go func() {
		code, body, err := f.proxy("POST", qualified(work, "/gmail/gmail/v1/users/me/messages/send"), generation)
		writeDone <- result{code, body, err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("write did not enter token renewal")
	}
	disconnectStarted, disconnectDone := make(chan struct{}), make(chan result, 1)
	go func() {
		close(disconnectStarted)
		code, body := f.call("DELETE", "/accounts/"+accountField(work, "account_id"), nil, generation)
		disconnectDone <- result{status: code, body: body}
	}()
	<-disconnectStarted
	// The renewal already owns the dispatch lease. A disconnect cannot publish
	// or reach provider revocation while that admitted request is still blocked.
	select {
	case got := <-disconnectDone:
		t.Fatalf("disconnect crossed pending dispatch: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
	f.expectIdentity(personal, "personal@example.test")
	unblock()
	written := <-writeDone
	removed := <-disconnectDone
	if written.err != nil || written.status != 200 || written.body["id"] != "message-from-work@example.test" {
		t.Fatalf("admitted write: %+v", written)
	}
	if removed.status != 200 || removed.body["provider_revoked"] != false {
		t.Fatalf("local disconnect with failed provider revoke: %+v", removed)
	}
	current := removed.body["account"].(map[string]any)
	if current["connected"] != false || current["binding_generation"] == generation {
		t.Fatalf("disconnect binding: %v", current)
	}
	services := current["services"].(map[string]any)
	for _, name := range []string{"gmail", "calendar"} {
		if services[name].(map[string]any)["connected"] != false {
			t.Fatalf("shared service survived disconnect: %v", services)
		}
	}
	events := f.provider.snapshot()
	writeIndex, revokeIndex := -1, -1
	for i, event := range events {
		if event == "write:work@example.test" {
			writeIndex = i
		}
		if event == "revoke:refresh-work" {
			revokeIndex = i
		}
	}
	if writeIndex < 0 || revokeIndex <= writeIndex {
		t.Fatalf("dispatch/revoke ordering: %v", events)
	}
	code, body, err := f.proxy("POST", qualified(work, "/gmail/gmail/v1/users/me/messages/send"), generation)
	if err != nil || code != 409 || body["error"] != "account_binding_changed" {
		t.Fatalf("stale write approval: %d %v %v", code, body, err)
	}
	if !reflect.DeepEqual(events, f.provider.snapshot()) {
		t.Fatal("stale write reached provider")
	}
	f.expectIdentity(personal, "personal@example.test")
}

func TestWorkspaceAccountQuotasAndSelectorsFailClosed(t *testing.T) {
	f := newWorkspaceFixture(t, 2)
	personal := f.hydrate(f.migrate())
	readOnly := map[string]any{}
	for _, service := range []string{"gmail", "calendar"} {
		readOnly[service] = map[string]any{"paths": []string{"/"}, "methods": []string{"GET"}, "daily_requests": 2}
	}
	f.must("PUT", "/roles/router", map[string]any{"access": readOnly}, "")
	work := f.connect(f.must("POST", "/accounts", map[string]string{"alias": "work"}, "")["account"].(map[string]any), "work")
	expanded := map[string]any{}
	for _, service := range []string{"gmail", "calendar"} {
		expanded[service] = map[string]any{"paths": []string{"/"}, "methods": []string{"GET", "POST"}, "daily_requests": 2}
	}
	f.must("PUT", "/roles/router", map[string]any{"access": expanded}, "")
	before := f.provider.snapshot()
	cases := []struct {
		path, gen string
		status    int
	}{
		{qualified(work, "/gmail/gmail/v1/users/me/profile"), "", 428},
		{qualified(work, "/gmail/gmail/v1/users/me/profile"), accountField(personal, "binding_generation"), 409},
		{"/_accounts/" + strings.Repeat("0", 32) + "/gmail/gmail/v1/users/me/profile", accountField(work, "binding_generation"), 404},
		{qualified(work, "/google-me-drive/about"), accountField(work, "binding_generation"), 404},
	}
	for _, test := range cases {
		code, _, err := f.proxy("GET", test.path, test.gen)
		if err != nil || code != test.status {
			t.Fatalf("selector %s: %d %v", test.path, code, err)
		}
	}
	if !reflect.DeepEqual(before, f.provider.snapshot()) {
		t.Fatal("invalid selector contacted provider")
	}
	f.expectIdentity(personal, "personal@example.test")
	f.expectIdentity(work, "work@example.test")
	code, _, err := f.proxy("GET", qualified(work, "/gmail/gmail/v1/users/me/profile"), accountField(work, "binding_generation"))
	if err != nil || code != 429 {
		t.Fatalf("adding an account bypassed aggregate daily quota: %d %v", code, err)
	}
	before = f.provider.snapshot()
	code, _, err = f.proxy("POST", qualified(work, "/gmail/gmail/v1/users/me/messages/send"), accountField(work, "binding_generation"))
	if err != nil || code != 403 {
		t.Fatalf("expanded role bypassed account grant ceiling: %d %v", code, err)
	}
	if !reflect.DeepEqual(before, f.provider.snapshot()) {
		t.Fatal("ungranted write reached provider")
	}
}

func TestWorkspaceAccountHydrationCachesByBinding(t *testing.T) {
	f := newWorkspaceFixture(t, 0)
	personal := f.migrate()
	id, generation := accountField(personal, "account_id"), accountField(personal, "binding_generation")
	type response struct {
		code int
		body map[string]any
	}
	results := make(chan response, 8)
	for range 8 {
		go func() {
			code, body := f.call("POST", "/accounts/"+id+"/identity", map[string]any{}, generation)
			results <- response{code, body}
		}()
	}
	for range 8 {
		got := <-results
		if got.code != 200 || got.body["account"].(map[string]any)["email"] != "personal@example.test" {
			t.Fatalf("concurrent hydration: %+v", got)
		}
	}
	if got := f.provider.snapshot(); !reflect.DeepEqual(got, []string{"token:personal", "profile:personal@example.test"}) {
		t.Fatalf("hydration was not cached per binding: %v", got)
	}
	f.must("PUT", "/keys/GOOGLE_WORKSPACE_REFRESH_TOKEN", map[string]string{"value": "refresh-other"}, "")
	replaced := f.listed(id)
	if replaced["email"] != nil || replaced["identity_state"] != "unknown" || replaced["binding_generation"] == generation {
		t.Fatalf("credential replacement retained verified identity or approval generation: %v", replaced)
	}
	before := f.provider.snapshot()
	if code, body := f.call("POST", "/accounts/"+id+"/identity", map[string]any{}, generation); code != 409 || body["error"] != "account_binding_changed" {
		t.Fatalf("stale hydration: %d %v", code, body)
	}
	if !reflect.DeepEqual(before, f.provider.snapshot()) {
		t.Fatal("stale hydration contacted provider")
	}
	replaced = f.hydrate(replaced)
	if replaced["email"] != "other@example.test" {
		t.Fatalf("replacement identity: %v", replaced)
	}
	f.must("PUT", "/keys/WORKSPACE_CLIENT_SECRET", map[string]string{"value": "rejected-client-secret"}, "")
	changed := f.listed(id)
	if changed["binding_generation"] == replaced["binding_generation"] || changed["email"] != nil {
		t.Fatalf("client binding change retained approvals or identity: %v", changed)
	}
	code, body := f.call("POST", "/accounts/"+id+"/identity", map[string]any{}, accountField(changed, "binding_generation"))
	if code != 409 || body["error"] != "account_reconnect_required" {
		t.Fatalf("rejected client: %d %v", code, body)
	}
	before = f.provider.snapshot()
	rejected := f.listed(id)
	if rejected["status"] != "reconnect_required" || rejected["connected"] != false {
		t.Fatalf("cached rejection status: %v", rejected)
	}
	if !reflect.DeepEqual(before, f.provider.snapshot()) {
		t.Fatal("status retried a rejected credential")
	}
}

func TestWorkspaceAccountLegacyRevokeDiagnostics(t *testing.T) {
	f := newWorkspaceFixture(t, 0)
	f.provider.mu.Lock()
	f.provider.rejectRevoke = true
	f.provider.mu.Unlock()
	disconnect := func() map[string]any {
		request := httptest.NewRequest("DELETE", "/keys/gmail", nil)
		request.RemoteAddr = "127.0.0.1:1234"
		request.Header.Set("Authorization", "Bearer consent-fixture")
		response := httptest.NewRecorder()
		f.in.consent.APIHandler().ServeHTTP(response, request)
		if response.Code != 200 {
			t.Fatalf("legacy disconnect: %d %s", response.Code, response.Body.String())
		}
		var result map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := disconnect()
	if before["deleted"] != true || before["revoked"] != false {
		t.Fatalf("provider refusal was not exercised: %v", before)
	}
	if _, reported := before["revoke_error"]; !reported {
		t.Fatalf("legacy baseline lost its diagnostic: %v", before)
	}
	f.must("PUT", "/keys/"+before["key"].(string), map[string]string{"value": "refresh-personal"}, "")
	personal := f.migrate()
	if after := disconnect(); !reflect.DeepEqual(before, after) {
		t.Fatalf("migration changed the legacy revoke result: before=%v after=%v", before, after)
	}
	if current := f.listed(accountField(personal, "account_id")); current["connected"] != false || current["status"] != "disconnected" {
		t.Fatalf("remote refusal restored a locally disconnected grant: %v", current)
	}
}

func TestWorkspaceAccountDefaultRejectsServiceKeyRebinding(t *testing.T) {
	f := newWorkspaceFixture(t, 0)
	personal := f.hydrate(f.migrate())
	for _, name := range []string{"gmail", "calendar"} {
		service := f.in.proxy.Config().Services[name]
		service.Key = "REBOUND_WORKSPACE_REFRESH"
		if code, body := f.call("PUT", "/services/"+name, service, ""); code != 400 {
			t.Fatalf("accepted unusable %s key rebinding: %d %v", name, code, body)
		}
	}
	if current := f.listed(accountField(personal, "account_id")); !reflect.DeepEqual(current, personal) {
		t.Fatalf("refused key rebinding changed the default: %v", current)
	}
	f.expectIdentity(personal, "personal@example.test")
}

func TestWorkspaceAccountCacheSurvivesUnrelatedChanges(t *testing.T) {
	f := newWorkspaceFixture(t, 0)
	f.hydrate(f.migrate())
	work := f.connect(f.must("POST", "/accounts", map[string]string{"alias": "work"}, "")["account"].(map[string]any), "work")
	f.expectIdentity(work, "work@example.test")
	before := f.provider.snapshot()
	f.must("PUT", "/keys/UNRELATED_KEY", map[string]string{"value": "synthetic-unrelated"}, "")
	f.expectIdentity(work, "work@example.test")
	after := f.provider.snapshot()
	if !reflect.DeepEqual(after[len(before):], []string{"profile:work@example.test"}) {
		t.Fatalf("unrelated state change discarded the account token: %v", after[len(before):])
	}
	// A genuine credential replacement must still retire the old cache entry.
	id := accountField(work, "account_id")
	f.must("PUT", "/keys/GOOGLE_WORKSPACE_ACCOUNT_"+id, map[string]string{"value": "refresh-other"}, "")
	replaced := f.hydrate(f.listed(id))
	f.expectIdentity(replaced, "other@example.test")
	if code, _, err := f.proxy("GET", qualified(work, "/gmail/gmail/v1/users/me/profile"), accountField(work, "binding_generation")); err != nil || code != 409 {
		t.Fatalf("old binding survived credential replacement: %d %v", code, err)
	}
}

func TestWorkspaceAccountAuditMatchesRefusalStatus(t *testing.T) {
	f := newWorkspaceFixture(t, 0)
	personal := f.hydrate(f.migrate())
	before := f.provider.snapshot()
	request := httptest.NewRequest("GET", qualified(personal, "/gmail/gmail/v1/users/me/profile"), nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Keyring-Token", f.token)
	response := httptest.NewRecorder()
	f.in.proxy.ServeHTTP(response, request)
	if response.Code != 428 {
		t.Fatalf("missing generation: %d %s", response.Code, response.Body.String())
	}
	decoder := json.NewDecoder(strings.NewReader(f.audit.String()))
	var audited int
	for {
		var record struct {
			Service string `json:"service"`
			Status  int    `json:"status"`
		}
		err := decoder.Decode(&record)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if record.Service == "gmail" {
			audited = record.Status
		}
	}
	if audited != response.Code {
		t.Fatalf("HTTP refusal %d was recorded as %d", response.Code, audited)
	}
	if !reflect.DeepEqual(before, f.provider.snapshot()) {
		t.Fatal("generation refusal reached the provider")
	}
}
