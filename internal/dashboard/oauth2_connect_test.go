package dashboard

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
)

const (
	gmailRefresh = "1//fixture-refresh-token-0123456789"
	gmailSecret  = "GOCSPX-fixture-client-secret-0123"
)

// A fake Google: the token endpoint trades the refresh token and client
// secret for an access token; the API accepts only that token.
func fakeGoogle(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var sends []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			_ = r.ParseForm()
			if r.PostForm.Get("refresh_token") != gmailRefresh || r.PostForm.Get("client_secret") != gmailSecret || r.PostForm.Get("client_id") != "fixture.apps.googleusercontent.com" {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, `{"error":"invalid_grant"}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"ya29.fixture-access","expires_in":3600,"token_type":"Bearer"}`)
		case "/gmail/v1/users/me/messages/send":
			if r.Header.Get("Authorization") != "Bearer ya29.fixture-access" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			sends = append(sends, string(body))
			mu.Unlock()
			io.WriteString(w, `{"id":"msg1","labelIds":["SENT"]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), sends...) }
}

// The owner connects a Gmail send-only service from the dashboard: refresh
// token and client secret added as keys, one pasted line with the oauth2
// settings, then an agent limited to POST .../messages/send can send, and
// nothing else, with the access token minted by the keyring.
func TestConnectOAuth2ServiceFromPastedSettings(t *testing.T) {
	e := newEnv(t)
	g, sends := fakeGoogle(t)
	e.request("POST", "/keys", url.Values{"name": {"GMAIL_LENSCALE_SECRET"}, "value": {gmailSecret}, "password": {password}})
	pasted := `{"service":"google-lenscale-gmail-send","base":"` + g.URL + `","auth":"oauth2","oauth2":{"token_url":"` + g.URL + `/token","client_id":"fixture.apps.googleusercontent.com","client_secret_key":"GMAIL_LENSCALE_SECRET"}}`
	_, conn := e.addAndConnect("GMAIL_LENSCALE_REFRESH", gmailRefresh, url.Values{"pasted": {pasted}})
	if conn.Header().Get("Location") != "/keys/GMAIL_LENSCALE_REFRESH?done=connected" {
		t.Fatalf("connect: %d %s", conn.Code, conn.Body.String())
	}
	svc := e.proxy.Config().Services["google-lenscale-gmail-send"]
	if svc.Auth != policy.AuthOAuth2 || svc.OAuth2 == nil || svc.OAuth2.ClientSecretKey != "GMAIL_LENSCALE_SECRET" {
		t.Fatalf("service = %+v", svc)
	}
	cfg := e.proxy.Config()
	access := cfg.AccessList
	role := access.Roles["phobos"]
	role.Access = map[string]policy.Access{"google-lenscale-gmail-send": {Methods: []string{"POST"}, Paths: []string{"/gmail/v1/users/me/messages/send"}, DailyRequests: 50}}
	access.Roles["phobos"] = role
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	e.proxy.Swap(next, mustKeys(t, e))
	call := func(method, path string) int {
		r := httptest.NewRequest(method, "/google-lenscale-gmail-send"+path, strings.NewReader(`{"raw":"Zml4dHVyZQ"}`))
		r.RemoteAddr = "127.0.0.1:5000"
		r.Header.Set("X-Keyring-Token", token)
		w := httptest.NewRecorder()
		e.proxy.ServeHTTP(w, r)
		return w.Code
	}
	if code := call("POST", "/gmail/v1/users/me/messages/send"); code != 200 {
		t.Fatalf("send: %d", code)
	}
	if got := sends(); len(got) != 1 {
		t.Fatalf("sends = %d", len(got))
	}
	if code := call("GET", "/gmail/v1/users/me/messages"); code != http.StatusForbidden {
		t.Fatalf("read the mailbox: %d, want 403", code)
	}
	if all := e.everyPage("/keys", "/keys/GMAIL_LENSCALE_REFRESH") + e.audit.String(); strings.Contains(all, gmailRefresh) || strings.Contains(all, gmailSecret) {
		t.Fatal("a secret is shown or logged")
	}
}

// The client secret must be a stored key's name; a pasted value is refused
// without being repeated.
func TestConnectOAuth2RefusesASecretValue(t *testing.T) {
	e := newEnv(t)
	pasted := `{"service":"gm","base":"https://gmail.googleapis.com","auth":"oauth2","oauth2":{"token_url":"https://oauth2.googleapis.com/token","client_id":"x.apps.googleusercontent.com","client_secret_key":"` + gmailSecret + `"}}`
	_, conn := e.addAndConnect("GMAIL_REFRESH", gmailRefresh, url.Values{"pasted": {pasted}})
	if conn.Code != http.StatusBadRequest || strings.Contains(conn.Body.String(), gmailSecret) || !strings.Contains(conn.Body.String(), "oauth2.client_secret_key") {
		t.Fatalf("secret value: %d", conn.Code)
	}
	if _, ok := e.proxy.Config().Services["gm"]; ok {
		t.Fatal("refused service was saved")
	}
}

// The service page shows the OAuth client ID, token URL and the secret's key
// name (never its value), and says when that key has no value.
func TestServicePageShowsOAuthSettings(t *testing.T) {
	e := newEnv(t)
	pasted := `{"service":"gm","base":"https://gmail.googleapis.com","auth":"oauth2","oauth2":{"token_url":"https://oauth2.googleapis.com/token","client_id":"123-abc.apps.googleusercontent.com","client_secret_key":"GM_SECRET"}}`
	e.request("POST", "/keys", url.Values{"name": {"GM_SECRET"}, "value": {gmailSecret}, "password": {password}})
	e.addAndConnect("GM_REFRESH", gmailRefresh, url.Values{"pasted": {pasted}})
	page := e.request("GET", "/services/gm", nil).Body.String()
	for _, want := range []string{"123-abc.apps.googleusercontent.com", "https://oauth2.googleapis.com/token", "GM_SECRET"} {
		if !strings.Contains(page, want) {
			t.Fatalf("service page lacks %q", want)
		}
	}
	if strings.Contains(page, gmailSecret) || strings.Contains(page, gmailRefresh) || strings.Contains(page, "no value stored") {
		t.Fatal("a secret is shown, or the stored secret is reported missing")
	}
	e.request("POST", "/keys/GM_SECRET/delete", url.Values{"password": {password}, "confirm_in_use": {"yes"}})
	if page := e.request("GET", "/services/gm", nil).Body.String(); !strings.Contains(page, "GM_SECRET <span class=\"mute\">(no value stored)") {
		t.Fatal("a missing client secret is not flagged")
	}
}

// #142: an OAuth service with a wrong client ID (Google: invalid_client) is
// fixed in the service's edit form; the next call works, the grant and the
// refresh token are unchanged, and the kind cannot be switched.
func TestEditOAuthServiceFixesAWrongClientID(t *testing.T) {
	e := newEnv(t)
	g, sends := fakeGoogle(t)
	e.request("POST", "/keys", url.Values{"name": {"GMAIL_SECRET"}, "value": {gmailSecret}, "password": {password}})
	pasted := `{"service":"gm","base":"` + g.URL + `","auth":"oauth2","oauth2":{"token_url":"` + g.URL + `/token","client_id":"wrong.apps.googleusercontent.com","client_secret_key":"GMAIL_SECRET"}}`
	e.addAndConnect("GMAIL_REFRESH", gmailRefresh, url.Values{"pasted": {pasted}})
	cfg := e.proxy.Config()
	access := cfg.AccessList
	role := access.Roles["phobos"]
	role.Access = map[string]policy.Access{"gm": {Methods: []string{"POST"}, Paths: []string{"/gmail/v1/users/me/messages/send"}, DailyRequests: 50}}
	access.Roles["phobos"] = role
	next, _ := policy.SaveAccess(cfg.Rules, access)
	e.proxy.Swap(next, mustKeys(t, e))
	send := func() int {
		r := httptest.NewRequest("POST", "/gm/gmail/v1/users/me/messages/send", strings.NewReader(`{"raw":"x"}`))
		r.RemoteAddr = "127.0.0.1:5000"
		r.Header.Set("X-Keyring-Token", token)
		w := httptest.NewRecorder()
		e.proxy.ServeHTTP(w, r)
		return w.Code
	}
	if code := send(); code != http.StatusServiceUnavailable {
		t.Fatalf("send with a wrong client ID: %d, want 503", code)
	}
	page := e.request("GET", "/services/gm", nil).Body.String()
	if !strings.Contains(page, `name="client_id" value="wrong.apps.googleusercontent.com"`) {
		t.Fatal("the edit form does not show the client ID")
	}
	w := e.edit("gm", url.Values{"base": {g.URL}, "auth": {"oauth2"}, "client_id": {"fixture.apps.googleusercontent.com"}, "token_url": {g.URL + "/token"}, "client_secret_key": {"GMAIL_SECRET"}})
	if w.Header().Get("Location") != "/services/gm?done=saved" {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	if code := send(); code != 200 || len(sends()) != 1 {
		t.Fatalf("send after the fix: %d, sends %d", code, len(sends()))
	}
	svc := e.proxy.Config().Services["gm"]
	if svc.Key != "GMAIL_REFRESH" || e.proxy.Config().Roles["phobos"].Access["gm"].DailyRequests != 50 {
		t.Fatal("the edit changed the key or the grant")
	}
	if !strings.Contains(e.audit.String(), `"changed":["oauth2"]`) {
		t.Fatalf("audit: %s", e.audit.String())
	}
	for name, form := range map[string]url.Values{
		"switch to bearer":  {"base": {g.URL}, "auth": {"bearer"}},
		"secret not stored": {"base": {g.URL}, "auth": {"oauth2"}, "client_id": {"x"}, "token_url": {g.URL + "/token"}, "client_secret_key": {"NOPE"}},
	} {
		if w := e.edit("gm", form); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, w.Code)
		}
	}
	if all := e.request("GET", "/services/gm", nil).Body.String() + e.audit.String(); strings.Contains(all, gmailSecret) || strings.Contains(all, gmailRefresh) {
		t.Fatal("a secret is shown or logged")
	}
}

// Jarvis 447635: a template placeholder saved as the client ID made Google
// answer invalid_client. Connect and edit refuse a placeholder, and a
// non-Google client ID for Google's token endpoint; a real one is accepted.
func TestOAuthPlaceholderClientIDRefused(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"GM_SECRET"}, "value": {gmailSecret}, "password": {password}})
	e.request("POST", "/keys", url.Values{"name": {"GM_REFRESH"}, "value": {gmailRefresh}, "password": {password}})
	connect := func(service, clientID string) *httptest.ResponseRecorder {
		pasted := `{"service":"` + service + `","base":"https://gmail.googleapis.com","auth":"oauth2","oauth2":{"token_url":"https://oauth2.googleapis.com/token","client_id":"` + clientID + `","client_secret_key":"GM_SECRET"}}`
		return e.request("POST", "/keys/GM_REFRESH/connect", url.Values{"pasted": {pasted}, "password": {password}})
	}
	for id, want := range map[string]string{
		"PASTE_YOUR_CLIENT_ID_HERE":           "placeholder",
		"123-abc.apps.example.com":            "ends in .apps.googleusercontent.com",
		"<client>.apps.googleusercontent.com": "placeholder",
	} {
		if w := connect("gm", id); w.Code != http.StatusBadRequest || !strings.Contains(html.UnescapeString(w.Body.String()), want) {
			t.Errorf("connect %s: %d, want 400 with %q", id, w.Code, want)
		}
	}
	if _, ok := e.proxy.Config().Services["gm"]; ok {
		t.Fatal("a placeholder client ID was saved")
	}
	// Opaque IDs of other providers that merely contain such words are fine.
	for _, id := range []string{"REPORTING_CLIENT_ID", "WORKYOURWAY", "your.app.client", "enter_47f9e2", "app_here", "client_id_7f3"} {
		if got := clientIDProblem(&policy.OAuth2{ClientID: id, TokenURL: "https://auth.example.com/token"}); got != "" {
			t.Errorf("%s refused: %s", id, got)
		}
	}
	for _, id := range []string{"YOUR_CLIENT_ID", "client_id", "Enter-Your-OAuth-Client-ID-Here", "YOUR_GOOGLE_CLIENT_ID", "${CLIENT}", "{{client_id}}"} {
		if clientIDProblem(&policy.OAuth2{ClientID: id, TokenURL: "https://auth.example.com/token"}) == "" {
			t.Errorf("%s accepted", id)
		}
	}
	if w := connect("gm", "123-abc.apps.googleusercontent.com"); w.Code != http.StatusSeeOther {
		t.Fatalf("real client ID: %d %s", w.Code, w.Body.String())
	}
	w := e.edit("gm", url.Values{"base": {"https://gmail.googleapis.com"}, "auth": {"oauth2"}, "client_id": {"PASTE_YOUR_CLIENT_ID_HERE"}, "token_url": {"https://oauth2.googleapis.com/token"}, "client_secret_key": {"GM_SECRET"}})
	if w.Code != http.StatusBadRequest || e.proxy.Config().Services["gm"].OAuth2.ClientID != "123-abc.apps.googleusercontent.com" {
		t.Fatalf("edit to a placeholder: %d, client ID now %q", w.Code, e.proxy.Config().Services["gm"].OAuth2.ClientID)
	}
	// A config that already holds one (saved before this check) still edits
	// its other fields; only a changed client ID is checked.
	cfg := e.proxy.Config()
	access := cfg.AccessList
	svc := access.Services["gm"]
	o := *svc.OAuth2
	o.ClientID = "PASTE_YOUR_CLIENT_ID_HERE"
	svc.OAuth2 = &o
	access.Services["gm"] = svc
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	e.proxy.Swap(next, mustKeys(t, e))
	w = e.edit("gm", url.Values{"base": {"https://gmail.googleapis.com"}, "auth": {"oauth2"}, "test_path": {"/gmail/v1/users/me/profile"}, "client_id": {"PASTE_YOUR_CLIENT_ID_HERE"}, "token_url": {"https://oauth2.googleapis.com/token"}, "client_secret_key": {"GM_SECRET"}})
	if w.Header().Get("Location") != "/services/gm?done=saved" {
		t.Fatalf("unrelated edit of an existing placeholder: %d %s", w.Code, w.Body.String())
	}
}
