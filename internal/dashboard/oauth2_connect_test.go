package dashboard

import (
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
