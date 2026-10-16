package consent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
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
	apiToken  = "consent-api-token-0123456789"
	roleToken = "role-token-phobos"
	router    = "10.0.0.5"
	public    = "http://127.0.0.1:9443/p/alice"
	origin    = "http://127.0.0.1:9443"
)

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type memKeys struct {
	mu   sync.Mutex
	keys map[string]string
}

func (m *memKeys) Load() (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.keys), nil
}

func (m *memKeys) Set(name, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[name] = value
	return nil
}

func (m *memKeys) Delete(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, name)
	return nil
}

func (m *memKeys) get(name string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[name]
}

// provider is a fake OAuth provider: a token endpoint that trades one code
// for a refresh token after checking PKCE, and a revoke endpoint.
type provider struct {
	srv       *httptest.Server
	mu        sync.Mutex
	challenge string // the code_challenge of the sign-in it expects
	exchanges []url.Values
	revoked   []url.Values
	noRefresh bool
	revokeErr bool
}

func newProvider(t *testing.T) *provider {
	p := &provider{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		defer p.mu.Unlock()
		switch r.URL.Path {
		case "/token":
			p.exchanges = append(p.exchanges, r.PostForm)
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if r.PostForm.Get("code") != "good-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, `{"error":"invalid_grant","error_description":"PKCE says no"}`)
				return
			}
			refresh := `"refresh_token":"1//person-refresh",`
			if p.noRefresh {
				refresh = ""
			}
			io.WriteString(w, `{`+refresh+`"access_token":"ya29.x","token_type":"Bearer","expires_in":3599}`)
		case "/revoke":
			p.revoked = append(p.revoked, r.PostForm)
			if p.revokeErr {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

type env struct {
	t     *testing.T
	s     *Server
	keys  *memKeys
	audit *bytes.Buffer
	cfg   *policy.Config
	clock time.Time
	prov  *provider
}

func newEnv(t *testing.T) *env {
	t.Helper()
	prov := newProvider(t)
	cfg := &policy.Config{
		Rules: policy.Rules{
			Listen:       "127.0.0.1:7701",
			AllowSources: []string{"127.0.0.1"},
			AuditLog:     "/tmp/audit.log",
			AccessFile:   "/tmp/access.json",
			Consent: &policy.Consent{
				Listen: "127.0.0.1:7710", PublicURL: public, APIListen: "127.0.0.1:7711",
				APIAllowSources: []string{router}, APITokenSHA256: sha(apiToken),
			},
		},
		AccessList: policy.AccessList{
			Services: map[string]policy.Service{
				"gmail": {Base: "https://gmail.googleapis.com", Key: "GMAIL_REFRESH", Auth: policy.AuthOAuth2, OAuth2: &policy.OAuth2{
					TokenURL: prov.srv.URL + "/token", ClientID: "client.apps", ClientSecretKey: "GOOGLE_SECRET",
					AuthURL: "https://accounts.example.com/auth", Scopes: []string{"https://mail.google.com/"},
					AuthParams: map[string]string{"access_type": "offline", "prompt": "consent"},
					RevokeURL:  prov.srv.URL + "/revoke",
				}},
				"proxy":      {Base: "https://proxy.example.com", Key: "PROXY_KEY", Auth: policy.AuthHeader, Header: "X-Api-Key"},
				"myproxy":    {Key: "MY_PROXY", Auth: policy.AuthEgressProxy, EgressProxy: &policy.EgressProxy{}},
				"fixedproxy": {Key: "FIXED_PROXY", Auth: policy.AuthEgressProxy, EgressProxy: &policy.EgressProxy{Type: policy.ProxyHTTPConnect, Address: "proxy.example.net:8080"}},
				"other":      {Base: "https://other.example.com", Key: "OTHER_KEY", Auth: policy.AuthBearer},
				"signer":     {Key: "SIGN_KEY", Auth: policy.AuthEd25519Sign},
				"nosign":     {Base: "https://x.example.com", Key: "NOSIGN_REFRESH", Auth: policy.AuthOAuth2, OAuth2: &policy.OAuth2{TokenURL: prov.srv.URL + "/token", ClientID: "c"}},
			},
			Roles: map[string]policy.Role{"phobos": {TokenSHA256: sha(roleToken), Access: map[string]policy.Access{"gmail": {Paths: []string{"/"}}}}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, keys: &memKeys{keys: map[string]string{"GOOGLE_SECRET": "google-client-secret", "OTHER_KEY": "other-value"}}, audit: &bytes.Buffer{}, cfg: cfg, prov: prov}
	e.clock = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	e.s = New(func() *policy.Config { return e.cfg }, e.keys, e.audit)
	e.s.now = func() time.Time { return e.clock }
	return e
}

func (e *env) api(method, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = router + ":5000"
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.s.APIHandler().ServeHTTP(w, r)
	return w
}

// link creates a link and returns its path below the pages listener.
func (e *env) link(service string) string {
	e.t.Helper()
	w := e.api("POST", "/links", apiToken, `{"service":"`+service+`","label":"Alice (+31 6...)"}`)
	if w.Code != http.StatusCreated {
		e.t.Fatalf("create link for %s: %d %s", service, w.Code, w.Body)
	}
	var out struct{ URL string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	u, err := url.Parse(out.URL)
	if err != nil || !strings.HasPrefix(out.URL, public+"/c/") {
		e.t.Fatalf("link url %q", out.URL)
	}
	return u.Path
}

func (e *env) page(method, path string, form url.Values, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	r.RemoteAddr = "203.0.113.9:4000"
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	e.s.PagesHandler().ServeHTTP(w, r)
	return w
}

var fromPage = map[string]string{"Origin": origin}

func TestValueLinkIsSingleUseAndBoundToItsService(t *testing.T) {
	e := newEnv(t)
	path := e.link("proxy")
	// Opening the page (or a chat app's preview) does not use the link.
	for range 2 {
		if w := e.page("GET", path, nil, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="value"`) {
			t.Fatalf("GET link page: %d %s", w.Code, w.Body)
		}
	}
	if w := e.page("POST", path, url.Values{"value": {"proxy-secret-value"}}, fromPage); w.Code != http.StatusOK {
		t.Fatalf("POST value: %d %s", w.Code, w.Body)
	}
	if got := e.keys.get("PROXY_KEY"); got != "proxy-secret-value" {
		t.Fatalf("PROXY_KEY = %q", got)
	}
	if e.keys.get("OTHER_KEY") != "other-value" || e.keys.get("GMAIL_REFRESH") != "" {
		t.Fatal("a link for one service changed another service's key")
	}
	for _, m := range []string{"GET", "POST"} {
		if w := e.page(m, path, url.Values{"value": {"second"}}, fromPage); w.Code != http.StatusGone {
			t.Fatalf("%s after use: %d", m, w.Code)
		}
	}
	if e.keys.get("PROXY_KEY") != "proxy-secret-value" {
		t.Fatal("a used link stored a second value")
	}
	if strings.Contains(e.audit.String(), "proxy-secret-value") || strings.Contains(e.audit.String(), strings.TrimPrefix(path, "/p/alice/c/")) {
		t.Fatalf("audit log holds the value or the link:\n%s", e.audit)
	}
}

func TestLinkExpires(t *testing.T) {
	e := newEnv(t)
	path := e.link("proxy")
	e.clock = e.clock.Add(DefaultLinkTTL)
	if w := e.page("GET", path, nil, nil); w.Code != http.StatusGone {
		t.Fatalf("GET expired link: %d", w.Code)
	}
	if w := e.page("POST", path, url.Values{"value": {"v"}}, fromPage); w.Code != http.StatusGone || e.keys.get("PROXY_KEY") != "" {
		t.Fatalf("POST expired link: %d, stored %q", w.Code, e.keys.get("PROXY_KEY"))
	}
	// A custom lifetime is bounded.
	for _, ttl := range []string{"30", "3601", "-5", "9223372036854775807", "18446744074"} {
		if w := e.api("POST", "/links", apiToken, `{"service":"proxy","ttl_seconds":`+ttl+`}`); w.Code != http.StatusBadRequest {
			t.Fatalf("ttl %s: %d", ttl, w.Code)
		}
	}
}

func TestPostNeedsThePageOrigin(t *testing.T) {
	e := newEnv(t)
	path := e.link("proxy")
	for _, hdr := range []map[string]string{nil, {"Origin": "https://evil.example"}, {"Origin": "null"}} {
		if w := e.page("POST", path, url.Values{"value": {"v"}}, hdr); w.Code != http.StatusForbidden {
			t.Fatalf("POST with Origin %v: %d", hdr, w.Code)
		}
	}
	// A refused post does not use up the link.
	if w := e.page("POST", path, url.Values{"value": {"v"}}, fromPage); w.Code != http.StatusOK {
		t.Fatalf("POST from the page after refused posts: %d", w.Code)
	}
}

func TestAPINeedsSourceAndToken(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name, source, token string
		want                int
	}{
		{"no token", router, "", http.StatusUnauthorized},
		{"role token", router, roleToken, http.StatusUnauthorized},
		{"wrong token", router, "nope", http.StatusUnauthorized},
		{"other source", "10.0.0.6", apiToken, http.StatusForbidden},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/links", strings.NewReader(`{"service":"proxy"}`))
		r.RemoteAddr = c.source + ":5000"
		if c.token != "" {
			r.Header.Set("Authorization", "Bearer "+c.token)
		}
		w := httptest.NewRecorder()
		e.s.APIHandler().ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%s: %d, want %d", c.name, w.Code, c.want)
		}
	}
	// Scopes, keys and paths are config, not link parameters.
	if w := e.api("POST", "/links", apiToken, `{"service":"gmail","scopes":["x"]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("link with scopes: %d", w.Code)
	}
	for _, svc := range []string{"signer", "nosign", "missing"} {
		if w := e.api("POST", "/links", apiToken, `{"service":"`+svc+`"}`); w.Code == http.StatusCreated {
			t.Fatalf("link for %s created", svc)
		}
	}
}

func TestPagesListenerServesNothingElse(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/", "/keys", "/login", "/links", "/_keyring/health", "/gmail/v1/x", "/p/alice", "/p/alice/c/", "/p/alicex/callback", "/p/alice/keys/gmail"} {
		for _, m := range []string{"GET", "POST", "DELETE"} {
			if w := e.page(m, p, nil, fromPage); w.Code != http.StatusNotFound {
				t.Errorf("%s %s on the pages listener: %d", m, p, w.Code)
			}
		}
	}
}

// startSignIn opens a gmail link, presses Connect, and returns the provider
// redirect and the cookie set on the browser.
func (e *env) startSignIn() (*url.URL, *http.Cookie) {
	e.t.Helper()
	path := e.link("gmail")
	if w := e.page("GET", path, nil, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Sign in") {
		e.t.Fatalf("gmail link page: %d %s", w.Code, w.Body)
	}
	w := e.page("POST", path, url.Values{}, fromPage)
	if w.Code != http.StatusSeeOther {
		e.t.Fatalf("Connect: %d %s", w.Code, w.Body)
	}
	to, _ := url.Parse(w.Header().Get("Location"))
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
		e.t.Fatalf("cookies %v", cookies)
	}
	e.prov.mu.Lock()
	e.prov.challenge = to.Query().Get("code_challenge")
	e.prov.mu.Unlock()
	if w := e.page("POST", path, url.Values{}, fromPage); w.Code != http.StatusGone {
		e.t.Fatalf("second Connect on the same link: %d", w.Code)
	}
	return to, cookies[0]
}

func callbackPath(q url.Values) string { return "/p/alice/callback?" + q.Encode() }

func TestOAuthSignInStoresRefreshToken(t *testing.T) {
	e := newEnv(t)
	to, cookie := e.startSignIn()
	q := to.Query()
	want := map[string]string{
		"response_type": "code", "client_id": "client.apps", "redirect_uri": public + "/callback",
		"scope": "https://mail.google.com/", "code_challenge_method": "S256",
		"access_type": "offline", "prompt": "consent",
	}
	if to.Scheme+"://"+to.Host+to.Path != "https://accounts.example.com/auth" {
		t.Fatalf("redirect to %s", to)
	}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("auth param %s = %q, want %q", k, q.Get(k), v)
		}
	}
	if len(q.Get("state")) < 40 || len(q.Get("code_challenge")) != 43 {
		t.Fatalf("state %q, challenge %q", q.Get("state"), q.Get("code_challenge"))
	}
	w := e.page("GET", callbackPath(url.Values{"code": {"good-code"}, "state": {q.Get("state")}}), nil, nil, cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Connected") {
		t.Fatalf("callback: %d %s", w.Code, w.Body)
	}
	if got := e.keys.get("GMAIL_REFRESH"); got != "1//person-refresh" {
		t.Fatalf("GMAIL_REFRESH = %q", got)
	}
	e.prov.mu.Lock()
	ex := e.prov.exchanges[0]
	e.prov.mu.Unlock()
	if ex.Get("grant_type") != "authorization_code" || ex.Get("redirect_uri") != public+"/callback" || ex.Get("client_secret") != "google-client-secret" || ex.Get("client_id") != "client.apps" {
		t.Fatalf("token request %v", ex)
	}
	// The state works once.
	if w := e.page("GET", callbackPath(url.Values{"code": {"good-code"}, "state": {q.Get("state")}}), nil, nil, cookie); w.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback: %d", w.Code)
	}
	for _, secret := range []string{"1//person-refresh", "google-client-secret", "good-code", q.Get("state"), cookie.Value} {
		if strings.Contains(e.audit.String(), secret) {
			t.Fatalf("audit log holds %q:\n%s", secret, e.audit)
		}
	}
}

func TestOAuthCallbackChecksStateAndBrowser(t *testing.T) {
	e := newEnv(t)
	to, cookie := e.startSignIn()
	state := to.Query().Get("state")
	good := url.Values{"code": {"good-code"}, "state": {state}}
	if w := e.page("GET", callbackPath(url.Values{"code": {"good-code"}, "state": {"forged"}}), nil, nil, cookie); w.Code != http.StatusBadRequest {
		t.Fatalf("forged state: %d", w.Code)
	}
	// Right state, another browser (an attacker who sends the person's
	// own callback, or a person sent the attacker's): refused, and the
	// sign-in is gone.
	other := &http.Cookie{Name: cookie.Name, Value: "someone-else"}
	if w := e.page("GET", callbackPath(good), nil, nil, other); w.Code != http.StatusForbidden {
		t.Fatalf("callback from another browser: %d", w.Code)
	}
	if w := e.page("GET", callbackPath(good), nil, nil, cookie); w.Code != http.StatusBadRequest {
		t.Fatalf("callback after a refused try: %d", w.Code)
	}
	if e.keys.get("GMAIL_REFRESH") != "" {
		t.Fatal("refresh token stored without a valid callback")
	}

	// No cookie at all.
	to, _ = e.startSignIn()
	if w := e.page("GET", callbackPath(url.Values{"code": {"good-code"}, "state": {to.Query().Get("state")}}), nil, nil); w.Code != http.StatusForbidden {
		t.Fatalf("callback without the cookie: %d", w.Code)
	}

	// The sign-in expires.
	to, cookie = e.startSignIn()
	e.clock = e.clock.Add(signInTTL)
	if w := e.page("GET", callbackPath(url.Values{"code": {"good-code"}, "state": {to.Query().Get("state")}}), nil, nil, cookie); w.Code != http.StatusBadRequest {
		t.Fatalf("expired sign-in: %d", w.Code)
	}
	if e.keys.get("GMAIL_REFRESH") != "" {
		t.Fatal("refresh token stored")
	}
}

func TestOAuthFailuresStoreNothing(t *testing.T) {
	e := newEnv(t)
	// The provider refuses (wrong code): its description is not shown.
	to, cookie := e.startSignIn()
	w := e.page("GET", callbackPath(url.Values{"code": {"bad-code"}, "state": {to.Query().Get("state")}}), nil, nil, cookie)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "invalid_grant") || strings.Contains(w.Body.String(), "PKCE says no") {
		t.Fatalf("refused code: %d %s", w.Code, w.Body)
	}
	// The person cancels at the provider.
	to, cookie = e.startSignIn()
	w = e.page("GET", callbackPath(url.Values{"error": {"access_denied"}, "state": {to.Query().Get("state")}}), nil, nil, cookie)
	// It is a failure even though the page answers 200: shown and announced
	// as a problem, never with the success look.
	if !strings.Contains(w.Body.String(), "access_denied") || !strings.Contains(w.Body.String(), `role="alert"`) {
		t.Fatalf("cancelled: %d %s", w.Code, w.Body)
	}
	// No refresh token in the reply.
	e.prov.mu.Lock()
	e.prov.noRefresh = true
	e.prov.mu.Unlock()
	to, cookie = e.startSignIn()
	w = e.page("GET", callbackPath(url.Values{"code": {"good-code"}, "state": {to.Query().Get("state")}}), nil, nil, cookie)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "no refresh token") {
		t.Fatalf("no refresh token: %d %s", w.Code, w.Body)
	}
	// The service's settings changed during the sign-in.
	e.prov.mu.Lock()
	e.prov.noRefresh = false
	e.prov.mu.Unlock()
	to, cookie = e.startSignIn()
	next := *e.cfg
	next.Services = maps.Clone(e.cfg.Services)
	svc := next.Services["gmail"]
	changed := *svc.OAuth2
	changed.Scopes = []string{"https://www.googleapis.com/auth/gmail.readonly"}
	svc.OAuth2 = &changed
	next.Services["gmail"] = svc
	e.cfg = &next
	w = e.page("GET", callbackPath(url.Values{"code": {"good-code"}, "state": {to.Query().Get("state")}}), nil, nil, cookie)
	if w.Code != http.StatusConflict {
		t.Fatalf("settings changed: %d %s", w.Code, w.Body)
	}
	if e.keys.get("GMAIL_REFRESH") != "" {
		t.Fatal("a failed sign-in stored a refresh token")
	}
}

func TestDeleteRevokesAndDeletes(t *testing.T) {
	e := newEnv(t)
	e.keys.Set("GMAIL_REFRESH", "1//person-refresh")
	w := e.api("DELETE", "/keys/gmail", apiToken, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"revoked":true`) {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if e.keys.get("GMAIL_REFRESH") != "" {
		t.Fatal("key not deleted")
	}
	e.prov.mu.Lock()
	rev := e.prov.revoked[0]
	e.prov.mu.Unlock()
	if rev.Get("token") != "1//person-refresh" || rev.Get("token_type_hint") != "refresh_token" || rev.Get("client_secret") != "google-client-secret" {
		t.Fatalf("revoke request %v", rev)
	}
	// The provider is down: the key is deleted anyway, and the caller is told.
	e.keys.Set("GMAIL_REFRESH", "1//again")
	e.prov.mu.Lock()
	e.prov.revokeErr = true
	e.prov.mu.Unlock()
	w = e.api("DELETE", "/keys/gmail", apiToken, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"revoked":false`) || e.keys.get("GMAIL_REFRESH") != "" {
		t.Fatalf("delete with revoke failing: %d %s, key %q", w.Code, w.Body, e.keys.get("GMAIL_REFRESH"))
	}
	// Fixed keys: deleted, no provider call. Signing keys: refused.
	if w := e.api("DELETE", "/keys/other", apiToken, ""); w.Code != http.StatusOK || e.keys.get("OTHER_KEY") != "" {
		t.Fatalf("delete fixed key: %d", w.Code)
	}
	if w := e.api("DELETE", "/keys/signer", apiToken, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("delete signing key: %d", w.Code)
	}
	if strings.Contains(e.audit.String(), "1//") {
		t.Fatalf("audit log holds a refresh token:\n%s", e.audit)
	}
}

func TestDefaultPortInPublicURL(t *testing.T) {
	e := newEnv(t)
	next := *e.cfg
	k := *e.cfg.Consent
	k.PublicURL = "https://connect.example.com:443/p/alice"
	next.Consent = &k
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
	e.cfg = &next
	w := e.api("POST", "/links", apiToken, `{"service":"proxy"}`)
	var out struct{ URL string }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if !strings.HasPrefix(out.URL, "https://connect.example.com/p/alice/c/") {
		t.Fatalf("link url %q", out.URL)
	}
	u, _ := url.Parse(out.URL)
	// Browsers send Origin without the default port.
	if w := e.page("POST", u.Path, url.Values{"value": {"v"}}, map[string]string{"Origin": "https://connect.example.com"}); w.Code != http.StatusOK {
		t.Fatalf("POST from the page: %d %s", w.Code, w.Body)
	}
}

func TestProxyLinkStoresAddressAndCredentialTogether(t *testing.T) {
	e := newEnv(t)
	path := e.link("myproxy")
	// Invalid pastes leave the link usable and never echo any input, even
	// when a malformed paste puts credential-looking text in the address.
	for _, bad := range []struct {
		value, part string
	}{
		{"alice:s3cret@10.0.0.1:1080", "address"},
		{"alice:s3cret@gate.example.com", "port"},
		{"alice:s3cret@gate.example.com:", "port"},
		{"alice:s3cret@gate.example.com:65536", "port"},
		{"alice:s3cret@gate.example.com:s3cret", "port"},
		{"ftp://alice:s3cret@gate.example.com:21", "scheme"},
		{":s3cret@gate.example.com:1080", "username"},
		{"alice:s3cret@bad/s3cret:1080", "address"},
		{"gate.example.com:1080", "credentials"},
		{"alice:s3cret\npw@gate.example.com:1080", "password"},
	} {
		w := e.page("POST", path, url.Values{"type": {"socks5"}, "proxy": {bad.value}}, fromPage)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), bad.part) {
			t.Fatalf("invalid %s: status=%d body=%s", bad.part, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), "s3cret") || strings.Contains(w.Body.String(), "gate.example.com") {
			t.Fatal("invalid proxy input echoed in response")
		}
	}
	if e.keys.get("MY_PROXY") != "" {
		t.Fatal("stored bad input")
	}
	ok := url.Values{"type": {"socks5"}, "proxy": {" alice:s3cret:p@w@gate.person.example:5959 "}}
	if w := e.page("POST", path, ok, fromPage); w.Code != http.StatusOK {
		t.Fatalf("good input: %d %s", w.Code, w.Body)
	}
	stored := e.keys.get("MY_PROXY")
	got, cred, err := (&policy.EgressProxy{}).Resolve(stored)
	if err != nil || got.Type != policy.ProxySOCKS5 || got.Address != "gate.person.example:5959" || cred != "alice:s3cret:p@w" {
		t.Fatalf("stored %q -> %+v %q %v", stored, got, cred, err)
	}
	if w := e.page("POST", path, ok, fromPage); w.Code != http.StatusGone {
		t.Fatalf("reused: %d", w.Code)
	}
	if strings.Contains(e.audit.String(), "s3cret") || strings.Contains(e.audit.String(), "gate.person") {
		t.Fatalf("audit holds proxy details:\n%s", e.audit)
	}

	// With the address in config, the form asks only for the credential.
	path = e.link("fixedproxy")
	if w := e.page("POST", path, url.Values{"username": {"bob"}, "password": {"pw"}, "proxy": {"eve:s3cret@evil.example:1"}}, fromPage); w.Code != http.StatusOK {
		t.Fatalf("fixed-address save: %d", w.Code)
	}
	if got := e.keys.get("FIXED_PROXY"); got != "bob:pw" {
		t.Fatalf("FIXED_PROXY = %q", got)
	}
}

func TestProxyPasteSchemesAndCredentials(t *testing.T) {
	for _, tc := range []struct {
		name, paste, selected, wantType, wantAddress, wantCredential string
		tls                                                          bool
	}{
		{"default", "alice:pw@8.8.8.8:8080", "", policy.ProxyHTTPConnect, "8.8.8.8:8080", "alice:pw", false},
		{"http overrides dropdown", "http://alice:pw@gate.example:8080", policy.ProxySOCKS5, policy.ProxyHTTPConnect, "gate.example:8080", "alice:pw", false},
		{"https", "https://alice:p@ss:word@gate.example:443", policy.ProxySOCKS5, policy.ProxyHTTPConnect, "gate.example:443", "alice:p@ss:word", true},
		{"socks5", "socks5://alice:pw@gate.example:1080", policy.ProxyHTTPConnect, policy.ProxySOCKS5, "gate.example:1080", "alice:pw", false},
		{"literal password", "alice:p%40+raw://pw@gate.example:8080", policy.ProxyHTTPConnect, policy.ProxyHTTPConnect, "gate.example:8080", "alice:p%40+raw://pw", false},
		{"empty password", "alice:@gate.example:8080", policy.ProxyHTTPConnect, policy.ProxyHTTPConnect, "gate.example:8080", "alice:", false},
		{"public IPv6", "alice:pw@[2001:4860:4860::8888]:8080", policy.ProxyHTTPConnect, policy.ProxyHTTPConnect, "[2001:4860:4860::8888]:8080", "alice:pw", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			w := e.page("POST", e.link("myproxy"), url.Values{"proxy": {tc.paste}, "type": {tc.selected}}, fromPage)
			if w.Code != http.StatusOK {
				t.Fatalf("save failed: %d %s", w.Code, w.Body)
			}
			got, credential, err := e.cfg.Services["myproxy"].EgressProxy.Resolve(e.keys.get("MY_PROXY"))
			if err != nil || got.Type != tc.wantType || got.TLS != tc.tls || got.Address != tc.wantAddress || credential != tc.wantCredential {
				t.Fatalf("stored proxy does not resolve to intended endpoint/credential: %+v %q %v", got, credential, err)
			}
			if strings.Contains(w.Body.String(), tc.paste) || strings.Contains(e.audit.String(), tc.wantAddress) || strings.Contains(e.audit.String(), tc.wantCredential) {
				t.Fatal("proxy details leaked through response or audit")
			}
		})
	}
}

func TestProxyPasteCannotOverrideConfiguredTypeOrTLS(t *testing.T) {
	e := newEnv(t)
	e.cfg.Services["myproxy"].EgressProxy.Type = policy.ProxyHTTPConnect
	e.cfg.Services["myproxy"].EgressProxy.TLS = true
	path := e.link("myproxy")
	for _, paste := range []string{"socks5://alice:pw@gate.example:1080", "http://alice:pw@gate.example:8080"} {
		if w := e.page("POST", path, url.Values{"proxy": {paste}}, fromPage); w.Code != http.StatusBadRequest {
			t.Fatalf("service constraint bypass: %d", w.Code)
		}
	}
	if e.keys.get("MY_PROXY") != "" {
		t.Fatal("saved proxy violating service constraint")
	}
	if w := e.page("POST", path, url.Values{"proxy": {"alice:pw@gate.example:443"}}, fromPage); w.Code != http.StatusOK {
		t.Fatalf("configured TLS proxy rejected: %d %s", w.Code, w.Body)
	}
	got, _, err := e.cfg.Services["myproxy"].EgressProxy.Resolve(e.keys.get("MY_PROXY"))
	if err != nil || got.Type != policy.ProxyHTTPConnect || !got.TLS {
		t.Fatalf("configured TLS lost: %+v %v", got, err)
	}
}
