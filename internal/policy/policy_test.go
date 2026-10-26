package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestExtraHeaderPolicy(t *testing.T) {
	for _, auth := range []string{AuthBearer, AuthHeader, AuthQuery} {
		t.Run(auth, func(t *testing.T) {
			var svc Service
			raw := `{"base":"https://service.example","auth":"` + auth + `","key":"PRIMARY","header":"CF-Access-Client-Id","param":"api_key","extra_headers":{"CF-Access-Client-Secret":"SECONDARY","X-Service-Token":"TERTIARY"}}`
			if err := json.Unmarshal([]byte(raw), &svc); err != nil {
				t.Fatal(err)
			}
			if err := svc.validate(); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(svc.KeyNames(), []string{"PRIMARY", "SECONDARY", "TERTIARY"}) {
				t.Fatal("required credential dependencies were lost")
			}
		})
	}
	for _, extras := range []string{
		`{"Authorization":"OTHER"}`, `{"Host":"OTHER"}`, `{"Connection":"OTHER"}`,
		`{"Transfer-Encoding":"OTHER"}`, `{"Content-Length":"OTHER"}`, `{"Cookie\r\nX-Evil":"OTHER"}`,
		`{"X-Keyring-Caller":"OTHER"}`, `{"X-Keyring-Token":"OTHER"}`,
		`{"cf-access-client-id":"OTHER"}`, `{"X-Token":"OTHER","x-token":"ANOTHER"}`,
		`{"X-Token":"PRIMARY"}`, `{"X-Token":"bad-name"}`,
		`{"X-One":"ONE","X-Two":"TWO","X-Three":"THREE"}`,
		`{"X-One":"ONE","X-Two":"ONE"}`,
	} {
		t.Run(extras, func(t *testing.T) {
			var svc Service
			if err := json.Unmarshal([]byte(`{"base":"https://service.example","auth":"header","key":"PRIMARY","header":"CF-Access-Client-Id","extra_headers":`+extras+`}`), &svc); err != nil {
				t.Fatal(err)
			}
			if svc.validate() == nil {
				t.Fatal("unsafe credential header mapping accepted")
			}
		})
	}
	for _, protected := range []string{"REFRESH", "CLIENT_SECRET"} {
		t.Run("protected-"+protected, func(t *testing.T) {
			cfg := validConfig()
			cfg.Services["oauth"] = Service{Base: "https://service.example", Auth: AuthOAuth2, Key: "REFRESH", OAuth2: &OAuth2{TokenURL: "https://oauth.example/token", ClientID: "client", ClientSecretKey: "CLIENT_SECRET"}}
			var svc Service
			if err := json.Unmarshal([]byte(`{"base":"https://service.example","auth":"bearer","key":"PRIMARY","extra_headers":{"X-Steal":"`+protected+`"}}`), &svc); err != nil {
				t.Fatal(err)
			}
			cfg.Services["leak"] = svc
			if cfg.Validate() == nil {
				t.Fatal("protected OAuth material could be sent as an extra header")
			}
		})
	}
}

func validConfig() *Config {
	return &Config{
		Rules: Rules{
			Listen:       "100.64.0.10:7701",
			AllowSources: []string{"100.64.0.20"},
			AuditLog:     "/tmp/audit.log",
		},
		AccessList: AccessList{
			Services: map[string]Service{
				"openrouter": {Base: "https://openrouter.ai", Key: "OPENROUTER_API_KEY", Auth: AuthBearer},
			},
			Roles: map[string]Role{
				"phobos": {TokenSHA256: hash("t1"), Access: map[string]Access{"openrouter": {Paths: []string{"/api/v1"}}}},
			},
		},
	}
}

func TestValidateRejectsUnsafeRules(t *testing.T) {
	cases := map[string]func(*Config){
		"wildcard listen":    func(c *Config) { c.Listen = "0.0.0.0:7701" },
		"allow every source": func(c *Config) { c.AllowSources = []string{"0.0.0.0/0"} },
		"no sources":         func(c *Config) { c.AllowSources = nil },
		"plain http to internet": func(c *Config) {
			c.Services["openrouter"] = Service{Base: "http://openrouter.ai", Key: "K", Auth: AuthBearer}
		},
		"credentials in base": func(c *Config) {
			c.Services["openrouter"] = Service{Base: "https://u:p@openrouter.ai", Key: "K", Auth: AuthBearer}
		},
		"unknown auth": func(c *Config) {
			c.Services["openrouter"] = Service{Base: "https://openrouter.ai", Key: "K", Auth: "basic"}
		},
		"header auth without name": func(c *Config) {
			c.Services["openrouter"] = Service{Base: "https://openrouter.ai", Key: "K", Auth: AuthHeader}
		},
		"bad token hash":          func(c *Config) { r := c.Roles["phobos"]; r.TokenSHA256 = "abc"; c.Roles["phobos"] = r },
		"unknown service in role": func(c *Config) { c.Roles["phobos"].Access["nope"] = Access{Paths: []string{"/"}} },
		"path with dots":          func(c *Config) { c.Roles["phobos"].Access["openrouter"] = Access{Paths: []string{"/a/../b"}} },
		"no paths":                func(c *Config) { c.Roles["phobos"].Access["openrouter"] = Access{} },
		"shared token": func(c *Config) {
			c.Roles["other"] = Role{TokenSHA256: hash("t1"), Access: map[string]Access{}}
		},
	}
	for name, mutate := range cases {
		c := validConfig()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	loopback := validConfig()
	loopback.Services["openrouter"] = Service{Base: "http://127.0.0.1:9", Key: "K", Auth: AuthBearer}
	if err := loopback.Validate(); err != nil {
		t.Fatalf("loopback http test server refused: %v", err)
	}
}

func TestRoleForTokenAndSources(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if name, _, ok := c.RoleForToken("t1"); !ok || name != "phobos" {
		t.Fatalf("RoleForToken(t1) = %q, %v", name, ok)
	}
	for _, token := range []string{"", "t2", hash("t1")} {
		if _, _, ok := c.RoleForToken(token); ok {
			t.Fatalf("RoleForToken(%q) matched", token)
		}
	}
	if !c.SourceAllowed(netip.MustParseAddr("100.64.0.20")) || !c.SourceAllowed(netip.MustParseAddr("::ffff:100.64.0.20")) {
		t.Fatal("allowed source refused")
	}
	if c.SourceAllowed(netip.MustParseAddr("100.64.0.21")) {
		t.Fatal("other source allowed")
	}
}

func TestAccessMatchesWholeSegmentsAndDefaultMethods(t *testing.T) {
	a := Access{Paths: []string{"/api/v1/"}}
	for p, want := range map[string]bool{"/api/v1": true, "/api/v1/chat": true, "/api/v10": false, "/api": false, "/": false} {
		if got := a.AllowsPath(p); got != want {
			t.Errorf("AllowsPath(%q) = %v, want %v", p, got, want)
		}
	}
	if !(Access{Paths: []string{"/"}}).AllowsPath("/anything/at/all") {
		t.Error(`"/" does not allow everything`)
	}
	if !a.AllowsMethod("POST") || a.AllowsMethod("DELETE") {
		t.Error("default methods wrong")
	}
	if (Access{Methods: []string{"GET"}}).AllowsMethod("POST") {
		t.Error("explicit method list ignored")
	}
}

func TestValidateTLSPin(t *testing.T) {
	pin := hash("cert")
	service := func(base, pin string) Service {
		var svc Service
		doc := `{"base":"` + base + `","key":"K","auth":"bearer","tls_pin_sha256":"` + pin + `"}`
		if err := json.Unmarshal([]byte(doc), &svc); err != nil {
			t.Fatal(err)
		}
		return svc
	}
	ok := validConfig()
	ok.Services["openrouter"] = service("https://100.111.92.43:9443", pin)
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid pin refused: %v", err)
	}
	for name, svc := range map[string]Service{
		"http base": service("http://127.0.0.1:9", pin),
		"short":     service("https://h.example", pin[:63]),
		"uppercase": service("https://h.example", strings.ToUpper(pin)),
		"colon hex": service("https://h.example", pin[:62]+":a"),
	} {
		c := validConfig()
		c.Services["openrouter"] = svc
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "tls_pin_sha256") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateOAuth2(t *testing.T) {
	google := func() *OAuth2 {
		return &OAuth2{TokenURL: "https://oauth2.googleapis.com/token", ClientID: "id.apps.googleusercontent.com", ClientSecretKey: "GOOGLE_CLIENT_SECRET"}
	}
	gmail := Service{Base: "https://gmail.googleapis.com", Key: "GMAIL_REFRESH", Auth: AuthOAuth2, OAuth2: google()}
	cases := map[string]func(*Config){
		"oauth2 without settings": func(c *Config) {
			s := gmail
			s.OAuth2 = nil
			c.Services["gmail"] = s
		},
		"token url over plain http": func(c *Config) {
			s := gmail
			s.OAuth2 = google()
			s.OAuth2.TokenURL = "http://oauth2.googleapis.com/token"
			c.Services["gmail"] = s
		},
		"no client id": func(c *Config) {
			s := gmail
			s.OAuth2 = google()
			s.OAuth2.ClientID = ""
			c.Services["gmail"] = s
		},
		"client secret is the refresh token": func(c *Config) {
			s := gmail
			s.OAuth2 = google()
			s.OAuth2.ClientSecretKey = "GMAIL_REFRESH"
			c.Services["gmail"] = s
		},
		"oauth2 settings on a bearer service": func(c *Config) {
			c.Services["openrouter"] = Service{Base: "https://openrouter.ai", Key: "OPENROUTER_API_KEY", Auth: AuthBearer, OAuth2: google()}
		},
		"refresh token sent as a bearer key": func(c *Config) {
			c.Services["gmail"] = gmail
			c.Services["leak"] = Service{Base: "https://example.com", Key: "GMAIL_REFRESH", Auth: AuthBearer}
		},
		"client secret sent as a bearer key": func(c *Config) {
			c.Services["gmail"] = gmail
			c.Services["leak"] = Service{Base: "https://example.com", Key: "GOOGLE_CLIENT_SECRET", Auth: AuthBearer}
		},
		"refresh token shared across clients": func(c *Config) {
			c.Services["gmail"] = gmail
			other := gmail
			other.OAuth2 = google()
			other.OAuth2.ClientID = "other.apps.googleusercontent.com"
			c.Services["drive"] = other
		},
		"oauth2 on a sign-only service": func(c *Config) {
			c.Services["sign"] = Service{Key: "SIGN", Auth: AuthEd25519Sign, OAuth2: google()}
		},
		"refresh token used as another client's secret": func(c *Config) {
			c.Services["gmail"] = gmail
			other := gmail
			other.Key = "OTHER_REFRESH"
			other.OAuth2 = google()
			other.OAuth2.TokenURL = "https://evil.example.com/token"
			other.OAuth2.ClientSecretKey = "GMAIL_REFRESH"
			c.Services["other"] = other
		},
		"client secret sent to two token endpoints": func(c *Config) {
			c.Services["gmail"] = gmail
			other := gmail
			other.Key = "OTHER_REFRESH"
			other.OAuth2 = google()
			other.OAuth2.TokenURL = "https://other.example.com/token"
			c.Services["other"] = other
		},
	}
	for name, mutate := range cases {
		c := validConfig()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// One Google login used by two APIs with one client: allowed.
	c := validConfig()
	c.Services["gmail"] = gmail
	drive := gmail
	drive.Base = "https://www.googleapis.com"
	drive.OAuth2 = google()
	c.Services["drive"] = drive
	if err := c.Validate(); err != nil {
		t.Fatalf("shared refresh token with the same client refused: %v", err)
	}
	if names := c.Services["gmail"].KeyNames(); !slices.Equal(names, []string{"GMAIL_REFRESH", "GOOGLE_CLIENT_SECRET"}) {
		t.Fatalf("KeyNames = %v", names)
	}
}

func TestValidateConsent(t *testing.T) {
	consent := func() *Consent {
		return &Consent{Listen: "127.0.0.1:7710", PublicURL: "https://connect.example.com/p/alice/", APIListen: "127.0.0.1:7711",
			APIAllowSources: []string{"10.0.0.5"}, APITokenSHA256: hash("consent-token")}
	}
	c := validConfig()
	c.Consent = consent()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid consent refused: %v", err)
	}
	if got := c.Consent.PublicBase().String(); got != "https://connect.example.com/p/alice" {
		t.Fatalf("PublicBase = %q", got)
	}
	if !c.Consent.APITokenMatches("consent-token") || c.Consent.APITokenMatches("") || c.Consent.APITokenMatches("t1") {
		t.Fatal("APITokenMatches")
	}
	if !c.Consent.APISourceAllowed(netip.MustParseAddr("10.0.0.5")) || c.Consent.APISourceAllowed(netip.MustParseAddr("10.0.0.6")) {
		t.Fatal("APISourceAllowed")
	}
	cases := map[string]func(*Config){
		"pages on the proxy port":    func(c *Config) { c.Consent.Listen = c.Listen },
		"api on the proxy port":      func(c *Config) { c.Consent.APIListen = c.Listen },
		"pages and api on one port":  func(c *Config) { c.Consent.APIListen = c.Consent.Listen },
		"wildcard pages":             func(c *Config) { c.Consent.Listen = "0.0.0.0:7710" },
		"public url over plain http": func(c *Config) { c.Consent.PublicURL = "http://connect.example.com" },
		"public url with a query":    func(c *Config) { c.Consent.PublicURL = "https://connect.example.com/?a=b" },
		"api open to everyone":       func(c *Config) { c.Consent.APIAllowSources = []string{"0.0.0.0/0"} },
		"no api sources":             func(c *Config) { c.Consent.APIAllowSources = nil },
		"bad token hash":             func(c *Config) { c.Consent.APITokenSHA256 = "x" },
		"api token is a role token":  func(c *Config) { c.Consent.APITokenSHA256 = hash("t1") },
		"pages on the dashboard port": func(c *Config) {
			c.AdminListen, c.AdminPasswordFile = "127.0.0.1:7702", "/x/admin.pw"
			c.Consent.Listen = c.AdminListen
		},
	}
	for name, mutate := range cases {
		c := validConfig()
		c.Consent = consent()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateOAuth2SignIn(t *testing.T) {
	svc := func() Service {
		return Service{Base: "https://gmail.googleapis.com", Key: "GMAIL_REFRESH", Auth: AuthOAuth2, OAuth2: &OAuth2{
			TokenURL: "https://oauth2.googleapis.com/token", ClientID: "id", AuthURL: "https://accounts.google.com/o/oauth2/v2/auth",
			Scopes: []string{"https://mail.google.com/"}, AuthParams: map[string]string{"access_type": "offline"}, RevokeURL: "https://oauth2.googleapis.com/revoke",
		}}
	}
	c := validConfig()
	c.Services["gmail"] = svc()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid sign-in refused: %v", err)
	}
	cases := map[string]func(*OAuth2){
		"auth url over http":       func(o *OAuth2) { o.AuthURL = "http://accounts.google.com/auth" },
		"scopes without auth url":  func(o *OAuth2) { o.AuthURL = "" },
		"scope with a space":       func(o *OAuth2) { o.Scopes = []string{"a b"} },
		"param overrides state":    func(o *OAuth2) { o.AuthParams = map[string]string{"state": "x"} },
		"param overrides redirect": func(o *OAuth2) { o.AuthParams = map[string]string{"redirect_uri": "https://evil.example.com"} },
		"param overrides pkce":     func(o *OAuth2) { o.AuthParams = map[string]string{"code_challenge_method": "plain"} },
		"revoke url over http":     func(o *OAuth2) { o.RevokeURL = "http://oauth2.googleapis.com/revoke" },
	}
	for name, mutate := range cases {
		c := validConfig()
		s := svc()
		mutate(s.OAuth2)
		c.Services["gmail"] = s
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Two services sharing a refresh token must ask for the same scopes.
	c = validConfig()
	c.Services["gmail"] = svc()
	drive := svc()
	drive.Base = "https://www.googleapis.com"
	drive.OAuth2.Scopes = []string{"https://www.googleapis.com/auth/drive"}
	c.Services["drive"] = drive
	if err := c.Validate(); err == nil {
		t.Fatal("shared refresh token with different scopes accepted")
	}
}

func TestContainerMode(t *testing.T) {
	// A file cannot turn it on.
	var fromFile Config
	if err := json.Unmarshal([]byte(`{"ContainerMode":true,"container_mode":true}`), &fromFile); err != nil || fromFile.ContainerMode {
		t.Fatalf("ContainerMode set from JSON: %v", err)
	}

	c := validConfig()
	c.Listen, c.AllowSources = "0.0.0.0:8080", nil
	if err := c.Validate(); err == nil {
		t.Fatal("wildcard listen without container mode accepted")
	}
	c.ContainerMode = true
	if err := c.Validate(); err != nil {
		t.Fatalf("container mode: %v", err)
	}
	if !c.SourceAllowed(netip.MustParseAddr("203.0.113.7")) {
		t.Fatal("container mode checked a source address")
	}
	c.AllowSources = []string{"10.0.0.1"}
	if err := c.Validate(); err == nil {
		t.Fatal("container mode with allow_sources accepted (they would prove nothing)")
	}

	consent := func() *Consent {
		return &Consent{Listen: "0.0.0.0:8081", PublicURL: "https://connect.example.com/p/x", APIListen: "0.0.0.0:8082", APITokenSHA256: hash("api")}
	}
	cases := map[string]func(*Config){
		"pages on the proxy port":      func(c *Config) { c.Consent.Listen = "127.0.0.1:8080" },
		"api on the proxy port":        func(c *Config) { c.Consent.APIListen = "10.1.2.3:8080" },
		"pages and api on one port":    func(c *Config) { c.Consent.APIListen = "127.0.0.1:8081" },
		"consent api sources in a box": func(c *Config) { c.Consent.APIAllowSources = []string{"10.0.0.1"} },
	}
	ok := validConfig()
	ok.ContainerMode, ok.Listen, ok.AllowSources, ok.Consent = true, "0.0.0.0:8080", nil, consent()
	if err := ok.Validate(); err != nil {
		t.Fatalf("container consent: %v", err)
	}
	if !ok.Consent.APISourceAllowed(netip.MustParseAddr("203.0.113.7")) {
		t.Fatal("container mode checked the consent API source")
	}
	for name, mutate := range cases {
		c := validConfig()
		c.ContainerMode, c.Listen, c.AllowSources, c.Consent = true, "0.0.0.0:8080", nil, consent()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Outside container mode the consent listeners keep refusing wildcards.
	f := validConfig()
	f.Consent = consent()
	f.Consent.APIAllowSources = []string{"10.0.0.5"}
	if err := f.Validate(); err == nil {
		t.Fatal("wildcard consent listen accepted outside container mode")
	}
}
