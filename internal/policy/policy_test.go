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
