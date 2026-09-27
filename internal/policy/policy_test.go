package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"net/netip"
	"testing"
)

func hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func validConfig() *Config {
	return &Config{
		Rules: Rules{
			Listen:       "100.111.92.43:7701",
			AllowSources: []string{"100.106.218.88"},
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
	if !c.SourceAllowed(netip.MustParseAddr("100.106.218.88")) || !c.SourceAllowed(netip.MustParseAddr("::ffff:100.106.218.88")) {
		t.Fatal("allowed source refused")
	}
	if c.SourceAllowed(netip.MustParseAddr("100.106.218.89")) {
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
