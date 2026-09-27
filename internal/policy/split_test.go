package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSplit(t *testing.T, accessMode os.FileMode) (rulesPath string, rules Rules) {
	t.Helper()
	dir := t.TempDir()
	rules = Rules{Listen: "127.0.0.1:7701", AllowSources: []string{"127.0.0.1"}, AuditLog: filepath.Join(dir, "audit.log"), AccessFile: filepath.Join(dir, "access.json")}
	rulesPath = filepath.Join(dir, "rules.json")
	raw := `{"listen":"127.0.0.1:7701","allow_sources":["127.0.0.1"],"audit_log":"` + rules.AuditLog + `","access_file":"` + rules.AccessFile + `"}`
	if err := os.WriteFile(rulesPath, []byte(raw), 0o640); err != nil {
		t.Fatal(err)
	}
	access := `{"services":{"openrouter":{"base":"https://openrouter.ai","key":"OPENROUTER_API_KEY","auth":"bearer"}},"roles":{"phobos":{"token_sha256":"` + hash("t1") + `","access":{"openrouter":{"paths":["/"]}}}}}`
	if err := os.WriteFile(rules.AccessFile, []byte(access), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rules.AccessFile, accessMode); err != nil {
		t.Fatal(err)
	}
	return rulesPath, rules
}

func TestLoadReadsRulesAndAccessFile(t *testing.T) {
	path, _ := writeSplit(t, 0o600)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Services["openrouter"]; !ok || len(cfg.Roles) != 1 || cfg.Listen != "127.0.0.1:7701" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestLoadRefusesAnUnmigratedRulesFile(t *testing.T) {
	for _, extra := range []string{`"services":{}`, `"roles":{}`} {
		path := filepath.Join(t.TempDir(), "rules.json")
		if err := os.WriteFile(path, []byte(`{"listen":"127.0.0.1:7701","allow_sources":["127.0.0.1"],"audit_log":"/tmp/a","access_file":"/tmp/x.json",`+extra+`}`), 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); !errors.Is(err, ErrNeedsMigration) || !strings.Contains(err.Error(), "keyring migrate") {
			t.Fatalf("with %s: err = %v, want ErrNeedsMigration naming the command", extra, err)
		}
	}
}

func TestLoadRefusesAnAccessFileOthersCanRead(t *testing.T) {
	path, _ := writeSplit(t, 0o644)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("err = %v, want refusal", err)
	}
}

func TestLoadRefusesARelativeAccessFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, []byte(`{"listen":"127.0.0.1:7701","allow_sources":["127.0.0.1"],"audit_log":"/tmp/a","access_file":"access.json"}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v", err)
	}
}

func TestSaveAccessNeverWritesAnInvalidList(t *testing.T) {
	path, rules := writeSplit(t, 0o600)
	before, _ := os.ReadFile(rules.AccessFile)
	bad := AccessList{Services: map[string]Service{"x": {Base: "http://example.com", Key: "K", Auth: AuthBearer}}}
	if _, err := SaveAccess(rules, bad); err == nil {
		t.Fatal("plain-http service accepted")
	}
	if after, _ := os.ReadFile(rules.AccessFile); string(after) != string(before) {
		t.Fatal("access file changed after a refused save")
	}
	good := AccessList{Services: map[string]Service{"tavily": {Base: "https://api.tavily.com", Key: "TAVILY_API_KEY", Auth: AuthBearer}}}
	if _, err := SaveAccess(rules, good); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Services["tavily"]; !ok || len(cfg.Services) != 1 {
		t.Fatalf("services after save = %v", cfg.Services)
	}
	if info, _ := os.Stat(rules.AccessFile); info.Mode().Perm() != 0o600 {
		t.Fatalf("access file mode %04o", info.Mode().Perm())
	}
}

func TestAdminListenMustBeLoopbackWithAPasswordFile(t *testing.T) {
	base := func() *Config {
		c := validConfig()
		c.AdminListen, c.AdminPasswordFile = "127.0.0.1:7702", "/etc/keyring/admin.pw"
		return c
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid admin settings refused: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"tailnet address": func(c *Config) { c.AdminListen = "100.111.92.43:7702" },
		"wildcard":        func(c *Config) { c.AdminListen = "0.0.0.0:7702" },
		"no port":         func(c *Config) { c.AdminListen = "127.0.0.1" },
		"port 0":          func(c *Config) { c.AdminListen = "127.0.0.1:0" },
		"same as listen": func(c *Config) {
			c.Listen = "127.0.0.1:7701"
			c.AllowSources = []string{"127.0.0.1"}
			c.AdminListen = "127.0.0.1:7701"
		},
		"no password file":       func(c *Config) { c.AdminPasswordFile = "" },
		"relative password file": func(c *Config) { c.AdminPasswordFile = "admin.pw" },
	} {
		c := base()
		mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
