package policy

import (
	"os"
	"strings"
	"testing"
)

const mainnetService = `"btc-main":{"key":"BTC_MAIN","auth":"bitcoin-psbt-sign","project":"ord","bitcoin":{"network":"mainnet","paths":["m/86'/0'/0'/0/*","m/86'/0'/0'/1/*"]}}`

// An access file written by hand is loaded with the same mainnet rules the
// dashboard and the instance API meet (owner, 2026-11-26): a grant on a
// mainnet service sets both sats limits, each above 0 and within its
// ceiling, the per-PSBT one no more than the daily one, and needs a
// signature notice channel (notify); a project grant never reaches a
// mainnet service.
func TestLoadRefusesMainnetGrantsOutsideTheLimits(t *testing.T) {
	path, rules := writeSplit(t, 0o600)
	writeRules := func(notify string) {
		raw := `{"listen":"127.0.0.1:7701","allow_sources":["127.0.0.1"],"audit_log":"` + rules.AuditLog + `","access_file":"` + rules.AccessFile + `"` + notify + `}`
		if err := os.WriteFile(path, []byte(raw), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	writeRules(`,"notify":{"channel":"gram","url":"http://100.106.218.88:7702/notify","token_key":"KEYRING_NOTIFY_TOKEN"}`)
	load := func(role string) (*Config, error) {
		access := `{"services":{` + mainnetService + `},"roles":{"phobos":{"token_sha256":"` + hash("t1") + `",` + role + `}}}`
		if err := os.WriteFile(rules.AccessFile, []byte(access), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}
	for name, c := range map[string]struct{ role, want string }{
		"no limits":              {`"access":{"btc-main":{"paths":["/"]}}`, "needs bitcoin_max_sats_per_tx and bitcoin_max_sats_per_day"},
		"no daily limit":         {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":1000}}`, "needs bitcoin_max_sats_per_tx and bitcoin_max_sats_per_day"},
		"no per-PSBT limit":      {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_day":1000}}`, "needs bitcoin_max_sats_per_tx and bitcoin_max_sats_per_day"},
		"per-PSBT above ceiling": {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":200001,"bitcoin_max_sats_per_day":1000000}}`, "bitcoin_max_sats_per_tx is above the mainnet ceiling of 200000 sats"},
		"daily above ceiling":    {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":200000,"bitcoin_max_sats_per_day":1000001}}`, "bitcoin_max_sats_per_day is above the mainnet ceiling of 1000000 sats"},
		"per-PSBT above daily":   {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":150000,"bitcoin_max_sats_per_day":100000}}`, "bitcoin_max_sats_per_tx is above bitcoin_max_sats_per_day"},
	} {
		_, err := load(c.role)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	for name, role := range map[string]string{
		"at the ceilings": `"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":200000,"bitcoin_max_sats_per_day":1000000}}`,
		"own grant beside the project grant": `"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":1000,"bitcoin_max_sats_per_day":1000}},` +
			`"projects":{"ord":{"paths":["/"]}}`,
	} {
		if _, err := load(role); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A project grant has no sats limits: it loads, but gives no access to
	// the mainnet service, so dropping the role's own grant revokes it.
	cfg, err := load(`"access":{},"projects":{"ord":{"paths":["/"]}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.AccessFor(cfg.Roles["phobos"], "btc-main"); ok {
		t.Fatal("a project grant reaches a mainnet service")
	}
	if _, ok := cfg.Grants(cfg.Roles["phobos"])["btc-main"]; ok {
		t.Fatal("Grants lists a mainnet service through a project grant")
	}
	writeRules("")
	if _, err := load(`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":1000,"bitcoin_max_sats_per_day":1000}}`); err == nil || !strings.Contains(err.Error(), "needs notify in the rules file (a signature notice channel; supported channels: gram)") {
		t.Fatalf("a mainnet grant without notify: %v", err)
	}
}

// Owner, 2026-11-26: the owner picks the signature notice channel; Gram is
// the only one for now. Its token goes to the channel only: no service may
// use it, and plain http reaches the tailnet or loopback only.
func TestValidateNotify(t *testing.T) {
	gram := func() *Notify {
		return &Notify{Channel: "gram", URL: "http://100.106.218.88:7702/notify", TokenKey: "KEYRING_NOTIFY_TOKEN"}
	}
	for name, c := range map[string]struct {
		change func(*Config)
		want   string
	}{
		"unknown channel": {func(c *Config) { c.Notify.Channel = "email" }, `notify: channel "email" is not supported; supported channels: gram`},
		"public http":     {func(c *Config) { c.Notify.URL = "http://203.0.113.5:7702/notify" }, "plain http only to a tailnet"},
		"token with part": {func(c *Config) { c.Notify.TokenKey = "NOTIFY.token" }, "is not a valid key name"},
		"token as service": {func(c *Config) {
			c.Services["api"] = Service{Base: "https://api.example.com", Key: "KEYRING_NOTIFY_TOKEN", Auth: AuthBearer}
		}, "service api: KEYRING_NOTIFY_TOKEN is the notify token and cannot be a service's key"},
		"token as a value": {func(c *Config) {
			c.Services["api"] = Service{Base: "https://api.example.com", Key: "KEYRING_NOTIFY_TOKEN.b", Auth: AuthBearer}
		}, "is the notify token"},
	} {
		cfg := validConfig()
		cfg.Notify = gram()
		c.change(cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg := validConfig()
	cfg.Notify = gram()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
