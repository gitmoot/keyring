package policy

import (
	"strings"
	"testing"
)

func bitcoinConfig() *Config {
	c := validConfig()
	c.Services["btc-ord"] = Service{Key: "BTC_ORD", Auth: AuthBitcoinPSBTSign, Bitcoin: &Bitcoin{Network: "regtest", Paths: []string{"m/86'/1'/0'/0/*", "m/84'/1'/0'/1/*"}}}
	c.Roles["phobos"].Access["btc-ord"] = Access{Paths: []string{"/"}, BitcoinMaxSatsPerTx: 100_000, BitcoinMaxSatsPerDay: 500_000}
	return c
}

func TestValidateBitcoinService(t *testing.T) {
	if err := bitcoinConfig().Validate(); err != nil {
		t.Fatalf("regtest service refused: %v", err)
	}
	for name, c := range map[string]struct {
		set  func(*Config)
		want string
	}{
		"mainnet (phase 2)": {func(c *Config) { c.Services["btc-ord"].Bitcoin.Network = "mainnet" }, "mainnet is not supported yet"},
		"unknown network":   {func(c *Config) { c.Services["btc-ord"].Bitcoin.Network = "testnet3" }, "network must be regtest, testnet or signet"},
		"purpose 44":        {func(c *Config) { c.Services["btc-ord"].Bitcoin.Paths = []string{"m/44'/1'/0'/0/*"} }, "purpose must be 86' (taproot) or 84'"},
		"no bitcoin settings": {func(c *Config) {
			s := c.Services["btc-ord"]
			s.Bitcoin = nil
			c.Services["btc-ord"] = s
		}, "bitcoin-psbt-sign requires only bitcoin settings"},
		"bitcoin settings on another auth": {func(c *Config) {
			s := c.Services["openrouter"]
			s.Bitcoin = &Bitcoin{Network: "regtest", Script: "p2tr"}
			c.Services["openrouter"] = s
		}, "bitcoin settings require auth bitcoin-psbt-sign"},
		"proxy settings": {func(c *Config) {
			s := c.Services["btc-ord"]
			s.Base = "https://example.com"
			c.Services["btc-ord"] = s
		}, "sign-only service cannot have proxy"},
		"key shared with a proxy service": {func(c *Config) {
			s := c.Services["openrouter"]
			s.Key = "BTC_ORD"
			c.Services["openrouter"] = s
		}, "a signing key cannot be shared"},
		"limit on another service": {func(c *Config) {
			c.Roles["phobos"].Access["openrouter"] = Access{Paths: []string{"/"}, BitcoinMaxSatsPerTx: 1}
		}, "apply only to bitcoin-psbt-sign services"},
		"limit on a project grant": {func(c *Config) {
			r := c.Roles["phobos"]
			r.Projects = map[string]Access{"ord": {Paths: []string{"/"}, BitcoinMaxSatsPerDay: 1}}
			c.Roles["phobos"] = r
		}, "bitcoin limits apply only to a single bitcoin-psbt-sign service"},
		"negative limit": {func(c *Config) {
			c.Roles["phobos"].Access["btc-ord"] = Access{Paths: []string{"/"}, BitcoinMaxSatsPerTx: -1}
		}, "negative"},
		"limit above 21M BTC": {func(c *Config) {
			c.Roles["phobos"].Access["btc-ord"] = Access{Paths: []string{"/"}, BitcoinMaxSatsPerDay: 2_100_000_000_000_001}
		}, "above 21 million"},
	} {
		cfg := bitcoinConfig()
		c.set(cfg)
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
