package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
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
		"mainnet with test paths": {func(c *Config) { c.Services["btc-ord"].Bitcoin.Network = "mainnet" }, "path 1: a mainnet service signs only for m/86'/0'/0'/0/*, m/86'/0'/0'/1/*, m/84'/0'/0'/0/*, m/84'/0'/0'/1/*"},
		"unknown network":         {func(c *Config) { c.Services["btc-ord"].Bitcoin.Network = "testnet3" }, "network must be mainnet, regtest, testnet or signet"},
		"purpose 44":              {func(c *Config) { c.Services["btc-ord"].Bitcoin.Paths = []string{"m/44'/1'/0'/0/*"} }, "purpose must be 86' (taproot) or 84'"},
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

// A stored Bitcoin key goes only to a Bitcoin signing service: any other
// service that would send it (its key, a pool value, an extra header, an
// OAuth client secret) is refused, naming the service and the store name.
func TestCheckBitcoinKeys(t *testing.T) {
	keys := map[string]string{"BTC_ORD": bitcointest.Master, "OPENROUTER_API_KEY": "sk-or-0123456789"}
	if err := bitcoinConfig().CheckBitcoinKeys(keys); err != nil {
		t.Fatalf("the signing service's own key: %v", err)
	}
	// Another value of the same key is not sent by a service naming one
	// value; only a pool sends them all.
	named := bitcoinConfig()
	named.Services["openrouter"] = Service{Base: "https://openrouter.ai", Key: "MIXED.token", Auth: AuthBearer}
	if err := named.CheckBitcoinKeys(map[string]string{"MIXED.token": "sk-or-0123456789", "MIXED.btc": bitcointest.WIF}); err != nil {
		t.Fatalf("a named value beside a Bitcoin value: %v", err)
	}
	for name, c := range map[string]struct {
		svc  Service
		keys map[string]string
		key  string
	}{
		"bearer key": {Service{Base: "https://openrouter.ai", Key: "OPENROUTER_API_KEY", Auth: AuthBearer},
			map[string]string{"OPENROUTER_API_KEY": bitcointest.WIF}, "OPENROUTER_API_KEY"},
		"pool value": {Service{Base: "https://openrouter.ai", Key: "POOL", Auth: AuthBearer, KeyPool: true},
			map[string]string{"POOL.1": "sk-or-0123456789", "POOL.2": "  " + bitcointest.Master + "\n"}, "POOL.2"},
		"extra header": {Service{Base: "https://openrouter.ai", Key: "OPENROUTER_API_KEY", Auth: AuthBearer, ExtraHeaders: map[string]string{"X-Secret": "EXTRA"}},
			map[string]string{"OPENROUTER_API_KEY": "sk-or-0123456789", "EXTRA": bitcointest.WIF}, "EXTRA"},
		"oauth client secret": {Service{Base: "https://openrouter.ai", Key: "REFRESH", Auth: AuthOAuth2, OAuth2: &OAuth2{TokenURL: "https://openrouter.ai/token", ClientID: "c", ClientSecretKey: "SECRET"}},
			map[string]string{"REFRESH": "r-0123456789", "SECRET": bitcointest.WIF}, "SECRET"},
		"signing service of another kind": {Service{Key: "SIGNER", Auth: AuthEd25519Sign},
			map[string]string{"SIGNER": bitcointest.WIF}, "SIGNER"},
	} {
		cfg := validConfig()
		cfg.Services["openrouter"] = c.svc
		err := cfg.CheckBitcoinKeys(c.keys)
		var refused *BitcoinKeyError
		if !errors.As(err, &refused) || refused.Service != "openrouter" || refused.Key != c.key {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if want := "service openrouter: " + c.key + " is a Bitcoin key; it can only be used by a Bitcoin signing service"; err.Error() != want {
			t.Errorf("%s: %q, want %q", name, err, want)
		}
	}
}
