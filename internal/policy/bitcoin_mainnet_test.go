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
// ceiling, the per-PSBT one no more than the daily one.
func TestLoadRefusesMainnetGrantsOutsideTheLimits(t *testing.T) {
	path, rules := writeSplit(t, 0o600)
	load := func(role string) error {
		access := `{"services":{` + mainnetService + `},"roles":{"phobos":{"token_sha256":"` + hash("t1") + `",` + role + `}}}`
		if err := os.WriteFile(rules.AccessFile, []byte(access), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		return err
	}
	for name, c := range map[string]struct{ role, want string }{
		"no limits":              {`"access":{"btc-main":{"paths":["/"]}}`, "needs bitcoin_max_sats_per_tx and bitcoin_max_sats_per_day"},
		"no daily limit":         {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":1000}}`, "needs bitcoin_max_sats_per_tx and bitcoin_max_sats_per_day"},
		"no per-PSBT limit":      {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_day":1000}}`, "needs bitcoin_max_sats_per_tx and bitcoin_max_sats_per_day"},
		"per-PSBT above ceiling": {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":200001,"bitcoin_max_sats_per_day":1000000}}`, "bitcoin_max_sats_per_tx is above the mainnet ceiling of 200000 sats"},
		"daily above ceiling":    {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":200000,"bitcoin_max_sats_per_day":1000001}}`, "bitcoin_max_sats_per_day is above the mainnet ceiling of 1000000 sats"},
		"per-PSBT above daily":   {`"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":150000,"bitcoin_max_sats_per_day":100000}}`, "bitcoin_max_sats_per_tx is above bitcoin_max_sats_per_day"},
		// A project grant has no sats limits, so it may not reach a
		// mainnet service the role has no grant of its own for.
		"project grant only": {`"access":{},"projects":{"ord":{"paths":["/"]}}`, "service btc-main signs on mainnet, which needs a grant of its own"},
	} {
		err := load(c.role)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	for name, role := range map[string]string{
		"at the ceilings": `"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":200000,"bitcoin_max_sats_per_day":1000000}}`,
		"own grant beside the project grant": `"access":{"btc-main":{"paths":["/"],"bitcoin_max_sats_per_tx":1000,"bitcoin_max_sats_per_day":1000}},` +
			`"projects":{"ord":{"paths":["/"]}}`,
	} {
		if err := load(role); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestValidateNotifyCommand(t *testing.T) {
	for name, c := range map[string]struct {
		command []string
		want    string
	}{
		"empty list":    {[]string{}, "notify_command: the first entry must be the absolute path of a program"},
		"relative path": {[]string{"herdr", "gram", "send"}, "notify_command: the first entry must be the absolute path of a program"},
		"NUL byte":      {[]string{"/usr/bin/true", "a\x00b"}, "holds a NUL byte"},
	} {
		cfg := validConfig()
		cfg.NotifyCommand = c.command
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg := validConfig()
	cfg.NotifyCommand = []string{"/usr/local/bin/herdr", "gram", "send"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
