package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// bitcoinRules writes the rules of oldRules, a bearer service api on API_KEY,
// with an access file, and returns the rules file and a store path next to it.
func bitcoinRules(t *testing.T) (rules, storePath string) {
	t.Helper()
	dir := t.TempDir()
	rules = filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rules, []byte(oldRules(dir, "127.0.0.1:7701")), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := migrate(rules, filepath.Join(dir, "access.json"), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	return rules, filepath.Join(dir, "keys.json")
}

const bitcoinKeyRefusal = "service api: API_KEY is a Bitcoin key; it can only be used by a Bitcoin signing service"

func TestBitcoinImportFromStdin(t *testing.T) {
	rules, storePath := bitcoinRules(t)
	var out, errOut bytes.Buffer
	code := run([]string{"bitcoin-import", "--config", rules, "--store", storePath, "--network", "regtest", "BTC_ORD"}, strings.NewReader(bitcointest.Master+"\n"), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	keys, err := store.Load(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if keys["BTC_ORD"] != bitcointest.Master {
		t.Fatal("stored value is not the imported key")
	}
	for _, want := range []string{"stored BTC_ORD", "fingerprint: 73c5da0a", "network:     regtest", "m/86'/1'/0'/0/0", "p2tr", "bcrt1p", "m/84'/1'/0'/0/0", "bcrt1q"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String()+errOut.String(), bitcointest.Master[:20]) {
		t.Fatal("key printed")
	}

	// An existing name is never replaced.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"bitcoin-import", "--config", rules, "--store", storePath, "--network", "regtest", "BTC_ORD"}, strings.NewReader(bitcointest.WIF+"\n"), &out, &errOut); code == 0 {
		t.Fatal("an existing key was replaced")
	}
	if after, _ := store.Load(storePath); after["BTC_ORD"] != bitcointest.Master {
		t.Fatal("existing key changed")
	}
}

func TestBitcoinImportRefusals(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{"key as an argument", []string{"--network", "regtest", "BTC_ORD", bitcointest.Master}, "", ""},
		{"no network", []string{"BTC_ORD"}, bitcointest.Master, ""},
		{"mainnet", []string{"--network", "mainnet", "BTC_ORD"}, bitcointest.Master, ""},
		{"mainnet key on regtest", []string{"--network", "regtest", "BTC_ORD"}, bitcointest.MasterMainnet, ""},
		{"not a key", []string{"--network", "regtest", "BTC_ORD"}, "hunter2", ""},
		{"empty stdin", []string{"--network", "regtest", "BTC_ORD"}, "", ""},
		// The bearer service api waits for API_KEY: it would send the key.
		{"a name a proxy service uses", []string{"--network", "regtest", "API_KEY"}, bitcointest.Master, bitcoinKeyRefusal},
		{"no settings to check", []string{"--network", "regtest", "BTC_ORD"}, bitcointest.Master, "--config is required"},
	}
	for _, c := range cases {
		rules, storePath := bitcoinRules(t)
		var out, errOut bytes.Buffer
		args := append([]string{"bitcoin-import", "--store", storePath}, c.args...)
		if c.want != "--config is required" {
			args = append([]string{args[0], "--config", rules}, args[1:]...)
		}
		if code := run(args, strings.NewReader(c.stdin+"\n"), &out, &errOut); code == 0 || !strings.Contains(errOut.String(), c.want) {
			t.Fatalf("%s: exit %d: %s", c.name, code, errOut.String())
		}
		if names, _ := store.Names(storePath); len(names) != 0 {
			t.Fatalf("%s: stored %v", c.name, names)
		}
		for _, secret := range []string{bitcointest.Master[:20], bitcointest.MasterMainnet[:20], "hunter2"} {
			if strings.Contains(out.String()+errOut.String(), secret) {
				t.Fatalf("%s: key in output: %s", c.name, out.String()+errOut.String())
			}
		}
	}
}

// keyring set stores a Bitcoin key only where no service but a Bitcoin
// signing service would use it, and so only with the settings to check.
func TestSetRefusesABitcoinKeyForAProxyService(t *testing.T) {
	rules, storePath := bitcoinRules(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--config", rules, "API_KEY"}, bitcoinKeyRefusal},
		{[]string{"BTC_ORD"}, "BTC_ORD is a Bitcoin key: pass --config"},
	} {
		var out, errOut bytes.Buffer
		args := append([]string{"set", "--store", storePath}, c.args...)
		if code := run(args, strings.NewReader(bitcointest.WIF+"\n"), &out, &errOut); code == 0 || !strings.Contains(errOut.String(), c.want) {
			t.Fatalf("%v: exit %d: %s", c.args, code, errOut.String())
		}
		if names, _ := store.Names(storePath); len(names) != 0 {
			t.Fatalf("%v: stored %v", c.args, names)
		}
		assertNoCLIBitcoinKey(t, out.String()+errOut.String())
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"set", "--store", storePath, "--config", rules, "BTC_ORD"}, strings.NewReader(bitcointest.WIF+"\n"), &out, &errOut); code != 0 {
		t.Fatalf("a Bitcoin key no service uses: exit %d: %s", code, errOut.String())
	}
}

// Consent links store keys as the dashboard does: a Bitcoin key for a proxy
// service is refused before anything is written, alone or in a bundle.
func TestConsentRefusesABitcoinKeyForAProxyService(t *testing.T) {
	rules, storePath := bitcoinRules(t)
	cfg, err := policy.Load(rules)
	if err != nil {
		t.Fatal(err)
	}
	k := storeKeys{path: storePath, metaPath: filepath.Join(filepath.Dir(storePath), "keymeta.json"), mu: &sync.Mutex{}, proxy: server.New(cfg, nil, &bytes.Buffer{})}
	for name, write := range map[string]func() error{
		"Set": func() error { return k.Set("API_KEY", bitcointest.WIF) },
		"SetAll": func() error {
			return k.SetAll(map[string]string{"API_KEY": bitcointest.WIF, "OTHER": "other-0123456789"})
		},
	} {
		if err := write(); err == nil || err.Error() != bitcoinKeyRefusal {
			t.Fatalf("%s: %v", name, err)
		}
		if names, _ := store.Names(storePath); len(names) != 0 {
			t.Fatalf("%s: stored %v", name, names)
		}
	}
	if err := k.SetAll(map[string]string{"API_KEY": "sk-api-0123456789", "BTC_ORD": bitcointest.WIF}); err != nil {
		t.Fatal(err)
	}
	if keys, _ := store.Load(storePath); keys["API_KEY"] != "sk-api-0123456789" || keys["BTC_ORD"] != bitcointest.WIF {
		t.Fatal("a bundle no proxy service gets a Bitcoin key from was not stored")
	}
}

// Settings written by hand that bind a bearer service to a Bitcoin key are
// refused when they are loaded: keyring check, the service start and a
// reload, which keeps the settings in force.
func TestBitcoinKeyOfAProxyServiceIsRefusedAtLoad(t *testing.T) {
	rules, storePath := bitcoinRules(t)
	if err := store.Set(storePath, "API_KEY", "sk-api-0123456789"); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(rules)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(storePath)
	h := server.New(cfg, keys, &bytes.Buffer{})
	rl := reloader{configPath: rules, storePath: storePath, fixed: cfg.Rules, handler: h}

	if err := store.Set(storePath, "API_KEY", bitcointest.WIF); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := check(rules, storePath, &out); err == nil || err.Error() != bitcoinKeyRefusal {
		t.Fatalf("check: %v", err)
	}
	if _, _, err := rl.reload(); err == nil || err.Error() != bitcoinKeyRefusal {
		t.Fatalf("reload: %v", err)
	}
	if h.Config() != cfg {
		t.Fatal("a refused reload changed the settings in force")
	}
	var stderr bytes.Buffer
	if err := serve(rules, storePath, &stderr); err == nil || err.Error() != bitcoinKeyRefusal {
		t.Fatalf("serve: %v", err)
	}
	assertNoCLIBitcoinKey(t, out.String()+stderr.String())
}

func assertNoCLIBitcoinKey(t *testing.T, output string) {
	t.Helper()
	for _, secret := range []string{bitcointest.Master[:20], bitcointest.WIF[:20]} {
		if strings.Contains(output, secret) {
			t.Fatalf("key in output: %s", output)
		}
	}
}
