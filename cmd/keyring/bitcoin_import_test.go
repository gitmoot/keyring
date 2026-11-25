package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
	"github.com/gitmoot/keyring/internal/store"
)

func TestBitcoinImportFromStdin(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "keys.json")
	var out, errOut bytes.Buffer
	code := run([]string{"bitcoin-import", "--store", storePath, "--network", "regtest", "BTC_ORD"}, strings.NewReader(bitcointest.Master+"\n"), &out, &errOut)
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
	if code := run([]string{"bitcoin-import", "--store", storePath, "--network", "regtest", "BTC_ORD"}, strings.NewReader(bitcointest.WIF+"\n"), &out, &errOut); code == 0 {
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
	}{
		{"key as an argument", []string{"--network", "regtest", "BTC_ORD", bitcointest.Master}, ""},
		{"no network", []string{"BTC_ORD"}, bitcointest.Master},
		{"mainnet", []string{"--network", "mainnet", "BTC_ORD"}, bitcointest.Master},
		{"mainnet key on regtest", []string{"--network", "regtest", "BTC_ORD"}, bitcointest.MasterMainnet},
		{"not a key", []string{"--network", "regtest", "BTC_ORD"}, "hunter2"},
		{"empty stdin", []string{"--network", "regtest", "BTC_ORD"}, ""},
	}
	for _, c := range cases {
		storePath := filepath.Join(t.TempDir(), "keys.json")
		var out, errOut bytes.Buffer
		args := append([]string{"bitcoin-import", "--store", storePath}, c.args...)
		if code := run(args, strings.NewReader(c.stdin+"\n"), &out, &errOut); code == 0 {
			t.Fatalf("%s: accepted", c.name)
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
