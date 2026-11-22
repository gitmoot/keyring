package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dashboardpkg "github.com/gitmoot/keyring/internal/dashboard"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// An install upgraded from v0.14.18 may have the pool that release accepted:
// "key":"CLAUDE_KEYS.main" with key_pool. The new release still checks and
// starts with it: the pool is converted to name the key, and main stays the
// value it tries first (by name order, backup1 would come first).
func TestUpgradeConvertsAPoolThatNamedOneValue(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.json")
	accessPath := filepath.Join(dir, "access.json")
	keysPath := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(rules, []byte(oldRules(dir, "127.0.0.1:7701")), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := migrate(rules, accessPath, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(rules)
	if err != nil {
		t.Fatal(err)
	}
	access := cfg.AccessList
	access.Services["claude-api"] = policy.Service{Base: "https://api.anthropic.com", Key: "CLAUDE_KEYS.main", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true}
	raw, _ := json.MarshalIndent(access, "", "  ")
	if err := os.WriteFile(accessPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"CLAUDE_KEYS.main": "sk-ant-main-0000", "CLAUDE_KEYS.backup1": "sk-ant-b1-1111", "API_KEY": "sk-api-0123456789"} {
		if err := store.Set(keysPath, name, value); err != nil {
			t.Fatal(err)
		}
	}

	// keyring check (the installer runs it before the restart) passes and
	// writes nothing.
	var out bytes.Buffer
	if err := check(rules, "", &out); err != nil {
		t.Fatalf("check with the old pool: %v", err)
	}
	if now, _ := os.ReadFile(accessPath); !bytes.Equal(now, raw) {
		t.Fatal("check changed the access file")
	}

	// The service start converts it once, on disk.
	cfg, err = loadConfig(rules, keysPath, true, &out)
	if err != nil {
		t.Fatalf("start with the old pool: %v", err)
	}
	if got := cfg.Services["claude-api"].Key; got != "CLAUDE_KEYS" {
		t.Fatalf("pool key = %s", got)
	}
	if _, err := policy.Load(rules); err != nil {
		t.Fatalf("converted access file: %v", err)
	}
	if !strings.Contains(out.String(), "CLAUDE_KEYS.main") || strings.Contains(out.String(), "sk-ant-") {
		t.Fatalf("output: %q", out.String())
	}
	keys, err := store.Load(keysPath)
	if err != nil {
		t.Fatal(err)
	}
	order, err := dashboardpkg.ValueOrder(metaPathOf(keysPath))
	if err != nil {
		t.Fatal(err)
	}
	members := policy.PoolMembers(cfg.Services["claude-api"], keys, order["CLAUDE_KEYS"])
	if len(members) != 2 || members[0] != "CLAUDE_KEYS.main" {
		t.Fatalf("pool tries %v", members)
	}
	if missing := missingKeys(cfg, keys); len(missing) > 0 {
		t.Fatalf("missing %v", missing)
	}

	// A second start changes nothing.
	before, _ := os.ReadFile(accessPath)
	out.Reset()
	if _, err := loadConfig(rules, keysPath, true, &out); err != nil || out.Len() > 0 {
		t.Fatalf("second start: %v %q", err, out.String())
	}
	if after, _ := os.ReadFile(accessPath); !bytes.Equal(before, after) {
		t.Fatal("second start rewrote the access file")
	}
}

// A conversion that would change what a v0.14.18 pool sends is refused, with
// the services named, and nothing is written: two pools of one key with
// different first values (a key has one list order now), and a pool whose
// key holds only a plain value (v0.14.18 never sent it).
func TestUpgradeRefusesPoolConversionsThatChangeWhatIsSent(t *testing.T) {
	pool := func(key string) policy.Service {
		return policy.Service{Base: "https://api.anthropic.com", Key: key, Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true}
	}
	for _, c := range []struct {
		name     string
		services map[string]policy.Service
		keys     map[string]string
		want     string
	}{
		{"different first values", map[string]policy.Service{"alpha": pool("CLAUDE_KEYS.main"), "beta": pool("CLAUDE_KEYS.backup")},
			map[string]string{"CLAUDE_KEYS.main": "sk-ant-main-0000", "CLAUDE_KEYS.backup": "sk-ant-b-1111"}, "alpha and beta"},
		{"only a plain value", map[string]policy.Service{"lone": pool("LONE.main")},
			map[string]string{"LONE": "sk-ant-lone-0000"}, "never sent the plain value LONE"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			rules := filepath.Join(dir, "rules.json")
			accessPath := filepath.Join(dir, "access.json")
			keysPath := filepath.Join(dir, "keys.json")
			if err := os.WriteFile(rules, []byte(oldRules(dir, "127.0.0.1:7701")), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := migrate(rules, accessPath, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			cfg, err := policy.Load(rules)
			if err != nil {
				t.Fatal(err)
			}
			access := cfg.AccessList
			maps.Copy(access.Services, c.services)
			raw, _ := json.MarshalIndent(access, "", "  ")
			if err := os.WriteFile(accessPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			for name, value := range c.keys {
				if err := store.Set(keysPath, name, value); err != nil {
					t.Fatal(err)
				}
			}
			_, err = loadConfig(rules, keysPath, true, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("start: %v", err)
			}
			if now, _ := os.ReadFile(accessPath); !bytes.Equal(now, raw) {
				t.Fatal("the access file was changed")
			}
			if _, err := os.Stat(metaPathOf(keysPath)); err == nil {
				t.Fatal("the key notes were written")
			}
		})
	}
}
