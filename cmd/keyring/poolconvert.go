package main

import (
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	dashboardpkg "github.com/gitmoot/keyring/internal/dashboard"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// metaPathOf is the dashboard's key notes file next to the key store.
func metaPathOf(storePath string) string {
	return filepath.Join(filepath.Dir(storePath), "keymeta.json")
}

// loadConfig is policy.Load, plus the one-time upgrade of v0.14.18 key pools:
// such a pool named one value of its key ("key":"CLAUDE_KEYS.main"), which
// is now refused, as a pool names the key. Each is converted to name the key,
// and the key's list (keymeta.json next to the store) gets the order v0.14.18
// tried: the value it named first, then the key's other values by name
// (lexically: "10" before "2"), so the pool keeps its whole failover order.
// Conversions that would change what a pool sends are refused before
// anything is written: two pools of one key with different first values,
// and a pool whose key also holds a plain value (v0.14.18 never sent it; a
// pool now would, once the key has no other values). Without write (keyring
// check) the conversion is checked in memory only; the service writes it
// when it starts. The key notes are written before the access file, so a
// failure in between is redone at the next start. With a store, its keys are
// returned. A stored Bitcoin key that a service other than a Bitcoin signing
// service would use does not stop the load: check refuses it, serve warns
// (bitcoinKeyWarnings) and the proxy refuses those calls.
func loadConfig(configPath, storePath string, write bool, out io.Writer) (*policy.Config, map[string]string, error) {
	rules, err := policy.LoadRules(configPath)
	if err != nil {
		return nil, nil, err
	}
	access, err := policy.LoadAccess(rules.AccessFile)
	if err != nil {
		return nil, nil, err
	}
	first, err := policy.ConvertNamedValuePools(&access)
	if err != nil {
		return nil, nil, fmt.Errorf("converting v0.14.18 key pools: %w", err)
	}
	cfg := &policy.Config{Rules: rules, AccessList: access}
	if err := cfg.Validate(); err != nil {
		if len(first) > 0 {
			return nil, nil, fmt.Errorf("converting v0.14.18 key pools (%s): %w", poolKeys(first), err)
		}
		return nil, nil, err
	}
	var keys map[string]string
	if storePath != "" {
		if keys, err = store.Load(storePath); err != nil {
			return nil, nil, err
		}
	}
	if len(first) == 0 {
		return cfg, keys, nil
	}
	order := map[string][]string{}
	for key, part := range first {
		order[key] = []string{part}
	}
	if storePath != "" {
		for _, key := range slices.Sorted(maps.Keys(first)) {
			if keys[key] != "" {
				return nil, nil, fmt.Errorf("converting v0.14.18 key pools: the pool on %s.%s never sent the plain value %s, but a pool on %s now would once its other values are gone; store that value as %s.<name>, or delete it, or remove key_pool, then start again", key, first[key], key, key, key)
			}
			order[key] = append(order[key], otherValues(keys, key, first[key])...)
		}
	}
	if !write {
		fmt.Fprintf(out, "key pools naming one value (%s) are converted to name the key when the service starts\n", poolKeys(first))
		return cfg, keys, nil
	}
	if err := dashboardpkg.PutValueOrder(metaPathOf(storePath), order); err != nil {
		return nil, nil, fmt.Errorf("converting key pools: %w", err)
	}
	cfg, err = policy.SaveAccess(rules, access)
	if err != nil {
		return nil, nil, fmt.Errorf("converting key pools: %w", err)
	}
	fmt.Fprintf(out, "converted key pools to name the key, each first value kept first: %s\n", poolKeys(first))
	return cfg, keys, nil
}

// otherValues are the names of key's stored values (key.part) other than
// skip, sorted by name as v0.14.18 tried a pool's backups.
func otherValues(keys map[string]string, key, skip string) []string {
	var parts []string
	for name, value := range keys {
		if base, part := store.SplitPart(name); base == key && part != "" && part != skip && value != "" {
			parts = append(parts, part)
		}
	}
	slices.Sort(parts)
	return parts
}

func poolKeys(first map[string]string) string {
	var names []string
	for _, key := range slices.Sorted(maps.Keys(first)) {
		names = append(names, key+"."+first[key])
	}
	return strings.Join(names, ", ")
}
