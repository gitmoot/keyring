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
)

// metaPathOf is the dashboard's key notes file next to the key store.
func metaPathOf(storePath string) string {
	return filepath.Join(filepath.Dir(storePath), "keymeta.json")
}

// loadConfig is policy.Load, plus the one-time upgrade of v0.14.18 key pools:
// such a pool named one value of its key ("key":"CLAUDE_KEYS.main"), which
// is now refused, as a pool names the key. Each is converted to name the key,
// and the value it named is put first in the key's list (keymeta.json at
// metaPath), so the pool still tries the same value first. With metaPath ""
// (keyring check) the conversion is checked in memory only; the service
// writes it when it starts. The key notes are written before the access
// file, so a failure in between is redone at the next start.
func loadConfig(configPath, metaPath string, out io.Writer) (*policy.Config, error) {
	rules, err := policy.LoadRules(configPath)
	if err != nil {
		return nil, err
	}
	access, err := policy.LoadAccess(rules.AccessFile)
	if err != nil {
		return nil, err
	}
	first := policy.ConvertNamedValuePools(&access)
	cfg := &policy.Config{Rules: rules, AccessList: access}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(first) == 0 {
		return cfg, nil
	}
	if metaPath == "" {
		fmt.Fprintf(out, "key pools naming one value (%s) are converted to name the key when the service starts\n", poolKeys(first))
		return cfg, nil
	}
	if err := dashboardpkg.PutValuesFirst(metaPath, first); err != nil {
		return nil, fmt.Errorf("converting key pools: %w", err)
	}
	cfg, err = policy.SaveAccess(rules, access)
	if err != nil {
		return nil, fmt.Errorf("converting key pools: %w", err)
	}
	fmt.Fprintf(out, "converted key pools to name the key, each first value kept first: %s\n", poolKeys(first))
	return cfg, nil
}

func poolKeys(first map[string]string) string {
	var names []string
	for _, key := range slices.Sorted(maps.Keys(first)) {
		names = append(names, key+"."+first[key])
	}
	return strings.Join(names, ", ")
}
