// Package store keeps key values in one JSON file that only its owner can
// read. Every change is written to a temporary file and renamed into place, so
// a crash never leaves a half-written store.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"

	"github.com/gitmoot/keyring/internal/fileutil"
)

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidName reports whether name can be a key name (an env-style identifier).
func ValidName(name string) bool { return namePattern.MatchString(name) }

// Load returns every key in the store. A missing file is an empty store. A
// file other users can read or write is refused: fix its mode first.
func Load(path string) (map[string]string, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is open to other users (mode %04o); run chmod 600 %s", path, perm, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys := map[string]string{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return keys, nil
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		// Never include the file content: it holds keys.
		return nil, fmt.Errorf("%s is not a valid key store", path)
	}
	for name := range keys {
		if !ValidName(name) {
			return nil, fmt.Errorf("%s holds an invalid key name %q", path, name)
		}
	}
	return keys, nil
}

// Names returns the key names, sorted, never the values.
func Names(path string) ([]string, error) {
	keys, err := Load(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(keys))
	for name := range keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// Set adds or replaces one key.
func Set(path, name, value string) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid key name %q: use letters, digits and _", name)
	}
	if value == "" {
		return errors.New("empty value")
	}
	keys, err := Load(path)
	if err != nil {
		return err
	}
	keys[name] = value
	return save(path, keys)
}

// Delete removes one key. Deleting a missing key is an error, so a typo is
// not mistaken for a removal.
func Delete(path, name string) error {
	keys, err := Load(path)
	if err != nil {
		return err
	}
	if _, ok := keys[name]; !ok {
		return fmt.Errorf("no key named %q", name)
	}
	delete(keys, name)
	return save(path, keys)
}

func save(path string, keys map[string]string) error {
	raw, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(path, append(raw, '\n'), 0o600)
}
