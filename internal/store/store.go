// Package store keeps key values in one JSON file that only its owner can
// read. Every change is written to a temporary file and renamed into place, so
// a crash never leaves a half-written store.
package store

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/gitmoot/keyring/internal/fileutil"
)

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[a-z0-9_]{1,32})?$`)

// ValidName reports whether name can be a key name: an env-style identifier,
// optionally with one ".part" for one of several values of the same key
// (e.g. MODAL.id and MODAL.secret).
func ValidName(name string) bool { return namePattern.MatchString(name) }

// SplitPart returns the key and part of a name: "MODAL.id" gives "MODAL",
// "id"; a name without a part gives the name and "".
func SplitPart(name string) (key, part string) {
	key, part, _ = strings.Cut(name, ".")
	return key, part
}

// ValidPart reports whether part can name one value of a key.
func ValidPart(part string) bool { return partPattern.MatchString(part) }

var partPattern = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

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

// SetAll validates and writes a credential bundle in one atomic store update.
func SetAll(path string, values map[string]string) error {
	for name, value := range values {
		if !ValidName(name) || value == "" {
			return errors.New("invalid credential bundle")
		}
	}
	keys, err := Load(path)
	if err != nil {
		return err
	}
	for name, value := range values {
		keys[name] = value
	}
	return save(path, keys)
}

// DeleteAll removes the named credentials together, including partial bundles.
func DeleteAll(path string, names []string) error {
	keys, err := Load(path)
	if err != nil {
		return err
	}
	for _, name := range names {
		delete(keys, name)
	}
	return save(path, keys)
}

// Move renames values (old name -> new name) and adds new ones (name ->
// value) in one atomic store update. Every old name must be stored; no new or
// added name may be (unless it is moved away in the same update): a move
// never overwrites a value.
func Move(path string, moves, add map[string]string) error {
	keys, err := Load(path)
	if err != nil {
		return err
	}
	values := make(map[string]string, len(moves))
	for from := range moves {
		v, ok := keys[from]
		if !ok {
			return fmt.Errorf("no key named %q", from)
		}
		values[from] = v
		delete(keys, from)
	}
	put := func(name, value string) error {
		if !ValidName(name) {
			return fmt.Errorf("invalid key name %q: use letters, digits and _", name)
		}
		if value == "" {
			return errors.New("empty value")
		}
		if _, taken := keys[name]; taken {
			return fmt.Errorf("a key named %q exists", name)
		}
		keys[name] = value
		return nil
	}
	for from, to := range moves {
		if err := put(to, values[from]); err != nil {
			return err
		}
	}
	for name, value := range add {
		if err := put(name, value); err != nil {
			return err
		}
	}
	return save(path, keys)
}

// OrderParts sorts the value names of one key (the parts of KEY.part): those
// in order first, as listed there, then the rest by number ("2" before "10"),
// then by name.
func OrderParts(parts, order []string) {
	rank := make(map[string]int, len(order))
	for i, p := range order {
		if _, dup := rank[p]; !dup {
			rank[p] = i
		}
	}
	slices.SortStableFunc(parts, func(a, b string) int {
		ra, inA := rank[a]
		rb, inB := rank[b]
		switch {
		case inA && inB:
			return ra - rb
		case inA:
			return -1
		case inB:
			return 1
		}
		na, errA := strconv.Atoi(a)
		nb, errB := strconv.Atoi(b)
		switch {
		case errA == nil && errB == nil && na != nb:
			return cmp.Compare(na, nb)
		case errA == nil && errB != nil:
			return -1
		case errA != nil && errB == nil:
			return 1
		}
		return strings.Compare(a, b)
	})
}

func save(path string, keys map[string]string) error {
	raw, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(path, append(raw, '\n'), 0o600)
}
