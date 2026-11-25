package store

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestSetLoadDeleteKeepsFilePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := Set(path, "OPENROUTER_API_KEY", "sk-or-test"); err != nil {
		t.Fatal(err)
	}
	if err := Set(path, "TAVILY_API_KEY", "tvly-test"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("store mode = %04o, want 0600", perm)
	}
	names, err := Names(path)
	if err != nil || !reflect.DeepEqual(names, []string{"OPENROUTER_API_KEY", "TAVILY_API_KEY"}) {
		t.Fatalf("names = %v, %v", names, err)
	}
	if err := Delete(path, "TAVILY_API_KEY"); err != nil {
		t.Fatal(err)
	}
	keys, err := Load(path)
	if err != nil || !reflect.DeepEqual(keys, map[string]string{"OPENROUTER_API_KEY": "sk-or-test"}) {
		t.Fatalf("keys after delete = %v, %v", keys, err)
	}
	if err := Delete(path, "TAVILY_API_KEY"); err == nil {
		t.Fatal("deleting a missing key succeeded")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".keys.json-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestLoadRefusesAStoreOthersCanRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`{"A":"secret-value"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Set the mode explicitly: WriteFile applies the umask.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("err = %v, want a refusal naming chmod 600", err)
	}
	if strings.Contains(err.Error(), "secret-value") {
		t.Fatal("error message leaks a key value")
	}
}

func TestLoadNeverPrintsContentOfABrokenStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`{"A":"secret-value"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("err = %v", err)
	}
}

func TestSetRejectsBadNamesAndEmptyValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	for _, name := range []string{"", "1ABC", "A-B", "A B"} {
		if err := Set(path, name, "v"); err == nil {
			t.Fatalf("Set(%q) succeeded", name)
		}
	}
	if err := Set(path, "A", ""); err == nil {
		t.Fatal("empty value accepted")
	}
}

func TestSetAllRejectsPartialCredentialBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	original := map[string]string{"PRIMARY": "old-primary", "EXTRA": "old-extra"}
	if err := SetAll(path, original); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []map[string]string{
		{"PRIMARY": "new-primary", "BAD-NAME": "new-extra"},
		{"PRIMARY": "new-primary", "EXTRA": ""},
	} {
		if err := SetAll(path, invalid); err == nil {
			t.Fatal("invalid credential bundle accepted")
		}
		got, err := Load(path)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("rejected bundle changed the existing store")
		}
	}
}

// SetChecked writes and returns the very map its check saw, and writes
// nothing when the check refuses.
func TestSetChecked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := Set(path, "A", "a"); err != nil {
		t.Fatal(err)
	}
	var checked map[string]string
	written, err := SetChecked(path, map[string]string{"B": "b"}, func(keys map[string]string) error {
		checked = keys
		return nil
	})
	disk, _ := Load(path)
	if err != nil || !reflect.DeepEqual(written, map[string]string{"A": "a", "B": "b"}) || !reflect.DeepEqual(written, checked) || !reflect.DeepEqual(disk, written) {
		t.Fatalf("written %v, checked %v, on disk %v, %v", written, checked, disk, err)
	}
	refusal := os.ErrPermission
	if _, err := SetChecked(path, map[string]string{"C": "c"}, func(map[string]string) error { return refusal }); err != refusal {
		t.Fatalf("refused: %v", err)
	}
	if after, _ := Load(path); !reflect.DeepEqual(after, disk) {
		t.Fatalf("a refused update wrote %v", after)
	}
}

// Writers hold the store's lock (a flock, so separate opens exclude each
// other as separate processes do) from their read to their rename: writes
// at the same time are all kept.
func TestConcurrentWritesAreAllKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	const writers = 24
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("K%d", i)
			if i%2 == 0 {
				errs <- Set(path, name, "v")
				return
			}
			_, err := SetChecked(path, map[string]string{name: "v"}, func(map[string]string) error { return nil })
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if keys, err := Load(path); err != nil || len(keys) != writers {
		t.Fatalf("%d of %d writes kept: %v", len(keys), writers, err)
	}
}
