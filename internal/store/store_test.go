package store

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".keys-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
}

func TestLoadRefusesAStoreOthersCanRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`{"A":"secret-value"}`), 0o644); err != nil {
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
