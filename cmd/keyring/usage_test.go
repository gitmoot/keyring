package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/server"
)

func TestUsageFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := usagePath(filepath.Join(dir, "keys.json"))
	if path != filepath.Join(dir, "usage.json") {
		t.Fatalf("usage path %s", path)
	}
	if rows, err := loadUsage(path); err != nil || rows != nil {
		t.Fatalf("missing file: %v %v", rows, err)
	}
	at := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	in := []server.Usage{{Role: "phobos", Service: "openrouter", Day: "2026-09-27", Calls: 3, LastUsed: at, LastStatus: 200}}
	if err := saveUsage(path, in); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", info.Mode().Perm())
	}
	out, err := loadUsage(path)
	if err != nil || len(out) != 1 || out[0].Calls != 3 || !out[0].LastUsed.Equal(at) {
		t.Fatalf("round trip: %+v %v", out, err)
	}
}
