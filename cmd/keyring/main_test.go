package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenAuditRefusesAFileOthersCanRead(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "new.log")
	f, err := openAudit(fresh)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if info, _ := os.Stat(fresh); info.Mode().Perm() != 0o600 {
		t.Fatalf("new audit log mode %04o", info.Mode().Perm())
	}
	open := filepath.Join(dir, "open.log")
	if err := os.WriteFile(open, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if f, err := openAudit(open); err == nil {
		f.Close()
		t.Fatal("audit log readable by others was accepted")
	}
}
