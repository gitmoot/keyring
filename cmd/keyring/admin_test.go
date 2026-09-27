package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/admin"
)

func TestAdminPasswordCommand(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.json")
	pw := filepath.Join(dir, "admin.pw")
	raw := `{"listen":"127.0.0.1:7701","allow_sources":["127.0.0.1"],"audit_log":"` + filepath.Join(dir, "a.log") +
		`","access_file":"` + filepath.Join(dir, "access.json") + `","admin_listen":"127.0.0.1:7702","admin_password_file":"` + pw + `"}`
	if err := os.WriteFile(rules, []byte(raw), 0o640); err != nil {
		t.Fatal(err)
	}
	const good = "a long enough password"
	var out, errOut bytes.Buffer
	if code := run([]string{"admin-password", "--config", rules}, strings.NewReader(good+"\n"+good+"x\n"), &out, &errOut); code == 0 {
		t.Fatal("different passwords accepted")
	}
	if _, err := os.Stat(pw); !os.IsNotExist(err) {
		t.Fatal("password file written after a mismatch")
	}
	if code := run([]string{"admin-password", "--config", rules}, strings.NewReader("short\nshort\n"), &out, &errOut); code == 0 {
		t.Fatal("short password accepted")
	}
	if code := run([]string{"admin-password", "--config", rules}, strings.NewReader(good+"\n"+good+"\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	h, err := admin.LoadPasswordFile(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Matches(good) {
		t.Fatal("stored hash does not match the password")
	}
	file, _ := os.ReadFile(pw)
	if strings.Contains(string(file), good) || strings.Contains(out.String()+errOut.String(), good) {
		t.Fatal("password written in clear")
	}
	if info, _ := os.Stat(pw); info.Mode().Perm() != 0o640 {
		t.Fatalf("password file mode %04o", info.Mode().Perm())
	}
}
