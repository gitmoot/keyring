package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/admin"
	"github.com/gitmoot/keyring/internal/policy"
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
	// An upgrade asks only when no password is set: the owner's stays.
	if code := run([]string{"admin-password", "--config", rules, "--if-missing"}, strings.NewReader("another password!!\nanother password!!\n"), &out, &errOut); code != 0 {
		t.Fatalf("--if-missing with a password set: exit %d", code)
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

func TestAdminPasswordRefusesADirectoryOthersCanChange(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the check applies when root writes the password file")
	}
	for name, setup := range map[string]func(dir string) error{
		"group-writable":    func(dir string) error { return os.Chmod(dir, 0o770) },
		"owned by the user": func(dir string) error { return os.Chown(dir, 65534, 65534) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			pwDir := filepath.Join(dir, "pw")
			if err := os.Mkdir(pwDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := setup(pwDir); err != nil {
				t.Fatal(err)
			}
			rules := filepath.Join(dir, "rules.json")
			pw := filepath.Join(pwDir, "admin.pw")
			raw := `{"listen":"127.0.0.1:7701","allow_sources":["127.0.0.1"],"audit_log":"` + filepath.Join(dir, "a.log") +
				`","access_file":"` + filepath.Join(dir, "access.json") + `","admin_listen":"127.0.0.1:7702","admin_password_file":"` + pw + `"}`
			if err := os.WriteFile(rules, []byte(raw), 0o640); err != nil {
				t.Fatal(err)
			}
			const good = "a long enough password"
			var out, errOut bytes.Buffer
			if code := run([]string{"admin-password", "--config", rules}, strings.NewReader(good+"\n"+good+"\n"), &out, &errOut); code == 0 {
				t.Fatal("password written into a directory others can change")
			}
			if _, err := os.Lstat(pw); !os.IsNotExist(err) {
				t.Fatal("password file written")
			}
		})
	}
}

func TestEnableDashboardOnceThenKeepsTheOwnersSettings(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.json")
	access := filepath.Join(dir, "access.json")
	raw := `{"listen":"127.0.0.1:7701","allow_sources":["127.0.0.1"],"audit_log":"` + filepath.Join(dir, "a.log") + `","access_file":"` + access + `"}`
	if err := os.WriteFile(rules, []byte(raw), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rules, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(access, []byte(`{"services":{},"roles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"enable-dashboard", "--config", rules, "--admin-listen", "0.0.0.0:7702"}, nil, &out, &errOut); code == 0 {
		t.Fatal("a non-loopback dashboard address was accepted")
	}
	if now, _ := os.ReadFile(rules); string(now) != raw {
		t.Fatal("rules changed by a refused enable")
	}
	if code := run([]string{"enable-dashboard", "--config", rules}, nil, &out, &errOut); code != 0 {
		t.Fatalf("enable: %d %s", code, errOut.String())
	}
	cfg, err := policy.Load(rules)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminListen != "127.0.0.1:7702" || cfg.AdminPasswordFile != filepath.Join(dir, "admin.pw") || cfg.Listen != "127.0.0.1:7701" || cfg.AccessFile != access {
		t.Fatalf("rules after enable: %+v", cfg.Rules)
	}
	if info, _ := os.Stat(rules); info.Mode().Perm() != 0o640 {
		t.Fatalf("rules mode %04o, want 0640 kept", info.Mode().Perm())
	}
	// The owner moved the dashboard; an upgrade must not move it back.
	moved := strings.Replace(mustRead(t, rules), "127.0.0.1:7702", "127.0.0.1:7800", 1)
	if err := os.WriteFile(rules, []byte(moved), 0o640); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"enable-dashboard", "--config", rules}, nil, &out, &errOut); code != 0 || mustRead(t, rules) != moved {
		t.Fatalf("second enable changed the owner's settings (exit %d)", code)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
