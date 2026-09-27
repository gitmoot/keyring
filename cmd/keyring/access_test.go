package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

func tokenHashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func oldRules(dir, listen string) string {
	return `{
  "listen": "` + listen + `",
  "allow_sources": ["127.0.0.1"],
  "audit_log": "` + filepath.Join(dir, "audit.log") + `",
  "services": {"api": {"base": "https://api.example.com", "key": "API_KEY", "auth": "bearer"}},
  "roles": {"phobos": {"token_sha256": "` + tokenHashOf("tok-phobos") + `", "access": {"api": {"paths": ["/v1"]}}}}
}`
}

func TestMigrateMovesServicesAndRolesOnce(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.json")
	access := filepath.Join(dir, "data", "access.json")
	if err := os.Mkdir(filepath.Dir(access), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rules, []byte(oldRules(dir, "127.0.0.1:7701")), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rules, 0o640); err != nil { // WriteFile applies the umask
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := migrate(rules, access, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "moved 1 services and 1 roles") {
		t.Fatalf("output %q", out.String())
	}
	cfg, err := policy.Load(rules)
	if err != nil {
		t.Fatalf("migrated files do not load: %v", err)
	}
	if cfg.AccessFile != access || len(cfg.Services) != 1 || len(cfg.Roles) != 1 {
		t.Fatalf("config after migrate = %+v", cfg)
	}
	if info, _ := os.Stat(access); info.Mode().Perm() != 0o600 {
		t.Fatalf("access mode %04o", info.Mode().Perm())
	}
	if info, _ := os.Stat(rules); info.Mode().Perm() != 0o640 {
		t.Fatalf("rules mode changed to %04o", info.Mode().Perm())
	}
	out.Reset()
	if err := migrate(rules, access, &out); err != nil || !strings.Contains(out.String(), "already migrated") {
		t.Fatalf("second run: %v %q", err, out.String())
	}
}

func TestMigrateWritesNothingForInvalidRules(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.json")
	access := filepath.Join(dir, "access.json")
	original := oldRules(dir, "0.0.0.0:7701")
	if err := os.WriteFile(rules, []byte(original), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := migrate(rules, access, &bytes.Buffer{}); err == nil {
		t.Fatal("wildcard listen accepted")
	}
	if _, err := os.Stat(access); !os.IsNotExist(err) {
		t.Fatal("access file written for invalid rules")
	}
	if now, _ := os.ReadFile(rules); string(now) != original {
		t.Fatal("rules file changed for invalid rules")
	}
}

func TestMigrateRefusesToOverwriteADifferentAccessFile(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.json")
	access := filepath.Join(dir, "access.json")
	if err := os.WriteFile(rules, []byte(oldRules(dir, "127.0.0.1:7701")), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(access, []byte(`{"services":{},"roles":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrate(rules, access, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatalf("err = %v", err)
	}
}

// serviceDir makes a data directory owned by an unprivileged user, as the
// installer does for _keyring. Needs root.
func serviceDir(t *testing.T) (dir, data string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: checks the owner migrate gives the access file")
	}
	dir = t.TempDir()
	data = filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(data, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	return dir, data
}

func ownerOf(t *testing.T, path string) (uid, gid int, mode os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid), info.Mode().Perm()
}

func TestMigrateAsRootAlwaysGivesTheServiceItsAccessFile(t *testing.T) {
	dir, data := serviceDir(t)
	rules := filepath.Join(dir, "rules.json")
	access := filepath.Join(data, "access.json")
	if err := os.WriteFile(rules, []byte(oldRules(dir, "127.0.0.1:7701")), 0o640); err != nil {
		t.Fatal(err)
	}
	// A run killed between writing the access file and chown left it root's.
	if err := os.WriteFile(access, []byte(`{"services":{"api":{"base":"https://api.example.com","key":"API_KEY","auth":"bearer"}},"roles":{"phobos":{"token_sha256":"`+tokenHashOf("tok-phobos")+`","access":{"api":{"paths":["/v1"]}}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(access, 0o644); err != nil { // WriteFile applies the umask
		t.Fatal(err)
	}
	if err := migrate(rules, access, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if uid, gid, mode := ownerOf(t, access); uid != 65534 || gid != 65534 || mode != 0o600 {
		t.Fatalf("after resumed migrate: %d:%d %04o, want 65534:65534 0600", uid, gid, mode)
	}
	// The installer runs migrate on every upgrade; an already split layout
	// with a root-owned access file (as a fresh install writes it) is fixed too.
	if err := os.Chown(access, 0, 0); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := migrate(rules, access, &out); err != nil || !strings.Contains(out.String(), "already migrated") {
		t.Fatalf("second run: %v %q", err, out.String())
	}
	if uid, _, _ := ownerOf(t, access); uid != 65534 {
		t.Fatalf("already-migrated run left the access file owned by %d", uid)
	}
}

func TestMigrateAsRootNeverHandsOverAnotherFile(t *testing.T) {
	for _, link := range []string{"symlink", "hardlink"} {
		t.Run(link, func(t *testing.T) {
			dir, data := serviceDir(t)
			rules := filepath.Join(dir, "rules.json")
			access := filepath.Join(data, "access.json")
			if err := os.WriteFile(rules, []byte(`{"listen":"127.0.0.1:7701","allow_sources":["127.0.0.1"],"audit_log":"`+filepath.Join(dir, "audit.log")+`","access_file":"`+access+`"}`), 0o640); err != nil {
				t.Fatal(err)
			}
			// A root-only file elsewhere, which the service user links into
			// its own directory hoping root will chown it.
			secret := filepath.Join(dir, "secret")
			if err := os.WriteFile(secret, []byte(`{"services":{},"roles":{}}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if link == "symlink" {
				err := os.Symlink(secret, access)
				if err != nil {
					t.Fatal(err)
				}
			} else if err := os.Link(secret, access); err != nil {
				t.Fatal(err)
			}
			if err := migrate(rules, access, &bytes.Buffer{}); err == nil {
				t.Fatal("migrate accepted a linked access file")
			}
			if uid, gid, mode := ownerOf(t, secret); uid != 0 || gid != 0 || mode != 0o600 {
				t.Fatalf("the linked file was handed over: %d:%d %04o", uid, gid, mode)
			}
		})
	}
}

func TestReloadAppliesAccessChangesAndRefusesListenChanges(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.json")
	access := filepath.Join(dir, "access.json")
	keysPath := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(rules, []byte(oldRules(dir, "127.0.0.1:7701")), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := migrate(rules, access, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := store.Set(keysPath, "API_KEY", "sk-reload-test-0123456789"); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(rules)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(keysPath)
	h := server.New(cfg, keys, &bytes.Buffer{})
	rl := reloader{configPath: rules, storePath: keysPath, fixed: cfg.Rules, handler: h}
	get := func(path string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "127.0.0.1:5000"
		r.Header.Set(server.TokenHeader, "tok-phobos")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := get("/api/v2/x"); code != http.StatusForbidden {
		t.Fatalf("before reload: %d", code)
	}
	// Owner widens access in the access file, then reloads.
	next := cfg.AccessList
	role := next.Roles["phobos"]
	role.Access = map[string]policy.Access{"api": {Paths: []string{"/v2"}}}
	next.Roles = map[string]policy.Role{"phobos": role}
	if _, err := policy.SaveAccess(cfg.Rules, next); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rl.reload(); err != nil {
		t.Fatal(err)
	}
	// The service is unreachable in the test, so an allowed call ends at the
	// upstream (502), not at the rules (403).
	if code := get("/api/v2/x"); code == http.StatusForbidden {
		t.Fatal("reload did not apply the new access")
	}
	if code := get("/api/v1/x"); code != http.StatusForbidden {
		t.Fatalf("old path after reload: %d, want 403", code)
	}
	// Changing listen needs a restart: the reload is refused and nothing changes.
	raw, _ := os.ReadFile(rules)
	if err := os.WriteFile(rules, bytes.Replace(raw, []byte("127.0.0.1:7701"), []byte("127.0.0.1:7702"), 1), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rl.reload(); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("listen change: err = %v", err)
	}
	if code := get("/api/v1/x"); code != http.StatusForbidden {
		t.Fatalf("after refused reload: %d, want the previous settings (403)", code)
	}
	// Turning the dashboard on also needs a restart.
	if err := os.WriteFile(rules, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	withAdmin := bytes.Replace(raw, []byte(`"listen":`), []byte(`"admin_listen": "127.0.0.1:7709", "admin_password_file": "/tmp/admin.pw", "listen":`), 1)
	if bytes.Equal(withAdmin, raw) {
		t.Fatal("test setup: could not add admin settings")
	}
	if err := os.WriteFile(rules, withAdmin, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rl.reload(); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("admin settings change: err = %v", err)
	}
}

func TestServiceFileCreatesOrFixesButNeverFollowsALink(t *testing.T) {
	dir, data := serviceDir(t)
	log := filepath.Join(data, "service.log")
	var out, errOut bytes.Buffer
	if code := run([]string{"service-file", log}, nil, &out, &errOut); code != 0 {
		t.Fatalf("create: %d %s", code, errOut.String())
	}
	if uid, gid, mode := ownerOf(t, log); uid != 65534 || gid != 65534 || mode != 0o600 {
		t.Fatalf("created %d:%d %04o, want 65534:65534 0600", uid, gid, mode)
	}
	if err := os.Chmod(log, 0o644); err != nil { // as launchd leaves it
		t.Fatal(err)
	}
	if code := run([]string{"service-file", log}, nil, &out, &errOut); code != 0 {
		t.Fatalf("fix: %d %s", code, errOut.String())
	}
	if _, _, mode := ownerOf(t, log); mode != 0o600 {
		t.Fatalf("existing log left %04o", mode)
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("root only"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "created-by-root")
	for name, plant := range map[string]func() error{
		"symlink":          func() error { return os.Symlink(secret, log) },
		"hard link":        func() error { return os.Link(secret, log) },
		"dangling symlink": func() error { return os.Symlink(missing, log) },
	} {
		if err := os.Remove(log); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := plant(); err != nil {
			t.Fatal(err)
		}
		if code := run([]string{"service-file", log}, nil, &out, &errOut); code == 0 {
			t.Errorf("%s: accepted", name)
		}
		if uid, gid, mode := ownerOf(t, secret); uid != 0 || gid != 0 || mode != 0o600 {
			t.Fatalf("%s: the linked file was handed over: %d:%d %04o", name, uid, gid, mode)
		}
		if _, err := os.Lstat(missing); err == nil {
			t.Fatalf("%s: root created the link's target", name)
		}
	}
}
