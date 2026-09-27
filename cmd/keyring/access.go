package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gitmoot/keyring/internal/admin"
	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// migrate moves "services" and "roles" out of an old rules file into an access
// file, and points the rules file at it. Nothing is written unless the result
// is valid. Running it again after a successful run does nothing.
func migrate(configPath, accessPath string, stdout io.Writer) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	servicesRaw, hasServices := fields["services"]
	rolesRaw, hasRoles := fields["roles"]
	if !hasServices && !hasRoles {
		rules, err := policy.LoadRules(configPath)
		if err != nil {
			return err
		}
		if err := ownAccessFile(rules.AccessFile); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "already migrated: access file %s\n", rules.AccessFile)
		return nil
	}
	if !filepath.IsAbs(accessPath) {
		return errors.New("--access must be an absolute path")
	}
	if !hasServices {
		servicesRaw = json.RawMessage("{}")
	}
	if !hasRoles {
		rolesRaw = json.RawMessage("{}")
	}
	var access policy.AccessList
	accessIn, _ := json.Marshal(map[string]json.RawMessage{"services": servicesRaw, "roles": rolesRaw})
	if err := strictJSON(accessIn, &access); err != nil {
		return fmt.Errorf("%s: services or roles: %w", configPath, err)
	}
	delete(fields, "services")
	delete(fields, "roles")
	fields["access_file"], _ = json.Marshal(accessPath)
	rulesOut, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return err
	}
	var rules policy.Rules
	if err := strictJSON(rulesOut, &rules); err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	accessOut, err := json.MarshalIndent(access, "", "  ")
	if err != nil {
		return err
	}
	cfg := &policy.Config{Rules: rules, AccessList: access}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("%s: not migrated: %w", configPath, err)
	}

	if existing, err := os.ReadFile(accessPath); err == nil {
		// A previous run wrote the access file but not the rules file.
		var prev policy.AccessList
		if err := strictJSON(existing, &prev); err != nil {
			return fmt.Errorf("%s already exists and is not an access file; move it away first", accessPath)
		}
		prevOut, _ := json.MarshalIndent(prev, "", "  ")
		if !bytes.Equal(prevOut, accessOut) {
			return fmt.Errorf("%s already exists with different content; move it away first", accessPath)
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		if err := fileutil.WriteAtomic(accessPath, append(accessOut, '\n'), 0o600); err != nil {
			return err
		}
	} else {
		return err
	}
	// Also on the paths that did not write: a run killed between writing and
	// chown must not leave a file the service cannot read.
	if err := ownAccessFile(accessPath); err != nil {
		return err
	}

	if err := rewriteRules(configPath, rulesOut); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "moved %d services and %d roles to %s\n", len(access.Services), len(access.Roles), accessPath)
	return nil
}

// rewriteRules replaces the rules file, keeping its mode and (as root) its
// owner and group.
func rewriteRules(configPath string, out []byte) error {
	info, err := os.Stat(configPath)
	if err != nil {
		return err
	}
	uid, gid, owned := fileutil.Owner(configPath)
	if err := fileutil.WriteAtomic(configPath, append(out, '\n'), info.Mode().Perm()); err != nil {
		return err
	}
	if owned && os.Geteuid() == 0 {
		return os.Chown(configPath, uid, gid)
	}
	return nil
}

// ownAccessFile gives the access file to the owner of its directory (the
// service user), mode 600, when run as root. The directory is the service
// user's, so the file is opened without following a symlink and must have one
// link: otherwise root could be tricked into handing over another file.
func ownAccessFile(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, gid, ok := fileutil.Owner(filepath.Dir(path))
	if !ok {
		return fmt.Errorf("%s: cannot read the directory's owner", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || uint64(st.Nlink) != 1 {
		return fmt.Errorf("%s must be a regular file with one link", path)
	}
	if err := f.Chown(uid, gid); err != nil {
		return err
	}
	return f.Chmod(0o600)
}

func strictJSON(raw []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// reloader re-reads the rules, access file, keys and dashboard password and
// swaps them in. The listeners, audit log and file paths are fixed at start:
// a change to them needs a restart, and the reload is refused so nothing
// half-applies.
type reloader struct {
	configPath, storePath string
	fixed                 policy.Rules
	handler               *server.Handler
	dashboard             *admin.Server // nil when the dashboard is off
	mu                    *sync.Mutex   // shared with the dashboard's changes; may be nil
}

func (rl reloader) reload() (*policy.Config, map[string]string, error) {
	if rl.mu != nil {
		rl.mu.Lock()
		defer rl.mu.Unlock()
	}
	cfg, err := policy.Load(rl.configPath)
	if err != nil {
		return nil, nil, err
	}
	f := rl.fixed
	if cfg.Listen != f.Listen || cfg.AuditLog != f.AuditLog || cfg.AccessFile != f.AccessFile ||
		cfg.AdminListen != f.AdminListen || cfg.AdminPasswordFile != f.AdminPasswordFile {
		return nil, nil, errors.New("listen, audit_log, access_file or admin settings changed; restart the service to apply")
	}
	keys, err := store.Load(rl.storePath)
	if err != nil {
		return nil, nil, err
	}
	var password admin.PasswordHash
	if rl.dashboard != nil {
		if password, err = admin.LoadPasswordFile(cfg.AdminPasswordFile); err != nil {
			return nil, nil, err
		}
	}
	rl.handler.Swap(cfg, keys)
	if rl.dashboard != nil && rl.dashboard.SetPassword(password) {
		rl.dashboard.WriteAudit(map[string]any{"time": time.Now().UTC().Format(time.RFC3339), "admin": "password_changed_sessions_ended"})
	}
	return cfg, keys, nil
}

func reloadMessage(cfg *policy.Config, err error, keysMissing []string) string {
	if err != nil {
		return "reload refused, previous settings kept: " + err.Error()
	}
	msg := fmt.Sprintf("reloaded: %d services, %d roles", len(cfg.Services), len(cfg.Roles))
	if len(keysMissing) > 0 {
		msg += "; keys not in the store (their services answer 503): " + strings.Join(keysMissing, ", ")
	}
	return msg
}
