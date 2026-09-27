package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gitmoot/keyring/internal/admin"
	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/policy"
)

// setAdminPassword asks for the dashboard password twice and writes its hash
// to the rules file's admin_password_file. Run as root, the file is owned by
// root with the rules file's group (the service can read it, not change it).
// With ifMissing, an existing password file is kept (installer upgrades).
func setAdminPassword(configPath string, ifMissing bool, stdin io.Reader, stdout, stderr io.Writer) error {
	rules, err := policy.LoadRules(configPath)
	if err != nil {
		return err
	}
	if rules.AdminPasswordFile == "" {
		return errors.New("the rules file has no admin_password_file")
	}
	if ifMissing {
		if _, err := os.Lstat(rules.AdminPasswordFile); err == nil {
			// Keep it only if the service can use it: a damaged file would
			// leave the dashboard off without anyone asked for a password.
			if _, err := admin.LoadPasswordFile(rules.AdminPasswordFile); err != nil {
				return fmt.Errorf("%w; run admin-password without --if-missing to set a new password", err)
			}
			fmt.Fprintln(stdout, "dashboard password already set: kept")
			return nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if os.Geteuid() == 0 {
		if err := rootOnlyDir(filepath.Dir(rules.AdminPasswordFile)); err != nil {
			return err
		}
	}
	in := bufio.NewReader(stdin)
	first, err := readHidden(in, stdin, stderr, "new dashboard password (not shown): ")
	if err != nil {
		return err
	}
	second, err := readHidden(in, stdin, stderr, "same password again: ")
	if err != nil {
		return err
	}
	if first != second {
		return errors.New("the two passwords differ; nothing changed")
	}
	line, err := admin.NewPasswordHash(first, admin.Iterations)
	if err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(rules.AdminPasswordFile, []byte(line+"\n"), 0o640); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if _, gid, ok := fileutil.Owner(configPath); ok {
			if err := os.Chown(rules.AdminPasswordFile, 0, gid); err != nil {
				return err
			}
		}
	}
	fmt.Fprintf(stdout, "dashboard password set in %s. A running keyring picks it up on reload (SIGHUP); existing sessions end.\n", rules.AdminPasswordFile)
	return nil
}

// startDashboard serves the dashboard when admin_listen is set. Without a
// password file the proxy still runs and the dashboard stays off.
func startDashboard(cfg *policy.Config, audit io.Writer, stderr io.Writer, register func(*admin.Server)) (*admin.Server, *http.Server, error) {
	if cfg.AdminListen == "" {
		return nil, nil, nil
	}
	password, err := admin.LoadPasswordFile(cfg.AdminPasswordFile)
	if err != nil {
		fmt.Fprintf(stderr, "dashboard off: %v (set it with: keyring admin-password, then restart)\n", err)
		return nil, nil, nil
	}
	listener, err := net.Listen("tcp", cfg.AdminListen)
	if err != nil {
		return nil, nil, fmt.Errorf("dashboard: %w", err)
	}
	dashboard := admin.New(cfg.AdminListen, password, audit)
	register(dashboard)
	srv := &http.Server{
		Handler:           dashboard,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "dashboard stopped: %v\n", err)
		}
	}()
	fmt.Fprintf(stderr, "dashboard on http://%s\n", cfg.AdminListen)
	return dashboard, srv, nil
}

// rootOnlyDir refuses a directory that anyone but root could change. The
// password file must stay root's: if the service or another user could
// replace it, or put a link in its place before the chown below, they could
// choose the dashboard password.
func rootOnlyDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	uid, _, ok := fileutil.Owner(dir)
	if !ok || uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: the password file's directory must be owned by root and writable only by root", dir)
	}
	return nil
}

// enableDashboard adds admin_listen and admin_password_file (admin.pw next to
// the rules file) to a rules file that has neither. A rules file that already
// names a dashboard is left as it is, so upgrades keep the owner's settings.
func enableDashboard(configPath, listen string, stdout io.Writer) error {
	rules, err := policy.LoadRules(configPath)
	if err != nil {
		return err
	}
	if rules.AdminListen != "" && rules.AdminPasswordFile != "" {
		fmt.Fprintf(stdout, "dashboard already on: http://%s\n", rules.AdminListen)
		return nil
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	// Fill in only what is missing: the owner's own settings stay.
	if rules.AdminListen == "" {
		fields["admin_listen"], _ = json.Marshal(listen)
	} else {
		listen = rules.AdminListen
	}
	if rules.AdminPasswordFile == "" {
		fields["admin_password_file"], _ = json.Marshal(filepath.Join(filepath.Dir(configPath), "admin.pw"))
	}
	out, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return err
	}
	var next policy.Rules
	if err := strictJSON(out, &next); err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	access, err := policy.LoadAccess(next.AccessFile)
	if err != nil {
		return err
	}
	if err := (&policy.Config{Rules: next, AccessList: access}).Validate(); err != nil {
		return fmt.Errorf("dashboard not enabled: %w", err)
	}
	if err := rewriteRules(configPath, out); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "dashboard enabled on http://%s; set its password with keyring admin-password\n", listen)
	return nil
}
