package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
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
func setAdminPassword(configPath string, stdin io.Reader, stdout, stderr io.Writer) error {
	rules, err := policy.LoadRules(configPath)
	if err != nil {
		return err
	}
	if rules.AdminPasswordFile == "" {
		return errors.New("the rules file has no admin_password_file")
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
func startDashboard(cfg *policy.Config, audit io.Writer, stderr io.Writer) (*admin.Server, *http.Server, error) {
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
