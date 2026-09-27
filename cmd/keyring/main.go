// Command keyring holds API keys and makes API calls on behalf of agents, so
// the agents never see a key.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gitmoot/keyring/internal/admin"
	dashboardpkg "github.com/gitmoot/keyring/internal/dashboard"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/relay"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

const usage = `Usage:
  keyring serve --config FILE --store FILE   run the keyring
  keyring check --config FILE [--store FILE] check the rules and access file (and which keys are missing)
  keyring migrate --config FILE --access FILE move services and roles from an old rules file into an access file
  keyring admin-password --config FILE       set the dashboard password (asked twice, not shown)
  keyring set --store FILE NAME              add or replace a key; the value is read from stdin
  keyring delete --store FILE NAME           remove a key
  keyring list --store FILE                  print key names (never values)
  keyring new-token                          make a role token and its hash for the rules file
  keyring relay --listen 127.0.0.1:7700 --upstream URL --tokens DIR
                                             on the agent machine: forward /<role>/<service>/... to the keyring
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet("keyring "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "rules file")
	storePath := fs.String("store", "", "key store file")
	accessPath := fs.String("access", "", "migrate: absolute path of the access file to create")
	listen := fs.String("listen", "127.0.0.1:7700", "relay: loopback address to listen on")
	upstream := fs.String("upstream", "", "relay: keyring URL, e.g. http://100.111.92.43:7701")
	tokensDir := fs.String("tokens", "", "relay: directory of <role>.token files (mode 700)")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	need := func(flags ...string) bool {
		for _, f := range flags {
			if (f == "config" && *configPath == "") || (f == "store" && *storePath == "") {
				fmt.Fprintf(stderr, "keyring %s: --%s is required\n", cmd, f)
				return false
			}
		}
		return true
	}
	var err error
	switch cmd {
	case "serve":
		if !need("config", "store") || fs.NArg() != 0 {
			return 2
		}
		err = serve(*configPath, *storePath, stderr)
	case "check":
		if !need("config") || fs.NArg() != 0 {
			return 2
		}
		err = check(*configPath, *storePath, stdout)
	case "migrate":
		if !need("config") || *accessPath == "" || fs.NArg() != 0 {
			fmt.Fprintln(stderr, "keyring migrate: --config and --access are required")
			return 2
		}
		err = migrate(*configPath, *accessPath, stdout)
	case "admin-password":
		if !need("config") || fs.NArg() != 0 {
			return 2
		}
		err = setAdminPassword(*configPath, stdin, stdout, stderr)
	case "set":
		if !need("store") || fs.NArg() != 1 {
			fmt.Fprintln(stderr, "keyring set: pass --store FILE and one NAME")
			return 2
		}
		var value string
		if value, err = readSecret(stdin, stderr, fs.Arg(0)); err == nil {
			err = store.Set(*storePath, fs.Arg(0), value)
		}
		if err == nil {
			fmt.Fprintf(stdout, "stored %s\n", fs.Arg(0))
		}
	case "delete":
		if !need("store") || fs.NArg() != 1 {
			return 2
		}
		if err = store.Delete(*storePath, fs.Arg(0)); err == nil {
			fmt.Fprintf(stdout, "deleted %s\n", fs.Arg(0))
		}
	case "list":
		if !need("store") || fs.NArg() != 0 {
			return 2
		}
		var names []string
		if names, err = store.Names(*storePath); err == nil {
			for _, n := range names {
				fmt.Fprintln(stdout, n)
			}
		}
	case "new-token":
		if fs.NArg() != 0 {
			return 2
		}
		raw := make([]byte, 32)
		if _, err = rand.Read(raw); err == nil {
			token := base64.RawURLEncoding.EncodeToString(raw)
			sum := sha256.Sum256([]byte(token))
			fmt.Fprintf(stdout, "token:  %s\nsha256: %s\n", token, hex.EncodeToString(sum[:]))
			fmt.Fprintln(stderr, "Put the token only on the machine that calls the keyring; put the sha256 in the rules file.")
		}
	case "relay":
		if *upstream == "" || *tokensDir == "" || fs.NArg() != 0 {
			fmt.Fprintln(stderr, "keyring relay: --upstream and --tokens are required")
			return 2
		}
		err = runRelay(*listen, *upstream, *tokensDir, stderr)
	default:
		fmt.Fprintf(stderr, "keyring: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "keyring %s: %v\n", cmd, err)
		return 1
	}
	return 0
}

func check(configPath, storePath string, stdout io.Writer) error {
	cfg, err := policy.Load(configPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "rules ok: %d services, %d roles\n", len(cfg.Services), len(cfg.Roles))
	if storePath == "" {
		return nil
	}
	keys, err := store.Load(storePath)
	if err != nil {
		return err
	}
	if missing := missingKeys(cfg, keys); len(missing) > 0 {
		return fmt.Errorf("keys not in the store: %s", strings.Join(missing, ", "))
	}
	fmt.Fprintln(stdout, "every service's key is in the store")
	return nil
}

func missingKeys(cfg *policy.Config, keys map[string]string) []string {
	var missing []string
	for _, svc := range cfg.Services {
		if keys[svc.Key] == "" {
			missing = append(missing, svc.Key)
		}
	}
	sort.Strings(missing)
	return missing
}

func serve(configPath, storePath string, stderr io.Writer) error {
	cfg, err := policy.Load(configPath)
	if err != nil {
		return err
	}
	keys, err := store.Load(storePath)
	if err != nil {
		return err
	}
	if missing := missingKeys(cfg, keys); len(missing) > 0 {
		fmt.Fprintf(stderr, "warning: keys not in the store (their services answer 503): %s\n", strings.Join(missing, ", "))
	}
	audit, err := openAudit(cfg.AuditLog)
	if err != nil {
		return err
	}
	defer audit.Close()
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	handler := server.New(cfg, keys, audit)
	usageFile := usagePath(storePath)
	if rows, err := loadUsage(usageFile); err != nil {
		// Usage is only statistics: start without it rather than not start.
		fmt.Fprintf(stderr, "usage history not loaded: %v\n", err)
	} else {
		handler.RestoreUsage(rows)
	}
	defer func() {
		if err := saveUsage(usageFile, handler.Usage()); err != nil {
			fmt.Fprintf(stderr, "usage not saved: %v\n", err)
		}
	}()
	// changes serializes the dashboard's writes and the SIGHUP reload.
	changes := &sync.Mutex{}
	dashboard, dashboardSrv, err := startDashboard(cfg, audit, stderr, func(a *admin.Server) {
		dashboardpkg.Register(&dashboardpkg.Backend{
			Mu: changes, StorePath: storePath, MetaPath: filepath.Join(filepath.Dir(storePath), "keymeta.json"),
			Rules: cfg.Rules, Proxy: handler, Admin: a,
		})
	})
	if err != nil {
		return err
	}
	if dashboardSrv != nil {
		defer dashboardSrv.Close()
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// Request bodies are small API payloads. No WriteTimeout: model
		// replies can stream for minutes.
		ReadTimeout: 5 * time.Minute,
		IdleTimeout: 2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// SIGHUP re-reads the access file, rules and keys without a restart.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	rl := reloader{configPath: configPath, storePath: storePath, fixed: cfg.Rules, handler: handler, dashboard: dashboard, mu: changes}
	saveTick := time.NewTicker(time.Minute)
	defer saveTick.Stop()
	// The final usage save (deferred above) must come after both the loop
	// below and in-flight requests are done: a tick save still running could
	// rename older counts over it, and a request still running would record
	// its call after it.
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-saveTick.C:
				if err := saveUsage(usageFile, handler.Usage()); err != nil {
					fmt.Fprintf(stderr, "usage not saved: %v\n", err)
				}
			case <-hup:
				next, keys, err := rl.reload()
				var missing []string
				if err == nil {
					missing = missingKeys(next, keys)
				}
				fmt.Fprintln(stderr, reloadMessage(next, err, missing))
			}
		}
	}()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	fmt.Fprintf(stderr, "keyring listening on %s: %d services, %d roles\n", cfg.Listen, len(cfg.Services), len(cfg.Roles))
	// Serve returns as soon as Shutdown closes the listener, before the
	// requests in flight finish; Shutdown returns when they have (or after
	// 10 seconds).
	serveErr := srv.Serve(listener)
	stop() // also ends the goroutines when Serve failed on its own
	<-drained
	<-loopDone
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

func runRelay(listen, upstreamURL, tokensDir string, stderr io.Writer) error {
	addr, err := netip.ParseAddrPort(listen)
	if err != nil || !addr.Addr().IsLoopback() {
		return fmt.Errorf("--listen %q: the relay must listen on a loopback address", listen)
	}
	upstream, err := relay.CheckUpstream(upstreamURL)
	if err != nil {
		return err
	}
	tokens, err := relay.LoadTokens(tokensDir)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           relay.New(upstream, tokens),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	roles := make([]string, 0, len(tokens))
	for role := range tokens {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	fmt.Fprintf(stderr, "keyring relay on %s -> %s; roles: %s\n", listen, upstream.Host, strings.Join(roles, ", "))
	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// openAudit opens the audit log for appending. The log names roles, services
// and paths, so a file other users can read is refused, as for the key store.
func openAudit(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("%s is open to other users (mode %04o); run chmod 600 %s", path, perm, path)
	}
	return f, nil
}

// readSecret reads one value from stdin. On a terminal, echo is turned off so
// the value is not shown.
func readSecret(stdin io.Reader, stderr io.Writer, name string) (string, error) {
	return readHidden(bufio.NewReader(stdin), stdin, stderr, "value for "+name+" (not shown): ")
}

// readHidden reads one line from in. When stdin is a terminal it prints
// prompt and turns echo off for the read.
func readHidden(in *bufio.Reader, stdin io.Reader, stderr io.Writer, prompt string) (string, error) {
	if f, ok := stdin.(*os.File); ok {
		if info, err := f.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprint(stderr, prompt)
			off := exec.Command("stty", "-echo")
			off.Stdin = f
			if off.Run() == nil {
				defer func() {
					on := exec.Command("stty", "echo")
					on.Stdin = f
					_ = on.Run()
					fmt.Fprintln(stderr)
				}()
			}
		}
	}
	line, err := in.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New("no value on stdin")
	}
	value := strings.TrimRight(line, "\r\n")
	if value == "" {
		return "", errors.New("empty value")
	}
	return value, nil
}
