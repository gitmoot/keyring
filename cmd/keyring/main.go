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
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

const usage = `Usage:
  keyring serve --config FILE --store FILE   run the keyring
  keyring check --config FILE [--store FILE] check the rules (and which keys are missing)
  keyring set --store FILE NAME              add or replace a key; the value is read from stdin
  keyring delete --store FILE NAME           remove a key
  keyring list --store FILE                  print key names (never values)
  keyring new-token                          make a role token and its hash for the rules file
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
	audit, err := os.OpenFile(cfg.AuditLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer audit.Close()
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           server.New(cfg, keys, audit),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	fmt.Fprintf(stderr, "keyring listening on %s: %d services, %d roles\n", cfg.Listen, len(cfg.Services), len(cfg.Roles))
	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// readSecret reads one value from stdin. On a terminal, echo is turned off so
// the value is not shown.
func readSecret(stdin io.Reader, stderr io.Writer, name string) (string, error) {
	if f, ok := stdin.(*os.File); ok {
		if info, err := f.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintf(stderr, "value for %s (not shown): ", name)
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
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", errors.New("no value on stdin")
	}
	value := strings.TrimRight(line, "\r\n")
	if value == "" {
		return "", errors.New("empty value")
	}
	return value, nil
}
