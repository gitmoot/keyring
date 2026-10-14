package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gitmoot/keyring/internal/instance"
)

// runInstance serves one person's keyring until SIGTERM or until it is
// deleted through its admin API.
func runInstance(adminListen, adminTokenSHA, statePath, auditPath string, container bool, stdout, stderr io.Writer) error {
	audit, auditName := stdout, "stdout"
	if auditPath != "" {
		f, err := openAudit(auditPath)
		if err != nil {
			return err
		}
		defer f.Close()
		audit, auditName = f, auditPath
	}
	in, err := instance.New(instance.Options{
		AdminListen: adminListen, AdminTokenSHA256: adminTokenSHA, StatePath: statePath,
		Audit: audit, AuditName: auditName, Log: stderr, Container: container,
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", adminListen)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           in.AdminHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(listener) }()
	fmt.Fprintf(stderr, "keyring instance: admin API on %s, locked\n", adminListen)
	var serveErr error
	select {
	case <-ctx.Done():
	case <-in.Wiped():
		fmt.Fprintln(stderr, "keyring instance: deleted")
	case serveErr = <-served:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	in.Close()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}
