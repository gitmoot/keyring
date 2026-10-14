package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/consent"
	dashboardpkg "github.com/gitmoot/keyring/internal/dashboard"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// storeKeys writes keys for consent links the way the dashboard does: under
// the shared change lock, noting the change for the dashboard, and swapping
// the new keys into the proxy.
type storeKeys struct {
	path, metaPath string
	mu             *sync.Mutex
	proxy          *server.Handler
}

func (k storeKeys) Load() (map[string]string, error) { return store.Load(k.path) }

func (k storeKeys) Set(name, value string) error {
	return k.change(name, false, func() error { return store.Set(k.path, name, value) })
}

func (k storeKeys) Delete(name string) error {
	return k.change(name, true, func() error { return store.Delete(k.path, name) })
}

func (k storeKeys) change(name string, deleted bool, write func() error) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := write(); err != nil {
		return err
	}
	if err := dashboardpkg.NoteKeyChange(k.metaPath, name, deleted, time.Now()); err != nil {
		return err
	}
	keys, err := store.Load(k.path)
	if err != nil {
		return err
	}
	k.proxy.Swap(k.proxy.Config(), keys)
	return nil
}

// startConsent serves consent links when the rules turn them on: the pages
// on consent.listen and the API on consent.api_listen. It returns the
// servers to close, none when consent is off.
func startConsent(cfg *policy.Config, keys consent.Keys, proxy *server.Handler, audit io.Writer, stderr io.Writer) ([]*http.Server, error) {
	k := cfg.Consent
	if k == nil {
		return nil, nil
	}
	c := consent.New(proxy.Config, keys, audit)
	var servers []*http.Server
	for _, l := range []struct {
		addr, what string
		handler    http.Handler
	}{
		{k.Listen, "consent pages", c.PagesHandler()},
		{k.APIListen, "consent API", c.APIHandler()},
	} {
		listener, err := net.Listen("tcp", l.addr)
		if err != nil {
			for _, s := range servers {
				s.Close()
			}
			return nil, fmt.Errorf("%s: %w", l.what, err)
		}
		srv := &http.Server{
			Handler:           l.handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       time.Minute,
			WriteTimeout:      time.Minute,
			IdleTimeout:       2 * time.Minute,
		}
		what := l.what
		go func() {
			if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Fprintf(stderr, "%s stopped: %v\n", what, err)
			}
		}()
		servers = append(servers, srv)
		fmt.Fprintf(stderr, "%s on http://%s\n", what, l.addr)
	}
	fmt.Fprintf(stderr, "consent links point at %s\n", k.PublicBase())
	return servers, nil
}
