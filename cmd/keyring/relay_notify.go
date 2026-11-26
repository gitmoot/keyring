package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/relay"
)

// relayNotify is the relay's optional notify listener (#187): the
// keyring's signature notices, sent on with herdr gram send.
type relayNotify struct {
	listen      string   // IP:port; "" is off
	allow       []string // source IPs
	tokenFile   string
	gramCommand string // a name looked up in PATH or an absolute path
	gramSet     bool   // --gram-command was given
}

// server checks the flags and builds the notify listener's server, nil when
// --notify-listen is not set. gramCommand becomes the resolved path.
func (n *relayNotify) server() (*http.Server, error) {
	if n.listen == "" {
		if len(n.allow) != 0 || n.tokenFile != "" || n.gramSet {
			return nil, errors.New("--notify-allow, --notify-token-file and --gram-command need --notify-listen")
		}
		return nil, nil
	}
	addr, err := netip.ParseAddrPort(n.listen)
	if err != nil || addr.Addr().IsUnspecified() || addr.Port() == 0 {
		return nil, fmt.Errorf("--notify-listen %q: want one specific IP:port (no wildcard address)", n.listen)
	}
	if len(n.allow) == 0 {
		return nil, errors.New("--notify-listen needs at least one --notify-allow IP (the keyring's)")
	}
	allow := make([]netip.Addr, 0, len(n.allow))
	for _, a := range n.allow {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("--notify-allow %q: want an IP address", a)
		}
		allow = append(allow, ip)
	}
	if n.tokenFile == "" {
		return nil, errors.New("--notify-listen needs --notify-token-file")
	}
	token, err := relay.ReadToken(n.tokenFile)
	if err != nil {
		return nil, err
	}
	command := n.gramCommand
	if filepath.IsAbs(command) {
		info, err := os.Stat(command)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return nil, fmt.Errorf("--gram-command %q: not an executable file", command)
		}
	} else if strings.ContainsRune(command, '/') {
		return nil, fmt.Errorf("--gram-command %q: give a name looked up in PATH or an absolute path", command)
	} else if path, err := exec.LookPath(command); err != nil {
		return nil, fmt.Errorf("--gram-command %q: not found in PATH; give its absolute path", command)
	} else {
		command = path
	}
	n.gramCommand = command
	return &http.Server{
		Handler:           relay.NewNotifier(token, allow, command),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
	}, nil
}
