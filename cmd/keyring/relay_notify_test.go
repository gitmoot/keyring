package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The notify listener starts only with a specific address, at least one
// allowed IP and a private token file; its flags alone are refused.
func TestRelayNotifyFlags(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "notify.token")
	if err := os.WriteFile(token, []byte("notice-token-0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gram := filepath.Join(dir, "herdr")
	if err := os.WriteFile(gram, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	open := filepath.Join(dir, "open.token")
	if err := os.WriteFile(open, []byte("notice-token-0123456789abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		n    relayNotify
		want string
	}{
		"allow without listen": {relayNotify{allow: []string{"100.111.92.43"}, gramCommand: "herdr"}, "need --notify-listen"},
		"wildcard":             {relayNotify{listen: "0.0.0.0:7702", allow: []string{"100.111.92.43"}, tokenFile: token, gramCommand: gram}, "no wildcard"},
		"no allowed IP":        {relayNotify{listen: "127.0.0.1:7702", tokenFile: token, gramCommand: gram}, "at least one --notify-allow"},
		"no token file":        {relayNotify{listen: "127.0.0.1:7702", allow: []string{"100.111.92.43"}, gramCommand: gram}, "needs --notify-token-file"},
		"open token file":      {relayNotify{listen: "127.0.0.1:7702", allow: []string{"100.111.92.43"}, tokenFile: open, gramCommand: gram}, "open to other users"},
		"relative command":     {relayNotify{listen: "127.0.0.1:7702", allow: []string{"100.111.92.43"}, tokenFile: token, gramCommand: "bin/herdr"}, "absolute path"},
	} {
		if _, err := c.n.server(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	n := relayNotify{listen: "127.0.0.1:7702", allow: []string{"100.111.92.43"}, tokenFile: token, gramCommand: gram}
	if srv, err := n.server(); err != nil || srv == nil {
		t.Fatalf("valid flags: %v", err)
	}
	if srv, err := (&relayNotify{gramCommand: "herdr"}).server(); err != nil || srv != nil {
		t.Fatalf("no notify listener: %v %v", srv, err)
	}
}
