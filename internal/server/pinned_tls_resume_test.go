package server

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// A resumed TLS session skips certificate verification unless the check runs
// in VerifyConnection: a session cached under a matching pin must not let a
// client with a different pin through.
func TestPinCheckedOnResumedSession(t *testing.T) {
	up, pin := tlsUpstream(t)
	addr := strings.TrimPrefix(up.URL, "https://")
	good, _ := hex.DecodeString(pin)
	cache := tls.NewLRUClientSessionCache(4)
	dial := func(cfg *tls.Config) (tls.ConnectionState, error) {
		cfg.ClientSessionCache = cache
		cfg.ServerName = "pinned.test"
		conn, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			return tls.ConnectionState{}, err
		}
		defer conn.Close()
		// TLS 1.3 tickets arrive after the handshake; read to receive one.
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
		_, _ = io.ReadAll(conn)
		return conn.ConnectionState(), nil
	}
	if _, err := dial(pinnedTLSConfig(good)); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	cs, err := dial(pinnedTLSConfig(good))
	if err != nil || !cs.DidResume {
		t.Fatalf("second handshake did not resume: resumed=%v err=%v", cs.DidResume, err)
	}
	bad := make([]byte, sha256.Size)
	if _, err := dial(pinnedTLSConfig(bad)); err == nil {
		t.Fatal("resumed session with a wrong pin accepted")
	}
}
