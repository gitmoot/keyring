package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/minisign"
	"github.com/gitmoot/keyring/internal/store"
)

func TestMinisignKeygenStoresKeyAndNeverReplacesIt(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "keys.json")
	var out, errOut bytes.Buffer
	if code := run([]string{"minisign-keygen", "--store", storePath, "HERDR_RELEASE_KEY"}, nil, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	keys, err := store.Load(storePath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(keys["HERDR_RELEASE_KEY"])
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		t.Fatal("stored value is not a 64-byte Ed25519 key")
	}
	priv := ed25519.PrivateKey(raw)
	if out.String() != minisign.PublicKeyFile(priv.Public().(ed25519.PublicKey)) {
		t.Fatalf("printed %q, want the key's minisign public key file", out.String())
	}
	if strings.Contains(out.String(), keys["HERDR_RELEASE_KEY"]) {
		t.Fatal("private key printed")
	}

	out.Reset()
	if code := run([]string{"minisign-keygen", "--store", storePath, "HERDR_RELEASE_KEY"}, nil, &out, &errOut); code == 0 {
		t.Fatal("an existing key was replaced")
	}
	after, err := store.Load(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if after["HERDR_RELEASE_KEY"] != keys["HERDR_RELEASE_KEY"] {
		t.Fatal("existing key changed")
	}
}
