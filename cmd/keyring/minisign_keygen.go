package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/gitmoot/keyring/internal/minisign"
	"github.com/gitmoot/keyring/internal/store"
)

// minisignKeygen makes a new Ed25519 key inside the store, so the private key
// is never shown or written anywhere else, and prints its minisign public key.
// An existing name is never replaced: rotate by generating a new name and
// pointing the service at it.
func minisignKeygen(storePath, name string, stdout io.Writer) error {
	if !store.ValidName(name) {
		return fmt.Errorf("invalid key name %q: use letters, digits and _", name)
	}
	keys, err := store.Load(storePath)
	if err != nil {
		return err
	}
	if _, exists := keys[name]; exists {
		return fmt.Errorf("%s already exists; generate under a new name to rotate", name)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := store.Set(storePath, name, base64.StdEncoding.EncodeToString(priv)); err != nil {
		return err
	}
	_, err = io.WriteString(stdout, minisign.PublicKeyFile(pub))
	return err
}
