package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/gitmoot/keyring/internal/bitcoin"
	"github.com/gitmoot/keyring/internal/store"
)

// bitcoinImport stores a Bitcoin private key (a master tprv or a WIF key)
// read from stdin, never from arguments, so it is not in the shell history
// or the process list (#187). The owner keeps the backup: the keyring never
// generates or shows a key. It prints what the owner can check against the
// wallet: fingerprint, network and first receive addresses. An existing name
// is never replaced.
func bitcoinImport(storePath, network, name string, stdin io.Reader, stdout, stderr io.Writer) error {
	if network == "" {
		return errors.New("pass --network regtest, testnet or signet")
	}
	if !store.ValidName(name) {
		return fmt.Errorf("invalid key name %q: use letters, digits and _", name)
	}
	keys, err := store.Load(storePath)
	if err != nil {
		return err
	}
	if _, exists := keys[name]; exists {
		return fmt.Errorf("%s already exists; import under a new name", name)
	}
	value, err := readHidden(bufio.NewReader(stdin), stdin, stderr, "Bitcoin key for "+name+" (tprv or WIF, not shown): ")
	if err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	d, err := bitcoin.Describe(value, network)
	if err != nil {
		// Describe's errors are fixed texts; never the value.
		return err
	}
	if err := store.Set(storePath, name, value); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "stored %s\nfingerprint: %s\nnetwork:     %s\nkind:        %s\nfirst receive addresses (check them in your wallet):\n", name, d.Fingerprint, d.Network, d.Kind)
	for _, a := range d.Addresses {
		fmt.Fprintf(stdout, "  %-17s %-7s %s\n", a.Path, a.Script, a.Address)
	}
	return nil
}
