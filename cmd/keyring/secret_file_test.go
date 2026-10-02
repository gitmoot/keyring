package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/store"
)

func TestSetImportsWholePrivatePEMWithoutEcho(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	material := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	dir := t.TempDir()
	source := filepath.Join(dir, "private.p8")
	if err := os.WriteFile(source, []byte(material), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{source, "/dev/stdin"} {
		destination := filepath.Join(t.TempDir(), "keys.json")
		var out, stderr bytes.Buffer
		if code := run([]string{"set", "--store", destination, "--file", path, "APPLE_ADS_KEY"}, strings.NewReader(material), &out, &stderr); code != 0 {
			t.Fatalf("import status %d", code)
		}
		keys, err := store.Load(destination)
		if err != nil {
			t.Fatal(err)
		}
		if keys["APPLE_ADS_KEY"] != material {
			t.Fatal("PEM truncated or altered")
		}
		if strings.Contains(out.String()+stderr.String(), "PRIVATE KEY") || strings.Contains(out.String()+stderr.String(), material) {
			t.Fatal("import echoed key")
		}
		info, err := os.Stat(destination)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatal("store not private")
		}
		// An ordinary interactive update still reads exactly one line.
		if code := run([]string{"set", "--store", destination, "OTHER_KEY"}, strings.NewReader("one-line\nignored\n"), &out, &stderr); code != 0 {
			t.Fatal("interactive set failed")
		}
		keys, err = store.Load(destination)
		if err != nil {
			t.Fatal(err)
		}
		if keys["OTHER_KEY"] != "one-line" || keys["APPLE_ADS_KEY"] != material {
			t.Fatal("interactive set damaged imported PEM")
		}
	}
}

type secretReadError struct{}

func (secretReadError) Read([]byte) (int, error) { return 0, errors.New("secret-in-reader-error") }

func TestSetFileImportRejectsUnsafeInputsWithoutChangingStore(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "private.p8")
	if err := os.WriteFile(source, []byte("secret-test-value\nsecond-line\n"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "keys.json")
	if err := store.Set(destination, "KEY", "previous"); err != nil {
		t.Fatal(err)
	}
	// First prove the feature is accepted, not just that an unknown flag fails.
	var out, stderr bytes.Buffer
	if code := run([]string{"set", "--store", destination, "--file", source, "KEY"}, nil, &out, &stderr); code != 0 {
		t.Fatal("valid import failed")
	}
	if err := os.Chmod(source, 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		reader     io.Reader
	}{
		{"public file", source, nil}, {"symlink", link, nil}, {"directory", dir, nil}, {"missing", filepath.Join(dir, "missing"), nil},
		{"empty", "/dev/stdin", strings.NewReader("")}, {"whitespace", "/dev/stdin", strings.NewReader("\n ")},
		{"oversize", "/dev/stdin", strings.NewReader(strings.Repeat("s", (1<<20)+1))}, {"read error", "/dev/stdin", secretReadError{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			stderr.Reset()
			if code := run([]string{"set", "--store", destination, "--file", tc.path, "KEY"}, tc.reader, &out, &stderr); code == 0 {
				t.Fatal("unsafe input accepted")
			}
			if strings.Contains(out.String()+stderr.String(), "secret-test-value") || strings.Contains(out.String()+stderr.String(), "secret-in-reader-error") {
				t.Fatal("secret leaked on failure")
			}
			keys, err := store.Load(destination)
			if err != nil {
				t.Fatal(err)
			}
			if keys["KEY"] != "secret-test-value\nsecond-line\n" {
				t.Fatal("failed import replaced previous key")
			}
		})
	}
}
