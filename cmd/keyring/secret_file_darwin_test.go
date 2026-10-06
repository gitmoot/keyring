package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/gitmoot/keyring/internal/store"
)

func TestSetDarwinPipeImportBoundary(t *testing.T) {
	const material = "synthetic-private-value\nsecond-line\n"
	destination := filepath.Join(t.TempDir(), "keys.json")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err := writer.WriteString(material); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"set", "--store", destination, "--file", "/dev/stdin", "KEY"}, reader, &out, &stderr); code != 0 {
		t.Fatalf("real Darwin anonymous pipe rejected: %s", stderr.String())
	}
	keys, err := store.Load(destination)
	if err != nil {
		t.Fatal(err)
	}
	if keys["KEY"] != material {
		t.Fatal("anonymous pipe import truncated or changed the value")
	}
	if strings.Contains(out.String()+stderr.String(), material) {
		t.Fatal("anonymous pipe import echoed the value")
	}

	// A filesystem-visible FIFO is not an anonymous pipe. Its permissions still
	// matter, even though both descriptor types carry os.ModeNamedPipe.
	fifo := filepath.Join(t.TempDir(), "public.fifo")
	if err := syscall.Mkfifo(fifo, 0666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fifo, 0666); err != nil {
		t.Fatal(err)
	}
	publicPipe, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer publicPipe.Close()
	publicWriter, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publicWriter.WriteString("replacement"); err != nil {
		publicWriter.Close()
		t.Fatal(err)
	}
	if err := publicWriter.Close(); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(t.TempDir(), "public.txt")
	if err := os.WriteFile(publicPath, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(publicPath, 0666); err != nil {
		t.Fatal(err)
	}
	publicFile, err := os.Open(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	defer publicFile.Close()
	device, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	for _, tc := range []struct {
		name  string
		input *os.File
	}{
		{"public named pipe", publicPipe},
		{"public regular file", publicFile},
		{"character device", device},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out.Reset()
			stderr.Reset()
			if code := run([]string{"set", "--store", destination, "--file", "/dev/stdin", "KEY"}, tc.input, &out, &stderr); code == 0 {
				t.Fatal("unsafe descriptor accepted")
			}
			keys, err := store.Load(destination)
			if err != nil {
				t.Fatal(err)
			}
			if keys["KEY"] != material {
				t.Fatal("refused import changed the stored value")
			}
		})
	}
}
