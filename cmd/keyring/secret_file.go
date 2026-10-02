package main

import (
	"errors"
	"io"
	"os"
	"strings"
)

// readSecretFile preserves multiline values, unlike the interactive one-line
// prompt. Never return an underlying read error: a reader can include secrets.
func readSecretFile(path string, stdin io.Reader) (string, error) {
	const limit = 1 << 20
	var input io.Reader
	if path == "/dev/stdin" {
		if f, ok := stdin.(*os.File); ok {
			info, err := f.Stat()
			if err != nil || (!info.Mode().IsRegular() && info.Mode()&os.ModeNamedPipe == 0) || info.Mode().Perm()&0o077 != 0 {
				return "", errors.New("--file /dev/stdin requires a private pipe or redirected file, not a terminal")
			}
		}
		input = stdin
	} else {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return "", errors.New("--file requires a private regular file (mode 600), not a symlink")
		}
		f, err := os.Open(path)
		if err != nil {
			return "", errors.New("could not open secret file")
		}
		defer f.Close()
		opened, err := f.Stat()
		if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
			return "", errors.New("secret file changed while opening")
		}
		input = f
	}
	raw, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil {
		return "", errors.New("could not read secret input")
	}
	if len(raw) > limit {
		return "", errors.New("secret input exceeds 1 MiB")
	}
	value := string(raw)
	if strings.TrimSpace(value) == "" {
		return "", errors.New("empty secret input")
	}
	return value, nil
}
