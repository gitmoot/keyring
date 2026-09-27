package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/server"
)

// usagePath keeps usage next to the key store, in the service's own directory.
func usagePath(storePath string) string {
	return filepath.Join(filepath.Dir(storePath), "usage.json")
}

func loadUsage(path string) ([]server.Usage, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rows []server.Usage
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func saveUsage(path string, rows []server.Usage) error {
	raw, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(path, append(raw, '\n'), 0o600)
}
