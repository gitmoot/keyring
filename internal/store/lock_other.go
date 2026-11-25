//go:build !unix

package store

import "sync"

// storeMu stands in for the store's file lock off Unix (keyring ships for
// Linux and macOS only): writers in this process still exclude each other.
var storeMu sync.Mutex

func lock(string) (func(), error) {
	storeMu.Lock()
	return storeMu.Unlock, nil
}
