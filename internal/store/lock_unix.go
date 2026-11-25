//go:build unix

package store

import (
	"os"
	"syscall"
)

// lock takes the store's lock, an exclusive flock of path + ".lock", and
// returns the function that releases it. Every writer (update) holds it from
// its read to its rename, so a write from another process, such as keyring
// set while the service runs, is never lost. Readers need no lock: the
// rename replaces the file whole.
func lock(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
