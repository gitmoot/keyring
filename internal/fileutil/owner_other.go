//go:build !unix

package fileutil

// Owner is not available off Unix.
func Owner(string) (uid, gid int, ok bool) { return 0, 0, false }
