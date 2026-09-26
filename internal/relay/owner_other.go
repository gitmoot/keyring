//go:build !unix

package relay

import "os"

// The relay only runs on Unix. Elsewhere token files cannot be checked, so
// LoadTokens refuses them.
const (
	noFollow = 0
	nonBlock = 0
)

func ownerUID(os.FileInfo) (int, bool) { return 0, false }
