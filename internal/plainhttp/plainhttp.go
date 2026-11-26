// Package plainhttp is the one rule for sending a credential over plain
// http: the relay's role token to the keyring, the keyring's notice token
// to a relay.
package plainhttp

import "net/netip"

// Tailnet is the Tailscale range: it encrypts traffic itself.
var Tailnet = netip.MustParsePrefix("100.64.0.0/10")

// Allowed reports whether plain http may carry a credential to host: an IP
// literal on loopback or the tailnet. Any other host needs https.
func Allowed(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && (addr.IsLoopback() || Tailnet.Contains(addr.Unmap()))
}
