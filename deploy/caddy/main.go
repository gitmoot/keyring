// Command keyring-caddy is Caddy with the Cloudflare DNS module, the HTTPS
// front of the keyring dashboard on the Mac (deploy/mac/https.sh). It is a
// separate module so its versions are pinned in go.sum and the keyring itself
// does not depend on Caddy.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddy-dns/cloudflare"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() {
	caddycmd.Main()
}
