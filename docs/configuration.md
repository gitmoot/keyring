# Configuration

How to run the keyring service: its commands and its two settings files.

```sh
keyring set --store keys.json OPENROUTER_API_KEY   # value read from stdin, not echoed
keyring list --store keys.json                     # names only
keyring new-token                                  # role token + sha256 for the access file
keyring check --config rules.json --store keys.json
keyring serve --config rules.json --store keys.json
kill -HUP <pid>                                    # re-read access file and keys, no restart
```

There are two settings files.

**`rules.json`**: who may connect. It is owned by root, and the service can only read it:

```json
{
  "listen": "192.0.2.10:7701",
  "allow_sources": ["192.0.2.20"],
  "audit_log": "/Library/Application Support/keyring/data/audit.log",
  "access_file": "/Library/Application Support/keyring/data/access.json"
}
```

**`access.json`**: which services exist and what each role may do. It is owned by the service user, mode 600:

```json
{
  "services": {
    "openrouter": {"base": "https://openrouter.ai", "key": "OPENROUTER_API_KEY", "auth": "bearer"},
    "tavily": {"base": "https://api.tavily.com", "key": "TAVILY_API_KEY", "auth": "header", "header": "X-Api-Key"}
  },
  "roles": {
    "my-agent": {
      "token_sha256": "<from keyring new-token>",
      "access": {"openrouter": {"paths": ["/api/v1"], "daily_requests": 2000}}
    }
  }
}
```

A rules file from before the split still holds `services` and `roles`. The service refuses it until you run `keyring migrate --config rules.json --access /absolute/path/access.json`, which moves them into the access file. Running it again does nothing.

`SIGHUP` re-reads the rules file, the access file and the keys. A change to `allow_sources` applies at once; a changed `listen`, `audit_log` or `access_file`, or an invalid file, is refused, and the previous settings stay in use. Daily counts carry over.

A stored Bitcoin private key (`tprv`/`xprv`/WIF) can only be used by a `bitcoin-psbt-sign` service: `check`, the start and `SIGHUP` refuse settings in which another service would use one, and `keyring set` stores one only with `--config rules.json`, to check that first. See [bitcoin.md](bitcoin.md).

### notify

`notify` in `rules.json` is the owner's signature notice setting: where a notice goes for every **mainnet** Bitcoin signature (never for a refusal, never on a test network). The owner picks the channel; **gram** is the only one supported for now, and any other `channel` is refused with the list of supported channels.

```json
"notify": {"channel": "gram", "url": "http://100.106.218.88:7702/notify", "token_key": "KEYRING_NOTIFY_TOKEN"}
```

- `channel`: `gram`. The keyring POSTs `{"text": "keyring: mainnet signature by <role> on <service>: txid …, N sats external, fee N sats, R sat/vB"}` to `url` with `Authorization: Bearer <token>`; a relay's notify listener sends it on with `herdr gram send` (see [relay](relay.md#signature-notices)).
- `url`: https, or plain http to a tailnet (100.64.0.0/10) or loopback IP only, so the token never crosses another network in clear. Redirects are not followed.
- `token_key`: the store key holding the token (no `.part`). It is never shown on the dashboard, not even on request, and no service may use it as its key (`check`, the start and `SIGHUP` refuse such settings). `keyring check` and the start warn when it is not stored.

A notice runs in the background for at most 30 seconds (longer than the relay's 20 for the gram command); a failure or timeout is written to the audit log and never delays or fails the signature. Mainnet signing answers 503 while the token is not stored. On the dashboard the token can be replaced but not renamed or deleted until `notify` changes. A change applies on `SIGHUP`. The dashboard's Bitcoin service pages show the channel and send a test notice (password asked, audited).

It is required for any mainnet service: `check`, the start and `SIGHUP` refuse a mainnet service without it, and signing answers 503 if it is somehow missing. Instance mode has no such setting and refuses mainnet services. `notify_command` (v0.16.0) is gone: a rules file that still has it is refused as an unknown field; replace it with `notify`. See [bitcoin.md](bitcoin.md#signature-notices).
