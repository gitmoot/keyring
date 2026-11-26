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

### notify_command

`notify_command` in `rules.json` is the owner's notification hook: it runs once for every **mainnet** Bitcoin signature (never for a refusal, never on a test network). It is an argv list, never a shell string: the first entry is the absolute path of a program, at most 32 entries, no NUL bytes; keyring appends one line as the last argument (`keyring: mainnet signature by <role> on <service>: txid …, N sats external, fee N sats, R sat/vB`). It runs in the background for at most 10 seconds; a failure or timeout is written to the audit log and never delays or fails the signature. A change applies on `SIGHUP`.

The service runs as `_keyring` without a desktop session, so desktop notifiers (for example `osascript`) are not expected to work. The owner picks the channel at setup; a network hook works from the service account, for example posting to a URL the owner controls:

```json
"notify_command": ["/usr/bin/curl", "-fsS", "-m", "8", "https://ntfy.example/your-topic", "-d"]
```

It is required for any mainnet service: `check`, the start and `SIGHUP` refuse a mainnet service without it, and signing answers 503 if it is somehow missing. Instance mode has no such setting and refuses mainnet services. See [bitcoin.md](bitcoin.md#mainnet).
