# Instance mode: one small keyring per person

`keyring serve` (files, `SIGHUP`, dashboard) stays the way to run the owner's keyring. `keyring instance` runs one person's keyring for a supervisor, such as a process manager on a host or, at Cloudflare, the person's Durable Object (#46). No hand-edited files are involved, and the person's keys stay in a separate process from every other person's.

```sh
keyring instance --admin-listen 127.0.0.1:7720 --admin-token-sha256 <hex> [--state /var/lib/keyring/alice.sealed] [--audit /var/log/keyring/alice.log]
```

- The admin API listens on a loopback address and needs `Authorization: Bearer <admin token>` on every call. Only the token's SHA-256 is given to the process.
- Everything the instance knows is one **sealed state**: network settings, services, roles (token hashes only), consent settings and key values. It is encrypted with AES-256-GCM and bound to the instance id. The 32-byte data key comes from the supervisor with `create`, `unlock` or `rotate`, and the keyring never writes it anywhere. With `--state` the sealed state is kept in that file (mode 600). Without it, the state lives only in memory and the supervisor stores it from `GET /state`.
- Every change is validated like the access file, and any new listener must be able to bind. Only then is the state sealed, written and applied; a refused change leaves everything as it was. Each change increases `version` by 1.
- The audit log (`--audit`, or stdout) takes one JSON line per proxied call and per admin change. It never contains a key value, token or data key.
- With no `create` or `unlock`, the instance serves only its admin API.

| Call | Body | Reply |
|---|---|---|
| `POST /create` | `{"id", "data_key", "listen", "allow_sources"}` | 201 `{"version"}`; refused if a state exists |
| `POST /unlock` | `{"data_key", "state"?}` (`state`: base64 sealed state; else the `--state` file) | `{"version"}`; 403 for a wrong key or another instance's state |
| `GET /status` | | settings, services, roles (no token hashes), key **names** |
| `GET /state` | | `{"version", "state"}` (base64 sealed state) |
| `PUT /network` | `{"listen", "allow_sources"}` | moves the proxy |
| `PUT /consent`, `DELETE /consent` | the `consent` block of `rules.json` | consent listeners start or stop |
| `PUT /services/<name>`, `DELETE /services/<name>` | a service, as in the access file | |
| `PUT /roles/<name>` | `{"access", "expires"?}` | `{"version", "token"}`; the token appears only when the role is new |
| `POST /roles/<name>/token` | | `{"token"}`; the old token stops working |
| `DELETE /roles/<name>` | | |
| `PUT /keys/<name>`, `DELETE /keys/<name>` | `{"value"}` | |
| `POST /rotate` | `{"data_key"}` | seals with the new key; the old key opens nothing written after this |
| `GET /usage` | | `{"day", "counts": [{"role", "service", "count"}]}`, today's daily-limit counts (UTC) |
| `DELETE /instance` | | overwrites and removes the state file, forgets the state and key, stops the listeners; the process exits |

After `DELETE /instance`, a copy of the sealed state that the supervisor still holds can be opened only with the data key. The supervisor deletes its copy of the key, and then nothing can open it.

One process per person, not one process for many people: the operating system keeps each person's keys in a separate address space, the proxy code is unchanged, and it matches one container per person at Cloudflare. An idle instance measured on Linux x64 (Go 1.24, one service, one role): about 12 MB resident, 8 threads, and 0 CPU ticks over 30 idle seconds.

Daily counts are kept in memory. A supervisor that stops the process (a container going to sleep) keeps the last `GET /usage` and passes it back as `"usage"` in `POST /unlock`. Counts from another day are ignored, and a restore never lowers a count, so a stop cannot give a role a fresh daily limit. Calls made after the supervisor's last `GET /usage` are lost if the process stops without warning, so the supervisor should fetch `/usage` just before it stops the process. Open consent links stay in memory: the supervisor keeps the process running until its last link and sign-in have expired. The audit log goes to stdout unless `--audit` is given.

**Container mode** (`--container`, #51) is for an instance in a container that only its supervisor can reach, such as a Cloudflare Container behind the person's Durable Object. In this mode:
- the admin API, the proxy and the consent listeners may use a wildcard address such as `0.0.0.0:8080`, and no two may share a port;
- `allow_sources` and `consent.api_allow_sources` must be empty, and no source address is checked, because every request arrives through the supervisor. The supervisor is the network boundary. It checks the router's proof (`X-Keyring-Caller`, #52) and the admin token before forwarding anything;
- the keyring never forwards `X-Keyring-Caller` upstream, even if the supervisor failed to remove it.

Container mode is set only by the flag; a rules or access file cannot turn it on, and `keyring serve` never uses it.
