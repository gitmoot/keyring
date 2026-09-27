# keyring

Keeps API keys on a separate machine. Agents call APIs **through** the keyring,
so a key never reaches the machine where agents run.

Status: the service (#2) is done; the relay (#3) is in progress. Nothing is deployed yet. Plan and steps: #1.

## Why

On the agent server every agent runs as root, so any agent can read every key
in `/root/.env`, and keys leak by accident into chats, PRs and logs. Moving
the keys to another machine means there is nothing on the agent server to
read or leak.

## How it works

```
agent server                           keyring machine (tailnet only)
┌──────────────────────┐               ┌───────────────────────────────┐
│ agent                │               │ keyring service               │
│   │ POST /openrouter/…               │  1. who is calling? (role)    │
│   ▼                  │   tailnet     │  2. allowed? (key, path, cap) │
│ local relay :7700 ───┼──────────────▶│  3. add the key, call the API │
│   (adds role token)  │               │  4. log it, return the answer │
└──────────────────────┘               └──────────────┬────────────────┘
                                                      ▼
                                             OpenRouter, Apple, …
```

Three ways to use a key:

| Mode  | What the agent does | Key leaves the keyring? |
|-------|---------------------|-------------------------|
| proxy | Sends the request without a key; the keyring adds it | never |
| sign  | Asks for a short-lived token (Apple JWTs) | only the token, minutes |
| run   | Asks for the raw key for one command | yes (last resort, logged) |

Per role: which keys, which API paths, a spending cap, and an expiry. Every
call is logged without the key. Rotating a key is one change on the keyring
machine.

## Limits

- Each role's token sits on the agent server, so a misbehaving root agent can
  use another role's access. It still cannot read the keys, and every call is
  logged and revocable.
- If the keyring machine is off or asleep, API calls fail.

## Using it

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
  "listen": "100.111.92.43:7701",
  "allow_sources": ["100.106.218.88"],
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
    "phobos": {
      "token_sha256": "<from keyring new-token>",
      "access": {"openrouter": {"paths": ["/api/v1"], "daily_requests": 2000}}
    }
  }
}
```

A rules file from before the split still holds `services` and `roles`. The service refuses it until you run `keyring migrate --config rules.json --access /absolute/path/access.json`, which moves them into the access file. Running it again does nothing.

`SIGHUP` re-reads the access file and keys. An invalid access file, or a changed `listen` or `audit_log`, is refused, and the previous settings stay in use. Daily counts carry over.

A call is `<METHOD> http://<listen>/<service>/<path>` with header `X-Keyring-Token: <role token>`. The keyring:
- accepts a path only in a plain form: printable ASCII after one decode, with no `..` or `.` segment, no `;`, no `%` left (double encoding), and no encoded `/`, `.` or `\`. It forwards the path it checked, escaped again, not the caller's raw text;
- drops the caller's `Authorization`, `Cookie` and role token, and every casing of the key's header or query parameter, then adds the key;
- does not follow redirects;
- replaces an echoed key with `[REDACTED]`, in headers and bodies, as sent, URL-encoded (either hex case), or with JSON-escaped slashes, even when split across chunks;
- refuses (502) a reply compressed with anything other than gzip, which it decodes, because it could not check that reply for the key;
- does not count a call against the daily limit if the service was unreachable;
- writes one audit line per call, with no keys, tokens, query strings or bodies. The audit log, like the store, is refused if other users can read it.

A service that echoes a key in some other encoding (for example base64 inside a larger text) is not protected; do not route such a service through the keyring.

Allowed methods default to GET, HEAD and POST.

## Dashboard (in progress, #15)

Add two lines to `rules.json` to serve a dashboard on a **loopback** address of the keyring machine:

```json
"admin_listen": "127.0.0.1:7702",
"admin_password_file": "/Library/Application Support/keyring/admin.pw"
```

Set the password as root with `keyring admin-password --config rules.json`. It asks twice, needs at least 12 characters, and stores only a PBKDF2-SHA256 hash, root-owned and mode 640. Reload with SIGHUP to apply it; that ends every session. Then open `http://127.0.0.1:7702` in a browser on that machine.

Safety:
- The dashboard listener only accepts a loopback address, and never serves the proxy. The proxy listener never serves the dashboard.
- Requests with a `Host` other than the listener's address are refused, against DNS rebinding.
- Every change needs a same-origin `Origin` header and the session's CSRF token.
- Sessions are in memory only: `HttpOnly`, `SameSite=Strict`, 30 minutes idle, 8 hours at most.
- Failed logins are slowed after 5 and locked for an hour after 20.
- Every login, logout and password change is written to the audit log without secrets.

## Relay on the agent server (step 2)

The relay listens only on loopback, holds one token per role (never an API key), and forwards to the keyring over the tailnet:

```sh
keyring relay --listen 127.0.0.1:7700 --upstream http://100.111.92.43:7701 --tokens /etc/keyring/tokens
```

`/etc/keyring/tokens` must be a real directory (not a symlink), owned by the relay's user, mode 700, inside a parent that only that user can write (for example root-owned `/etc/keyring`). Each `<role>.token` file must be a regular file owned by that user, mode 600. A call picks its role in the path:

```sh
curl http://127.0.0.1:7700/phobos/openrouter/api/v1/models
# SDKs: set the base URL to http://127.0.0.1:7700/<role>/openrouter/api/v1 and any placeholder key
curl http://127.0.0.1:7700/_relay/health       # is the keyring reachable?
```

The relay replaces any caller-supplied role token with the role's own. It refuses plain http except to a tailnet or loopback address. If the keyring is unreachable, calls fail with 502 `keyring unreachable ... never fall back to local keys`. Install steps are in `deploy/keyring-relay.service`.
