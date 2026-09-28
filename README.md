# keyring

Keeps API keys on a separate machine. Agents call APIs **through** the keyring,
so a key never reaches the machine where agents run.

Status: the service, the relay and the Mac installer are done and in use; the dashboard is #15. Plan and steps: #1.

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
    "phobos": {
      "token_sha256": "<from keyring new-token>",
      "access": {"openrouter": {"paths": ["/api/v1"], "daily_requests": 2000}}
    }
  }
}
```

A rules file from before the split still holds `services` and `roles`. The service refuses it until you run `keyring migrate --config rules.json --access /absolute/path/access.json`, which moves them into the access file. Running it again does nothing.

`SIGHUP` re-reads the rules file, the access file and the keys. A change to `allow_sources` applies at once; a changed `listen`, `audit_log` or `access_file`, or an invalid file, is refused, and the previous settings stay in use. Daily counts carry over.

A call is `<METHOD> http://<listen>/<service>/<path>` with header `X-Keyring-Token: <role token>`. The keyring:
- accepts a path only in a plain form: printable ASCII after one decode, with no `..` or `.` segment, no `;`, no `%` left (double encoding), and no encoded `/`, `.` or `\`. It forwards the path it checked, escaped again, not the caller's raw text;
- drops the caller's `Authorization`, `Cookie` and role token, and every casing of the key's header or query parameter, then adds the key;
- does not follow redirects;
- replaces an echoed key with `[REDACTED]`, in headers and bodies, as sent, URL-encoded (either hex case), or with JSON-escaped slashes, even when split across chunks;
- refuses (502) a reply compressed with anything other than gzip, which it decodes, because it could not check that reply for the key;
- does not count a call against the daily limit if the service was unreachable;
- writes one audit line per call, with no keys, tokens, query strings or bodies. The audit log, like the store, is refused if other users can read it.

A service that echoes a key in some other encoding (for example base64 inside a larger text) is not protected; do not route such a service through the keyring.

Allowed methods default to GET, HEAD and POST. A role's `"expires"` ends all its access (401); an access's own `"expires"` (RFC 3339, like `"2026-12-31T00:00:00Z"`) ends only that service (403).

A service may name a harmless request for the dashboard's Test button: `"test_method": "GET"` (GET, HEAD or POST; default GET) and `"test_path": "/api/v1/key"` (may carry a query). The test goes out exactly like a proxied call.

## Dashboard (#15)

`admin_https` in `rules.json` (set by `keyring enable-dashboard --https-host NAME --device IP ...`) also serves the dashboard as `https://NAME` through a local HTTPS proxy, to the listed device IPs only. The proxy must put the client's IP in `X-Keyring-Client`; any other client, or a request without it, gets 403 before the login page. Over HTTPS the session cookie is `Secure` and the page sends HSTS. The Mac installer sets this up with Caddy (`deploy/mac/README.md`, built from `deploy/caddy`, versions pinned in its `go.sum`). A reload refuses a change to `admin_https`; restart the keyring.

The Mac installer turns it on and asks for its password (`deploy/mac/README.md`). By hand: `keyring enable-dashboard --config rules.json` adds two lines to `rules.json`, serving the dashboard on a **loopback** address of the keyring machine:

```json
"admin_listen": "127.0.0.1:7702",
"admin_password_file": "/Library/Application Support/keyring/admin.pw"
```

Set the password as root with `keyring admin-password --config rules.json`. It asks twice, needs at least 12 characters, and stores only a PBKDF2-SHA256 hash, root-owned and mode 640, in a directory only root can change (it refuses any other). Reload with SIGHUP to apply it; that ends every session. Then open `http://127.0.0.1:7702` in a browser on that machine.

Safety:
- The dashboard listener only accepts a loopback address, and never serves the proxy. The proxy listener never serves the dashboard.
- Requests with a `Host` other than the listener's address are refused, against DNS rebinding.
- Every change needs a same-origin `Origin` header and the session's CSRF token.
- Sessions are in memory only: `HttpOnly`, `SameSite=Strict`, 30 minutes idle, 8 hours at most.
- Every change to keys or access asks for the password, however recently you logged in. Browsers send the session cookie to every port of `127.0.0.1`, so any other local web page you open could get it; with the cookie alone it can only look at names and usage.
- Failed passwords (at login or on a change) are slowed after 5 and locked for an hour after 20. Attempts sent at once count too.
- Every login, logout, password change and failed password is written to the audit log without secrets.

The pages are one column and work on a phone; they follow the system's light or dark mode.

The **Keys** page (`/keys`) lists every key the access file names or the store holds: its services, how many agents use it, status, last use and calls today. A value is never shown, not even in part.
- **Add key** asks for a name and a value only. The key works as soon as a service names it.
- **Connect to a service** on a key's page adds the service that uses it. The API is guessed from the key's name (`OPENROUTER_API_KEY` is OpenRouter, `vCF_TOKEN` is Cloudflare), with the base URL, how the key is sent and a test request filled in from a built-in list; pick another, or "Other" and fill in the fields. An agent that works out the settings can hand them over as JSON to paste: `{"service":"acme","base":"https://api.acme.com","auth":"header","header":"X-Api-Key","test_path":"/v1/ping"}` (unknown fields are refused). The whole access list is checked before anything is written.
- **Test** sends the service's test request and stores only the result (working, or failing with the HTTP status), never the reply. A result is dropped if the key was replaced or deleted while the test ran. Test is the one action that does not ask for the password: it changes nothing but the stored result.
- **Replace** takes effect at once; it clears the leaked flag and the test result.
- **Mark as leaked** flags the key until it is replaced.
- **Delete** asks for a tick when a role still uses the key; its calls then answer 503.
- Add, replace, mark as leaked and delete ask for the password every time. They work only on keys the page lists.

Test results and leaked flags are in `keymeta.json` next to the store (mode 600, no values). Every change is written to the audit log with the key name, never the value.

**Access requests.** An agent asks instead of the owner typing grants: `keyring request --upstream http://<keyring>:7701 --role NAME --service S [--service S ...] [--note TEXT] [--new /etc/keyring/tokens]`. With `--new` (a new agent) it makes the role's token in that directory if missing and sends only its SHA-256. The request goes to `POST /_keyring/requests` on the keyring's own listener, so only `allow_sources` can file one. It is checked (known services; a fingerprint exactly for a new agent; no token reuse), kept in `requests.json` next to the store (at most 20 pending, duplicates merged) and **grants nothing** until the owner taps Approve (with the password) at the top of the Agents page. Approving gives full access (every method and path, no limit) to the services asked for; Decline drops it. Both are audited.

The **Agents** page (`/access`) shows each agent with the services it may use: the methods, today's calls and the daily limit. Calls today count every attempt, refused ones too; the limit counts only calls that went out. "Add a service…" lists the services it may not use yet.
- **Open a service** to switch access on or off. A service not granted yet opens as full access (every method and path, no limit); "Limit access" sets the methods (read only, full, or a custom list), the allowed paths, the daily limit and an end date (UTC). A refused change leaves the access file as it was.
- **Add agent** makes a role with no access and shows its token once, with a copy button and the file it belongs in on the calling machine. Only the token's SHA-256 is kept.
- **New token** on an agent's page shows a new token once; the old one stops working at once. Sending the form twice (reloading the result page) does not replace the token again.
- **Revoke** removes the agent after a tick; its calls fail at once (401).
- Every change asks for the password and takes effect on the next call. The dashboard edits the access file on disk, so hand edits made since the last reload are kept, and applied.

## Relay on the agent server (step 2)

The relay listens only on loopback, holds one token per role (never an API key), and forwards to the keyring over the tailnet:

```sh
keyring relay --listen 127.0.0.1:7700 --upstream http://192.0.2.10:7701 --tokens /etc/keyring/tokens
```

`/etc/keyring/tokens` must be a real directory (not a symlink), owned by the relay's user, mode 700, inside a parent that only that user can write (for example root-owned `/etc/keyring`). Each `<role>.token` file must be a regular file owned by that user, mode 600. A call picks its role in the path:

```sh
curl http://127.0.0.1:7700/phobos/openrouter/api/v1/models
# SDKs: set the base URL to http://127.0.0.1:7700/<role>/openrouter/api/v1 and any placeholder key
curl http://127.0.0.1:7700/_relay/health       # is the keyring reachable?
```

The relay replaces any caller-supplied role token with the role's own. It refuses plain http except to a tailnet or loopback address. If the keyring is unreachable, calls fail with 502 `keyring unreachable ... never fall back to local keys`. Install steps are in `deploy/keyring-relay.service`.
