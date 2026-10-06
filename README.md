# keyring

Keeps API keys on a separate machine. Agents call APIs **through** the keyring,
so a key never reaches the machine where agents run.

Apple Ads and App Store Connect also support **sign-only** access: the Mac
signs a short-lived JWT while the private key stays in the keyring. They use
separate services, identities, keys and role grants.

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

### Apple Ads signing (not an API proxy)

Configure this service in the access file; these three identifiers are public,
fixed configuration, never caller-supplied claims:

```json
{
  "services": {
    "apple-ads": {
      "key": "APPLE_ADS_PRIVATE_KEY",
      "auth": "apple-ads-sign",
      "apple_ads": {
        "client_id": "SEARCHADS.your-client-id",
        "team_id": "YOUR_TEAM_ID",
        "key_id": "YOUR_KEY_ID"
      }
    }
  }
}
```

Merge it into the existing access file; do not replace existing roles or services.
Store the full unencrypted P-256 PEM under `APPLE_ADS_PRIVATE_KEY` with the
bounded, non-echoing `keyring set --file` import described in
[the Mac operator instructions](deploy/mac/README.md#apple-ads-signing-upgrade-and-key-import).
PKCS#8 `PRIVATE KEY` and SEC1 `EC PRIVATE KEY` encodings are supported.
`base`, `header`, `param`, `test_method`, and `test_path` must be absent.
No other service may share this signing key, and no other service name may
use `apple-ads-sign`. Dashboard access edits preserve its identity; dashboard
**Test** is unavailable because this service has no upstream.

A separately approved role needs `POST` permission on service `apple-ads` path
`/`, for example `"apple-ads": {"methods":["POST"],"paths":["/"]}` inside that
role's `access` map. Its token, allowed source, role/service expiry, daily
request limit and audit checks apply as for proxy calls.

Call `POST /_keyring/sign/apple-ads` on the keyring with `X-Keyring-Token`, or
`POST /<role>/_keyring/sign/apple-ads` through the loopback relay. The request
must have **zero body bytes** (not even `{}` or whitespace), no query string
(not even a bare `?`), and the exact unencoded path. The caller config is
`APPLE_ADS_SIGN_URL=http://127.0.0.1:7700/<role>/_keyring/sign/apple-ads`.
The relay supplies the role token; never put it in that URL.

The JSON response is `{"token":"<JWT>","expires_at":"<RFC3339 UTC time>"}`
with `Cache-Control: no-store`. Its ES256 header uses the fixed key ID.
Claims are `iss=team_id`, `sub=client_id`,
`aud=https://appleid.apple.com`, `iat=server time`, and `exp` at most
20 minutes later and no later than either access expiry. Expiry is rounded
down to whole seconds; if no positive validity window remains, signing fails.
The caller retains its public client ID and exchanges the JWT at
`https://appleid.apple.com/auth/oauth2/token` with
`grant_type=client_credentials`, `scope=searchadsorg`, `client_id` and
`client_secret=<JWT>`. There is no private-key fallback.

Missing, malformed, encrypted or non-P-256 keys fail closed with a generic
503; claims/body/query errors never reach a signer. Wrong methods, expired or
unauthorized roles/access, proxy requests to `/apple-ads/...`, and dashboard
Test requests cannot send the PEM upstream. Neither PEM, JWT nor caller body
is written to audit. Tokens themselves remain sensitive and must not be logged.

**Scope warning:** a signing grant lets its holder obtain an Apple OAuth token
with the underlying key's Apple privileges. Keyring methods/paths restrict
signing, **not subsequent direct Apple API requests**. The 20-minute JWT bound
does not shorten Apple's approximately one-hour OAuth token lifetime, and
revoking a role does not revoke already issued Apple tokens. A sign-only role
is not an Apple read-only scope. Existing campaign holds remain operational
requirements. An Apple Ads grant does not authorize App Store Connect signing.

### App Store Connect signing

App Store Connect uses a separate P-256 API key and issuer, not the Apple Ads
client identity. Configure the fixed public identity in the access file:

```json
{
  "services": {
    "appstoreconnect": {
      "key": "APP_STORE_CONNECT_PRIVATE_KEY",
      "auth": "app-store-connect-sign",
      "app_store_connect": {
        "issuer_id": "YOUR_APP_STORE_CONNECT_ISSUER_ID",
        "key_id": "YOUR_APP_STORE_CONNECT_KEY_ID"
      }
    }
  }
}
```

Import the private key only on the Mac using the protected-file procedure in
[the Mac deployment guide](deploy/mac/README.md#app-store-connect-signing).
Grant an approved role `POST` on this service's `/` path. A temporary release
grant should have an explicit expiry and request limit. Neither an Apple Ads
grant nor a proxy grant permits this signer.

The caller sends an empty `POST` through its loopback relay to
`/<role>/_keyring/sign/appstoreconnect`. The keyring route is
`/_keyring/sign/appstoreconnect`. As with Apple Ads, request bodies, query
strings and encoded paths are refused; no caller supplies JWT claims.
The `no-store` JSON response contains `token` and `expires_at`.

The token has an ES256 header with the configured `kid`, and fixed claims:
`iss=issuer_id`, `aud=appstoreconnect-v1`, `iat=server time`, and `exp` at most
20 minutes later, further bounded by the role and grant expiry. It has no
Apple Ads `sub` claim. Use this token as `Authorization: Bearer <token>` in
direct calls to `https://api.appstoreconnect.apple.com`; there is no OAuth
exchange. Refresh it by requesting another signature, never by loading a
private key locally. Keep tokens out of command arguments, logs and receipts.

**Signing authority is not API path authority.** This grants the underlying
key's Apple permissions, not access to one app or a read-only Apple scope.
Keyring path/method rules restrict token issuance, not subsequent Apple API
calls. Removing a grant stops new signatures; already issued App Store
tokens remain usable until expiry. No `base`, proxy/test settings, mixed
Apple identities, or key reuse by another service are allowed. Dashboard
Test remains unavailable so it cannot send a PEM upstream.


A Docker caller needs a separate relay sharing its loopback network namespace;
`127.0.0.1` in a container is not host loopback. Keep role-token files only in
the relay, and do not deploy or grant another role without owner approval.

Build the token-only relay image from the reviewed keyring checkout:

```sh
docker build -f deploy/relay.Dockerfile --build-arg VERSION=REVIEWED_RELEASE \
  -t keyring-relay:REVIEWED_RELEASE .
```

Replace `REVIEWED_RELEASE` with the release being installed; the build uses
this checkout's source, not a downloaded binary. The image includes a static
keyring and CA bundle, runs as UID/GID `65532:65532`, and its entrypoint is
`/usr/local/bin/keyring relay`. Supply the flags
`--listen 127.0.0.1:7700 --upstream https://KEYRING_HOST:7701 --tokens /run/keyring/tokens`
(use the existing approved upstream URL and scheme, not a guessed address).
Mount only the caller's role-token directory read-only, owned by UID 65532,
directory mode 0700 and token mode 0600. It contains no Apple private key.
The image pre-creates `/run/keyring` owned by UID 65532: the relay checks
ownership of both the token directory and its parent before starting.
Join the caller's network namespace instead of publishing relay ports.
Building this image does not deploy it or authorize a role.


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

The Keys and Agents pages are sortable tables (click a column); forms are one column. Everything works on a phone (the tables scroll sideways with the name column pinned) and follows the system's light or dark mode.

The **Keys** page (`/keys`) is a table of every key the access file names or the store holds: key, API, status, the agents with access (green: full access, amber: limited), last use, calls today, calls over the last 7 days, and when the value was last added or replaced here. Filters above it show only working, failing, untested, leaked, missing or unused keys. A value is never shown, not even in part.
- **Add key** asks for a name and a value only. The key works as soon as a service names it.
- **Connect to a service** on a key's page adds the service that uses it. The API is guessed from the key's name (`OPENROUTER_API_KEY` is OpenRouter, `vCF_TOKEN` is Cloudflare), with the base URL, how the key is sent and a test request filled in from a built-in list; pick another, or "Other" and fill in the fields. An agent that works out the settings can hand them over as JSON to paste: `{"service":"acme","base":"https://api.acme.com","auth":"header","header":"X-Api-Key","test_path":"/v1/ping"}` (unknown fields are refused). The whole access list is checked before anything is written.
- **Test** sends the service's test request and stores only the result (working, or failing with the HTTP status), never the reply. A result is dropped if the key was replaced or deleted while the test ran. Test is the one action that does not ask for the password: it changes nothing but the stored result.
- **Replace** takes effect at once; it clears the leaked flag and the test result.
- **Mark as leaked** flags the key until it is replaced.
- **Delete** asks for a tick when a role still uses the key; its calls then answer 503.
- Add, replace, mark as leaked and delete ask for the password every time. They work only on keys the page lists.

Test results and leaked flags are in `keymeta.json` next to the store (mode 600, no values). Every change is written to the audit log with the key name, never the value.

**Access requests.** An agent asks instead of the owner typing grants: `keyring request --upstream http://<keyring>:7701 --role NAME --service S [--service S ...] [--note TEXT] [--new /etc/keyring/tokens]`. With `--new` (a new agent) it makes the role's token in that directory if missing and sends only its SHA-256. The request goes to `POST /_keyring/requests` on the keyring's own listener, so only `allow_sources` can file one. It is checked (known services; a fingerprint exactly for a new agent; no token reuse), kept in `requests.json` next to the store (at most 20 pending, duplicates merged) and **grants nothing** until the owner taps Approve (with the password) at the top of the Agents page. Approving gives full access (every method and path, no limit) to the services asked for; Decline drops it. Both are audited.

The **Agents** page (`/access`) is a table of agents: the APIs each may use (green: full access, amber: limited; after six, "+N more"), calls today, last call and end date. Click an API to change that access, or "Edit access" for the agent's page, where "Add a service…" lists the APIs it may not use yet. Calls today count every attempt, refused ones too; a daily limit counts only calls that went out.
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
