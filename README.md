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
`base`, `header`, `param`, `test_method`, `test_path`, and `tls_pin_sha256` must be absent.
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

A service with its own self-signed certificate (such as macserve on the Mac Studio) can be trusted by pinning that certificate: `"tls_pin_sha256": "<64 lowercase hex>"`, the SHA-256 of the leaf certificate's DER bytes (`openssl x509 -in cert.pem -outform der | shasum -a 256`). The keyring then accepts exactly that certificate for that service, on every handshake including resumed sessions, and skips the system CA roots, hostname and expiry checks for it; a different certificate is refused with 502 "upstream certificate does not match the pinned certificate". Only `https` bases may carry a pin, and a malformed pin is refused when the file loads. Services without a pin keep using the system CA roots. When the upstream's certificate is renewed, update the pin.

### OAuth services with refresh tokens

Google (Gmail, Drive, Sheets, Calendar) and similar APIs give a long-lived refresh token and access tokens that expire after about an hour. A service with `"auth": "oauth2"` stores the refresh token under its `key`; the keyring mints access tokens from it and sends `Authorization: Bearer <access token>`:

```json
"gmail": {
  "base": "https://gmail.googleapis.com", "key": "GMAIL_REFRESH_TOKEN", "auth": "oauth2",
  "test_path": "/gmail/v1/users/me/profile",
  "oauth2": {"token_url": "https://oauth2.googleapis.com/token", "client_id": "<id>.apps.googleusercontent.com", "client_secret_key": "GOOGLE_CLIENT_SECRET"}
}
```

- `client_id` is public configuration. `client_secret_key` names the store key holding the client secret; leave it out for a public client. `token_url` must be `https` (plain `http` only to a loopback test server).
- The refresh token and client secret go only to `token_url`, never to the API, and are masked like a key if the API echoes them. Access tokens are cached in memory only, never written to the store or the log, and replaced a minute before they expire (or after 10 minutes if the provider gives no lifetime). Concurrent calls share one refresh.
- If the API answers 401, the cached access token is dropped and the next call mints a new one.
- A refresh that the provider refuses (`invalid_grant`, `invalid_client`, `unauthorized_client`: revoked or expired consent) fails closed with 503 and a message to connect the account again; other refresh failures give 502. Nothing else is tried, the call does not count against the daily limit, and the token endpoint is asked again only after 10 seconds. The dashboard shows the key as failing with the reason until a refresh works.
- Several services can share one refresh token (one Google login for Gmail and Drive) only if they are all `oauth2` with the same `oauth2` settings. A refresh token or client secret can never be the key of a service that sends its key upstream.
- Per-role paths, methods, daily limits and expiry apply as for any service. Replacing the refresh token (dashboard or `keyring set` and `SIGHUP`) stops use of tokens minted from the old one.

To get the refresh token, store it with `keyring set` or the dashboard, or let the account's owner sign in through a consent link (next section).

### Personal and business Google accounts through gcloud (host only)

`auth: "gcloud"` uses the Google CLI's own login and token minting. It needs
no manually created OAuth app. Keyring never reads gcloud refresh tokens or
reuses its OAuth client identity. Install gcloud on the **Keyring host**, not
on an agent using the relay. This mode is unavailable in per-person containers.

Each account has a separate private gcloud directory and an explicit email.
After the owner approves setup, sign in **as the Keyring service user** with
the fixed gcloud executable, for each account:

```sh
CLOUDSDK_CONFIG=/private/keyring/google-personal /absolute/path/to/gcloud \
  auth login personal@example.com --configuration=default --enable-gdrive-access
```

The directory must already be private (0700), accessible only to that service
user and the host administrator. Use another directory for the business
account. Follow Google's browser login; do not copy credentials from an agent,
extract refresh tokens, or change existing personal login state. Account access
to a Shared Drive must be granted separately by its owner.

Add the bindings to **root-owned rules.json**, not access.json:

```json
"google_accounts": {
  "personal": {
    "executable": "/absolute/path/to/gcloud",
    "config_dir": "/private/keyring/google-personal",
    "account": "personal@example.com",
    "quota_project": "owner-approved-quota-project"
  },
  "business": {
    "executable": "/absolute/path/to/gcloud",
    "config_dir": "/private/keyring/google-business",
    "account": "business@example.com"
  }
}
```

`quota_project` is optional. When set it overrides `X-Goog-User-Project`;
otherwise the caller's header is preserved. The selected Google account must
have permission to use that quota project. Executable and configuration paths
are privileged host configuration: requests and dashboard forms cannot set them.
Keyring runs fixed argv, never a request-supplied shell command. Environment
credential overrides are not inherited. Google validates the returned token's
email and remaining lifetime before Keyring sends it upstream.

In access.json, configure separate service names and **separate role grants**
for each account. Example personal services (repeat with `business`):

```json
"google-personal-drive": {
  "base": "https://www.googleapis.com/drive/v3",
  "auth": "gcloud", "google_account": "personal"
},
"google-personal-upload": {
  "base": "https://www.googleapis.com/upload/drive/v3",
  "auth": "gcloud", "google_account": "personal"
},
"google-personal-sheets": {
  "base": "https://sheets.googleapis.com/v4",
  "auth": "gcloud", "google_account": "personal"
}
```

These services have **no `key` field**. Check the configuration and reload as
usual. Nothing grants an agent access just because the owner signed in.
Keep personal and business relay role tokens separate; grant only intended
service paths and methods. The dashboard shows account bindings, their service
names and the last credential status without exposing tokens. It is an
administrator dashboard, not a shared Google-data browser.

Relay requests use `/<role>/<service>/<path>`: Drive listing/downloads go to
the drive service (`/files`, `/files/ID?alt=media`), uploads to the upload service
(`/files?uploadType=...`), and Sheets to the sheets service (`/spreadsheets/...`).
Clients must validate and translate upload session URLs/redirects back through
the same account's relay services; never bypass the relay or fall back to a
local Google login. Shared Drive operations also require the relevant Google
API flags (`supportsAllDrives`, `includeItemsFromAllDrives`, `driveId`, `corpora`).
Google-account paths accept encoded spaces for Sheets A1 names such as
`'My Tab'!A1:append`; control characters, encoded separators, double encoding
and traversal remain rejected. Other authentication modes retain their existing
no-whitespace path rule.

For Drivekey's full operations, the approved grants need Drive paths `/about`,
`/files`, `/changes`, `/drives` with GET/POST; upload `/files` with POST/PATCH
(this client's resumable chunks use POST, replacement uses PATCH); and Sheets
`/spreadsheets` with GET/POST when using
batch reads/writes and append. Narrow these to the operations the role needs.

Renewal is single-flight per complete account binding, with a 30-second deadline
including command descendants, bounded output, and redacted failures. Tokens
are cached only until their verified expiry, with early renewal. Callers wait for
that renewal rather than continuing with the old token; this matches OAuth mode.
An in-flight renewal remains single-flight across configuration reloads, including
removing and re-adding the same binding. A failed renewal fails closed (502), with
the existing 10-second error-cache delay; **no background retry or diagnostic
probe runs**. It never uses another account or a stale token. An upstream 401
invalidates only the token used and is returned **without replay**, including
POST/PATCH writes. Only a confirmed reauthentication requirement asks the owner
to sign in; runtime, network and unknown failures must not be treated as login
problems. Host logout alone does not erase an already minted in-memory access
token: revoke the role first to stop new proxy calls immediately, then perform
owner-approved logout and remove/reload the host binding. Historical audit
records remain.

Drivekey's explicit relay-profile support is tracked in
[drivekey#14](https://github.com/jerryfane/drivekey/issues/14).
Provider support alone is not proof of live two-account or Shared Drive access;
complete that acceptance with owner-authorized fixtures and readback.

#### Google renewal diagnosis and recovery

A failed renewal retains the existing HTTP **502 / text/plain** response with
fixed, safe wording. Its machine-readable contract is exactly:

- `X-Keyring-Google-Cause`
- `X-Keyring-Google-Stage`: `configuration`, `command_start`, `command`, or
  `token_validation`
- `X-Keyring-Google-Recovery`

| Cause | Recovery | Next action |
|---|---|---|
| `reauth_required` | `owner_reauth` | Owner signs in to the affected account only. This does not establish a Workspace-policy cause. |
| `credentials_invalid` | `owner_review_credentials` | Review the rejected, expired, revoked or mismatched credential before choosing a repair. |
| `permission_denied` | `repair_host` | Inspect service-user access to the private configuration/runtime. |
| `configuration_error` | `repair_host` | Repair the existing private/default configuration. |
| `runtime_unavailable` | `repair_host` | Repair the installed executable or Python/SDK runtime. |
| `network_error` | `check_connectivity` | Inspect connectivity/TLS, not a new login. |
| `provider_error` | `inspect_provider` | Inspect the provider/token-validation failure, not a new login. |
| `timeout` | `inspect_host`, or `check_connectivity` at `token_validation` | Inspect the recorded stage's time-bound failure. |
| `output_limit` | `repair_host` | Inspect the installed command's excessive output. |
| `unknown` | `inspect_host` | Use the protected incident record; sign-in is not established as the remedy. |

Only the exact `reauth_required` + `owner_reauth` pair may prescribe sign-in.
Missing, invalid or inconsistent fields must never do so. No account identity,
email, raw error text, URL, code or token is included in these headers. Keyring
strips all three reserved headers, case-insensitively, from **every forwarded
upstream response**, regardless of service authentication or HTTP status.

The owner dashboard's **Host Google accounts** table shows the last diagnosis and
recent incident/recovery history; opening it does not run gcloud. Agents receive
only the diagnosis for a request their role is already authorized to make.
`google-renewals.json`, beside the host's key store, is written atomically at mode
0600 after each actual renewal attempt. It retains at most **64 complete account
bindings**, with **8 incidents per binding**; loading is limited to **1 MiB**.
Google account binding names are limited to **128 characters**. Configuration
validation rejects longer names rather than accepting an account whose history
cannot be retained.
Changing an account behind a reused label does not expose the old binding's
history. An insecure, oversized or corrupt history is not read or overwritten;
the owner dashboard warns if persistence is unavailable.

Records contain binding labels, a binding fingerprint, UTC first/last failure
and last-success times, fixed category/stage/evidence codes, exit and bound flags
when applicable, and recovery outcomes. Repeated identical failures update the
same incident; a changed diagnosis preserves the prior one. A successfully
validated renewal closes the active incident without deleting it. Raw command
stdout/stderr, credentials, auth URLs/codes, environments and token-info request
URLs are never retained. SDK/runtime versions are not inferred from error text;
use the host deployment record when available. No version or extra token command
is issued to obtain a diagnosis.

For **confirmed reauthentication only**, reuse the existing trusted wrapper,
service user, private directory and default configuration. For example, on a Mac
installed as `_keyring`, with the business binding below (use that binding's
actual configured email):

```sh
(cd / && sudo -u _keyring /usr/bin/env -i \
  PATH=/usr/local/libexec:/usr/bin:/bin \
  HOME='/Library/Application Support/keyring/google/business' \
  CLOUDSDK_CONFIG='/Library/Application Support/keyring/google/business' \
  CLOUDSDK_CORE_DISABLE_FILE_LOGGING=true \
  CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=true \
  CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true \
  CLOUDSDK_PYTHON_SITEPACKAGES=0 LANG=C.UTF-8 \
  /bin/sh -c 'set -eu; cd "$CLOUDSDK_CONFIG"; test -f configurations/config_default;
    /usr/local/libexec/keyring-gcloud auth login business@example.com \
      --account=business@example.com --configuration=default \
      --enable-gdrive-access --no-launch-browser --force --no-activate')
```

The initial `cd /` is **before sudo**, avoiding inaccessible-working-directory
warnings. `--force` starts fresh authorization; `--no-activate` preserves the
configured active account and project. Verify these flags against the installed
SDK before using them. Keep Google's URL and verification code in the owner's
Mac terminal/browser, never in chat or an incident record. Do not delete
credentials, change projects/grants, alter Google policy or start another
account's login as a repair. Reauthentication may recur; this feature does not
bypass Google consent or guarantee unattended renewal.

Provider/consumer integration and its exact contract are tracked in
[keyring#68](https://github.com/gitmoot/keyring/issues/68) and
[drivekey#18](https://github.com/jerryfane/drivekey/issues/18).



### Consent links (off by default)

A consent link lets the owner of an account connect it themselves: "tap here to connect Gmail", or paste a proxy or API key into a one-time page instead of a chat. Nothing changes unless `rules.json` has a `consent` block:

```json
"consent": {
  "listen": "127.0.0.1:7710",
  "public_url": "https://connect.example.com/p/alice",
  "api_listen": "127.0.0.1:7711",
  "api_allow_sources": ["127.0.0.1"],
  "api_token_sha256": "<from keyring new-token>"
}
```

- `listen` serves the link pages and the OAuth callback, and nothing else: not the proxy, the dashboard or the API. Put it behind an HTTPS reverse proxy at `public_url`, forwarding the path unchanged (the pages live under the path of `public_url`). `public_url` must be `https` (plain `http` only on loopback, for tests).
- `api_listen` serves the API, only to `api_allow_sources` and only with `Authorization: Bearer <API token>`. The API token is not a role token (the same token for both is refused). Each of the three listeners has its own address.
- A change to `consent` needs a restart; `SIGHUP` refuses it.

API:
- `POST /links` `{"service": "gmail", "ttl_seconds": 900, "label": "Alice"}` returns `{"url", "expires_at"}` (201). `ttl_seconds` is 60 to 3600 (default 900); the label (at most 100 characters) is shown on the page. Scopes, paths and keys cannot be set here: they come from the access file. Only `bearer`, `header` and `query` services, and `oauth2` services with an `auth_url`, can get a link; signing keys stay with the owner.
- `DELETE /keys/<service>` deletes the service's stored key. For an `oauth2` service with a `revoke_url`, the provider is asked to revoke the refresh token first (RFC 7009); the key is deleted even if that fails, and the reply says `"revoked": false`.

The link:
- Opening it changes nothing (chat apps fetch links for previews). The page's button (or form) uses it up. A link is used once, expires, names one service, and lives in memory only: a restart ends every open link.
- Posts must come from the page itself (`Origin` checked).
- Fixed key: the page has one password field; the value is stored under the service's key.
- OAuth: the button sends the person to `auth_url` with the code flow and PKCE (S256), the config's `scopes` and `auth_params`, a single-use `state`, and `redirect_uri` = `public_url` + `/callback` (register that with the provider). The browser that pressed the button gets an HttpOnly cookie; the callback is accepted only once, within 10 minutes, with that `state` and that cookie, and only if the service's `oauth2` settings did not change meanwhile. The keyring then trades the code for tokens and stores the refresh token. A reply without a refresh token is refused (Google needs `"auth_params": {"access_type": "offline", "prompt": "consent"}`).
- Consent pages send only their origin as referrer (`strict-origin`), never the capability-link path. This also preserves the browser's `Origin` header on form POSTs; missing, `null` and cross-origin submissions remain refused.

```json
"oauth2": {
  "token_url": "https://oauth2.googleapis.com/token", "client_id": "<id>.apps.googleusercontent.com", "client_secret_key": "GOOGLE_CLIENT_SECRET",
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
  "scopes": ["https://mail.google.com/"],
  "auth_params": {"access_type": "offline", "prompt": "consent"},
  "revoke_url": "https://oauth2.googleapis.com/revoke"
}
```

The audit log records links created, sign-ins started, connections, failures and deletions, never a value, code, token, link or state. A link connects whoever opens it to this keyring: a forwarded link connects the wrong account. Keep links short-lived and send them only to the person they are for.

### Instance mode: one small keyring per person

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

### Egress proxy tunnels: a person's own proxy (off by default)

An `egress-proxy` service lets an agent's traffic go out through a person's own proxy. The keyring holds the proxy credential (`user:password`, for example stored through a consent link), and it is never returned to anyone.

```json
"myproxy": {"key": "PROXY_CREDENTIAL", "auth": "egress-proxy",
  "egress_proxy": {"type": "http-connect", "address": "proxy.example.net:8080", "tls": false, "ports": [443], "idle_seconds": 300, "max_seconds": 3600}}
```

- `type` is `http-connect` (CONNECT with `Proxy-Authorization: Basic`, optionally over TLS with `"tls": true`) or `socks5` (username and password).
- **The person can paste the whole proxy.** Leave `address` (and optionally `type`) out of the config: the consent page has one password box for `username:password@host:port`. Without a scheme, the type dropdown applies (HTTP by default); an optional `http://`, `https://` or `socks5://` prefix selects the type, subject to any configured type/TLS restriction. Credentials are required, as before; bare `host:port` is rejected. Passwords may contain `@` and `:`: the parser splits at the last `@` and the first credential colon. Paste credentials literally, not URL-encoded; the stored URL is encoded by `policy.ProxyURL`. The form never repeats the pasted value, and errors name the invalid part without quoting it. A new link replaces the address and credential together; deleting the key removes both. Public-IP/DNS address checks run on save and before every tunnel, including DNS resolution checks against private addresses. With `address` fixed in config, the form still asks only for username and password and cannot replace the configured endpoint.
- The service has no `base` and serves only `/<service>/_tunnel?host=H&port=P`. On every other service `/_tunnel` is an ordinary path and is forwarded as before. The request must be a WebSocket upgrade (RFC 6455, no subprotocol). The keyring connects through the proxy first, then answers 101. After that, binary frames carry the raw TCP bytes both ways.
- `host` is a name, passed to the proxy unresolved so the person's proxy does the DNS lookup, or a public IP. Private, loopback, link-local, CGNAT (including Tailscale's 100.64.0.0/10), reserved, IPv6 outside global unicast 2000::/3 (so IPv4-compatible, SIIT and unique-local forms) and IPv4-carrying global ranges (NAT64, 6to4, Teredo), and any address with a zone (`%eth0`), are refused with 403, as is a port not in `ports` (default `[443]`).
- Before the upgrade, errors are plain HTTP: 400 bad target or no upgrade; 401 token; 403 access, destination or port; 429 daily limit; 503 no credential stored; 502 proxy unreachable or refused (wrong credential). A failed tunnel does not count against `daily_requests`.
- After the upgrade, close codes are: 1000 normal, 1002 protocol error (unmasked frame, RSV bits, bad fragmentation, control frame over 125 bytes), 1003 text frame, 1008 `daily_bytes` reached, 1009 frame over 1 MiB, 1011 upstream error, 4000 idle (`idle_seconds`, default 300), 4001 `max_seconds` (default 3600). Each write to the client has a 30-second deadline, so a client that stops reading cannot hold a tunnel open.
- Per role: `daily_requests` counts tunnels, and `daily_bytes` (egress-proxy only) counts bytes both ways. Both are in an instance's `GET /usage` and are restored on unlock. The audit has one line per tunnel: role, service, `host:port`, close code, bytes up and down, and duration. It never holds the credential or tunnel contents.

### Ed25519 signing (not an API proxy)

For artifacts that need a signature without the key leaving this process — the
first use is adspower-desk update manifests. A sign-only service with
`"auth": "ed25519-sign"` holds the base64 of a 64-byte Ed25519 private key
(Go's `ed25519.PrivateKey`: seed || public key). It takes no base, no identity
fields and no test path, and may not share a key with any other service.

`POST /<role>/<service>` where the path is exactly `/_keyring/sign/<service>`
— the service is in the path, so one access rule controls one key. Body:
`{"message_base64": "<base64 bytes to sign, 1-8192 bytes>"}`. Reply:
`{"signature_base64": "...", "public_key_base64": "..."}`, `Cache-Control:
no-store`. Malformed bodies 400, missing access or a non-sign service 403, a
key that is not a base64 64-byte key 503. The Apple paths still take their
fixed services; this route covers every other sign-only service.

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
- **Connect to a service** on a key's page adds the service that uses it. The API is guessed from the key's name (`OPENROUTER_API_KEY` is OpenRouter, `vCF_TOKEN` is Cloudflare), with the base URL, how the key is sent and a test request filled in from a built-in list; pick another, or "Other" and fill in the fields. An agent that works out the settings can hand them over as JSON to paste: `{"service":"acme","base":"https://api.acme.com","auth":"header","header":"X-Api-Key","test_path":"/v1/ping"}` (unknown fields are refused); add `"tls_pin_sha256"` for a pinned self-signed service. The whole access list is checked before anything is written.
- **Test** sends the service's test request and stores only the result (working, or failing with the HTTP status), never the reply. A result is dropped if the key was replaced or deleted while the test ran. Test is the one action that does not ask for the password: it changes nothing but the stored result.
- **Replace** takes effect at once; it clears the leaked flag and the test result.
- **Mark as leaked** flags the key until it is replaced.
- Under **Leaked or no longer needed**, **Delete value only** keeps the service settings: the key stays listed as missing and its calls answer 503.
- **Remove completely** deletes the key's stored value and notes, every service that references it, and those services' grants from all agents. The form lists the services that will be removed. It also works when the value was already deleted, so the empty row goes away and stays gone after reload. Other keys and agents are kept; a service using several credentials may leave its other keys listed for separate removal. This removes the key from this keyring, not from the provider's account.
- Both deletion choices ask for a tick when a role still uses the key. Add, replace, mark as leaked and delete ask for the password every time. They work only on keys the page lists.

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
