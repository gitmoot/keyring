# Personal and business Google accounts through gcloud (host only)

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
POST/PATCH writes. The next call mints a new token. Because gcloud can keep
minting tokens that Google refuses (for example "Active session is invalid"
after the account signed out everywhere), a 401 also marks the account refused:
the dashboard status reads "Google refused the gcloud token (HTTP 401); run
gcloud auth login for this account" until Google accepts a call again. Nothing
is deleted and the 401 alone is not treated as a login requirement. Only a
confirmed reauthentication requirement asks the owner
to sign in; runtime, network and unknown failures must not be treated as login
problems. Host logout alone does not erase an already minted in-memory access
token: revoke the role first to stop new proxy calls immediately, then perform
owner-approved logout and remove/reload the host binding. Historical audit
records remain.

Provider support alone is not proof of live two-account or Shared Drive access;
complete that acceptance with owner-authorized fixtures and readback.

## Google renewal diagnosis and recovery

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
[keyring#68](https://github.com/gitmoot/keyring/issues/68).
