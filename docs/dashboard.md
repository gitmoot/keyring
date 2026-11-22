# Dashboard

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

The **Activity** page (`/activity`) searches the audit log, read-only, so the owner can see who did what without a terminal or `sudo`: a UTC time window by the minute (default: the last hour; the end minute is included), and optionally a service, an agent and text the path contains. It lists each matching call (time, agent, service, method and path, status, source address, note) and dashboard event, newest first, at most 500 (narrow the search for more). It shows only what the audit log holds: no key values, no query strings. The log is streamed, never loaded whole.

**Agents searching the audit log.** The owner can allow an agent to run the same search (off by default; agent's page, "Allow audit search", with the password; stored as `"audit_read": true` on the role). The agent calls `GET /_keyring/audit` on the keyring with its role token (through a relay: `http://127.0.0.1:7700/<role>/_keyring/audit`) with `from` and `to` (UTC minutes such as `2026-11-15T16:39`, the end minute included, or RFC 3339; default the last hour), and optionally `service`, `role` and `path` (contains). It gets JSON `{"from","to","rows":[...],"more","limit"}`. It sees every agent's calls and dashboard events, never key values or query strings. One search runs at a time (another gets 429); each search is itself audited. Without the grant the answer is 403.

The **Keys** page (`/keys`) is a table of every key the access file names or the store holds: key, API, status, the agents with access (with a dot: full or limited access), last use, calls today, calls over the last 7 days, and when the value was last added or replaced here. Filters above it show only working, failing, untested, leaked, missing or unused keys. Values are not shown in the table; a key's page can show its value on request (below).
- **Show value** (a key's page) shows the stored value, or each named value, after
  the dashboard password, with a Copy button. It is the answer to that one request:
  never in a URL, a log or a cached page, and the audit log records `key_revealed`
  with the key name, never the value. It works for every key, including .p8 and other
  private keys, from anywhere the dashboard is reachable. A single-line value that holds
  a non-ASCII character (often an invisible one from copying, such as U+200B) is flagged
  with its code point and position, and so is a value wrapped in quotes; nothing is changed.
- **Upload key file** (Keys page) stores a key that comes as a file, such as an Apple
  `.p8` or a `.pem` private key, from the browser: name, file, and the dashboard
  password, with Replace ticked to overwrite an existing name. It is stored exactly
  like `keyring set --file`. A PEM file must hold one usable, unencrypted private key; a
  `.p8` must be the EC P-256 key Apple issues; public keys, certificates and broken
  files are refused before anything is stored. Other text files are stored as they are.
  The file is read in memory (the request is capped at 64 KiB) and not shown back;
  the key's page shows its kind and a short public-key fingerprint, the audit log
  records name, kind and fingerprint, and for an Apple key the Connect form offers the
  APNs and Sign in with Apple settings to paste.
- **Add key** asks for a name and one or more values, one per row (up to 32; the form starts with four rows and **Add another value** adds more; without the page script, add the key and then add values on its page). Each row has an optional label (free text, at most 80 characters, shown next to the value) and an optional value name. One value without a name is the key's plain value (`API_KEY`); several are numbered `1`, `2`, `3` (`CLAUDE_KEYS.1`, …) unless named (`MODAL.id`, `MODAL.secret`). A number is never given twice, even after its value is removed. The key works as soon as a service names it. Space, tab or line breaks around a pasted value are removed; a value with a line break or control character inside it is refused, because such a key cannot be sent in a header. `keyring set --file` keeps the value exactly (a multi-line private key is legitimate), so a key imported that way with a stray trailing newline is caught by the proxy check above. A key has either one plain value or several numbered or named values, never both.
- **Connect to a service** on a key's page adds the service that uses it. The API is guessed from the key's name (`OPENROUTER_API_KEY` is OpenRouter, `vCF_TOKEN` is Cloudflare), with the base URL, how the key is sent and a test request filled in from a built-in list; pick another, or "Other" and fill in the fields. An agent that works out the settings can hand them over as JSON to paste: `{"service":"acme","base":"https://api.acme.com","auth":"header","header":"X-Api-Key","test_path":"/v1/ping"}` (unknown fields are refused); add `"tls_pin_sha256"` for a pinned self-signed service. The whole access list is checked before anything is written.
- **Edit a service** (`/services/<name>`, reached from the service chip on a key's page): change its key, base URL, how the key is sent, header or parameter, test request, pinned certificate, project and whether the agent's name is sent ([`forward_role`](proxy.md)), in the same fields as Connect or from the same pasted JSON. Agents keep their access, with the same methods, paths and limits, so a wrong base URL or key is fixed without deleting the service and asking again. The password is asked, the whole access list is checked before anything is written, and the change is audit-logged as `service_edited` with the names of the settings that changed, never their values. The key may be changed to any listed key; the service name cannot be changed. Pasted JSON replaces every field the form shows (leave out `fixed_headers` to remove them); extra credential header names are shown but their values are never. For an OAuth service the form shows its client ID, token URL and client secret key instead of how the key is sent. Sign-only, Google and egress-proxy services are not edited here because they carry settings the form does not show: change those in `access.json`.
- **Test** sends the service's test request and stores only the result (working, or failing with the HTTP status), never the reply. A result is dropped if the key was replaced or deleted while the test ran. Test is the one action that does not ask for the password: it changes nothing but the stored result.
- **Replace** takes effect at once; it clears the leaked flag and the test result. It trims and checks the new value the same way Add does. On a key with several values it asks which value to replace.
- **Add a value** adds one more value, last in the key's list, numbered unless named, with an optional label. On a key with one plain value both are numbered: `KEY` becomes `KEY.1` and the new one `KEY.2`, and every service that used `KEY` (as its key, an extra header or an OAuth client secret) is changed to `KEY.1` in the same step and keeps working.
- **Order and labels** lists the values in order with their labels. **Move up** moves a value one place up; a [key pool](proxy.md#key-pools-several-keys-behind-one-service) tries the values in this order. **Label** sets or clears a value's label.
- **Rename** renames the key (all its values move: `MODAL.id` becomes `NEW.id`) or one of its values (`MODAL.secret` becomes `MODAL.token`). Every reference in `access.json` follows, agents keep their access, and the key's test result and dates move with it. A name already in use, or not a valid name, is refused. A key pool's counts and set-aside state for the renamed values start over (they are kept in memory by value name).
- **Remove value** (under Leaked or no longer needed, a key with several values) deletes one value. A value a service sends as its key or an extra header is kept; a key pool names the key, so a pooled value can be removed and the pool stops using it. The key's last value is removed with Delete instead.
- Opening `/keys/<name>/connect` in the browser shows the key's page, where the Connect form is. On that form, **Settings** stay closed unless a connect was refused; the pasted-settings box is unchanged.
- **Mark as leaked** flags the key until it is replaced.
- Under **Leaked or no longer needed**, **Delete value only** keeps the service settings: the key stays listed as missing and its calls answer 503.
- **Remove completely** deletes the key's stored value and notes, every service that references it, and those services' grants from all agents. The form lists the services that will be removed. It also works when the value was already deleted, so the empty row goes away and stays gone after reload. Other keys and agents are kept; a service using several credentials may leave its other keys listed for separate removal. This removes the key from this keyring, not from the provider's account.
- Both deletion choices ask for a tick when a role still uses the key. Add, replace, rename, add, label, move or remove a value, mark as leaked and delete ask for the password every time, and are audit-logged with names only (`key_renamed`, `key_value_added`, `key_value_labelled`, `key_value_moved`, `key_value_renamed`, `key_value_removed`). They work only on keys the page lists.

Test results and leaked flags are in `keymeta.json` next to the store (mode 600, no values). Every change is written to the audit log with the key name, never the value.

**Access requests.** An agent asks instead of the owner typing grants: `keyring request --upstream http://<keyring>:7701 --role NAME --service S [--service S ...] [--project P ...] [--note TEXT] [--new /etc/keyring/tokens]` (`--project` asks for a whole project; see Projects). With `--new` (a new agent) it makes the role's token in that directory if missing and sends only its SHA-256. The request goes to `POST /_keyring/requests` on the keyring's own listener, so only `allow_sources` can file one. It is checked (known services; a fingerprint exactly for a new agent; no token reuse), kept in `requests.json` next to the store (at most 20 pending, duplicates merged) and **grants nothing** until the owner taps Approve (with the password) at the top of the Agents page. Approving gives full access (every method and path, no limit) to the services asked for; Decline drops it. Both are audited.

The **Agents** page (`/access`) is a table of agents: the APIs each may use (green: full access, amber: limited; after six, "+N more"), calls today, last call and end date. Click an API to change that access, or "Edit access" for the agent's page, where "Add a service…" lists the APIs it may not use yet. Calls today count every attempt, refused ones too; a daily limit counts only calls that went out.
- **Open a service** to switch access on or off. A service not granted yet opens as full access (every method and path, no limit); "Limit access" sets the methods (read only, full, or a custom list), the allowed paths, the daily limit and an end date (UTC). A refused change leaves the access file as it was.
- **Add agent** makes a role with no access and shows its token once, with a copy button and the file it belongs in on the calling machine. Only the token's SHA-256 is kept.
- **New token** on an agent's page shows a new token once; the old one stops working at once. Sending the form twice (reloading the result page) does not replace the token again.
- **Revoke** removes the agent after a tick; its calls fail at once (401).
- Every change asks for the password and takes effect on the next call. The dashboard edits the access file on disk, so hand edits made since the last reload are kept, and applied.
