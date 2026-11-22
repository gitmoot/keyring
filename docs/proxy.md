# Proxy: services and calls

What the keyring does with each call, and the service settings that shape it.

A call is `<METHOD> http://<listen>/<service>/<path>` with header `X-Keyring-Token: <role token>`. The keyring:
- accepts a path only in a plain form: printable ASCII after one decode, with no `..` or `.` segment, no `;`, no `%` left (double encoding), and no encoded `/`, `.` or `\`. It forwards the path it checked, escaped again, not the caller's raw text;
- drops the caller's `Authorization`, `Cookie` and role token, and every casing of the key's header or query parameter, then adds the key. The one exception is a Cloudflare Worker static-asset upload, `POST /accounts/<32 lowercase hex>/workers/assets/upload`, on a `bearer` service whose base is `https://api.cloudflare.com/client/v4`: that call is authenticated by a short-lived upload token Cloudflare returned earlier in the same `wrangler deploy`, so the keyring forwards the caller's own single `Authorization: Bearer <token>` and does not send the account token. A call to it without one is refused (401) and not counted. The role still needs access to that path, and the account token is still masked in replies;
- drops inbound edge metadata: `CF-Connecting-IP`, `CF-Connecting-IPv6`, `CF-IPCountry`, `CF-Ray`, `CF-Visitor`, `CF-EW-Via`, `CF-Pseudo-IPv4`, `CDN-Loop`, `True-Client-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Real-IP`. This avoids Cloudflare Error 1000 at upstream services. Other `CF-*` headers are not blanket-blocked; configured `CF-Access-Client-*` credentials still work;
- does not follow redirects;
- replaces an echoed key with `[REDACTED]`, in headers and bodies, as sent, URL-encoded (either hex case), or with JSON-escaped slashes, even when split across chunks;
- refuses (502) a reply compressed with anything other than gzip, which it decodes, because it could not check that reply for the key;
- does not count a call against the daily limit if the service was unreachable;
- writes one audit line per call, with no keys, tokens, query strings or bodies. The audit log, like the store, is refused if other users can read it.

**Naming the caller to a service you run.** With `"forward_role": true` on a service, every call carries `X-Keyring-Role: <role>`, so a service the fleet runs itself (a build server, for example) can log which agent sent a call; through a relay all callers otherwise look the same. It is off by default (third-party APIs get no role names) and refused for services that forward nothing (signing, `gcloud-login`, `egress-proxy`). The keyring drops a caller-sent `X-Keyring-Role` on every call, so the header cannot be forged through it; anything that reaches the service without the keyring can still send one. Turn it on with the "Tell the service which agent is calling" box on the service's edit form, with `"forward_role": true` in pasted settings, or in `access.json`; the service page shows it.

A service that echoes a key in some other encoding (for example base64 inside a larger text) is not protected; do not route such a service through the keyring.

Allowed methods default to GET, HEAD and POST. A role's `"expires"` ends all its access (401); an access's own `"expires"` (RFC 3339, like `"2026-12-31T00:00:00Z"`) ends only that service (403).

A service may name a harmless request for the dashboard's Test button: `"test_method": "GET"` (GET, HEAD or POST; default GET) and `"test_path": "/api/v1/key"` (may carry a query). The test goes out exactly like a proxied call.

**Authorization schemes other than Bearer.** A `bearer` service sends `Authorization: Bearer <key>`. An API that wants another scheme names it with `"scheme"`: one HTTP token (letters, digits and ``!#$%&'*+-.^_`|~``, at most 32 characters, no spaces), allowed only with `"auth": "bearer"`. Higgsfield, for example, wants `Authorization: Key <key id>:<key secret>`: store `KEY_ID:KEY_SECRET` as one value and connect it with `{"service":"higgsfield","base":"https://api.higgsfield.ai","auth":"bearer","scheme":"Key"}`. Everything else works as for Bearer: the caller's `Authorization` is dropped, the key is masked in replies, and key pools work. On the dashboard, type the scheme in "Scheme (if not Bearer)" or paste it; the service page shows what is sent.

Static `bearer`, `header`, and `query` services may add up to two secret headers:
`"extra_headers": {"CF-Access-Client-Secret": "ACCESS_SECRET"}` maps each header
to a distinct store key, not a credential value. For Cloudflare Access, use
`"auth": "header", "header": "CF-Access-Client-Id", "key": "ACCESS_ID"` as the
primary credential. Header names are case-insensitive; duplicates, primary
collisions, `Authorization`, `X-Keyring-*`, routing and hop-by-hop headers are
refused. Signing keys and OAuth credentials cannot be reused as extra headers.
**A key with several values** (dashboard): on **Add key**, paste one value per row (one
to 32 values; **Add another value** adds rows). Names are optional: values without one
are numbered `1`, `2`, `3` (stored as `CLAUDE_KEYS.1`, `CLAUDE_KEYS.2`, …), and a number
is never given again, even after its value is removed. Name a value where a service must
tell them apart, for example `MODAL` with `id` ← `wk-…` and `secret` ← `ws-…`, stored as
`MODAL.id` and `MODAL.secret`. Each value may also have a label, free text up to 80
characters ("Jerry's Max account") that is shown next to it and never routes. The key is
shown with its value names and labels, never the values. On the key's page, **Connect to a service**
asks which value is sent as the key and, optionally, a header for each other value
(Modal: `id` as `Modal-Key`, `secret` as `Modal-Secret`); pasted settings say the same
with `"key_part": "id", "extra_headers": {"Modal-Secret": "secret"}`. **Add a value**
adds one (a key with one plain value becomes `KEY.1` and `KEY.2`; services that sent
`KEY` send `KEY.1`), **Order and labels** moves a value up the list and sets its label,
**Replace** replaces one, **Remove value** deletes one that no service sends, and
**Delete** removes all of them. **Rename** renames
the key or a value and changes every service that names it. Access files may name the
values directly (`"key": "MODAL.id"`). A store holding such values cannot be read by a
keyring older than this release, so delete them before downgrading.

Separate keys work too: add each value as its own key, open the primary key, choose
**Connect to a service** and paste the settings with `extra_headers` naming the other
key, for example on `MODAL_PROXY_ID`
`{"service":"modal-ocr","base":"https://WORKSPACE--app-web.modal.run","auth":"header","header":"Modal-Key","test_path":"/health","extra_headers":{"Modal-Secret":"MODAL_PROXY_SECRET"}}`.
The named keys must already have stored values; otherwise the paste is refused,
and neither the refusal message nor the re-shown form repeats what was pasted. On a service's edit page, pasted settings without
`extra_headers` keep the stored ones, a new map replaces them and `{}` removes them.
The audit log names the headers and keys, never values. **Test** sends every secret.
The proxy replaces caller-supplied values, requires the complete bundle before
dispatch (503 if a value is missing), and redacts every injected credential.
A stored key sent in a header (`bearer`, `header` and extra headers) must be a legal
header value, with no line break or other control character (tab and space are fine).
Go will not send one that is not, so the proxy answers 503 `stored key NAME contains a
line break or control character` instead of a network error, sends nothing, and does not
count the call against the daily limit. The dashboard Test button says the same.
Existing role paths, methods and quotas still apply.

Static `bearer`, `header`, and `query` services also support `fixed_headers`
for **nonsecret** constants, such as `"fixed_headers": {"CF-R2-Jurisdiction": "default"}`.
Each configured value replaces all caller values for that header, including
duplicate and differently cased names. The proxy and dashboard Test button use
the same setting. These constants are not store key names and are not added to
response-secret redaction: backup bytes containing `default` stay unchanged.
Actual credentials remain redacted; never place a credential in `fixed_headers`.

At most two fixed headers are allowed. Names must be valid HTTP header names,
unique without regard to case, and must not collide with primary or extra
credential headers. Authorization, cookies, routing, hop-by-hop, framing,
encoding and `X-Keyring-*` headers are refused. Values must contain 1–512
printable ASCII bytes with no surrounding whitespace.

An authorized owner can set `fixed_headers` on a service in `access.json`, then
reload through the normal owner-operated service procedure. In the dashboard,
open **Keys → an existing stored key → Connect to a service → Or paste settings
from an agent**, and include the field in the settings JSON:

```json
{
  "service": "r2-backup",
  "base": "https://api.cloudflare.com/client/v4/accounts/ACCOUNT_ID/r2/buckets/BUCKET_NAME",
  "auth": "bearer",
  "fixed_headers": {"CF-R2-Jurisdiction": "default"}
}
```

Use the confirmed account, bucket and jurisdiction, and confirm with the
dashboard password. Do not paste or replace the stored API credential. Creating
the service does not grant agent access. Separately configure the intended role
with only the approved methods and paths (for object backups, `GET`, `PUT`,
`DELETE` and `/objects`), then verify the effective scope before enabling use.

A one-time consent link collects the primary credential and every extra header
in password fields, never displays stored values, and saves the complete bundle
atomically. Missing or multiline values leave the link usable without changing
any credential. Changing the extra-header mapping invalidates previously issued
links. Disconnecting the service removes the entire bundle. Unrelated Workspace
account revocation does not block saving or disconnecting a static bundle;
changes to an account's own refresh or client secret still respect its gate.

A service with its own self-signed certificate (such as a build server you run) can be trusted by pinning that certificate: `"tls_pin_sha256": "<64 lowercase hex>"`, the SHA-256 of the leaf certificate's DER bytes (`openssl x509 -in cert.pem -outform der | shasum -a 256`). The keyring then accepts exactly that certificate for that service, on every handshake including resumed sessions, and skips the system CA roots, hostname and expiry checks for it; a different certificate is refused with 502 "upstream certificate does not match the pinned certificate". Only `https` bases may carry a pin, and a malformed pin is refused when the file loads. Services without a pin keep using the system CA roots. When the upstream's certificate is renewed, update the pin.

## Finding services

An agent lists and searches the services instead of guessing a name:

```sh
keyring services --role my-agent                         # through the relay at 127.0.0.1:7700
keyring services --role my-agent --search cloudflare     # words in the name, provider host or project
keyring services --upstream http://<keyring>:7701        # a new agent, before it has a role
```

Each line shows the service, its provider host, its kind (`proxy`, `sign`, `tunnel` or `login`), its project, whether this role may use it (methods and paths) and the path to call. `--json` prints the keyring's answer (`GET /_keyring/services?search=`, through the relay `/<role>/_keyring/services`). Results are ranked by how many search words match; words shorter than 3 letters are ignored unless they are all short. Key names and other settings are never shown.

A service in a **client-owned** project is listed only to roles with access to it, and a call to it from any other role gets the same answer as a name that does not exist. Every other service is listed to every agent, so it can ask for it.

A wrong name says what was meant: a call answers `403 no service named cloudflare-workers-ai (did you mean cloudflare-vcf?); list them with: keyring services --role my-agent`, and `keyring request` answers `unknown service "cloudflare-workers-ai" (did you mean cloudflare-vcf?)`. A service the role can see but may not use answers with the `keyring request` command to ask for it. Each listing is audited (note `services list`, with the search words).

## Key pools: several keys behind one service

A service with `"key_pool": true` uses every value of its key: one key such as `CLAUDE_KEYS` holding `1`, `2`, `3` (or named values). Agents call one service (`claude-api`) and never know which value answered.

```json
"claude-api": {"base": "https://api.anthropic.com", "key": "CLAUDE_KEYS", "auth": "header", "header": "x-api-key", "key_pool": true}
```

- `key` names the key itself, never one of its values. The values are tried in the key's list order, kept by the dashboard (**Move up** on the key's page; values the list does not know follow by number, then by name). A key with one plain value is a pool of one. A value added to the key later joins the pool, last. Every value of a pooled key may be sent upstream, so no other service may use one (except another pool of the same key). Pools work with `bearer`, `header` and `query` services, without `extra_headers`.
- Each call goes out with the first value that is not set aside. If the provider says the value is the problem, the value is set aside and **the same request goes out again with the next value**: the agent only sees the answer that worked. If every value is refused, the agent gets the last refusal.
- A value is set aside on 401 or 403 (rejected), 402 (billing) and 429 (rate limit), and for the Anthropic API on a 429 without `retry-after` (monthly spend cap) and on a 400 that says a spend limit or the credit balance stopped it. It is set aside for the `retry-after` time of a 429 (seconds or an HTTP date; 1 s to 1 h), otherwise for an hour (a minute for another provider's 429), counted from when the refusal came back. Other answers, such as a malformed request (other 400s) or the provider being down (5xx), are passed on without trying another value: every value would fail the same way.
- What is known about a value lives in memory, is tied to that stored value (replacing it starts over, so does putting an earlier value back, and an answer to a value no longer stored is ignored) and starts empty after a restart. Values that are set aside are still tried, last, rather than refusing the call.
- A value that cannot be sent in a header (a line break or control character pasted with it) is skipped by a `bearer` or `header` pool; the call is refused only when no value can be sent. The key page shows the value failing when no service pooling it can send it, and otherwise names the services that cannot.
- The Cloudflare asset upload carries the caller's upload token, never a pool value, and its answer says nothing about the pool.
- To send a request again the keyring keeps its body, up to 32 MiB; a larger body goes out once, with the first value in line. A streamed answer is never retried once it has started: every refusal above comes before the answer begins.
- The key's dashboard page shows each value's state (working, busy with when it is back, failing with the reason, ready), its calls today and over 7 days, refusals today and last use. The key's status says how many values are set aside, and turns failing when all are; a pool with any value stored is not shown as having no value. Each audit line of a pooled call names the value that answered (`"key": "CLAUDE_KEYS.backup1"`, never its value) and how many were tried (`"attempts"`).
- Turn it on with `"key_pool": true` in pasted settings when connecting the key (without `key_part`: a paste with both is refused) or on the service's edit page; on the edit page, settings that leave `key_pool` out keep it as it is and `"key_pool": false` turns it off. The edit page's Key list offers both the key and its values: turning the pool on, a value picked stands for its key; turning it off on a key with several values, pick the value the service sends in the same save.
- Upgrading from v0.14.18: that release took a pool naming one value (`"key": "CLAUDE_KEYS.main"`). Such a pool keeps working: `keyring check` accepts it, and at the next start the service rewrites it to `"key": "CLAUDE_KEYS"` and sets the key's list to the order v0.14.18 tried: `main` first, then the other values by name (`10` before `2`). Nothing else changes. Two cases would change what a pool sends, so the start refuses them with the services named and writes nothing: two pools of one key with different first values (a key has one list order now; give both the same `key`), and a pool whose key also holds a plain value (`CLAUDE_KEYS` beside `CLAUDE_KEYS.main`: v0.14.18 never sent it; store it as a named value or delete it).

Setting one up in the dashboard:

1. **Add key**, name it (`CLAUDE_KEYS`) and paste one Claude key per row, with an optional label each (**Add another value** for more, up to 32). They are numbered `1`, `2`, `3`. On an existing key, **Add a value** adds one.
2. Under **Order and labels**, put the value to try first at the top with **Move up**.
3. Under **Connect to a service**, paste `{"service":"claude-api","base":"https://api.anthropic.com","auth":"header","header":"x-api-key","key_pool":true}`, then grant the agents the service. If a service already uses the key, turn the pool on there instead, because no other service may use a pooled key's values: on that service's edit page pick the key `CLAUDE_KEYS` and paste the same settings without `service`.
