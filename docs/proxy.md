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

Static `bearer`, `header`, and `query` services may add up to two secret headers:
`"extra_headers": {"CF-Access-Client-Secret": "ACCESS_SECRET"}` maps each header
to a distinct store key, not a credential value. For Cloudflare Access, use
`"auth": "header", "header": "CF-Access-Client-Id", "key": "ACCESS_ID"` as the
primary credential. Header names are case-insensitive; duplicates, primary
collisions, `Authorization`, `X-Keyring-*`, routing and hop-by-hop headers are
refused. Signing keys and OAuth credentials cannot be reused as extra headers.
**A key with several values** (dashboard): on **Add key**, open "This key has several
values", name each value and paste it, for example `MODAL` with `id` ← `wk-…` and
`secret` ← `ws-…`. They are stored as `MODAL.id` and `MODAL.secret` and shown as one
key with its value names, never the values. On the key's page, **Connect to a service**
asks which value is sent as the key and, optionally, a header for each other value
(Modal: `id` as `Modal-Key`, `secret` as `Modal-Secret`); pasted settings say the same
with `"key_part": "id", "extra_headers": {"Modal-Secret": "secret"}`. **Replace or add a
value** names the value; **Delete** removes all of them. Access files may name the
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
