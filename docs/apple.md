# Apple: Ads, App Store Connect, Sign in with Apple, APNs

## Apple Ads signing (not an API proxy)

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
[the Mac operator instructions](../deploy/mac/README.md#apple-ads-signing-upgrade-and-key-import).
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

## App Store Connect signing

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
[the Mac deployment guide](../deploy/mac/README.md#app-store-connect-signing).
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


## Sign in with Apple client secret

Auth `sign-in-with-apple-sign` signs the short-lived `client_secret` an app sends to
`https://appleid.apple.com/auth/token` and `/auth/revoke` (for example to revoke a
user's Apple sign-in when they delete their account). The key (`.p8` for Sign in
with Apple) never leaves the keyring; the service is sign-only and proxies nothing.

```json
"myapp-siwa": {"key": "MYAPP_SIWA_KEY", "auth": "sign-in-with-apple-sign",
  "sign_in_with_apple": {"client_id": "com.example.app", "team_id": "ABCDE12345", "key_id": "KEY1234567"}}
```

- Any service name except `apple-ads` and `appstoreconnect`, whose sign paths are fixed. `team_id` and `key_id` are Apple's 10-character IDs; `client_id`
  is the app's bundle ID or Services ID.
- A granted role calls `POST http://127.0.0.1:7700/<role>/_keyring/sign/<service>`
  with an empty body and gets `{"token": "<JWT>", "expires_at": "<RFC 3339>"}`:
  ES256, header `kid` = key ID, claims `iss` = team ID, `sub` = client ID,
  `aud` = `https://appleid.apple.com`, `iat`, and `exp` at most 20 minutes later
  (earlier if the grant ends sooner). Grant `POST` on path `/`.
- The caller then sends Apple the form itself, e.g. `client_id`, `client_secret` (the
  token), `token` and `token_type_hint` to `/auth/revoke`.
- Import the `.p8` with `keyring set --file` (multi-line), then on the key's dashboard
  page **Connect to a service** with
  `{"service":"myapp-siwa","auth":"sign-in-with-apple-sign","sign_in_with_apple":{"client_id":"…","team_id":"…","key_id":"…"}}`.
- An unusable key gets 503 `Apple signing unavailable` and is not counted.

## Apple Push Notification service (APNs)

Auth `apns` proxies push requests to Apple with a provider token minted from an Apple
push key (`.p8`); the `.p8` itself never leaves the keyring and is never logged.

```json
"apns": {"base": "https://api.push.apple.com", "key": "MYAPP_APNS_KEY", "auth": "apns",
         "apns": {"key_id": "ABC123DEFG", "team_id": "TEAM456789"}}
```

- `base` is exactly `https://api.push.apple.com`, or `https://api.sandbox.push.apple.com`
  for development builds (use a second service, e.g. `apns-sandbox`, with the same key).
  No other host, port or path is accepted, nor `header`, `param`, a TLS pin, extra
  headers or a test request.
- `key_id` and `team_id` are Apple's 10-character IDs (Certificates, Identifiers & Profiles).
- Each call carries `authorization: bearer <JWT>`: ES256, header `kid` = key ID, claims
  `iss` = team ID and `iat` only. One token is reused for 40 minutes, across reloads
  with the same key, then replaced (Apple accepts tokens up to an hour old and refuses
  refreshes more often than every 20 minutes). A caller's own `Authorization` is
  dropped; `apns-*` headers and the JSON body pass through unchanged. The request goes
  out over HTTP/2, which APNs requires.
- Import the `.p8` with the dashboard's **Upload key file** (Keys page), or with
  `keyring set --file` as in
  [the Mac operator instructions](../deploy/mac/README.md#apple-ads-signing-upgrade-and-key-import).
  Then, on the key's dashboard page, **Connect to a service** with pasted settings
  `{"service":"apns","base":"https://api.push.apple.com","auth":"apns","apns":{"key_id":"…","team_id":"…"}}`.
- A stored value that is not an ES256 `.p8` gets 503 `stored key NAME is not a usable
  APNs .p8 key`; nothing is sent and the call is not counted.
- Grant a role `POST` on path `/3/device`. It calls
  `POST http://127.0.0.1:7700/<role>/apns/3/device/<device token>` with the usual
  `apns-topic`, `apns-push-type`, `apns-priority`, `apns-expiration` and
  `apns-collapse-id` headers; Apple's status, `apns-id` header and JSON `reason` come
  back unchanged.
