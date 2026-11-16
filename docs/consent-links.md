# Consent links (off by default)

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
- `POST /links` `{"service": "gmail", "ttl_seconds": 900, "label": "Alice"}` returns `{"url", "expires_at"}` (201). `ttl_seconds` is 60 to 3600 (default 900); the label (at most 100 characters) is shown on the page. An optional `return_url` (https, at most 512 characters, on one of the consent block's `return_origins`, e.g. `"return_origins": ["https://app.example.com"]`) makes the done page say "Taking you back…" and go there after 3 seconds, with a button to go at once; without it the page says the person can close it. Scopes, paths and keys cannot be set here: they come from the access file. Only `bearer`, `header` and `query` services, and `oauth2` services with an `auth_url`, can get a link; signing keys stay with the owner.
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
