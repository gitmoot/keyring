# OAuth services with refresh tokens

Google (Gmail, Drive, Sheets, Calendar) and similar APIs give a long-lived refresh token and access tokens that expire after about an hour. A service with `"auth": "oauth2"` stores the refresh token under its `key`; the keyring mints access tokens from it and sends `Authorization: Bearer <access token>`:

```json
"gmail": {
  "base": "https://gmail.googleapis.com", "key": "GMAIL_REFRESH_TOKEN", "auth": "oauth2",
  "test_path": "/gmail/v1/users/me/profile",
  "oauth2": {"token_url": "https://oauth2.googleapis.com/token", "client_id": "<id>.apps.googleusercontent.com", "client_secret_key": "GOOGLE_CLIENT_SECRET"}
}
```

- `client_id` is public configuration. Connect and the edit form refuse a client ID that is a template value (`PASTE_YOUR_CLIENT_ID_HERE`, `YOUR_CLIENT_ID`, `client_id`, or `<…>`, `{{` or `${` syntax) and, for `oauth2.googleapis.com` or `accounts.google.com`, one not ending in `.apps.googleusercontent.com`. Config loading does not check this, so an existing config still starts. `client_secret_key` names the store key holding the client secret; leave it out for a public client. `token_url` must be `https` (plain `http` only to a loopback test server).
- The refresh token and client secret go only to `token_url`, never to the API, and are masked like a key if the API echoes them. Access tokens are cached in memory only, never written to the store or the log, and replaced a minute before they expire (or after 10 minutes if the provider gives no lifetime). Concurrent calls share one refresh.
- If the API answers 401, the cached access token is dropped and the next call mints a new one.
- A refresh that the provider refuses (`invalid_grant`, `invalid_client`, `unauthorized_client`: revoked or expired consent) fails closed with 503 and a message to connect the account again; other refresh failures give 502. Nothing else is tried, the call does not count against the daily limit, and the token endpoint is asked again only after 10 seconds. The dashboard shows the key as failing with the reason until a refresh works; the owner's view (never the agent's 503 or the audit) also shows the provider's own `error_description`, e.g. `provider said: "Unauthorized"` (Google: wrong client secret) or `"The OAuth client was not found."` (wrong client ID). It is dropped if it repeats the refresh token, secret or client ID, or is not printable ASCII, and cut at 160 bytes.
- Several services can share one refresh token (one Google login for Gmail and Drive) only if they are all `oauth2` with the same `oauth2` settings. A refresh token or client secret can never be the key of a service that sends its key upstream.
- Per-role paths, methods, daily limits and expiry apply as for any service. Replacing the refresh token (dashboard or `keyring set` and `SIGHUP`) stops use of tokens minted from the old one.

To get the refresh token, store it with `keyring set` or the dashboard, or let the account's owner sign in through a [consent link](consent-links.md).

From the dashboard: add the refresh token and the client secret as two keys, open the
refresh token's key, choose **Connect to a service** and paste the settings with an
`oauth2` block naming the secret's key (never its value), for example
`{"service":"gmail-send","base":"https://gmail.googleapis.com","auth":"oauth2","oauth2":{"token_url":"https://oauth2.googleapis.com/token","client_id":"<id>.apps.googleusercontent.com","client_secret_key":"GMAIL_CLIENT_SECRET"}}`.
A Gmail refresh token for one scope (for example `https://www.googleapis.com/auth/gmail.send`)
can be made with Google's OAuth 2.0 Playground using your own OAuth client: add
`https://developers.google.com/oauthplayground` as an authorized redirect URI of a
*Web application* client, tick "Use your own OAuth credentials", authorize only that
scope, and exchange the code. `gmail.send` cannot read the profile, so such a service
has no test request; a first real send is the test.
