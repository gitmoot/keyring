# Ed25519 and minisign signing

## Ed25519 signing (not an API proxy)

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
fixed services; this route covers only `ed25519-sign` services.

## Minisign release signing (not an API proxy)

For release files signed with [minisign](https://jedisct1.github.io/minisign/)
— for example an app's update manifests (#102). A service with
`"auth": "minisign-sign"` holds the same kind of key as `ed25519-sign` and
takes one setting:

```json
"myapp-release": {
  "key": "MYAPP_RELEASE_KEY",
  "auth": "minisign-sign",
  "minisign": {"trusted_comment_prefix": "myapp-preview "}
}
```

Make the key on the keyring machine with `keyring minisign-keygen --store
FILE MYAPP_RELEASE_KEY`. It is generated straight into the store, never shown,
and the command prints the minisign public key (`untrusted comment: …` and the
`RW…` line). It refuses a name that already exists. To rotate, generate a new
name, embed both public keys in the release, then point the service at the new
key. One service and one key per product: the key may not be shared with any
other service, so it cannot sign through the raw `ed25519-sign` route.

`/_keyring/minisign/<service>`, exact path, no query:
- `GET` returns `{"key_id", "public_key", "public_key_file"}` for embedding.
- `POST {"blake2b512_hex": "<b2sum of the file>", "trusted_comment":
  "myapp-preview <build_id> <commit>"}` returns `{"minisig", "key_id",
  "public_key"}`. Write `minisig` to `<file>.minisig`; `minisign -Vm <file>
  -p <pub>` verifies it. The file never leaves the caller.

Only prehashed (`ED`) signatures are made; verifiers should refuse legacy ones.
The trusted comment is signed, must start with the service's prefix and be
longer than it, and is at most 256 bytes of printable ASCII on one line.
Unknown body fields, other lengths and other methods are refused (400/405).
The owner approves a role in the dashboard as for any service; both `GET` and
`POST` count toward its daily limit. Every call is in the audit log with role,
time, status and, for signatures, the digest and trusted comment; never the key.
