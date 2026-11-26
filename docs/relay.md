# Relay on the agent server

The relay listens only on loopback, holds one token per role (never an API key), and forwards to the keyring over the tailnet:

```sh
keyring relay --listen 127.0.0.1:7700 --upstream http://192.0.2.10:7701 --tokens /etc/keyring/tokens
```

`/etc/keyring/tokens` must be a real directory (not a symlink), owned by the relay's user, mode 700, inside a parent that only that user can write (for example root-owned `/etc/keyring`). Each `<role>.token` file must be a regular file owned by that user, mode 600. A call picks its role in the path:

```sh
curl http://127.0.0.1:7700/my-agent/openrouter/api/v1/models
# SDKs: set the base URL to http://127.0.0.1:7700/<role>/openrouter/api/v1 and any placeholder key
curl http://127.0.0.1:7700/_relay/health       # is the keyring reachable?
```

The relay replaces any caller-supplied role token with the role's own. It refuses plain http except to a tailnet or loopback address. If the keyring is unreachable, calls fail with 502 `keyring unreachable ... never fall back to local keys`. Install steps are in `deploy/keyring-relay.service`.

A reply that breaks off at the keyring is passed on to the caller as a broken connection, never a clean end, so a cut streamed answer cannot pass for a complete one. This needs a reply whose end is marked (chunks or `Content-Length`, as the keyring sends to HTTP/1.1); a reply that ends when its connection closes cannot be told from a cut one. An HTTP/1.0 caller gets the whole answer at once with its `Content-Length`, or 502 before anything is sent if it breaks off or passes 32 MiB. `HEAD` is answered as is.

## Signature notices

The keyring sends the owner a notice for every mainnet Bitcoin signature through the channel set in its rules (`notify`, see [Bitcoin](bitcoin.md#signature-notices)). For the **gram** channel the keyring's machine cannot run `herdr`, so a relay on a host that can takes the notices with an optional second listener:

```sh
keyring relay --listen 127.0.0.1:7700 --upstream http://100.111.92.43:7701 --tokens /etc/keyring/tokens \
  --notify-listen 100.106.218.88:7702 --notify-allow 100.111.92.43 \
  --notify-token-file /etc/keyring/notify.token --gram-command /root/.local/bin/herdr
```

- `--notify-listen IP:PORT`: one specific address (no wildcard), normally the relay host's tailnet IP. It serves `POST /notify` only; everything else is 404, other methods 405. It never forwards to the keyring.
- `--notify-allow IP` (repeat): the only source IPs answered (the keyring's tailnet IP); any other gets 403.
- `--notify-token-file FILE`: the notice token, the same value stored on the keyring under `notify.token_key`. Same checks as role token files: a regular file, not a symlink, owned by the relay's user, mode 600. A wrong or missing `Authorization: Bearer` token gets 401 (compared in constant time).
- `--gram-command PATH`: `herdr` looked up in `PATH` (the default) or an absolute path; checked at start.

A notice is a JSON body of at most 4 KiB, `{"text": "..."}` and nothing else (413 over the size, 400 otherwise). Line breaks and tabs become spaces, other control and non-printing characters are dropped; the text must then be 1 to 1000 characters and not start with `-`. The relay then runs `<gram-command> gram send --from keyring <text>` as an argument list, never through a shell, for at most 20 seconds: 204 when it succeeds, 502 when it fails or times out. At most 60 notices run in any minute; more get 429. The keyring writes any refusal to its audit log and never waits on it to sign.

Under systemd, `herdr gram send` talks to the herdr server over its unix socket in the home directory, so the unit's sandbox needs `ProtectHome=read-only` (instead of `yes`), `AF_UNIX` added to `RestrictAddressFamilies`, and `Environment=HOME=/root` (the home of the user running herdr). Without them every notice gets 502.

## Relay in a Docker container

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
