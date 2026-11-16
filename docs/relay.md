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
