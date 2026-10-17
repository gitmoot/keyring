# The unchanged keyring binary, for one person's container. Build context: the
# repository root (wrangler.jsonc sets image_build_context).
FROM golang:1.24-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum* ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION}" -o /keyring ./cmd/keyring

# The official x86_64 archive includes Python; it needs glibc, not Alpine's musl.
# Release-tagged bases follow the existing Go build image convention.
FROM debian:bookworm-slim AS google-sdk
RUN test "$(dpkg --print-architecture)" = amd64 \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN curl --fail --show-error --silent --location \
        https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-589.0.0-linux-x86_64.tar.gz \
        --output /tmp/google-cloud-cli.tar.gz \
    && echo 'f865da648f6fdae2015abb5b32eaa0eb10520e88f0ca735cfb33795868c8d26f  /tmp/google-cloud-cli.tar.gz' | sha256sum --check --strict - \
    && tar -xzf /tmp/google-cloud-cli.tar.gz -C /opt \
    && rm /tmp/google-cloud-cli.tar.gz

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 -o 65532 -g 65532 /var/lib/keyring /var/lib/keyring/google
COPY --from=google-sdk /opt/google-cloud-sdk /opt/google-cloud-sdk
ENV CLOUDSDK_PYTHON=/opt/google-cloud-sdk/platform/bundledpythonunix/bin/python3 \
    CLOUDSDK_CONFIG=/var/lib/keyring/google \
    CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=true \
    CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true
COPY --from=build /keyring /usr/local/bin/keyring
USER 65532:65532
# The admin API answers as soon as the process starts; the other ports open
# after the instance is created or unlocked.
EXPOSE 8090
# The Durable Object starts it with its own arguments (keyring instance --container ...).
ENTRYPOINT ["/usr/local/bin/keyring"]
