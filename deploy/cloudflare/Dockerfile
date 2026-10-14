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

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /keyring /usr/local/bin/keyring
USER 65532:65532
# The admin API answers as soon as the process starts; the other ports open
# after the instance is created or unlocked.
EXPOSE 8090
# The Durable Object starts it with its own arguments (keyring instance --container ...).
ENTRYPOINT ["/usr/local/bin/keyring"]
