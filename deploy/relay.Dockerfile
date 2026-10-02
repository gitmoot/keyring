FROM golang:1.24-alpine AS build
RUN apk add --no-cache ca-certificates \
    && mkdir -p /run/keyring/tokens \
    && chmod 700 /run/keyring /run/keyring/tokens
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=${VERSION}" -o /keyring ./cmd/keyring

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /keyring /usr/local/bin/keyring
COPY --from=build --chown=65532:65532 /run/keyring /run/keyring
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/keyring", "relay"]
