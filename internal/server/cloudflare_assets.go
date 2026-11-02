package server

// Cloudflare Worker static-asset uploads (gitmoot/keyring#104).
//
// `wrangler deploy` with static assets first asks the API for an upload
// session (account token, through the keyring as usual). That reply carries a
// short-lived JWT, and POST /accounts/<id>/workers/assets/upload must then
// authenticate with that JWT, not with the account token. Everywhere else the
// keyring replaces the caller's Authorization with the service's key; on this
// one exact call it forwards the caller's own bearer token instead, and never
// sends the account token. A caller that sends none is refused before any
// quota is spent.
//
// This gives a caller nothing it did not already have: the token it sends is
// one Cloudflare issued to it, it still needs access to this service and path,
// and the account token is neither sent nor shown (it stays masked in replies).

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/gitmoot/keyring/internal/policy"
)

var cloudflareAssetsUploadPath = regexp.MustCompile(`^/accounts/[0-9a-f]{32}/workers/assets/upload$`)

// maxCallerBearer bounds the forwarded token; Cloudflare's are about 1 KiB.
const maxCallerBearer = 8192

// cloudflareAssetsUpload reports whether the request is the one asset-upload
// call, on a bearer service whose base is Cloudflare's v4 API.
func cloudflareAssetsUpload(svc policy.Service, method, rest string) bool {
	if svc.Auth != policy.AuthBearer || method != http.MethodPost || !cloudflareAssetsUploadPath.MatchString(rest) {
		return false
	}
	base := svc.BaseURL()
	return base.Scheme == "https" && base.Host == "api.cloudflare.com" && strings.TrimSuffix(base.Path, "/") == "/client/v4"
}

// callerBearer returns the token of exactly one Authorization header of the
// form "<Bearer, any case> <one or more spaces><token>" (RFC 9110 11.1, RFC
// 6750 2.1), or false. The token has no whitespace and is at most
// maxCallerBearer bytes.
func callerBearer(h http.Header) (string, bool) {
	values := h.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	scheme, rest, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token := strings.TrimLeft(rest, " ")
	if token == "" || len(token) > maxCallerBearer || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}
