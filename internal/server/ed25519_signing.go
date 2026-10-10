package server

// Generic Ed25519 signing (auth "ed25519-sign"), used for artifacts the owner
// wants signed without the private key ever leaving this process — unlike the
// Apple signers, which issue fixed-shape tokens, this signs caller-supplied
// bytes. First user: adspower-desk update manifests (owner, 2026-10-10).
//
// Route: POST "/_keyring/sign/<service>" where <service> is the service name.
// The path carries the service, so one access rule controls exactly one key.
// Body:   {"message_base64": "<base64 of the bytes to sign>"}
// Reply:  {"signature_base64": "...", "public_key_base64": "..."}
// The service's key is the base64 of a 64-byte Ed25519 private key
// (ed25519.PrivateKey: seed || public key).

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const ed25519SignPrefix = "/_keyring/sign/"

// ed25519MaxMessage caps a signing request. Update manifests sign a 32-byte
// digest; the bound only stops a request being a download, not a signature
// over chosen bytes — the service's daily cap and the owner's approval are
// what bound use.
const ed25519MaxMessage = 8192

// ed25519SignService resolves "/_keyring/sign/<service>" to the service name,
// or "". The Apple paths resolve earlier, so they are refused here too.
func ed25519SignService(path string) string {
	rest, found := strings.CutPrefix(path, ed25519SignPrefix)
	if !found || rest == "" || rest == "apple-ads" || rest == "appstoreconnect" {
		return ""
	}
	for _, r := range rest {
		if r == '/' || r == '%' || r == '?' || r < 33 || r > 126 {
			return ""
		}
	}
	return rest
}

func parseEd25519Key(value string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("key is not a base64 64-byte Ed25519 private key")
	}
	return ed25519.PrivateKey(raw), nil
}

type ed25519SignRequest struct {
	MessageBase64 string `json:"message_base64"`
}

type ed25519SignResponse struct {
	SignatureBase64 string `json:"signature_base64"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

func decodeEd25519Request(body io.Reader) ([]byte, error) {
	var req ed25519SignRequest
	decoder := json.NewDecoder(io.LimitReader(body, ed25519MaxMessage*2))
	if err := decoder.Decode(&req); err != nil {
		return nil, errors.New("body must be JSON with message_base64")
	}
	message, err := base64.StdEncoding.DecodeString(req.MessageBase64)
	if err != nil || len(message) == 0 || len(message) > ed25519MaxMessage {
		return nil, errors.New("message_base64 must decode to 1-8192 bytes")
	}
	return message, nil
}

func signEd25519(key ed25519.PrivateKey, message []byte) ed25519SignResponse {
	return ed25519SignResponse{
		SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(key, message)),
		PublicKeyBase64: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
	}
}
