package server

// Minisign release signing (auth "minisign-sign"), first for herdr update
// manifests (issue #102). The caller sends the BLAKE2b-512 digest of the file
// (`b2sum`) and a trusted comment that must start with the service's prefix;
// the keyring returns the .minisig file. The key is the same base64 64-byte
// Ed25519 private key as ed25519-sign; it cannot be used through the raw
// /_keyring/sign/ route, because that route requires auth ed25519-sign.
//
// Route: "/_keyring/minisign/<service>".
//   POST {"blake2b512_hex": "<128 hex>", "trusted_comment": "<prefix>..."}
//        -> {"minisig": "...", "key_id": "...", "public_key": "..."}
//   GET  -> {"key_id": "...", "public_key": "...", "public_key_file": "..."}

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/gitmoot/keyring/internal/minisign"
)

const minisignPrefix = "/_keyring/minisign/"

// minisignService resolves "/_keyring/minisign/<service>" to the service
// name, or "".
func minisignService(path string) string {
	rest, found := strings.CutPrefix(path, minisignPrefix)
	if !found || rest == "" {
		return ""
	}
	for _, r := range rest {
		if r == '/' || r == '%' || r == '?' || r < 33 || r > 126 {
			return ""
		}
	}
	return rest
}

type minisignRequest struct {
	Digest         []byte
	DigestHex      string
	TrustedComment string
}

func decodeMinisignRequest(body io.Reader, prefix string) (minisignRequest, error) {
	var in struct {
		Blake2b512Hex  string `json:"blake2b512_hex"`
		TrustedComment string `json:"trusted_comment"`
	}
	decoder := json.NewDecoder(io.LimitReader(body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return minisignRequest{}, errors.New("body must be JSON with blake2b512_hex and trusted_comment")
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return minisignRequest{}, errors.New("body must be exactly one JSON object")
	}
	digest, err := hex.DecodeString(in.Blake2b512Hex)
	if err != nil || len(digest) != minisign.DigestSize {
		return minisignRequest{}, errors.New("blake2b512_hex must be 128 hex characters (b2sum of the file)")
	}
	if !minisign.ValidTrustedComment(prefix, in.TrustedComment) {
		return minisignRequest{}, errors.New("trusted_comment must be printable ASCII, at most 256 bytes, starting with " + strconv.Quote(prefix) + " and longer than it")
	}
	return minisignRequest{Digest: digest, DigestHex: hex.EncodeToString(digest), TrustedComment: in.TrustedComment}, nil
}

type minisignSignResponse struct {
	Minisig   string `json:"minisig"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type minisignPublicKeyResponse struct {
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
	PublicKeyFile string `json:"public_key_file"`
}

func minisignPublic(key ed25519.PrivateKey) minisignPublicKeyResponse {
	pub := key.Public().(ed25519.PublicKey)
	return minisignPublicKeyResponse{KeyID: minisign.KeyIDHex(pub), PublicKey: minisign.PublicKey(pub), PublicKeyFile: minisign.PublicKeyFile(pub)}
}

func signMinisign(key ed25519.PrivateKey, service string, req minisignRequest) (minisignSignResponse, error) {
	sig, err := minisign.Sign(key, req.Digest, req.TrustedComment, "signature from keyring service "+service)
	if err != nil {
		return minisignSignResponse{}, err
	}
	pub := key.Public().(ed25519.PublicKey)
	return minisignSignResponse{Minisig: sig, KeyID: minisign.KeyIDHex(pub), PublicKey: minisign.PublicKey(pub)}, nil
}
