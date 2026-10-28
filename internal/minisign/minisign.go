// Package minisign writes minisign public keys and signatures
// (https://jedisct1.github.io/minisign/) from an Ed25519 key, so a release
// can be signed without the private key leaving the keyring.
//
// Only prehashed ("ED") signatures are made: the caller sends the BLAKE2b-512
// digest of the file (what `b2sum` prints) and never the file itself.
// Verifiers should refuse legacy ("Ed") signatures, e.g. minisign-verify's
// allow_legacy = false.
package minisign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// DigestSize is the size of a BLAKE2b-512 digest.
const DigestSize = 64

// MaxTrustedComment bounds the signed trusted comment.
const MaxTrustedComment = 256

// KeyID is the 8-byte key number minisign stores beside the key. minisign
// picks it at random; the keyring derives it from the public key, so it needs
// no storage and changes whenever the key does.
func KeyID(pub ed25519.PublicKey) [8]byte {
	sum := sha256.Sum256(pub)
	var id [8]byte
	copy(id[:], sum[:8])
	return id
}

// KeyIDHex is the key ID as minisign prints it: the little-endian number in
// upper-case hex.
func KeyIDHex(pub ed25519.PublicKey) string {
	id := KeyID(pub)
	var reversed [8]byte
	for i := range id {
		reversed[i] = id[7-i]
	}
	return strings.ToUpper(hex.EncodeToString(reversed[:]))
}

// PublicKey is the base64 public key line (what `minisign -P` takes).
func PublicKey(pub ed25519.PublicKey) string {
	id := KeyID(pub)
	raw := make([]byte, 0, 2+len(id)+ed25519.PublicKeySize)
	raw = append(raw, 'E', 'd')
	raw = append(raw, id[:]...)
	raw = append(raw, pub...)
	return base64.StdEncoding.EncodeToString(raw)
}

// PublicKeyFile is the content of a minisign .pub file.
func PublicKeyFile(pub ed25519.PublicKey) string {
	return "untrusted comment: minisign public key " + KeyIDHex(pub) + "\n" + PublicKey(pub) + "\n"
}

// ValidTrustedComment reports whether comment may be signed under prefix:
// one line of printable ASCII, at most MaxTrustedComment bytes, starting
// with prefix and longer than it.
func ValidTrustedComment(prefix, comment string) bool {
	if len(comment) > MaxTrustedComment || len(comment) <= len(prefix) || !strings.HasPrefix(comment, prefix) {
		return false
	}
	return printable(comment)
}

// ValidPrefix reports whether prefix can restrict trusted comments: 1-64
// bytes of printable ASCII that does not start with a space.
func ValidPrefix(prefix string) bool {
	return prefix != "" && len(prefix) <= 64 && prefix[0] != ' ' && printable(prefix)
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Sign returns a minisign .minisig file for the BLAKE2b-512 digest. The
// untrusted comment is not signed; the trusted comment is.
func Sign(priv ed25519.PrivateKey, digest []byte, trustedComment, untrustedComment string) (string, error) {
	if len(digest) != DigestSize {
		return "", errors.New("digest must be 64 bytes (BLAKE2b-512)")
	}
	if len(trustedComment) > MaxTrustedComment || !printable(trustedComment) || !printable(untrustedComment) {
		return "", errors.New("comments must be one line of printable ASCII")
	}
	id := KeyID(priv.Public().(ed25519.PublicKey))
	signature := ed25519.Sign(priv, digest)
	line := make([]byte, 0, 2+len(id)+ed25519.SignatureSize)
	line = append(line, 'E', 'D')
	line = append(line, id[:]...)
	line = append(line, signature...)
	global := ed25519.Sign(priv, append(signature, trustedComment...))
	return "untrusted comment: " + untrustedComment + "\n" +
		base64.StdEncoding.EncodeToString(line) + "\n" +
		"trusted comment: " + trustedComment + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n", nil
}
