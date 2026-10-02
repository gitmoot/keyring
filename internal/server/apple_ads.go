package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const appleAdsSignPath = "/_keyring/sign/apple-ads"

// Parse at snapshot load, never on the request path. Invalid material remains
// unavailable; parser errors and private key bytes are never logged or returned.
func parseAppleAdsKey(value string) *ecdsa.PrivateKey {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "-----BEGIN PRIVATE KEY-----") && !strings.HasPrefix(value, "-----BEGIN EC PRIVATE KEY-----") {
		return nil
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || len(block.Headers) != 0 || len(strings.TrimSpace(string(rest))) != 0 {
		return nil
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		key, _ = parsed.(*ecdsa.PrivateKey)
	case "EC PRIVATE KEY":
		key, _ = x509.ParseECPrivateKey(block.Bytes)
	}
	if key == nil || key.Curve != elliptic.P256() {
		return nil
	}
	return key
}

func signAppleAds(key *ecdsa.PrivateKey, identity *policy.AppleAds, role policy.Role, access policy.Access, now time.Time) (string, time.Time, error) {
	unavailable := errors.New("Apple Ads signing unavailable")
	if key == nil || identity == nil {
		return "", time.Time{}, unavailable
	}
	expires := now.Add(20 * time.Minute)
	for _, bound := range []*time.Time{role.Expires, access.Expires} {
		if bound != nil && bound.Before(expires) {
			expires = *bound
		}
	}
	// NumericDate has whole-second precision. Round down so a token never
	// outlives an access boundary, and refuse a zero-length validity window.
	expires = time.Unix(expires.Unix(), 0).UTC()
	if !expires.After(now) {
		return "", time.Time{}, unavailable
	}
	header, _ := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}{"ES256", identity.KeyID, "JWT"})
	claims, _ := json.Marshal(struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		IssuedAt int64  `json:"iat"`
		Expires  int64  `json:"exp"`
	}{identity.TeamID, identity.ClientID, "https://appleid.apple.com", now.Unix(), expires.Unix()})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", time.Time{}, unavailable
	}
	// JOSE uses fixed-width R || S, not ASN.1 DER.
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature[:]), expires, nil
}
