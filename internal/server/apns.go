package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

// Apple Push Notification service provider tokens (auth apns).
//
// APNs authenticates with an ES256 JWT whose header carries the key ID and
// whose claims carry the team ID and the issue time, nothing else. Apple
// rejects a token older than an hour and one refreshed more often than every
// 20 minutes (TooManyProviderTokenUpdates), so one token per service is reused
// for apnsTokenAge and then replaced.
const apnsTokenAge = 40 * time.Minute

type apnsSigner struct {
	identity [32]byte // what the token is minted from: key ID, team ID, key
	key      *ecdsa.PrivateKey
	keyID    string
	teamID   string

	mu     sync.Mutex
	cached string
	minted time.Time
}

var errAPNsKey = errors.New("APNs key unavailable")

// apnsSigners builds a minter for every apns service, reusing one from
// previous (and its cached token) when the key and identity are unchanged.
// Keys are parsed here, never on the request path.
func apnsSigners(config *policy.Config, keys map[string]string, previous map[string]*apnsSigner) map[string]*apnsSigner {
	out := map[string]*apnsSigner{}
	for name, svc := range config.Services {
		if svc.Auth != policy.AuthAPNs || svc.APNs == nil {
			continue
		}
		identity := sha256.Sum256([]byte(svc.APNs.KeyID + "\x00" + svc.APNs.TeamID + "\x00" + keys[svc.Key]))
		if old, ok := previous[name]; ok && old.identity == identity {
			out[name] = old
			continue
		}
		out[name] = &apnsSigner{identity: identity, key: parseAppleSigningKey(keys[svc.Key]), keyID: svc.APNs.KeyID, teamID: svc.APNs.TeamID}
	}
	return out
}

// token returns the cached provider token, minting a new one when there is
// none or it is apnsTokenAge old.
func (a *apnsSigner) token(now time.Time) (string, error) {
	if a == nil || a.key == nil {
		return "", errAPNsKey
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cached != "" && !now.Before(a.minted) && now.Sub(a.minted) < apnsTokenAge {
		return a.cached, nil
	}
	header, _ := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{"ES256", a.keyID})
	claims, _ := json.Marshal(struct {
		Issuer   string `json:"iss"`
		IssuedAt int64  `json:"iat"`
	}{a.teamID, now.Unix()})
	token, err := signES256(a.key, header, claims)
	if err != nil {
		return "", errAPNsKey
	}
	a.cached, a.minted = token, now
	return token, nil
}

// signES256 returns the compact JWS of header and claims signed with key.
func signES256(key *ecdsa.PrivateKey, header, claims []byte) (string, error) {
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	// JOSE uses fixed-width R || S, not ASN.1 DER.
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature[:]), nil
}
