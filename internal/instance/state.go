// Package instance runs one person's keyring from a sealed state that a
// supervisor hands it, and changes that state only through an authenticated
// admin API. The data key that seals the state comes from the supervisor and
// is never written anywhere by the keyring.
package instance

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/gitmoot/keyring/internal/policy"
)

// KeySize is the data key length: AES-256.
const KeySize = 32

var (
	sealMagic = []byte("KRI1")
	idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	// errSealed is every failure to open a sealed state: wrong key, wrong
	// instance, damaged or not a sealed state. One message, so a caller
	// learns nothing about which.
	errSealed = errors.New("the state cannot be opened with this data key for this instance")
)

// ValidID reports whether id may name an instance.
func ValidID(id string) bool { return idPattern.MatchString(id) }

// State is everything an instance knows: its network settings, services,
// roles and key values.
type State struct {
	ID           string                    `json:"id"`
	Version      uint64                    `json:"version"`
	Listen       string                    `json:"listen"`
	AllowSources []string                  `json:"allow_sources"`
	Consent      *policy.Consent           `json:"consent,omitempty"`
	Services     map[string]policy.Service `json:"services"`
	Roles        map[string]policy.Role    `json:"roles"`
	Keys         map[string]string         `json:"keys"`
}

// clone returns a deep enough copy to change without touching s.
func (s *State) clone() *State {
	c := *s
	c.AllowSources = append([]string(nil), s.AllowSources...)
	if s.Consent != nil {
		k := *s.Consent
		k.APIAllowSources = append([]string(nil), s.Consent.APIAllowSources...)
		c.Consent = &k
	}
	c.Services = make(map[string]policy.Service, len(s.Services))
	for n, v := range s.Services {
		c.Services[n] = v
	}
	c.Roles = make(map[string]policy.Role, len(s.Roles))
	for n, v := range s.Roles {
		c.Roles[n] = v
	}
	c.Keys = make(map[string]string, len(s.Keys))
	for n, v := range s.Keys {
		c.Keys[n] = v
	}
	return &c
}

// config builds and validates the proxy settings for s. auditName only
// fills the field Validate requires; the instance writes its own audit.
func (s *State) config(auditName string) (*policy.Config, error) {
	// Round-trip through JSON so the config never shares maps or pointers
	// with the state, and every parsed field is rebuilt by Validate.
	raw, err := json.Marshal(struct {
		policy.Rules
		policy.AccessList
	}{
		policy.Rules{Listen: s.Listen, AllowSources: s.AllowSources, AuditLog: auditName, Consent: s.Consent},
		policy.AccessList{Services: s.Services, Roles: s.Roles},
	})
	if err != nil {
		return nil, err
	}
	var cfg policy.Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func aad(id string) []byte { return []byte("keyring-instance-v1\x00" + id) }

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("data key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts s with key, bound to s.ID.
func seal(s *State, key []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	// The id is outside the ciphertext too, so open knows what to bind to.
	idLen := []byte{byte(len(s.ID))}
	out := append(append(append(append([]byte{}, sealMagic...), idLen...), s.ID...), nonce...)
	return aead.Seal(out, nonce, plain, aad(s.ID)), nil
}

// open decrypts a sealed state. The id inside must match the one it was
// sealed for, so a blob cannot be passed off as another instance's.
func open(blob, key []byte) (*State, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(blob, sealMagic) || len(blob) < len(sealMagic)+1 {
		return nil, errSealed
	}
	rest := blob[len(sealMagic):]
	idLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < idLen+aead.NonceSize() {
		return nil, errSealed
	}
	id := string(rest[:idLen])
	nonce, ct := rest[idLen:idLen+aead.NonceSize()], rest[idLen+aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, aad(id))
	if err != nil {
		return nil, errSealed
	}
	var s State
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || s.ID != id {
		return nil, errSealed
	}
	if s.Services == nil {
		s.Services = map[string]policy.Service{}
	}
	if s.Roles == nil {
		s.Roles = map[string]policy.Role{}
	}
	if s.Keys == nil {
		s.Keys = map[string]string{}
	}
	return &s, nil
}

// decodeKey reads a base64 data key.
func decodeKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(key) != KeySize {
		return nil, fmt.Errorf("data_key must be the base64 of %d random bytes", KeySize)
	}
	return key, nil
}
