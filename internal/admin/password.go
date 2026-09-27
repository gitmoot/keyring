package admin

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	// Iterations for new password hashes (OWASP 2023 guidance for
	// PBKDF2-SHA256).
	Iterations = 600000
	// MinPasswordLength is the shortest password accepted.
	MinPasswordLength = 12
	hashPrefix        = "pbkdf2-sha256"
	saltBytes         = 16
	keyBytes          = 32
)

// PasswordHash is a parsed "pbkdf2-sha256$<iterations>$<salt>$<hash>" line.
type PasswordHash struct {
	iterations int
	salt, hash []byte
}

// NewPasswordHash hashes password with a random salt.
func NewPasswordHash(password string, iterations int) (string, error) {
	if len(password) < MinPasswordLength {
		return "", fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyBytes)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", hashPrefix, iterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// ParsePasswordHash reads one hash line.
func ParsePasswordHash(line string) (PasswordHash, error) {
	parts := strings.Split(strings.TrimSpace(line), "$")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return PasswordHash{}, errors.New("not a keyring password hash")
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1000 {
		return PasswordHash{}, errors.New("bad iteration count in password hash")
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	hash, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(hash) != keyBytes {
		return PasswordHash{}, errors.New("bad salt or hash in password hash")
	}
	return PasswordHash{iterations: iterations, salt: salt, hash: hash}, nil
}

// Matches reports whether password matches, in constant time.
func (p PasswordHash) Matches(password string) bool {
	if len(p.hash) == 0 {
		return false
	}
	key, err := pbkdf2.Key(sha256.New, password, p.salt, p.iterations, keyBytes)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(key, p.hash) == 1
}

// Equal reports whether two hashes are the same stored value.
func (p PasswordHash) Equal(q PasswordHash) bool {
	return p.iterations == q.iterations && subtle.ConstantTimeCompare(p.salt, q.salt) == 1 && subtle.ConstantTimeCompare(p.hash, q.hash) == 1
}

// LoadPasswordFile reads the hash file. It must not be writable by group or
// others, and not readable by others.
func LoadPasswordFile(path string) (PasswordHash, error) {
	info, err := os.Stat(path)
	if err != nil {
		return PasswordHash{}, err
	}
	if perm := info.Mode().Perm(); perm&0o027 != 0 {
		return PasswordHash{}, fmt.Errorf("%s must not be writable by group or readable by others (mode %04o); run chmod 640 %s", path, perm, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return PasswordHash{}, err
	}
	hash, err := ParsePasswordHash(string(raw))
	if err != nil {
		return PasswordHash{}, fmt.Errorf("%s: %w", path, err)
	}
	return hash, nil
}
