package server

import (
	"bytes"
	"io"
)

// Mask replaces a key the service echoes back.
const Mask = "[REDACTED]"

// redactor replaces every occurrence of secret in a byte stream, including one
// split across writes. It holds back only a tail that could still become the
// secret, so streamed events are not delayed otherwise.
type redactor struct {
	w      io.Writer
	secret []byte
	carry  []byte
}

func newRedactor(w io.Writer, secret []byte) *redactor {
	return &redactor{w: w, secret: secret}
}

func (r *redactor) Write(p []byte) (int, error) {
	if len(r.secret) == 0 {
		return r.w.Write(p)
	}
	data := make([]byte, 0, len(r.carry)+len(p))
	data = append(data, r.carry...)
	data = append(data, p...)
	data = bytes.ReplaceAll(data, r.secret, []byte(Mask))
	hold := pendingPrefix(data, r.secret)
	r.carry = append(r.carry[:0], data[len(data)-hold:]...)
	if _, err := r.w.Write(data[:len(data)-hold]); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close writes the held-back tail: the stream ended, so it cannot complete
// the secret.
func (r *redactor) Close() error {
	if len(r.carry) == 0 {
		return nil
	}
	_, err := r.w.Write(r.carry)
	r.carry = nil
	return err
}

// pendingPrefix returns the length of the longest tail of data that is a
// proper prefix of secret.
func pendingPrefix(data, secret []byte) int {
	n := len(secret) - 1
	if n > len(data) {
		n = len(data)
	}
	for ; n > 0; n-- {
		if bytes.Equal(data[len(data)-n:], secret[:n]) {
			return n
		}
	}
	return 0
}
