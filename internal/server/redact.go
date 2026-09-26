package server

import (
	"bytes"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Mask replaces a key the service echoes back.
const Mask = "[REDACTED]"

var percentHex = regexp.MustCompile(`%[0-9A-F]{2}`)

// secretForms lists the ways a key can come back from a service: as sent, URL
// query- or path-encoded (with upper- or lowercase hex), and with JSON-escaped
// slashes. Longest first, so a longer form is masked before a shorter one it
// contains. Encodings that depend on position (base64 of a larger text) cannot
// be listed; a service that echoes a key that way is not supported.
func secretForms(key string) [][]byte {
	if key == "" {
		return nil
	}
	seen := map[string]bool{}
	var forms []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			forms = append(forms, s)
		}
	}
	for _, f := range []string{key, url.QueryEscape(key), url.PathEscape(key)} {
		add(f)
		add(percentHex.ReplaceAllStringFunc(f, strings.ToLower))
		add(strings.ReplaceAll(f, "/", `\/`))
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	out := make([][]byte, len(forms))
	for i, f := range forms {
		out[i] = []byte(f)
	}
	return out
}

// maskString replaces every form of the key in s.
func maskString(s string, forms [][]byte) string {
	for _, f := range forms {
		s = strings.ReplaceAll(s, string(f), Mask)
	}
	return s
}

// redactor replaces every form of the key in a byte stream, including one
// split across writes. It holds back only a tail that could still become a
// form of the key, so streamed events are not delayed otherwise.
type redactor struct {
	w     io.Writer
	forms [][]byte
	carry []byte
}

func newRedactor(w io.Writer, forms [][]byte) *redactor {
	return &redactor{w: w, forms: forms}
}

func (r *redactor) Write(p []byte) (int, error) {
	if len(r.forms) == 0 {
		return r.w.Write(p)
	}
	data := make([]byte, 0, len(r.carry)+len(p))
	data = append(data, r.carry...)
	data = append(data, p...)
	for _, f := range r.forms {
		data = bytes.ReplaceAll(data, f, []byte(Mask))
	}
	hold := 0
	for _, f := range r.forms {
		if n := pendingPrefix(data, f); n > hold {
			hold = n
		}
	}
	r.carry = append(r.carry[:0], data[len(data)-hold:]...)
	if _, err := r.w.Write(data[:len(data)-hold]); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close writes the held-back tail: the stream ended, so it cannot complete
// a form of the key.
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
