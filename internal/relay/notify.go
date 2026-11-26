package relay

// The notify listener ("keyring relay --notify-listen", #187) takes the
// keyring's signature notices and hands each to herdr gram send, which the
// keyring's own machine cannot run. It serves POST /notify only, to the
// allowed source IPs only, with the notice token as a bearer token.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	// NotifyPath is the only path the notify listener serves.
	NotifyPath = "/notify"
	// notifyBodyLimit bounds a notice body.
	notifyBodyLimit = 4 << 10
	// notifyTextLimit bounds a notice's text, in characters.
	notifyTextLimit = 1000
	// notifyPerMinute is how many notices may run in any minute.
	notifyPerMinute = 60
	// notifyTimeout bounds one run of the gram command.
	notifyTimeout = 20 * time.Second
)

// Notifier serves the notify listener.
type Notifier struct {
	tokenHash [sha256.Size]byte
	allow     map[netip.Addr]bool
	// command is the gram command: it runs as
	// <command> gram send --from keyring <text>, never through a shell.
	command string

	mu   sync.Mutex
	sent []time.Time // the notices of the last minute, oldest first
}

// NewNotifier builds the notify listener's handler. token is the notice
// token (ReadToken), allow the source IPs it answers, command the gram
// command's path.
func NewNotifier(token string, allow []netip.Addr, command string) *Notifier {
	n := &Notifier{tokenHash: sha256.Sum256([]byte(token)), allow: map[netip.Addr]bool{}, command: command}
	for _, a := range allow {
		n.allow[a.Unmap()] = true
	}
	return n
}

// NotifyText cleans a notice's text: invalid UTF-8 and characters that do
// not print are dropped, line breaks and tabs become spaces. It reports
// false for a text that is then empty, longer than 1000 characters, or
// starts with "-" (herdr would read it as an option).
func NotifyText(raw string) (string, bool) {
	text := strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case r == utf8.RuneError || !unicode.IsPrint(r) && r != ' ':
			return -1
		}
		return r
	}, strings.ToValidUTF8(raw, "")))
	if text == "" || utf8.RuneCountInString(text) > notifyTextLimit || strings.HasPrefix(text, "-") {
		return "", false
	}
	return text, true
}

func (n *Notifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != NotifyPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	src, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !n.allow[src.Addr().Unmap()] {
		http.Error(w, "source not allowed", http.StatusForbidden)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	// Hashes compare in constant time whatever the length sent.
	if got := sha256.Sum256([]byte(token)); !ok || subtle.ConstantTimeCompare(got[:], n.tokenHash[:]) != 1 {
		http.Error(w, "wrong token", http.StatusUnauthorized)
		return
	}
	if r.ContentLength > notifyBodyLimit {
		http.Error(w, "body over 4 KiB", http.StatusRequestEntityTooLarge)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, notifyBodyLimit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "body over 4 KiB", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	var body struct {
		Text *string `json:"text"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() || body.Text == nil {
		http.Error(w, `want {"text": "..."}`, http.StatusBadRequest)
		return
	}
	text, ok := NotifyText(*body.Text)
	if !ok {
		http.Error(w, "text must be 1 to 1000 printable characters, not starting with -", http.StatusBadRequest)
		return
	}
	if !n.take() {
		http.Error(w, "over 60 notices a minute", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), notifyTimeout)
	defer cancel()
	// No stdin, stdout or stderr: Run returns as soon as the command ends
	// or is killed.
	if err := exec.CommandContext(ctx, n.command, "gram", "send", "--from", "keyring", text).Run(); err != nil {
		msg := "gram command failed: " + err.Error()
		if ctx.Err() != nil {
			msg = "gram command timed out"
		}
		http.Error(w, msg, http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// take counts one notice, or reports false when the last minute already
// had notifyPerMinute.
func (n *Notifier) take() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	cut := 0
	for cut < len(n.sent) && now.Sub(n.sent[cut]) >= time.Minute {
		cut++
	}
	n.sent = n.sent[cut:]
	if len(n.sent) >= notifyPerMinute {
		return false
	}
	n.sent = append(n.sent, now)
	return true
}
