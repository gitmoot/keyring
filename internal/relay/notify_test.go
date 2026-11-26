package relay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const notifyToken = "notice-token-0123456789abcdef"

// gramScript is a fake herdr that writes each argument on a line of its own,
// then "--", to the file it returns.
func gramScript(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "argv")
	script := filepath.Join(dir, "herdr")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done >> '"+out+"'\necho -- >> '"+out+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return script, out
}

func notifyCall(n *Notifier, from, auth, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", NotifyPath, strings.NewReader(body))
	r.RemoteAddr = from + ":40000"
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	n.ServeHTTP(w, r)
	return w
}

// Owner, 2026-11-26: the relay's notify listener takes the keyring's notices
// from the allowed IPs only, with the notice token, a small JSON body, and
// runs the gram command with exact argv (never a shell), control characters
// stripped.
func TestNotifyListener(t *testing.T) {
	script, out := gramScript(t)
	keyring := "100.111.92.43"
	n := NewNotifier(notifyToken, []netip.Addr{netip.MustParseAddr(keyring)}, script)
	bearer := "Bearer " + notifyToken
	for name, c := range map[string]struct {
		from, auth, body string
		want             int
	}{
		"other IP":      {"100.64.0.9", bearer, `{"text":"hi"}`, http.StatusForbidden},
		"wrong token":   {keyring, "Bearer notice-token-0123456789abcdeX", `{"text":"hi"}`, http.StatusUnauthorized},
		"no token":      {keyring, "", `{"text":"hi"}`, http.StatusUnauthorized},
		"oversize":      {keyring, bearer, `{"text":"` + strings.Repeat("a", 4<<10) + `"}`, http.StatusRequestEntityTooLarge},
		"not JSON":      {keyring, bearer, `hi`, http.StatusBadRequest},
		"empty text":    {keyring, bearer, `{"text":"\u0007\u001b"}`, http.StatusBadRequest},
		"long text":     {keyring, bearer, `{"text":"` + strings.Repeat("a", 1001) + `"}`, http.StatusBadRequest},
		"option-like":   {keyring, bearer, `{"text":"--file /etc/shadow"}`, http.StatusBadRequest},
		"extra fields":  {keyring, bearer, `{"text":"hi","from":"x"}`, http.StatusBadRequest},
		"trailing data": {keyring, bearer, `{"text":"hi"}]`, http.StatusBadRequest},
	} {
		if w := notifyCall(n, c.from, c.auth, c.body); w.Code != c.want {
			t.Errorf("%s: %d, want %d", name, w.Code, c.want)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a refused notice ran the gram command")
	}
	w := notifyCall(n, keyring, bearer, `{"text":"keyring: mainnet\u001b[31m signature;\n$(id) `+"`id`"+` 'x'"}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("notice: %d %s", w.Code, w.Body.String())
	}
	raw, _ := os.ReadFile(out)
	if want := "gram\nsend\n--from\nkeyring\nkeyring: mainnet[31m signature; $(id) `id` 'x'\n--\n"; string(raw) != want {
		t.Fatalf("argv:\n%s\nwant:\n%s", raw, want)
	}
	// Only POST /notify.
	r := httptest.NewRequest("GET", NotifyPath, nil)
	r.RemoteAddr = keyring + ":40000"
	rec := httptest.NewRecorder()
	n.ServeHTTP(rec, r)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}
	r = httptest.NewRequest("POST", "/alice/api/v1", strings.NewReader(`{"text":"hi"}`))
	r.RemoteAddr = keyring + ":40000"
	r.Header.Set("Authorization", bearer)
	rec = httptest.NewRecorder()
	n.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("other path: %d", rec.Code)
	}
}

// A failing gram command answers 502; more than 60 notices a minute 429.
func TestNotifyListenerFailsAndLimits(t *testing.T) {
	keyring := netip.MustParseAddr("100.111.92.43")
	failing := filepath.Join(t.TempDir(), "herdr")
	if err := os.WriteFile(failing, []byte("#!/bin/sh\nexit 4\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if w := notifyCall(NewNotifier(notifyToken, []netip.Addr{keyring}, failing), keyring.String(), "Bearer "+notifyToken, `{"text":"hi"}`); w.Code != http.StatusBadGateway {
		t.Fatalf("failing command: %d", w.Code)
	}
	script, out := gramScript(t)
	n := NewNotifier(notifyToken, []netip.Addr{keyring}, script)
	for i := range 60 {
		if w := notifyCall(n, keyring.String(), "Bearer "+notifyToken, `{"text":"hi"}`); w.Code != http.StatusNoContent {
			t.Fatalf("notice %d: %d", i+1, w.Code)
		}
	}
	if w := notifyCall(n, keyring.String(), "Bearer "+notifyToken, `{"text":"hi"}`); w.Code != http.StatusTooManyRequests {
		t.Fatalf("notice 61: %d", w.Code)
	}
	raw, _ := os.ReadFile(out)
	if runs := strings.Count(string(raw), "--\n"); runs != 60 {
		t.Fatalf("the gram command ran %d times", runs)
	}
}

// A notice already taken runs its full time even when the caller goes
// away: the command has its own context, not the request's.
func TestNotifyRunsPastTheCaller(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "done")
	slow := filepath.Join(dir, "herdr")
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nsleep 0.5\necho done > '"+out+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	keyring := netip.MustParseAddr("100.111.92.43")
	n := NewNotifier(notifyToken, []netip.Addr{keyring}, slow)
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("POST", NotifyPath, strings.NewReader(`{"text":"hi"}`)).WithContext(ctx)
	r.RemoteAddr = keyring.String() + ":40000"
	r.Header.Set("Authorization", "Bearer "+notifyToken)
	time.AfterFunc(50*time.Millisecond, cancel)
	w := httptest.NewRecorder()
	n.ServeHTTP(w, r)
	if _, err := os.Stat(out); err != nil || w.Code != http.StatusNoContent {
		t.Fatalf("the gram command was cut short: %d %v", w.Code, err)
	}
}
