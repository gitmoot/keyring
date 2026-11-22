package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// #161 review: a cut-off or oversized answer is an error, never printed as
// if it were the list; an answer without the "ask" hint does not crash.
func TestServicesCLIRejectsBadAnswers(t *testing.T) {
	// Each case has its own server answering a fixed body, so no handler
	// goroutine reads state the test changes.
	run := func(body string, declared int, asJSON bool) (string, error) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if declared > 0 {
				w.Header().Set("Content-Length", strconv.Itoa(declared))
			}
			io.WriteString(w, body)
		}))
		defer srv.Close()
		var out bytes.Buffer
		err := listServices("", srv.URL, "", "", asJSON, &out)
		return out.String(), err
	}
	// Complete, valid JSON with an overstated Content-Length: only the read
	// error can make this fail, so ignoring it would print the list (#162-f1).
	if out, err := run(`{"services":[{"name":"a","auth":"bearer","kind":"proxy"}]}`, 1000, true); err == nil || out != "" || !strings.Contains(err.Error(), "reading the keyring's answer") {
		t.Fatalf("cut-off answer: err %v, printed %q", err, out)
	}
	if out, err := run(`{"services":[],"x":"`+strings.Repeat("a", 4<<20)+`"}`, 0, true); err == nil || out != "" {
		t.Fatalf("oversized answer: err %v, printed %d bytes", err, len(out))
	}
	if out, err := run(`{"services":[{"name":"a","auth":"bearer","kind":"proxy"}]}`, 0, false); err != nil || !strings.Contains(out, "a ") {
		t.Fatalf("answer without ask: %v %q", err, out)
	}
}
