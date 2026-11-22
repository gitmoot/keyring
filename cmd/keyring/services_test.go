package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #161 review: a cut-off or oversized answer is an error, never printed as
// if it were the list; an answer without the "ask" hint does not crash.
func TestServicesCLIRejectsBadAnswers(t *testing.T) {
	var body string
	var short bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if short {
			w.Header().Set("Content-Length", "1000")
		}
		io.WriteString(w, body)
	}))
	defer srv.Close()
	run := func(asJSON bool) (string, error) {
		var out bytes.Buffer
		err := listServices("", srv.URL, "", "", asJSON, &out)
		return out.String(), err
	}
	body, short = `{"services":[{"name":"a","auth":"bearer","kind":"proxy"}]`, true
	if out, err := run(true); err == nil || out != "" {
		t.Fatalf("cut-off answer: err %v, printed %q", err, out)
	}
	body, short = `{"services":[],"x":"`+strings.Repeat("a", 4<<20)+`"}`, false
	if out, err := run(true); err == nil || out != "" {
		t.Fatalf("oversized answer: err %v, printed %d bytes", err, len(out))
	}
	body = `{"services":[{"name":"a","auth":"bearer","kind":"proxy"}]}`
	if out, err := run(false); err != nil || !strings.Contains(out, "a ") {
		t.Fatalf("answer without ask: %v %q", err, out)
	}
}
