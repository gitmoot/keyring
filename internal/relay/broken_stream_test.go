package relay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRelayPassesBrokenStreamOnAsBrokenConnection(t *testing.T) {
	var cut atomic.Bool
	cut.Store(true)
	keyring := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "event: content_block_delta\n\n")
		w.(http.Flusher).Flush()
		if !cut.Load() {
			_, _ = io.WriteString(w, "event: message_stop\n\n")
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer keyring.Close()
	front := httptest.NewServer(New(mustUpstream(t, keyring.URL), map[string]string{"phobos": tokenPhobos}))
	defer front.Close()
	get := func() (string, error) {
		resp, err := http.Post(front.URL+"/phobos/anthropic/v1/messages", "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}
	if body, err := get(); err == nil {
		t.Fatalf("stream cut at the keyring ended cleanly for the caller: %q", body)
	} else if !strings.Contains(body, "content_block_delta") {
		t.Fatalf("the part before the cut was not passed on: %q", body)
	}
	cut.Store(false)
	if body, err := get(); err != nil || !strings.HasSuffix(body, "message_stop\n\n") {
		t.Fatalf("complete stream: %q, %v", body, err)
	}
}
