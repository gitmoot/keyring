package relay

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRelayGivesHTTP10CallerWholeAnswerOrA502(t *testing.T) {
	// The keyring cuts the answer to /cut and completes every other one.
	keyring := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "event: content_block_delta\n\n")
		w.(http.Flusher).Flush()
		if r.URL.Path != "/anthropic/v1/messages/cut" {
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
	get := func(path string) (*http.Response, string) {
		conn, err := net.Dial("tcp", front.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "GET /phobos/anthropic/v1/"+path+" HTTP/1.0\r\nHost: x\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("HTTP/1.0 body: %v", err)
		}
		return resp, string(body)
	}
	if resp, body := get("messages/cut"); resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "content_block_delta") {
		t.Fatalf("cut stream to an HTTP/1.0 caller: %d %q", resp.StatusCode, body)
	}
	if resp, body := get("messages"); resp.StatusCode != 200 || resp.ContentLength != int64(len(body)) || !strings.HasSuffix(body, "message_stop\n\n") {
		t.Fatalf("complete answer to an HTTP/1.0 caller: %d len %d %q", resp.StatusCode, resp.ContentLength, body)
	}
}
