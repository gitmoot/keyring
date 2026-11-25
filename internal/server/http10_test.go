package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// getHTTP10 sends an HTTP/1.0 request and reads the whole reply.
func getHTTP10(t *testing.T, srv *httptest.Server, path string, headers string) (*http.Response, string) {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET "+path+" HTTP/1.0\r\nHost: x\r\n"+headers+"\r\n")
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

func TestHTTP10CallerGetsWholeAnswerOrA502(t *testing.T) {
	up := brokenUpstream(t)
	defer up.Close()
	h, audit := newHandler(t, up.URL, bearer, allowAll)
	front := serveFromCaller(h)
	resp, body := getHTTP10(t, front, "/api/v1/messages", TokenHeader+": "+testToken+"\r\n")
	front.Close()
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "content_block_delta") {
		t.Fatalf("cut stream to an HTTP/1.0 caller: %d %q", resp.StatusCode, body)
	}
	if !strings.Contains(audit.String(), `"upstream read failed"`) {
		t.Fatalf("audit line: %s", audit.String())
	}

	up = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "event: content_block_delta\n\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "event: message_stop\n\n")
	}))
	defer up.Close()
	h, _ = newHandler(t, up.URL, bearer, allowAll)
	front = serveFromCaller(h)
	defer front.Close()
	resp, body = getHTTP10(t, front, "/api/v1/messages", TokenHeader+": "+testToken+"\r\n")
	if resp.StatusCode != 200 || resp.ContentLength != int64(len(body)) || !strings.HasSuffix(body, "message_stop\n\n") {
		t.Fatalf("complete answer to an HTTP/1.0 caller: %d len %d %q", resp.StatusCode, resp.ContentLength, body)
	}
}
