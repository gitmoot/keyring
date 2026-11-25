package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// brokenUpstream sends headers and part of a chunked body, then drops the
// connection without the final chunk.
func brokenUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: content_block_delta\n\n")
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
}

func serveFromCaller(h http.Handler) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = caller + ":51000"
		h.ServeHTTP(w, r)
	}))
}

func getThrough(t *testing.T, url string) (string, error) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set(TokenHeader, testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func TestBrokenUpstreamStreamReachesCallerAsBrokenConnection(t *testing.T) {
	up := brokenUpstream(t)
	defer up.Close()
	h, audit := newHandler(t, up.URL, bearer, allowAll)
	front := serveFromCaller(h)
	body, err := getThrough(t, front.URL+"/api/v1/messages")
	front.Close() // waits for the handler, so the audit line is written
	if err == nil {
		t.Fatalf("stream cut upstream ended cleanly for the caller: %q", body)
	}
	if !strings.Contains(body, "content_block_delta") {
		t.Fatalf("the part before the cut was not passed on: %q", body)
	}
	if !strings.Contains(audit.String(), `"upstream read failed"`) {
		t.Fatalf("audit line: %s", audit.String())
	}

	// A complete stream still ends cleanly.
	up = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "event: content_block_delta\n\n")
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "event: message_stop\n\n")
	}))
	defer up.Close()
	h, audit = newHandler(t, up.URL, bearer, allowAll)
	front = serveFromCaller(h)
	body, err = getThrough(t, front.URL+"/api/v1/messages")
	front.Close()
	if err != nil || !strings.HasSuffix(body, "message_stop\n\n") {
		t.Fatalf("complete stream: %q, %v", body, err)
	}
	if strings.Contains(audit.String(), "upstream read failed") {
		t.Fatalf("audit line: %s", audit.String())
	}
}
