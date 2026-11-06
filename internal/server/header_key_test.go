package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
)

// A key with a line break or control character cannot be put in an HTTP
// header: Go refuses to send the request. That is a problem with the stored
// key, not with the network, and must be said so (the owner chased a network
// problem after replacing a key, gitmoot/keyring#109).
func TestUnsendableKeyIsReportedAsTheKeyAndNotCharged(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
	}{
		{"trailing newline", testKey + "\n"},
		{"trailing carriage return", testKey + "\r"},
		{"line break inside", "sk-first-line\nsk-second-line"},
		{"control character", "sk-abc\x1bdef"},
		{"NUL", "sk-abc\x00def"},
		{"DEL", "sk-abc\x7fdef"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, seen := upstream(t)
			h, audit := newHandlerKey(t, up.URL, bearer, policy.Access{Paths: []string{"/"}, Methods: []string{"GET"}, DailyRequests: 1}, tc.key)
			w := call(h, "GET", "/api/v1/x", testToken, nil)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "stored key API_KEY contains a line break or control character") {
				t.Fatalf("status = %d, body %q: want 503 naming the key problem, not an upstream error", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "unreachable") {
				t.Fatalf("a key problem is reported as a network problem: %q", w.Body.String())
			}
			if seen.count() != 0 {
				t.Fatal("a request with an unsendable key reached the service")
			}
			if strings.Contains(w.Body.String()+audit.String(), "sk-") {
				t.Fatalf("key text appears in the reply or audit log: %q %q", w.Body.String(), audit.String())
			}
		})
	}
}

// The refusals above must not use up the daily limit: after the key is fixed
// the first call goes through.
func TestUnsendableKeyDoesNotSpendTheDailyLimit(t *testing.T) {
	up, _ := upstream(t)
	h, _ := newHandlerKey(t, up.URL, bearer, policy.Access{Paths: []string{"/"}, Methods: []string{"GET"}, DailyRequests: 1}, testKey+"\n")
	for i := 0; i < 3; i++ {
		if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("call %d: status = %d, want 503", i, w.Code)
		}
	}
	h.Swap(h.Config(), map[string]string{"API_KEY": testKey})
	if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK {
		t.Fatalf("after the key is fixed: status = %d, want 200 (refused calls spent the limit?)", w.Code)
	}
}

// Valid keys are untouched: ordinary characters, spaces, tabs and non-ASCII
// bytes are legal in a header value and must keep working.
func TestSendableKeysStillWork(t *testing.T) {
	for _, key := range []string{testKey, "sk live with spaces", "sk\twith\ttab", "sk-caf\u00e9-\u00fc"} {
		up, seen := upstream(t)
		h, _ := newHandlerKey(t, up.URL, bearer, allowAll, key)
		if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK {
			t.Fatalf("key %q: status = %d, want 200", key, w.Code)
		}
		if got := seen.last(t).Header.Get("Authorization"); got != "Bearer "+key {
			t.Fatalf("key %q was changed on the way: %q", key, got)
		}
	}
}

// A line break in an extra credential header's key (two-header services) is
// the same problem and is named the same way.
func TestUnsendableExtraKeyIsReported(t *testing.T) {
	up, seen := upstream(t)
	svc := policy.Service{Auth: policy.AuthHeader, Header: "CF-Access-Client-Id", ExtraHeaders: map[string]string{"CF-Access-Client-Secret": "EXTRA_KEY"}}
	h, _ := newHandler(t, up.URL, svc, allowAll)
	h.Swap(h.Config(), map[string]string{"API_KEY": testKey, "EXTRA_KEY": "secret\n"})
	w := call(h, "GET", "/api/v1/x", testToken, nil)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "stored key EXTRA_KEY contains a line break or control character") || seen.count() != 0 {
		t.Fatalf("status = %d, body %q, service calls = %d", w.Code, w.Body.String(), seen.count())
	}
}

// The dashboard's Test button reports the same cause instead of "service
// unreachable", and sends nothing.
func TestKeyTestNamesAnUnsendableKey(t *testing.T) {
	up, seen := upstream(t)
	svc := policy.Service{Auth: policy.AuthBearer, TestPath: "/v1/check"}
	h, _ := newHandler(t, up.URL, svc, allowAll)
	got := h.Config().Services["api"]
	if _, err := h.TestKey(context.Background(), got, testKey+"\n"); err == nil || !strings.Contains(err.Error(), "stored key API_KEY contains a line break or control character") || strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("TestKey error = %v, want the key problem named", err)
	}
	if seen.count() != 0 {
		t.Fatal("the test request was sent with an unsendable key")
	}
	if status, err := h.TestKey(context.Background(), got, testKey); err != nil || status != http.StatusOK {
		t.Fatalf("a good key: %d %v", status, err)
	}
}
