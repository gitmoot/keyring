package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
)

// tlsUpstream is an https server with a self-signed certificate, and the
// SHA-256 of that certificate's DER.
func tlsUpstream(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/redirect":
			http.Redirect(w, r, "https://elsewhere.example/steal", http.StatusFound)
		default:
			_, _ = io.WriteString(w, "ok "+r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		}
	}))
	t.Cleanup(srv.Close)
	sum := sha256.Sum256(srv.Certificate().Raw)
	return srv, hex.EncodeToString(sum[:])
}

// pinned builds a bearer service from the documented JSON form, with an
// optional tls_pin_sha256 and test_path.
func pinned(t *testing.T, pin, testPath string) policy.Service {
	t.Helper()
	var svc policy.Service
	doc := `{"auth":"bearer","key":"API_KEY","test_path":` + strconv.Quote(testPath) + `,"tls_pin_sha256":` + strconv.Quote(pin) + `}`
	if err := json.Unmarshal([]byte(doc), &svc); err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestPinnedServiceTrustsExactlyItsCertificate(t *testing.T) {
	up, pin := tlsUpstream(t)

	h, audit := newHandler(t, up.URL, pinned(t, pin, ""), allowAll)
	w := call(h, "GET", "/api/v1/caps", testToken, nil)
	if w.Code != 200 || !strings.HasPrefix(w.Body.String(), "ok GET /v1/caps Bearer ") {
		t.Fatalf("matching pin: %d %q", w.Code, w.Body.String())
	}
	if w := call(h, "GET", "/api/v1/redirect", testToken, nil); w.Code != http.StatusFound {
		t.Fatalf("pinned client followed a redirect: %d", w.Code)
	}
	if strings.Contains(audit.String(), testKey) {
		t.Fatal("key in audit log")
	}

	wrong := strings.Repeat("0", 64)
	h, audit = newHandler(t, up.URL, pinned(t, wrong, ""), allowAll)
	w = call(h, "GET", "/api/v1/caps", testToken, nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "does not match the pinned certificate") {
		t.Fatalf("wrong pin: %d %q", w.Code, w.Body.String())
	}
	if !strings.Contains(audit.String(), "does not match the pinned certificate") {
		t.Fatalf("audit lacks pin mismatch note: %s", audit.String())
	}

	// Without a pin the same self-signed upstream is still refused: system
	// roots only.
	h, _ = newHandler(t, up.URL, bearer, allowAll)
	w = call(h, "GET", "/api/v1/caps", testToken, nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "upstream unreachable") {
		t.Fatalf("unpinned self-signed upstream: %d %q", w.Code, w.Body.String())
	}
}

func TestTestKeyUsesPinnedClient(t *testing.T) {
	up, pin := tlsUpstream(t)
	h, _ := newHandler(t, up.URL, pinned(t, pin, "/v1/capabilities"), allowAll)
	svc := h.Config().Services["api"]
	if status, err := h.TestKey(context.Background(), svc, testKey); err != nil || status != 200 {
		t.Fatalf("matching pin: %d %v", status, err)
	}
	other, _ := newHandler(t, up.URL, pinned(t, strings.Repeat("a", 64), "/v1/capabilities"), allowAll)
	if _, err := other.TestKey(context.Background(), other.Config().Services["api"], testKey); err == nil || !strings.Contains(err.Error(), "pinned certificate") {
		t.Fatalf("wrong pin: %v", err)
	}
	plain, _ := newHandler(t, up.URL, pinned(t, "", "/v1/capabilities"), allowAll)
	if _, err := plain.TestKey(context.Background(), plain.Config().Services["api"], testKey); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("unpinned self-signed: %v", err)
	}
}
