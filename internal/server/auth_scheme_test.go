package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
)

func TestBearerServiceSendsItsAuthorizationScheme(t *testing.T) {
	for scheme, want := range map[string]string{"": "Bearer " + testKey, "Key": "Key " + testKey} {
		var got []string
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Values("Authorization")
			w.Write([]byte("echo " + testKey))
		}))
		h, _ := newHandler(t, up.URL, policy.Service{Auth: policy.AuthBearer, Scheme: scheme}, allowAll)
		w := call(h, "GET", "/api/v1/generations", testToken, map[string]string{"Authorization": "Key caller-supplied"})
		up.Close()
		if w.Code != http.StatusOK {
			t.Fatalf("scheme %q: %d %s", scheme, w.Code, w.Body.String())
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("scheme %q: upstream got Authorization %q, want only the stored key with scheme %q", scheme, got, strings.Fields(want)[0])
		}
		if strings.Contains(w.Body.String(), testKey) {
			t.Errorf("scheme %q: key echoed back unmasked", scheme)
		}
	}
}
