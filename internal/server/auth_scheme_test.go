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

// The Cloudflare asset upload sends the caller's own Bearer upload token; a
// scheme set for the stored account token does not apply to it.
func TestAssetUploadKeepsBearerWithAScheme(t *testing.T) {
	h, _ := newHandler(t, cfBase, policy.Service{Auth: policy.AuthBearer, Scheme: "Key"}, allowAll)
	rec := &cfRecorder{}
	h.client = &http.Client{Transport: rec}
	w := call(h, "POST", "/api"+cfUploadPath, testToken, map[string]string{"Authorization": "Bearer " + cfUploadJWT})
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	if out, _ := rec.last(t); out.Header.Get("Authorization") != "Bearer "+cfUploadJWT {
		t.Fatalf("upload sent Authorization %q", out.Header.Get("Authorization"))
	}
	call(h, "GET", "/api/zones", testToken, nil)
	if out, _ := rec.last(t); out.Header.Get("Authorization") != "Key "+testKey {
		t.Fatal("other calls do not send the stored key with its scheme")
	}
}
