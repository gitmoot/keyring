package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
)

const (
	cfBase       = "https://api.cloudflare.com/client/v4"
	cfAccount    = "0123456789abcdef0123456789abcdef"
	cfUploadPath = "/accounts/" + cfAccount + "/workers/assets/upload"
	cfUploadJWT  = "upload-session.jwt.from-the-same-deploy"
)

// cfRecorder answers every request and remembers what the service would have
// received. The reply echoes the account token, as a careless API might.
type cfRecorder struct {
	mu    sync.Mutex
	calls []*http.Request
	body  []string
}

func (c *cfRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.calls = append(c.calls, r.Clone(r.Context()))
	c.body = append(c.body, string(b))
	c.mu.Unlock()
	return &http.Response{
		StatusCode: 200, Header: http.Header{}, Request: r,
		Body: io.NopCloser(strings.NewReader("echo " + testKey)),
	}, nil
}

func (c *cfRecorder) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

func (c *cfRecorder) last(t *testing.T) (*http.Request, string) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.calls) == 0 {
		t.Fatal("the service was never called")
	}
	return c.calls[len(c.calls)-1], c.body[len(c.body)-1]
}

func cloudflareHandler(t *testing.T, base string, access policy.Access) (*Handler, *cfRecorder) {
	t.Helper()
	h, _ := newHandler(t, base, bearer, access)
	rec := &cfRecorder{}
	h.client = &http.Client{Transport: rec}
	return h, rec
}

func TestAssetUploadSendsTheCallersTokenNotTheAccountToken(t *testing.T) {
	h, svc := cloudflareHandler(t, cfBase, allowAll)
	w := call(h, "POST", "/api"+cfUploadPath+"?base64=true", testToken, map[string]string{"Authorization": "Bearer " + cfUploadJWT})
	if w.Code != 200 {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	out, body := svc.last(t)
	if got := out.Header.Get("Authorization"); got != "Bearer "+cfUploadJWT {
		t.Fatalf("service received Authorization %q, want the caller's upload token", got)
	}
	if out.URL.String() != cfBase+cfUploadPath+"?base64=true" || body != "payload" {
		t.Fatalf("request not forwarded as sent: %s %q", out.URL, body)
	}
	for name, values := range out.Header {
		for _, v := range values {
			if strings.Contains(v, testKey) {
				t.Fatalf("account token sent in %s", name)
			}
		}
	}
	if strings.Contains(w.Body.String(), testKey) {
		t.Fatal("account token echoed by the service was not masked")
	}
}

func TestAssetUploadWithoutATokenIsRefusedAndNotCharged(t *testing.T) {
	h, svc := cloudflareHandler(t, cfBase, policy.Access{Paths: []string{"/"}, Methods: []string{"POST"}, DailyRequests: 1})
	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"none", nil},
		{"not bearer", map[string]string{"Authorization": "Basic abc"}},
		{"empty bearer", map[string]string{"Authorization": "Bearer "}},
		{"space inside", map[string]string{"Authorization": "Bearer a b"}},
		{"oversized", map[string]string{"Authorization": "Bearer " + strings.Repeat("a", 8193)}},
	} {
		if w := call(h, "POST", "/api"+cfUploadPath, testToken, tc.headers); w.Code != 401 {
			t.Errorf("%s: status = %d, want 401", tc.name, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/api"+cfUploadPath, strings.NewReader("payload"))
	r.RemoteAddr = caller + ":51000"
	r.Header.Set(TokenHeader, testToken)
	r.Header.Add("Authorization", "Bearer one")
	r.Header.Add("Authorization", "Bearer two")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Errorf("two Authorization headers: status = %d, want 401", w.Code)
	}
	if svc.count() != 0 {
		t.Fatal("a refused upload reached the service")
	}
	// None of the refusals spent the daily limit of one.
	if w := call(h, "POST", "/api"+cfUploadPath, testToken, map[string]string{"Authorization": "Bearer " + cfUploadJWT}); w.Code != 200 {
		t.Fatalf("refusals used up the daily limit: status = %d", w.Code)
	}
}

// Every other call keeps the account token, whatever the caller sends: the
// exception covers exactly one path and no other.
func TestOnlyTheExactUploadCallDropsTheAccountToken(t *testing.T) {
	account := "/accounts/" + cfAccount
	cases := []struct {
		name, base, method, path string
	}{
		{"upload by GET", cfBase, "GET", account + "/workers/assets/upload"},
		{"script upload", cfBase, "POST", account + "/workers/scripts/app/assets-upload-session"},
		{"longer path", cfBase, "POST", account + "/workers/assets/upload/extra"},
		{"prefix path", cfBase, "POST", account + "/workers/assets/uploads"},
		{"short account id", cfBase, "POST", "/accounts/abc/workers/assets/upload"},
		{"upper-case account id", cfBase, "POST", "/accounts/" + strings.ToUpper(cfAccount) + "/workers/assets/upload"},
		{"another host", "https://api.example.com/client/v4", "POST", account + "/workers/assets/upload"},
		{"another base path", "https://api.cloudflare.com/other", "POST", account + "/workers/assets/upload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, svc := cloudflareHandler(t, tc.base, allowAll)
			if w := call(h, tc.method, "/api"+tc.path, testToken, map[string]string{"Authorization": "Bearer " + cfUploadJWT}); w.Code != 200 {
				t.Fatalf("status = %d", w.Code)
			}
			out, _ := svc.last(t)
			if got := out.Header.Get("Authorization"); got != "Bearer "+testKey {
				t.Fatalf("service received Authorization %q, want the account token", got)
			}
		})
	}
}

func TestAssetUploadStillNeedsAccessToThePath(t *testing.T) {
	h, svc := cloudflareHandler(t, cfBase, policy.Access{Paths: []string{"/accounts/" + cfAccount + "/workers/scripts"}, Methods: []string{"POST"}})
	w := call(h, "POST", "/api"+cfUploadPath, testToken, map[string]string{"Authorization": "Bearer " + cfUploadJWT})
	if w.Code != 403 || svc.count() != 0 {
		t.Fatalf("status = %d, service calls = %d: a role without this path must not upload", w.Code, svc.count())
	}
}
