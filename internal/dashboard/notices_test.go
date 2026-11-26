package dashboard

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/store"
)

// noticeTokenKey is the notice token's store key in newEnv's rules.
const noticeTokenKey = "KEYRING_NOTIFY_TOKEN"

// Owner, 2026-11-26: the Bitcoin service page shows the signature notice
// channel (Gram, the only one offered) and sends a test notice after the
// password, audited; the token is named, never shown, not even on request.
func TestSignatureNoticesOnTheServicePage(t *testing.T) {
	e := newEnv(t)
	addMainnet(e)
	const token = "notice-token-0123456789abcdef"
	if err := store.Set(e.backend.StorePath, noticeTokenKey, token); err != nil {
		t.Fatal(err)
	}
	page := e.request("GET", "/services/btc-main", nil).Body.String()
	for _, want := range []string{"<h2>Signature notices</h2>", "<dt>Channel</dt><dd>Gram</dd>", "/notify</dd>", "<dt>Channels offered</dt><dd>Gram</dd>",
		`action="/services/btc-main/test-notice"`, noticeTokenKey + " <span class=\"mute\">never shown</span>"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the service page lacks %q", want)
		}
	}
	if strings.Contains(page, token) {
		t.Fatal("the service page shows the notice token")
	}
	e.seenAuth.Store("")
	if w := e.request("POST", "/services/btc-main/test-notice", url.Values{"password": {"wrong"}}); w.Code != http.StatusForbidden || e.seenAuth.Load() != "" {
		t.Fatalf("without the password: %d, relay saw %q", w.Code, e.seenAuth.Load())
	}
	w := e.request("POST", "/services/btc-main/test-notice", url.Values{"password": {password}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Test notice sent: it should reach you on Gram shortly.") {
		t.Fatalf("test notice: %d %s", w.Code, w.Body.String())
	}
	if e.seenAuth.Load() != "Bearer "+token {
		t.Fatal("the relay did not get the notice token")
	}
	if !strings.Contains(e.audit.String(), `"admin":"signature_notice_test"`) || !strings.Contains(e.audit.String(), `"sent":true`) || strings.Contains(e.audit.String(), token) {
		t.Fatalf("audit: %s", e.audit.String())
	}
	// The relay refusing it shows on the page and in the audit.
	e.status.Store(http.StatusBadGateway)
	w = e.request("POST", "/services/btc-main/test-notice", url.Values{"password": {password}})
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "The test notice was not sent: the relay answered 502 Bad Gateway") || !strings.Contains(e.audit.String(), `"sent":false`) {
		t.Fatalf("refused test notice: %d", w.Code)
	}
	// Never shown.
	if w := e.request("POST", "/keys/"+noticeTokenKey+"/reveal", url.Values{"password": {password}}); w.Code != http.StatusSeeOther || !strings.HasSuffix(w.Header().Get("Location"), "?error=never-shown") {
		t.Fatalf("reveal: %d %s", w.Code, w.Header().Get("Location"))
	}
	key := e.request("GET", "/keys/"+noticeTokenKey+"?error=never-shown", nil).Body.String()
	if strings.Contains(key, "/reveal") || !strings.Contains(key, "The signature notice token is never shown") || strings.Contains(key, token) {
		t.Fatal("the key page offers to show the notice token")
	}
}
