package dashboard

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// An Apple push key, imported with `keyring set --file` (it is multi-line),
// is connected from its key page with one pasted line; no agent gets access
// by that, and the key's text never shows.
func TestConnectAPNsKey(t *testing.T) {
	e := newEnv(t)
	const p8 = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfixture\n-----END PRIVATE KEY-----"
	if err := store.Set(e.backend.StorePath, "TANDEM_APNS_KEY", p8); err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(e.proxy.Config(), keys)
	pasted := `{"service":"apns","base":"https://api.push.apple.com","auth":"apns","apns":{"key_id":"ABC123DEFG","team_id":"TEAM456789"}}`
	w := e.request("POST", "/keys/TANDEM_APNS_KEY/connect", url.Values{"pasted": {pasted}, "password": {password}})
	if w.Header().Get("Location") != "/keys/TANDEM_APNS_KEY?done=connected" {
		t.Fatalf("connect: %d %s", w.Code, w.Body.String())
	}
	svc := e.proxy.Config().Services["apns"]
	if svc.Auth != policy.AuthAPNs || svc.Key != "TANDEM_APNS_KEY" || svc.APNs == nil || svc.APNs.KeyID != "ABC123DEFG" || svc.APNs.TeamID != "TEAM456789" {
		t.Fatalf("service = %+v", svc)
	}
	for role, rl := range e.proxy.Config().Roles {
		if _, ok := rl.Access["apns"]; ok {
			t.Fatalf("connecting gave %s access", role)
		}
	}
	// Another host is refused by the policy check, and nothing is written.
	before := e.accessBytes()
	bad := strings.Replace(strings.Replace(pasted, "api.push.apple.com", "push.example.com", 1), `"apns","base"`, `"apns2","base"`, 1)
	if w := e.request("POST", "/keys/TANDEM_APNS_KEY/connect", url.Values{"pasted": {bad}, "password": {password}}); w.Code != http.StatusBadRequest || !bytesEqual(e.accessBytes(), before) {
		t.Fatalf("APNs service to another host: %d", w.Code)
	}
	if strings.Contains(e.everyPage("/keys", "/keys/TANDEM_APNS_KEY", "/services/apns")+e.audit.String(), "fixture") {
		t.Fatal("key text on a page or in the audit log")
	}
}
