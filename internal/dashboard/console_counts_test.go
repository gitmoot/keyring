package dashboard

import (
	"net/url"
	"regexp"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

func stat(t *testing.T, page, label string) string {
	t.Helper()
	m := regexp.MustCompile(`<small>` + label + `</small><b>(\d+)</b>`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no %q in the numbers strip", label)
	}
	return m[1]
}

// One call to a service that sends two keys is one call, not one per key
// (review of #121).
func TestCallsTodayCountsAServiceWithTwoKeysOnce(t *testing.T) {
	e := newEnv(t)
	api, _ := twoSecretAPI(t)
	e.request("POST", "/keys", url.Values{"name": {"MODAL_PROXY_SECRET"}, "value": {modalSecret}, "password": {password}})
	e.addAndConnect("MODAL_PROXY_ID", modalID, url.Values{"pasted": {`{"service":"modal-ocr","base":"` + api.URL + `","auth":"header","header":"Modal-Key","extra_headers":{"Modal-Secret":"MODAL_PROXY_SECRET"}}`}})
	cfg := e.proxy.Config()
	access := cfg.AccessList
	role := access.Roles["phobos"]
	role.Access = map[string]policy.Access{"modal-ocr": {Paths: []string{"/"}}}
	access.Roles["phobos"] = role
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	e.proxy.Swap(next, mustKeys(t, e))
	if code := e.call("GET", "/modal-ocr/health", token); code != 200 {
		t.Fatalf("call: %d", code)
	}
	if got := stat(t, e.request("GET", "/keys", nil).Body.String(), "Calls today"); got != "1" {
		t.Fatalf("Calls today = %s after one call, want 1", got)
	}
}

// The sidebar counts the same keys the Keys page lists, including a key a
// service names that has no stored value yet (review of #121).
func TestSidebarKeyCountIncludesKeysWithoutAValue(t *testing.T) {
	e := newEnv(t)
	cfg := e.proxy.Config()
	access := cfg.AccessList
	access.Services["later"] = policy.Service{Base: "https://api.example.com", Key: "NOT_STORED_YET", Auth: policy.AuthBearer}
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	e.proxy.Swap(next, mustKeys(t, e))
	page := e.request("GET", "/keys", nil).Body.String()
	want := stat(t, page, "Keys")
	side := regexp.MustCompile(`href="/keys" class="nav[^"]*">Keys<span class="n">(\d+)</span>`).FindStringSubmatch(page)
	if side == nil || side[1] != want {
		t.Fatalf("sidebar Keys = %v, page lists %s", side, want)
	}
}

func mustKeys(t *testing.T, e *env) map[string]string {
	t.Helper()
	keys, err := store.Load(e.backend.StorePath)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}
