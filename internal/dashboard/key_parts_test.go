package dashboard

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

func addModal(e *env) *http.Response {
	w := e.request("POST", "/keys", url.Values{"name": {"MODAL"}, "value": {""},
		"part": {"id", "secret", "", ""}, "part_value": {modalID, modalSecret, "", ""}, "password": {password}})
	return w.Result()
}

func grantPhobos(t *testing.T, e *env, service string) {
	t.Helper()
	cfg := e.proxy.Config()
	access := cfg.AccessList
	role := access.Roles["phobos"]
	role.Access = map[string]policy.Access{service: {Paths: []string{"/"}}}
	access.Roles["phobos"] = role
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	e.proxy.Swap(next, mustKeys(t, e))
}

// The owner adds one key MODAL with two named values, connects a service with
// the form (id as the key, secret as an extra header), tests it, and an agent's
// call sends both. One row on the Keys page; no value is ever shown.
func TestKeyWithTwoNamedValues(t *testing.T) {
	e := newEnv(t)
	api, seen := twoSecretAPI(t)
	if res := addModal(e); res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/keys/MODAL?done=added" {
		t.Fatalf("add: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	keys := mustKeys(t, e)
	if keys["MODAL.id"] != modalID || keys["MODAL.secret"] != modalSecret || keys["MODAL"] != "" {
		t.Fatalf("stored names = %v", sortedNames(keys))
	}
	w := e.request("POST", "/keys/MODAL/connect", url.Values{"service": {"modal-ocr"}, "base": {api.URL}, "auth": {"header"},
		"header": {"Modal-Key"}, "test_path": {"/health"}, "key_part": {"id"}, "part_header_secret": {"Modal-Secret"}, "password": {password}})
	if w.Header().Get("Location") != "/keys/MODAL?done=connected" {
		t.Fatalf("connect: %d %s", w.Code, w.Body.String())
	}
	svc := e.proxy.Config().Services["modal-ocr"]
	if svc.Key != "MODAL.id" || svc.ExtraHeaders["Modal-Secret"] != "MODAL.secret" {
		t.Fatalf("service = key %s extra %v", svc.Key, svc.ExtraHeaders)
	}
	if loc := e.request("POST", "/keys/MODAL/test", url.Values{}).Header().Get("Location"); !strings.Contains(loc, "done=tested") {
		t.Fatalf("test: %s", loc)
	}
	grantPhobos(t, e, "modal-ocr")
	if code := e.call("GET", "/modal-ocr/health", token); code != 200 {
		t.Fatalf("agent call: %d", code)
	}
	for i, h := range seen() {
		if h.Get("Modal-Key") != modalID || h.Get("Modal-Secret") != modalSecret {
			t.Fatalf("request %d did not carry both values", i)
		}
	}
	page := e.request("GET", "/keys", nil).Body.String()
	if strings.Count(page, `href="/keys/MODAL"`) != 1 || strings.Contains(page, "MODAL.id") {
		t.Fatal("MODAL is not one row on the Keys page")
	}
	key := e.request("GET", "/keys/MODAL", nil).Body.String()
	if !strings.Contains(key, ">id<") || !strings.Contains(key, ">secret<") || !strings.Contains(key, "Working") {
		t.Fatal("the key page does not list both values or the test result")
	}
	if all := page + key + e.audit.String(); strings.Contains(all, modalID) || strings.Contains(all, modalSecret) {
		t.Fatal("a value is shown or logged")
	}
}

// One value of the key is replaced; a new one can be added; a single-value
// key keeps working as before; delete removes every value.
func TestReplaceAndDeleteNamedValues(t *testing.T) {
	e := newEnv(t)
	addModal(e)
	if loc := e.request("POST", "/keys/MODAL/replace", url.Values{"part": {"secret"}, "value": {"ws-new-secret-0123456789"}, "password": {password}}).Header().Get("Location"); loc != "/keys/MODAL?done=replaced" {
		t.Fatalf("replace: %s", loc)
	}
	if loc := e.request("POST", "/keys/MODAL/replace", url.Values{"part": {"region"}, "value": {"eu-west-1"}, "password": {password}}).Header().Get("Location"); loc != "/keys/MODAL?done=replaced" {
		t.Fatalf("add a value: %s", loc)
	}
	keys := mustKeys(t, e)
	if keys["MODAL.secret"] != "ws-new-secret-0123456789" || keys["MODAL.id"] != modalID || keys["MODAL.region"] != "eu-west-1" {
		t.Fatalf("after replace: %v", sortedNames(keys))
	}
	if loc := e.request("POST", "/keys/MODAL/replace", url.Values{"value": {"x-0123456789"}, "password": {password}}).Header().Get("Location"); loc != "/keys/MODAL?error=part" {
		t.Fatalf("replace without naming the value: %s", loc)
	}
	if loc := e.request("POST", "/keys/MODAL/delete", url.Values{"password": {password}}).Header().Get("Location"); loc != "/keys?done=deleted" {
		t.Fatalf("delete: %s", loc)
	}
	for name := range mustKeys(t, e) {
		if base, _ := store.SplitPart(name); base == "MODAL" {
			t.Fatalf("%s left after delete", name)
		}
	}
	if loc := e.request("POST", "/keys/API_KEY/replace", url.Values{"part": {"id"}, "value": {"x-0123456789"}, "password": {password}}).Header().Get("Location"); loc != "/keys/API_KEY?error=part" {
		t.Fatalf("part on a single-value key: %s", loc)
	}
}

// Bad forms store nothing: one named value only, a bad name, a duplicate,
// a missing value, a name already used, a dotted key name.
func TestNamedValueRefusals(t *testing.T) {
	e := newEnv(t)
	before := len(mustKeys(t, e))
	for name, form := range map[string]url.Values{
		"one value only":  {"name": {"MODAL"}, "part": {"id"}, "part_value": {modalID}},
		"bad value name":  {"name": {"MODAL"}, "part": {"Id!", "secret"}, "part_value": {modalID, modalSecret}},
		"duplicate name":  {"name": {"MODAL"}, "part": {"id", "id"}, "part_value": {modalID, modalSecret}},
		"missing value":   {"name": {"MODAL"}, "part": {"id", "secret"}, "part_value": {modalID, ""}},
		"dotted key name": {"name": {"MODAL.id"}, "value": {modalID}},
		"name in use":     {"name": {"API_KEY"}, "part": {"id", "secret"}, "part_value": {modalID, modalSecret}},
	} {
		form.Set("password", password)
		if w := e.request("POST", "/keys", form); w.Code == http.StatusSeeOther || strings.Contains(w.Body.String(), modalSecret) {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if after := len(mustKeys(t, e)); after != before {
		t.Fatalf("a refused form stored %d values", after-before)
	}
	// Connecting a key with values must say which value is the key.
	addModal(e)
	if w := e.request("POST", "/keys/MODAL/connect", url.Values{"service": {"m"}, "base": {"https://example.modal.run"}, "auth": {"bearer"}, "password": {password}}); w.Code != http.StatusBadRequest {
		t.Fatalf("connect without key_part: %d", w.Code)
	}
}

// Pasted settings name the key's values by part name.
func TestPasteNamesValuesByPart(t *testing.T) {
	e := newEnv(t)
	addModal(e)
	pasted := `{"service":"modal-ocr","base":"https://ws--app-web.modal.run","auth":"header","header":"Modal-Key","key_part":"id","extra_headers":{"Modal-Secret":"secret"}}`
	if loc := e.request("POST", "/keys/MODAL/connect", url.Values{"pasted": {pasted}, "password": {password}}).Header().Get("Location"); loc != "/keys/MODAL?done=connected" {
		t.Fatalf("paste: %s", loc)
	}
	if svc := e.proxy.Config().Services["modal-ocr"]; svc.Key != "MODAL.id" || svc.ExtraHeaders["Modal-Secret"] != "MODAL.secret" {
		t.Fatalf("service = %s %v", svc.Key, svc.ExtraHeaders)
	}
}
