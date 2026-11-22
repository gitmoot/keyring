package dashboard

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
)

// Owner, 2026-11-22: a key can be renamed. Its service follows, so an
// agent's call still sends the same value, and the key's test result stays.
func TestRenameKeyKeepsItsServiceWorking(t *testing.T) {
	e := newEnv(t)
	if loc := e.request("POST", "/keys/API_KEY/test", url.Values{}).Header().Get("Location"); loc != "/keys/API_KEY?done=tested" {
		t.Fatalf("test: %s", loc)
	}
	e.request("POST", "/keys", url.Values{"name": {"OTHER"}, "value": {"other-value-0123456789"}, "password": {password}})
	for name, form := range map[string]url.Values{
		"wrong password": {"new_name": {"OPENAI_KEY"}, "password": {"nope"}},
		"name taken":     {"new_name": {"OTHER"}, "password": {password}},
		"starts digit":   {"new_name": {"9KEY"}, "password": {password}},
		"dotted":         {"new_name": {"OPENAI_KEY.main"}, "password": {password}},
	} {
		if loc := e.request("POST", "/keys/API_KEY/rename", form).Header().Get("Location"); !strings.HasPrefix(loc, "/keys/API_KEY?error=") {
			t.Errorf("%s: %s", name, loc)
		}
	}
	if loc := e.request("POST", "/keys/API_KEY/rename", url.Values{"new_name": {"OPENAI_KEY"}, "password": {password}}).Header().Get("Location"); loc != "/keys/OPENAI_KEY?done=renamed" {
		t.Fatalf("rename: %s", loc)
	}
	keys := mustKeys(t, e)
	if _, old := keys["API_KEY"]; old || keys["OPENAI_KEY"] != oldValue {
		t.Fatalf("stored names = %v", sortedNames(keys))
	}
	if got := e.proxy.Config().Services["api"].Key; got != "OPENAI_KEY" {
		t.Fatalf("service key = %s", got)
	}
	saved, err := policy.LoadAccess(e.proxy.Config().AccessFile)
	if err != nil || saved.Services["api"].Key != "OPENAI_KEY" {
		t.Fatalf("access file key = %s, %v", saved.Services["api"].Key, err)
	}
	if code := e.proxyCall(); code != 200 || e.seenAuth.Load() != "Bearer "+oldValue {
		t.Fatalf("call after rename: %d", code)
	}
	if page := e.request("GET", "/keys/OPENAI_KEY", nil).Body.String(); !strings.Contains(page, "Working") {
		t.Fatal("the test result did not move with the key")
	}
	if w := e.request("GET", "/keys/API_KEY", nil); w.Code != http.StatusNotFound {
		t.Fatalf("old name still has a page: %d", w.Code)
	}
	if audit := e.audit.String(); !strings.Contains(audit, "key_renamed") || strings.Contains(audit, oldValue) {
		t.Fatal("the rename is not audited, or a value is")
	}
}

// Renaming a value, and then its key, moves every reference: the key a
// service sends and the extra header naming the other value.
func TestRenameValueAndKeyMoveEveryReference(t *testing.T) {
	e := newEnv(t)
	api, _ := twoSecretAPI(t)
	addModal(e)
	if loc := e.request("POST", "/keys/MODAL/connect", url.Values{"service": {"modal-ocr"}, "base": {api.URL}, "auth": {"header"},
		"header": {"Modal-Key"}, "key_part": {"id"}, "part_header_secret": {"Modal-Secret"}, "password": {password}}).Header().Get("Location"); loc != "/keys/MODAL?done=connected" {
		t.Fatalf("connect: %s", loc)
	}
	grantPhobos(t, e, "modal-ocr")
	if loc := e.request("POST", "/keys/MODAL/rename-value", url.Values{"part": {"secret"}, "new_part": {"id"}, "password": {password}}).Header().Get("Location"); loc != "/keys/MODAL?error=value-taken" {
		t.Fatalf("rename onto another value: %s", loc)
	}
	if loc := e.request("POST", "/keys/MODAL/rename-value", url.Values{"part": {"secret"}, "new_part": {"token"}, "password": {password}}).Header().Get("Location"); loc != "/keys/MODAL?done=value-renamed" {
		t.Fatalf("rename value: %s", loc)
	}
	if svc := e.proxy.Config().Services["modal-ocr"]; svc.Key != "MODAL.id" || svc.ExtraHeaders["Modal-Secret"] != "MODAL.token" {
		t.Fatalf("service = %s %v", svc.Key, svc.ExtraHeaders)
	}
	if code := e.call("GET", "/modal-ocr/run", token); code != 200 {
		t.Fatalf("call after value rename: %d", code)
	}
	if loc := e.request("POST", "/keys/MODAL/rename", url.Values{"new_name": {"MODAL_WS"}, "password": {password}}).Header().Get("Location"); loc != "/keys/MODAL_WS?done=renamed" {
		t.Fatalf("rename key: %s", loc)
	}
	if svc := e.proxy.Config().Services["modal-ocr"]; svc.Key != "MODAL_WS.id" || svc.ExtraHeaders["Modal-Secret"] != "MODAL_WS.token" {
		t.Fatalf("service = %s %v", svc.Key, svc.ExtraHeaders)
	}
	if code := e.call("GET", "/modal-ocr/run", token); code != 200 {
		t.Fatalf("call after key rename: %d", code)
	}
	if audit := e.audit.String(); strings.Contains(audit, modalID) || strings.Contains(audit, modalSecret) {
		t.Fatal("a value is in the audit log")
	}
}

// The one value of a plain key gets a name (API_KEY becomes API_KEY.main);
// the service that used API_KEY uses API_KEY.main and keeps working.
func TestNamingTheOnlyValueKeepsItsServiceWorking(t *testing.T) {
	e := newEnv(t)
	if loc := e.request("POST", "/keys/API_KEY/rename-value", url.Values{"new_part": {"main"}, "password": {password}}).Header().Get("Location"); loc != "/keys/API_KEY?done=value-named" {
		t.Fatalf("name the value: %s", loc)
	}
	keys := mustKeys(t, e)
	if _, plain := keys["API_KEY"]; plain || keys["API_KEY.main"] != oldValue {
		t.Fatalf("stored names = %v", sortedNames(keys))
	}
	if got := e.proxy.Config().Services["api"].Key; got != "API_KEY.main" {
		t.Fatalf("service key = %s", got)
	}
	if code := e.proxyCall(); code != 200 || e.seenAuth.Load() != "Bearer "+oldValue {
		t.Fatalf("call after naming: %d", code)
	}
}

// Owner, 2026-11-22: pasting key-pool settings on a key added with one plain
// value said only "leave key_part out". It now says to name the value first;
// once named and given a backup, the same paste makes a working pool.
func TestPoolSettingsOnAOneValueKey(t *testing.T) {
	e := newEnv(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "sk-ant-b1-1111" {
			w.WriteHeader(401)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-main-0000"}, "password": {password}})
	pasted := `{"service":"claude-api","base":"` + up.URL + `","auth":"header","header":"x-api-key","key_part":"main","key_pool":true}`
	w := e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {pasted}, "password": {password}})
	if body := html.UnescapeString(w.Body.String()); w.Code != http.StatusBadRequest || !strings.Contains(body, "Give it a name first (below)") || !strings.Contains(body, `href="#name-value"`) || !strings.Contains(body, `id="name-value"`) {
		t.Fatalf("paste on a one-value key: %d", w.Code)
	}
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/rename-value", url.Values{"new_part": {"main"}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=value-named" {
		t.Fatalf("name the value: %s", loc)
	}
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/replace", url.Values{"part": {"backup1"}, "value": {"sk-ant-b1-1111"}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=replaced" {
		t.Fatalf("add backup: %s", loc)
	}
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {pasted}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=connected" {
		t.Fatalf("paste after naming: %s", loc)
	}
	if w := e.saveCell("phobos", "claude-api", url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}}); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatalf("grant: %d", w.Code)
	}
	if code := e.call("POST", "/claude-api/v1/messages", token); code != 200 {
		t.Fatalf("pooled call: %d", code)
	}
}

// A key may have one named value, or more than four (up to 32); the form
// offers a button for more rows.
func TestAddKeyWithOneOrManyNamedValues(t *testing.T) {
	e := newEnv(t)
	if !strings.Contains(e.request("GET", "/new/key", nil).Body.String(), `data-addrow="part-rows"`) {
		t.Fatal("the add-key form has no Add another value button")
	}
	form := func(name string, n int) url.Values {
		f := url.Values{"name": {name}, "value": {""}, "password": {password}}
		for i := range n {
			f.Add("part", fmt.Sprintf("v%d", i))
			f.Add("part_value", fmt.Sprintf("value-%d-0123456789", i))
		}
		return f
	}
	for _, n := range []int{1, 6, 32} {
		name := fmt.Sprintf("KEY_%d", n)
		if loc := e.request("POST", "/keys", form(name, n)).Header().Get("Location"); loc != "/keys/"+name+"?done=added" {
			t.Fatalf("%d values: %s", n, loc)
		}
	}
	if w := e.request("POST", "/keys", form("KEY_33", 33)); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "At most 32 values") {
		t.Fatalf("33 values: %d", w.Code)
	}
	if len(mustKeys(t, e)) != 1+1+6+32 {
		t.Fatal("a refused form stored values, or an accepted one did not")
	}
}

// One value of a key can be removed, unless a service sends it: as its key,
// as an extra header, or as the value a key pool tries first. Another pooled
// value just leaves the pool.
func TestRemoveOneValue(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {""},
		"part": {"main", "backup1", "backup2"}, "part_value": {"sk-ant-main-0000", "sk-ant-b1-1111", "sk-ant-b2-2222"}, "password": {password}})
	e.withService("claude-api", policy.Service{Base: "https://api.anthropic.com", Key: "CLAUDE_KEYS.main", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true})
	addModal(e)
	e.request("POST", "/keys/MODAL/connect", url.Values{"service": {"modal-ocr"}, "base": {"https://ws.modal.run"}, "auth": {"header"},
		"header": {"Modal-Key"}, "key_part": {"id"}, "part_header_secret": {"Modal-Secret"}, "password": {password}})
	e.request("POST", "/keys", url.Values{"name": {"SOLO"}, "value": {""}, "part": {"only"}, "part_value": {"solo-value-0123456789"}, "password": {password}})
	remove := func(key, part string) string {
		return e.request("POST", "/keys/"+key+"/remove-value", url.Values{"part": {part}, "password": {password}}).Header().Get("Location")
	}
	if loc := remove("CLAUDE_KEYS", "backup1"); loc != "/keys/CLAUDE_KEYS?done=value-removed" {
		t.Fatalf("remove a pooled backup: %s", loc)
	}
	for _, c := range []struct{ key, part, want string }{
		{"CLAUDE_KEYS", "main", "/keys/CLAUDE_KEYS?error=value-pool-first&service=claude-api"},
		{"MODAL", "secret", "/keys/MODAL?error=value-used&service=modal-ocr"},
		{"MODAL", "id", "/keys/MODAL?error=value-used&service=modal-ocr"},
		{"SOLO", "only", "/keys/SOLO?error=value-only"},
		{"API_KEY", "", "/keys/API_KEY?error=value-plain"},
	} {
		if loc := remove(c.key, c.part); loc != c.want {
			t.Errorf("remove %s.%s: %s", c.key, c.part, loc)
		}
	}
	keys := mustKeys(t, e)
	if _, ok := keys["CLAUDE_KEYS.backup1"]; ok {
		t.Fatal("backup1 is still stored")
	}
	for _, kept := range []string{"CLAUDE_KEYS.main", "CLAUDE_KEYS.backup2", "MODAL.id", "MODAL.secret", "SOLO.only", "API_KEY"} {
		if _, ok := keys[kept]; !ok {
			t.Errorf("%s was removed", kept)
		}
	}
	page := html.UnescapeString(e.request("GET", "/keys/CLAUDE_KEYS?error=value-pool-first&service=claude-api", nil).Body.String())
	if !strings.Contains(page, "Service claude-api is a key pool that tries this value first") {
		t.Fatal("the refusal does not say which pool")
	}
}

// Owner, 2026-11-22: opening /keys/{name}/connect in the browser showed an
// error; it opens the key's page, where the connect form is.
func TestOpeningTheConnectAddressOpensTheKey(t *testing.T) {
	e := newEnv(t)
	if w := e.request("GET", "/keys/API_KEY/connect", nil); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/keys/API_KEY" {
		t.Fatalf("GET connect: %d %s", w.Code, w.Header().Get("Location"))
	}
}

// Owner, 2026-11-22: on "Connect to a service" the Settings are closed until
// a connect fails.
func TestConnectSettingsAreClosedUntilAnError(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"PLAIN_THING"}, "value": {"thing-value-0123456789"}, "password": {password}})
	page := e.request("GET", "/keys/PLAIN_THING", nil).Body.String()
	if !strings.Contains(page, "<details><summary>Settings") {
		t.Fatal("Settings are open on a fresh key page")
	}
	w := e.request("POST", "/keys/PLAIN_THING/connect", url.Values{"pasted": {"{not json"}, "password": {password}})
	if !strings.Contains(w.Body.String(), "<details open><summary>Settings") {
		t.Fatal("Settings stay closed after a failed connect")
	}
}
