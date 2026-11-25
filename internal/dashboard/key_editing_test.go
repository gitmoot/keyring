package dashboard

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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

// Owner, 2026-11-22: values need no names. Values added without one are
// numbered 1, 2, 3; a number is never given again, even after its value is
// removed. Each value may have a label (at most 80 characters).
func TestUnnamedValuesAreNumberedNeverReused(t *testing.T) {
	e := newEnv(t)
	if loc := e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-a-0000", "sk-ant-b-1111", "sk-ant-c-2222"},
		"label": {"Jerry's Max", "", ""}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=added" {
		t.Fatalf("add: %s", loc)
	}
	keys := mustKeys(t, e)
	if keys["CLAUDE_KEYS.1"] != "sk-ant-a-0000" || keys["CLAUDE_KEYS.2"] != "sk-ant-b-1111" || keys["CLAUDE_KEYS.3"] != "sk-ant-c-2222" {
		t.Fatalf("stored names = %v", sortedNames(keys))
	}
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/remove-value", url.Values{"part": {"3"}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=value-removed" {
		t.Fatalf("remove 3: %s", loc)
	}
	add := func(label string) string {
		return e.request("POST", "/keys/CLAUDE_KEYS/add-value", url.Values{"value": {"sk-ant-d-3333"}, "label": {label}, "password": {password}}).Header().Get("Location")
	}
	if loc := add(strings.Repeat("x", 81)); loc != "/keys/CLAUDE_KEYS?error=label" {
		t.Fatalf("81-character label: %s", loc)
	}
	if loc := add("Spare"); loc != "/keys/CLAUDE_KEYS?done=value-added" {
		t.Fatalf("add a value: %s", loc)
	}
	keys = mustKeys(t, e)
	if _, reused := keys["CLAUDE_KEYS.3"]; reused || keys["CLAUDE_KEYS.4"] != "sk-ant-d-3333" {
		t.Fatalf("stored names after remove and add = %v", sortedNames(keys))
	}
	page := html.UnescapeString(e.request("GET", "/keys/CLAUDE_KEYS", nil).Body.String())
	if !strings.Contains(page, "1 · Jerry's Max") || !strings.Contains(page, "4 · Spare") || strings.Contains(page, "sk-ant-") {
		t.Fatal("the key page does not show the numbered values with their labels")
	}
}

// recordingAPI answers 200 and records the x-api-key of each call; keys in
// reject answer 401.
func recordingAPI(t *testing.T, reject ...string) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("x-api-key")
		mu.Lock()
		seen = append(seen, key)
		mu.Unlock()
		if slices.Contains(reject, key) {
			w.WriteHeader(401)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(up.Close)
	return up, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// Owner, 2026-11-22: the key-pool paste failed. The paste names no value: a
// pool over a key with unnamed values tries them in list order and moves on
// when one is refused. key_part with key_pool is refused.
func TestPastedPoolFailsOverInListOrder(t *testing.T) {
	e := newEnv(t)
	up, seen := recordingAPI(t, "sk-ant-a-0000")
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-a-0000", "sk-ant-b-1111"}, "password": {password}})
	settings := `"service":"claude-api","base":"` + up.URL + `","auth":"header","header":"x-api-key","key_pool":true`
	w := e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {`{` + settings + `,"key_part":"1"}`}, "password": {password}})
	if w.Code != http.StatusBadRequest || !strings.Contains(html.UnescapeString(w.Body.String()), "Leave key_part out") {
		t.Fatalf("key_part with key_pool: %d", w.Code)
	}
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {`{` + settings + `}`}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=connected" {
		t.Fatalf("paste: %s", loc)
	}
	if got := e.proxy.Config().Services["claude-api"].Key; got != "CLAUDE_KEYS" {
		t.Fatalf("pool key = %s", got)
	}
	grantPhobos(t, e, "claude-api")
	if code := e.call("POST", "/claude-api/v1/messages", token); code != 200 {
		t.Fatalf("pooled call: %d", code)
	}
	if got := seen(); !slices.Equal(got, []string{"sk-ant-a-0000", "sk-ant-b-1111"}) {
		t.Fatalf("upstream saw %d calls in another order", len(got))
	}
}

// Owner, 2026-11-22: pool order is list order. Move up puts a value before
// the one above it, and the pool tries it first from then on.
func TestMoveUpChangesWhichValueAPoolTriesFirst(t *testing.T) {
	e := newEnv(t)
	up, seen := recordingAPI(t)
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-a-0000", "sk-ant-b-1111"}, "password": {password}})
	pasted := `{"service":"claude-api","base":"` + up.URL + `","auth":"header","header":"x-api-key","key_pool":true}`
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {pasted}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=connected" {
		t.Fatalf("paste: %s", loc)
	}
	grantPhobos(t, e, "claude-api")
	e.call("POST", "/claude-api/v1/messages", token)
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/move-up", url.Values{"part": {"2"}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=value-moved" {
		t.Fatalf("move up: %s", loc)
	}
	e.call("POST", "/claude-api/v1/messages", token)
	if got := seen(); !slices.Equal(got, []string{"sk-ant-a-0000", "sk-ant-b-1111"}) {
		t.Fatal("the pool did not try the moved-up value first")
	}
}

// Adding a value to a key with one plain value numbers both (API_KEY becomes
// API_KEY.1, the new one API_KEY.2); the service that sent API_KEY sends
// API_KEY.1 and keeps working.
func TestAddingAValueToAPlainKeyKeepsItsService(t *testing.T) {
	e := newEnv(t)
	if loc := e.request("POST", "/keys/API_KEY/add-value", url.Values{"value": {"sk-dash-second-0123456789"}, "password": {password}}).Header().Get("Location"); loc != "/keys/API_KEY?done=value-added" {
		t.Fatalf("add a value: %s", loc)
	}
	keys := mustKeys(t, e)
	if _, plain := keys["API_KEY"]; plain || keys["API_KEY.1"] != oldValue || keys["API_KEY.2"] != "sk-dash-second-0123456789" {
		t.Fatalf("stored names = %v", sortedNames(keys))
	}
	if got := e.proxy.Config().Services["api"].Key; got != "API_KEY.1" {
		t.Fatalf("service key = %s", got)
	}
	if code := e.proxyCall(); code != 200 || e.seenAuth.Load() != "Bearer "+oldValue {
		t.Fatalf("call after adding a value: %d", code)
	}
}

// A key may have one named value, or more than four (up to 32); the form
// offers a button for more rows.
func TestAddKeyWithOneOrManyNamedValues(t *testing.T) {
	e := newEnv(t)
	if !strings.Contains(e.request("GET", "/new/key", nil).Body.String(), `data-addrow="value-rows" data-max="32"`) {
		t.Fatal("the add-key form has no Add another value button up to 32 values")
	}
	form := func(name string, n int) url.Values {
		f := url.Values{"name": {name}, "password": {password}}
		for i := range n {
			f.Add("part", fmt.Sprintf("v%d", i))
			f.Add("value", fmt.Sprintf("value-%d-0123456789", i))
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

// Owner, 2026-11-25: the add-key form asks for one value; label and value
// name wait in closed details, and + adds more rows, each a copy of the
// first. The key page's Add a value card hides them the same way.
func TestAddKeyFormStartsWithOneValue(t *testing.T) {
	e := newEnv(t)
	page := e.request("GET", "/new/key", nil).Body.String()
	start := strings.Index(page, `<form method="post" action="/keys">`)
	form := page[start : start+strings.Index(page[start:], "</form>")]
	if n := strings.Count(form, `name="value"`); n != 1 {
		t.Fatalf("the form starts with %d value inputs, want 1", n)
	}
	hiddenOnly := func(where, s string) {
		t.Helper()
		closed := `<details class="more"><summary>Label or name</summary>`
		outside := s
		for {
			i := strings.Index(outside, closed)
			if i < 0 {
				break
			}
			end := strings.Index(outside[i:], "</details>")
			outside = outside[:i] + outside[i+end:]
		}
		if strings.Count(s, closed) != 1 || strings.Contains(outside, `name="label"`) || strings.Contains(outside, `name="part"`) {
			t.Fatalf("%s: label or value name is shown outside one closed details", where)
		}
	}
	hiddenOnly("add-key form", form)
	if !strings.Contains(form, `data-removerow aria-label="Remove this value" hidden`) || !strings.Contains(form, `aria-label="Add another value" hidden>+ Add value`) {
		t.Fatal("the rows lack their + and × buttons, hidden until the script runs")
	}
	keyPage := e.request("GET", "/keys/API_KEY", nil).Body.String()
	card := keyPage[strings.Index(keyPage, `id="add-value"`):]
	hiddenOnly("Add a value card", card[:strings.Index(card, "</form>")])

	// What three copied rows send, the last one left empty: the values in
	// order, each with its label and value name, empty ones too.
	if loc := e.request("POST", "/keys", url.Values{"name": {"ROWS"}, "value": {"row-a-0123456789", "row-b-0123456789", "row-c-0123456789", ""},
		"label": {"", "Backup", "", ""}, "part": {"", "", "", ""}, "password": {password}}).Header().Get("Location"); loc != "/keys/ROWS?done=added" {
		t.Fatalf("add: %s", loc)
	}
	keys := mustKeys(t, e)
	if keys["ROWS.1"] != "row-a-0123456789" || keys["ROWS.2"] != "row-b-0123456789" || keys["ROWS.3"] != "row-c-0123456789" || len(keys) != 1+3 {
		t.Fatalf("stored names = %v", sortedNames(keys))
	}
	if !strings.Contains(html.UnescapeString(e.request("GET", "/keys/ROWS", nil).Body.String()), "2 · Backup") {
		t.Fatal("the second row's label is not on the second value")
	}
}

// One value of a key can be removed, unless a service sends it: as its key
// or as an extra header. A key pool names the key, so a pooled value just
// leaves the pool, until one value is left.
func TestRemoveOneValue(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-main-0000", "sk-ant-b1-1111", "sk-ant-b2-2222"},
		"part": {"main", "backup1", "backup2"}, "password": {password}})
	e.withService("claude-api", policy.Service{Base: "https://api.anthropic.com", Key: "CLAUDE_KEYS", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true})
	addModal(e)
	e.request("POST", "/keys/MODAL/connect", url.Values{"service": {"modal-ocr"}, "base": {"https://ws.modal.run"}, "auth": {"header"},
		"header": {"Modal-Key"}, "key_part": {"id"}, "part_header_secret": {"Modal-Secret"}, "password": {password}})
	e.request("POST", "/keys", url.Values{"name": {"SOLO"}, "value": {"solo-value-0123456789"}, "part": {"only"}, "password": {password}})
	remove := func(key, part string) string {
		return e.request("POST", "/keys/"+key+"/remove-value", url.Values{"part": {part}, "password": {password}}).Header().Get("Location")
	}
	for _, part := range []string{"backup1", "main"} {
		if loc := remove("CLAUDE_KEYS", part); loc != "/keys/CLAUDE_KEYS?done=value-removed" {
			t.Fatalf("remove pooled %s: %s", part, loc)
		}
	}
	for _, c := range []struct{ key, part, want string }{
		{"CLAUDE_KEYS", "backup2", "/keys/CLAUDE_KEYS?error=value-only"},
		{"MODAL", "secret", "/keys/MODAL?error=value-used&service=modal-ocr"},
		{"MODAL", "id", "/keys/MODAL?error=value-used&service=modal-ocr"},
		{"SOLO", "only", "/keys/SOLO?error=value-only"},
		{"API_KEY", "", "/keys/API_KEY?error=value-only"},
	} {
		if loc := remove(c.key, c.part); loc != c.want {
			t.Errorf("remove %s.%s: %s", c.key, c.part, loc)
		}
	}
	keys := mustKeys(t, e)
	for _, gone := range []string{"CLAUDE_KEYS.backup1", "CLAUDE_KEYS.main"} {
		if _, ok := keys[gone]; ok {
			t.Errorf("%s is still stored", gone)
		}
	}
	for _, kept := range []string{"CLAUDE_KEYS.backup2", "MODAL.id", "MODAL.secret", "SOLO.only", "API_KEY"} {
		if _, ok := keys[kept]; !ok {
			t.Errorf("%s was removed", kept)
		}
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

// The list order is routing: a rename whose key notes cannot be written
// fails and changes nothing, and a pool keeps trying the moved-up value
// first, before and after a rename that succeeds.
func TestRenameKeepsThePoolOrderOrChangesNothing(t *testing.T) {
	e := newEnv(t)
	up, seen := recordingAPI(t)
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-a-0000", "sk-ant-b-1111"}, "password": {password}})
	pasted := `{"service":"claude-api","base":"` + up.URL + `","auth":"header","header":"x-api-key","key_pool":true}`
	e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {pasted}, "password": {password}})
	grantPhobos(t, e, "claude-api")
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/move-up", url.Values{"part": {"2"}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=value-moved" {
		t.Fatalf("move up: %s", loc)
	}
	metaPath := e.backend.MetaPath
	e.backend.MetaPath = filepath.Join(t.TempDir(), "missing", "keymeta.json")
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/rename", url.Values{"new_name": {"CLAUDE_POOL"}, "password": {password}}).Header().Get("Location"); loc == "/keys/CLAUDE_POOL?done=renamed" {
		t.Fatal("rename succeeded without its key notes")
	}
	e.backend.MetaPath = metaPath
	if got := e.proxy.Config().Services["claude-api"].Key; got != "CLAUDE_KEYS" {
		t.Fatalf("after the failed rename the pool names %s", got)
	}
	e.call("POST", "/claude-api/v1/messages", token)
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/rename", url.Values{"new_name": {"CLAUDE_POOL"}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_POOL?done=renamed" {
		t.Fatalf("rename: %s", loc)
	}
	e.call("POST", "/claude-api/v1/messages", token)
	if got := seen(); !slices.Equal(got, []string{"sk-ant-b-1111", "sk-ant-b-1111"}) {
		t.Fatal("the pool lost its order")
	}
}

// A value may be named with a large number; numbering the next value
// without a name still works.
func TestALargeNumberNameKeepsNumberingWorking(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"BIG"}, "value": {"big-value-0123456789"}, "part": {"9223372036854775807"}, "password": {password}})
	if loc := e.request("POST", "/keys/BIG/add-value", url.Values{"value": {"next-value-0123456789"}, "password": {password}}).Header().Get("Location"); loc != "/keys/BIG?done=value-added" {
		t.Fatalf("add a value: %s", loc)
	}
	if mustKeys(t, e)["BIG.1"] != "next-value-0123456789" {
		t.Fatalf("stored names = %v", sortedNames(mustKeys(t, e)))
	}
}

// The service editor turns a key pool on and off with the key in the same
// paste: on, the value picked stands for its key; off, a key with several
// values is refused until one value is picked.
func TestServiceEditorTurnsAPoolOnAndOff(t *testing.T) {
	e := newEnv(t)
	addModal(e)
	if loc := e.request("POST", "/keys/MODAL/connect", url.Values{"service": {"modal-ocr"}, "base": {"https://ws.modal.run"}, "auth": {"header"},
		"header": {"Modal-Key"}, "key_part": {"id"}, "password": {password}}).Header().Get("Location"); loc != "/keys/MODAL?done=connected" {
		t.Fatalf("connect: %s", loc)
	}
	settings := `"base":"https://ws.modal.run","auth":"header","header":"Modal-Key"`
	page := e.request("GET", "/services/modal-ocr", nil).Body.String()
	if !strings.Contains(page, "<option>MODAL</option>") || !strings.Contains(page, "MODAL.id</option>") {
		t.Fatal("the editor does not offer both the key and its values")
	}
	if w := e.edit("modal-ocr", url.Values{"key": {"MODAL.id"}, "pasted": {`{` + settings + `,"key_pool":true}`}}); w.Header().Get("Location") != "/services/modal-ocr?done=saved" {
		t.Fatalf("pool on: %d %s", w.Code, w.Body)
	}
	if svc := e.proxy.Config().Services["modal-ocr"]; !svc.KeyPool || svc.Key != "MODAL" {
		t.Fatalf("pool on: key %s pool %v", svc.Key, svc.KeyPool)
	}
	w := e.edit("modal-ocr", url.Values{"key": {"MODAL"}, "pasted": {`{` + settings + `,"key_pool":false}`}})
	if w.Code != http.StatusBadRequest || !strings.Contains(html.UnescapeString(w.Body.String()), "MODAL has several values") {
		t.Fatalf("pool off on the bare key: %d", w.Code)
	}
	if w := e.edit("modal-ocr", url.Values{"key": {"MODAL.secret"}, "pasted": {`{` + settings + `,"key_pool":false}`}}); w.Header().Get("Location") != "/services/modal-ocr?done=saved" {
		t.Fatalf("pool off: %d %s", w.Code, w.Body)
	}
	if svc := e.proxy.Config().Services["modal-ocr"]; svc.KeyPool || svc.Key != "MODAL.secret" {
		t.Fatalf("pool off: key %s pool %v", svc.Key, svc.KeyPool)
	}
}
