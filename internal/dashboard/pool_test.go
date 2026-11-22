package dashboard

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
)

// Owner, 2026-11-22: the key page shows each pooled value's state and use,
// so it is clear which keys are used and which have problems.
func TestKeyPageShowsEachPooledValue(t *testing.T) {
	e := newEnv(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "sk-ant-main-0000" {
			w.WriteHeader(401)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return
		}
		io.WriteString(w, `{"ok":true}`)
	}))
	defer up.Close()
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {""},
		"part": {"main", "backup1", "", ""}, "part_value": {"sk-ant-main-0000", "sk-ant-b1-1111", "", ""}, "password": {password}})
	e.withService("claude-api", policy.Service{Base: up.URL, Key: "CLAUDE_KEYS.main", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true})
	if w := e.saveCell("phobos", "claude-api", url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}}); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatalf("grant: %d %s", w.Code, w.Body)
	}
	if code := e.call("POST", "/claude-api/v1/messages", token); code != 200 {
		t.Fatalf("pooled call: %d; audit %s", code, e.audit.String())
	}
	page := html.UnescapeString(e.request("GET", "/keys/CLAUDE_KEYS", nil).Body.String())
	for _, want := range []string{"Failing: 401 key rejected", "Working", "1 today", "1 refused today", "1 of 2 values set aside (main: 401 key rejected)", "Key pool:"} {
		if !strings.Contains(page, want) {
			t.Errorf("key page lacks %q", want)
		}
	}
	if strings.Contains(page, "sk-ant-") {
		t.Fatal("a key value is on the page")
	}
	if !strings.Contains(e.request("GET", "/services/claude-api", nil).Body.String(), "Key pool") {
		t.Error("service page does not say it is a key pool")
	}
}

// A pool works while any of its values is stored: one whose first value is
// missing is not shown as having no value.
func TestPoolWithoutItsFirstValueHasAValue(t *testing.T) {
	e := newEnv(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"ok":true}`) }))
	defer up.Close()
	if w := e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {""},
		"part": {"backup1", "backup2", "", ""}, "part_value": {"sk-ant-b1-1111", "sk-ant-b2-2222", "", ""}, "password": {password}}); w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	e.withService("claude-api", policy.Service{Base: up.URL, Key: "CLAUDE_KEYS.main", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true})
	if w := e.saveCell("phobos", "claude-api", url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}}); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatalf("grant: %d %s", w.Code, w.Body)
	}
	if code := e.call("POST", "/claude-api/v1/messages", token); code != 200 {
		t.Fatalf("pooled call without main: %d", code)
	}
	rows, err := e.backend.rows()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Name == "CLAUDE_KEYS" && (!row.HasValue || row.State == "novalue" || row.Status == "No value stored") {
			t.Fatalf("pool with backup1 stored shows %q (%s)", row.Status, row.State)
		}
	}
	if page := e.request("GET", "/keys/CLAUDE_KEYS", nil).Body.String(); strings.Contains(page, "No value stored") {
		t.Fatal("key page says no value is stored")
	}
}

// A value stored under the bare name is not a pool member: a pool with only
// that has nothing to send and shows no value, as the proxy refuses its
// calls.
func TestPoolWithOnlyABareValueHasNoValue(t *testing.T) {
	e := newEnv(t)
	if w := e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-bare-0000"}, "password": {password}}); w.Code != http.StatusSeeOther {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	e.withService("claude-api", policy.Service{Base: "https://api.anthropic.com", Key: "CLAUDE_KEYS.main", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true})
	rows, err := e.backend.rows()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Name == "CLAUDE_KEYS" && (row.HasValue || row.State != "novalue") {
			t.Fatalf("pool with only a bare value shows %q (%s), HasValue %v", row.Status, row.State, row.HasValue)
		}
	}
}

// Pasted settings on the service page keep key_pool when they leave it out;
// an explicit false turns it off.
func TestEditKeepsKeyPool(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {""},
		"part": {"main", "backup1", "", ""}, "part_value": {"sk-ant-main-0000", "sk-ant-b1-1111", "", ""}, "password": {password}})
	base := `"base":"https://api.anthropic.com","auth":"header","header":"x-api-key"`
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {`{"service":"claude-api",` + base + `,"key_part":"main","key_pool":true}`}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=connected" {
		t.Fatalf("connect: %s", loc)
	}
	pool := func() bool { return e.proxy.Config().Services["claude-api"].KeyPool }
	if !pool() {
		t.Fatal("connect did not turn key_pool on")
	}
	if w := e.edit("claude-api", url.Values{"pasted": {`{` + base + `}`}}); w.Header().Get("Location") != "/services/claude-api?done=saved" || !pool() {
		t.Fatalf("paste without key_pool: %d, key_pool %v", w.Code, pool())
	}
	if w := e.edit("claude-api", url.Values{"pasted": {`{` + base + `,"key_pool":false}`}}); w.Header().Get("Location") != "/services/claude-api?done=saved" || pool() {
		t.Fatalf("paste with key_pool false: %d, key_pool %v", w.Code, pool())
	}
}
