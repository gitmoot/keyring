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
