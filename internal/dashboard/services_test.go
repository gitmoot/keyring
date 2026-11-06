package dashboard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

func (e *env) accessBytes() []byte {
	e.t.Helper()
	raw, err := os.ReadFile(e.proxy.Config().AccessFile)
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

// withService adds svc to the running config, as an owner editing access.json
// and reloading would.
func (e *env) withService(name string, svc policy.Service) {
	e.t.Helper()
	access, err := policy.LoadAccess(e.proxy.Config().AccessFile)
	if err != nil {
		e.t.Fatal(err)
	}
	access.Services[name] = svc
	cfg, err := policy.SaveAccess(e.proxy.Config().Rules, access)
	if err != nil {
		e.t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(cfg, keys)
}

func (e *env) edit(name string, form url.Values) *httptest.ResponseRecorder {
	if form.Get("password") == "" {
		form.Set("password", password)
	}
	return e.request("POST", "/services/"+name, form)
}

// Fixing a service's settings must not touch who may use it: the old way was
// delete and re-add, which dropped every grant.
func TestEditServiceChangesSettingsAndKeepsGrants(t *testing.T) {
	e := newEnv(t)
	var gotAuth, gotHeader atomic.Value
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		gotHeader.Store(r.Header.Get("X-Api-Key"))
		w.WriteHeader(http.StatusOK)
	}))
	defer next.Close()
	const other = "sk-edit-other-VALUE-0123456789"
	e.request("POST", "/keys", url.Values{"name": {"OTHER_KEY"}, "value": {other}, "password": {password}})
	grantsBefore := e.proxy.Config().Roles["phobos"].Access

	page := e.request("GET", "/services/api", nil).Body.String()
	for _, want := range []string{`<h1 class="mono">api</h1>`, `href="/access/phobos/api"`, `<option selected>API_KEY</option>`, `<option>OTHER_KEY</option>`, `name="base" value="` + e.proxy.Config().Services["api"].Base + `"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("service page lacks %q:\n%s", want, page)
		}
	}
	if !strings.Contains(e.request("GET", "/keys/API_KEY", nil).Body.String(), `href="/services/api"`) {
		t.Fatal("the key page does not link to the service")
	}

	// Wrong base URL, wrong key: fixed in place.
	w := e.edit("api", url.Values{"key": {"OTHER_KEY"}, "base": {next.URL}, "auth": {"bearer"}, "test_path": {"/ping"}})
	if w.Header().Get("Location") != "/services/api?done=saved" {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	svc := e.proxy.Config().Services["api"]
	if svc.Base != next.URL || svc.Key != "OTHER_KEY" || svc.TestPath != "/ping" {
		t.Fatalf("running service not updated: %+v", svc)
	}
	if !reflect.DeepEqual(e.proxy.Config().Roles["phobos"].Access, grantsBefore) {
		t.Fatal("an edit changed an agent's access")
	}
	if e.proxyCall() != http.StatusOK || gotAuth.Load() != "Bearer "+other {
		t.Fatalf("the agent's next call did not use the new base and key: %v", gotAuth.Load())
	}
	// The saved file, not just memory, has the change (a reload keeps it).
	if reloaded, err := policy.LoadAccess(e.proxy.Config().AccessFile); err != nil || reloaded.Services["api"].Key != "OTHER_KEY" || reloaded.Roles["phobos"].Access["api"].Paths[0] != "/v1" {
		t.Fatalf("access file after edit: %+v %v", reloaded, err)
	}

	// Another auth kind.
	w = e.edit("api", url.Values{"key": {"OTHER_KEY"}, "base": {next.URL}, "auth": {"header"}, "header": {"X-Api-Key"}})
	if w.Header().Get("Location") != "/services/api?done=saved" {
		t.Fatalf("switch to header auth: %d %s", w.Code, w.Body.String())
	}
	if e.proxyCall() != http.StatusOK || gotHeader.Load() != other || gotAuth.Load() != "" {
		t.Fatalf("header auth not applied: X-Api-Key=%v Authorization=%v", gotHeader.Load(), gotAuth.Load())
	}

	if strings.Contains(e.audit.String(), other) || strings.Contains(e.everyPage("/services/api", "/keys/OTHER_KEY"), other) {
		t.Fatal("a key value appears in a page or the audit log")
	}
	if !strings.Contains(e.audit.String(), `"admin":"service_edited"`) || !strings.Contains(e.audit.String(), `"changed":["base","key","test_path"]`) {
		t.Fatalf("audit lacks the edit and the names of what changed: %s", e.audit.String())
	}
}

func TestRefusedEditChangesNothing(t *testing.T) {
	e := newEnv(t)
	before := e.accessBytes()
	cases := []struct {
		name   string
		form   url.Values
		status int
		want   string
	}{
		{"wrong password", url.Values{"password": {"nope"}, "base": {"https://api.example.com"}, "auth": {"bearer"}}, 403, "Enter your dashboard password"},
		{"invalid base", url.Values{"base": {"ftp://api.example.com"}, "auth": {"bearer"}}, 400, "base"},
		{"unknown key", url.Values{"key": {"NO_SUCH_KEY"}, "base": {"https://api.example.com"}, "auth": {"bearer"}}, 400, "no key named NO_SUCH_KEY"},
		{"header auth without a header", url.Values{"base": {"https://api.example.com"}, "auth": {"header"}}, 400, "header"},
		{"pasted names another service", url.Values{"pasted": {`{"service":"other","base":"https://api.example.com","auth":"bearer"}`}}, 400, "cannot be renamed"},
		{"pasted is not json", url.Values{"pasted": {"base=x"}}, 400, "not valid"},
		{"pasted has an unknown field", url.Values{"pasted": {`{"base":"https://api.example.com","auth":"bearer","key":"API_KEY"}`}}, 400, "not valid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := e.edit("api", tc.form)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.want) {
				t.Fatalf("status = %d, want %d containing %q:\n%s", w.Code, tc.status, tc.want, w.Body.String())
			}
			if !bytes.Equal(e.accessBytes(), before) {
				t.Fatal("a refused edit changed the access file")
			}
		})
	}
	if w := e.edit("missing", url.Values{"base": {"https://api.example.com"}, "auth": {"bearer"}}); w.Code != http.StatusNotFound {
		t.Fatalf("unknown service: %d", w.Code)
	}
	if w := e.request("GET", "/services/missing", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown service page: %d", w.Code)
	}
	if e.proxyCall() != http.StatusOK {
		t.Fatal("the service stopped working after refused edits")
	}
}

// The form shows base, key, auth, test path and pin. Settings it does not own
// must come through an edit unchanged, and the extra credential header names
// are shown without their values.
func TestEditKeepsWhatTheFormDoesNotShow(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"ACCESS_SECRET"}, "value": {"cf-secret-VALUE-0123456789"}, "password": {password}})
	e.withService("guarded", policy.Service{Base: "https://protected.example.com", Key: "API_KEY", Auth: policy.AuthHeader, Header: "CF-Access-Client-Id",
		ExtraHeaders: map[string]string{"CF-Access-Client-Secret": "ACCESS_SECRET"}, FixedHeaders: map[string]string{"CF-R2-Jurisdiction": "default"}})

	page := e.request("GET", "/services/guarded", nil).Body.String()
	if !strings.Contains(page, "CF-Access-Client-Secret") || !strings.Contains(page, "CF-R2-Jurisdiction: default") || strings.Contains(page, "cf-secret-VALUE") {
		t.Fatalf("service page: extra credentials must show by name only:\n%s", page)
	}
	w := e.edit("guarded", url.Values{"base": {"https://other.example.com"}, "auth": {"header"}, "header": {"CF-Access-Client-Id"}})
	if w.Header().Get("Location") != "/services/guarded?done=saved" {
		t.Fatalf("typed edit: %d %s", w.Code, w.Body.String())
	}
	svc := e.proxy.Config().Services["guarded"]
	if svc.Base != "https://other.example.com" || svc.ExtraHeaders["CF-Access-Client-Secret"] != "ACCESS_SECRET" || svc.FixedHeaders["CF-R2-Jurisdiction"] != "default" {
		t.Fatalf("typed edit lost settings the form does not show: %+v", svc)
	}
	// Pasted settings replace the fixed headers (documented on the page) but
	// still not the extra credentials.
	w = e.edit("guarded", url.Values{"pasted": {`{"base":"https://other.example.com","auth":"header","header":"CF-Access-Client-Id","fixed_headers":{"X-Region":"eu"}}`}})
	if w.Header().Get("Location") != "/services/guarded?done=saved" {
		t.Fatalf("pasted edit: %d %s", w.Code, w.Body.String())
	}
	svc = e.proxy.Config().Services["guarded"]
	if !reflect.DeepEqual(svc.FixedHeaders, map[string]string{"X-Region": "eu"}) || svc.ExtraHeaders["CF-Access-Client-Secret"] != "ACCESS_SECRET" {
		t.Fatalf("pasted edit: %+v", svc)
	}
}

// Sign-only, OAuth, Google and egress-proxy services carry fields the form
// cannot show; saving would silently drop them, so they are refused.
func TestServicesWithOtherSettingsAreNotEditedHere(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"SIGN_KEY"}, "value": {"AAAA"}, "password": {password}})
	e.withService("signer", policy.Service{Key: "SIGN_KEY", Auth: policy.AuthEd25519Sign})
	before := e.accessBytes()
	page := e.request("GET", "/services/signer", nil).Body.String()
	if strings.Contains(page, `action="/services/signer"`) || !strings.Contains(page, "access.json") {
		t.Fatalf("a sign-only service shows an edit form:\n%s", page)
	}
	w := e.edit("signer", url.Values{"base": {"https://x.example.com"}, "auth": {"bearer"}})
	if w.Code != http.StatusConflict || !bytes.Equal(e.accessBytes(), before) {
		t.Fatalf("sign-only edit: %d, file changed = %v", w.Code, !bytes.Equal(e.accessBytes(), before))
	}
	if e.proxy.Config().Services["signer"].Auth != policy.AuthEd25519Sign {
		t.Fatal("the signer was turned into another kind of service")
	}
}

// A request without the session's CSRF token never reaches the handler.
func TestEditNeedsASession(t *testing.T) {
	e := newEnv(t)
	before := e.accessBytes()
	e.cookie = ""
	w := e.request("POST", "/services/api", url.Values{"password": {password}, "base": {"https://x.example.com"}, "auth": {"bearer"}})
	if w.Code == http.StatusSeeOther && strings.Contains(w.Header().Get("Location"), "done=saved") || !bytes.Equal(e.accessBytes(), before) {
		t.Fatalf("an unauthenticated edit was applied: %d", w.Code)
	}
	if w := e.request("GET", "/services/api", nil); strings.Contains(w.Body.String(), `<h1 class="mono">api</h1>`) {
		t.Fatal("the service page was served without a session")
	}
}
