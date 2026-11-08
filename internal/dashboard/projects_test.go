package dashboard

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// projectEnv puts the test service "api" in project "noted", adds a second
// project service "noted-stripe" on its own key, and gives role phobos access
// to both plus a service outside the project.
func projectEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"STRIPE_KEY"}, "value": {"sk-stripe-test-0123456789"}, "password": {password}})
	access, err := policy.LoadAccess(e.proxy.Config().AccessFile)
	if err != nil {
		t.Fatal(err)
	}
	api := access.Services["api"]
	api.Project = "noted"
	access.Services["api"] = api
	access.Services["noted-stripe"] = policy.Service{Base: api.Base, Key: "STRIPE_KEY", Auth: policy.AuthBearer, Project: "noted"}
	access.Services["own"] = policy.Service{Base: api.Base, Key: "STRIPE_KEY", Auth: policy.AuthBearer}
	rl := access.Roles["phobos"]
	rl.Access["noted-stripe"] = policy.Access{Paths: []string{"/"}}
	rl.Access["own"] = policy.Access{Paths: []string{"/"}}
	access.Roles["phobos"] = rl
	cfg, err := policy.SaveAccess(e.proxy.Config().Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(cfg, keys)
	return e
}

func TestProjectPageShowsWhatTheProjectHolds(t *testing.T) {
	e := projectEnv(t)
	e.proxyCall()
	page := e.request("GET", "/projects/noted", nil).Body.String()
	for _, want := range []string{`<h1 class="mono">noted</h1>`, `href="/services/api"`, `href="/services/noted-stripe"`, `href="/keys/STRIPE_KEY"`, `href="/agents/phobos"`, "api, noted-stripe"} {
		if !strings.Contains(page, want) {
			t.Fatalf("project page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `href="/services/own"`) {
		t.Fatal("a service outside the project is listed")
	}
	if strings.Contains(page, "sk-") {
		t.Fatal("a key value appears on the project page")
	}
	list := e.request("GET", "/projects", nil).Body.String()
	if !strings.Contains(list, `href="/projects/noted"`) || !strings.Contains(list, ">2<") {
		t.Fatalf("projects list:\n%s", list)
	}
	if w := e.request("GET", "/projects/nope", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown project: %d", w.Code)
	}
}

// Pause, end date and client ownership are set from the page, need the
// password, take effect on the next call, and are audit-logged.
func TestProjectSettingsFromTheDashboard(t *testing.T) {
	e := projectEnv(t)
	if e.proxyCall() != http.StatusOK {
		t.Fatal("setup: the call should work before pausing")
	}
	before := e.accessBytes()
	if w := e.request("POST", "/projects/noted", url.Values{"paused": {"yes"}, "password": {"wrong"}}); w.Code != http.StatusForbidden || !bytes.Equal(e.accessBytes(), before) {
		t.Fatalf("wrong password: %d", w.Code)
	}
	if w := e.request("POST", "/projects/noted", url.Values{"paused": {"yes"}, "password": {password}}); w.Header().Get("Location") != "/projects/noted?done=saved" {
		t.Fatalf("pause: %d %s", w.Code, w.Body.String())
	}
	if !e.proxy.Config().Projects["noted"].Paused || e.proxyCall() != http.StatusForbidden {
		t.Fatal("pausing did not stop the project's calls")
	}
	if page := e.request("GET", "/projects/noted", nil).Body.String(); !strings.Contains(page, `<span class="pill warn">paused</span>`) {
		t.Fatal("the page does not show the pause")
	}
	if !strings.Contains(e.audit.String(), `"admin":"project_changed"`) || !strings.Contains(e.audit.String(), `"changed":["paused"]`) {
		t.Fatalf("audit: %s", e.audit.String())
	}
	// Resume: no settings left, so the entry is removed and calls work again.
	if w := e.request("POST", "/projects/noted", url.Values{"password": {password}}); w.Header().Get("Location") != "/projects/noted?done=saved" {
		t.Fatalf("resume: %d", w.Code)
	}
	if _, kept := e.proxy.Config().Projects["noted"]; kept || e.proxyCall() != http.StatusOK {
		t.Fatal("resuming did not restore the project")
	}
	// An end date in the past counts as paused; one ahead does not.
	if w := e.request("POST", "/projects/noted", url.Values{"expires": {"2020-01-01"}, "password": {password}}); w.Header().Get("Location") != "/projects/noted?done=saved" || e.proxyCall() != http.StatusForbidden {
		t.Fatalf("past end date: %d", w.Code)
	}
	ahead := time.Now().AddDate(1, 0, 0).Format("2006-01-02")
	if w := e.request("POST", "/projects/noted", url.Values{"expires": {ahead}, "password": {password}}); w.Header().Get("Location") != "/projects/noted?done=saved" || e.proxyCall() != http.StatusOK {
		t.Fatalf("future end date: %d", w.Code)
	}
	if exp := e.proxy.Config().Projects["noted"].Expires; exp == nil || exp.Format("2006-01-02") != ahead {
		t.Fatalf("end date stored as %v", exp)
	}
	if w := e.request("POST", "/projects/noted", url.Values{"expires": {"31/03/2027"}, "password": {password}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad date: %d", w.Code)
	}
}

// Removing an agent from a project takes its access to every project service
// and nothing else.
func TestRevokeAgentFromProject(t *testing.T) {
	e := projectEnv(t)
	if w := e.request("POST", "/projects/noted/revoke", url.Values{"role": {"phobos"}, "password": {"wrong"}}); w.Code != http.StatusForbidden || len(e.proxy.Config().Roles["phobos"].Access) != 3 {
		t.Fatalf("wrong password: %d", w.Code)
	}
	w := e.request("POST", "/projects/noted/revoke", url.Values{"role": {"phobos"}, "password": {password}})
	if w.Header().Get("Location") != "/projects/noted?done=revoked" {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	acc := e.proxy.Config().Roles["phobos"].Access
	if _, ok := acc["api"]; ok {
		t.Fatal("access to api kept")
	}
	if _, ok := acc["noted-stripe"]; ok {
		t.Fatal("access to noted-stripe kept")
	}
	if _, ok := acc["own"]; !ok {
		t.Fatal("access outside the project was removed")
	}
	if e.proxyCall() != http.StatusForbidden {
		t.Fatal("the agent can still call the project's service")
	}
	for _, s := range []string{`"service":"api"`, `"service":"noted-stripe"`} {
		if !strings.Contains(e.audit.String(), s) {
			t.Fatalf("no per-service audit line for %s: %s", s, e.audit.String())
		}
	}
	if w := e.request("POST", "/projects/noted/revoke", url.Values{"role": {"phobos"}, "password": {password}}); w.Code != http.StatusBadRequest {
		t.Fatalf("second revoke: %d", w.Code)
	}
	if w := e.request("POST", "/projects/noted/revoke", url.Values{"role": {"nobody"}, "password": {password}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown role: %d", w.Code)
	}
}

// The handover list shows only when the keys are client-owned, lists each
// project key with when it was added and last replaced, and never a value.
func TestHandoverList(t *testing.T) {
	e := projectEnv(t)
	if page := e.request("GET", "/projects/noted", nil).Body.String(); strings.Contains(page, "Handover") {
		t.Fatal("handover shown for a project not marked client-owned")
	}
	e.request("POST", "/projects/noted", url.Values{"client_owned": {"yes"}, "password": {password}})
	page := e.request("GET", "/projects/noted", nil).Body.String()
	today := time.Now().UTC().Format("2 Jan 2006")
	if !strings.Contains(page, "Handover") || !strings.Contains(page, `href="/keys/API_KEY"`) || !strings.Contains(page, `href="/keys/STRIPE_KEY"`) {
		t.Fatalf("handover list:\n%s", page)
	}
	// STRIPE_KEY was added in the dashboard today; API_KEY was stored directly
	// in the test setup, so when it was added is unknown.
	if !strings.Contains(page, "<td>"+today+"</td><td>"+today+"</td>") || !strings.Contains(page, "<td>unknown</td><td>unknown</td>") {
		t.Fatalf("handover dates:\n%s", page)
	}
	if strings.Contains(page, "sk-") {
		t.Fatal("a value appears in the handover list")
	}
	// Replacing keeps when it was added: the row still shows both dates, not
	// "unknown".
	e.request("POST", "/keys/STRIPE_KEY/replace", url.Values{"value": {"sk-stripe-test-rotated-9876"}, "password": {password}})
	page = e.request("GET", "/projects/noted", nil).Body.String()
	if !strings.Contains(page, `href="/keys/STRIPE_KEY">STRIPE_KEY</a></td><td>`+today+"</td><td>"+today+"</td>") {
		t.Fatalf("replace lost the added date:\n%s", page)
	}
}

// The Keys and Agents pages filter by project; "Personal" is everything
// outside a project, and other filters and sorting keep the project choice.
func TestKeysAndAgentsFilterByProject(t *testing.T) {
	e := projectEnv(t)
	// A key outside any project, used only by the no-project service.
	e.request("POST", "/keys", url.Values{"name": {"OWN_KEY"}, "value": {"sk-own-0123456789"}, "password": {password}})
	access, _ := policy.LoadAccess(e.proxy.Config().AccessFile)
	own := access.Services["own"]
	own.Key = "OWN_KEY"
	access.Services["own"] = own
	cfg, err := policy.SaveAccess(e.proxy.Config().Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(cfg, keys)

	all := e.request("GET", "/keys", nil).Body.String()
	if !strings.Contains(all, `href="/keys?project=noted"`) || !strings.Contains(all, `href="/keys?project=-"`) || !strings.Contains(all, `<a class="chip" href="/projects/noted">noted</a>`) {
		t.Fatalf("keys page lacks the project filter or chips:\n%s", all)
	}
	noted := e.request("GET", "/keys?project=noted", nil).Body.String()
	if !strings.Contains(noted, `href="/keys/API_KEY"`) || !strings.Contains(noted, `href="/keys/STRIPE_KEY"`) || strings.Contains(noted, `href="/keys/OWN_KEY"`) {
		t.Fatalf("project filter:\n%s", noted)
	}
	personal := e.request("GET", "/keys?project=-", nil).Body.String()
	if !strings.Contains(personal, `href="/keys/OWN_KEY"`) || strings.Contains(personal, `href="/keys/API_KEY"`) {
		t.Fatalf("personal filter:\n%s", personal)
	}
	// Sorting and the status filter keep the project.
	if !strings.Contains(noted, "project=noted&amp;sort=") || !strings.Contains(noted, `name="project" value="noted"`) {
		t.Fatalf("project not kept by sort links or search:\n%s", noted)
	}

	agents := e.request("GET", "/access?project=noted", nil).Body.String()
	if !strings.Contains(agents, `href="/agents/phobos"`) || !strings.Contains(agents, `href="/access?project=noted"`) {
		t.Fatalf("agents project filter:\n%s", agents)
	}
	if strings.Contains(agents, `/access/phobos/own"`) {
		t.Fatal("agents page filtered by project still shows a service outside it")
	}
	// An agent with no access in the project is not listed under it.
	e.request("POST", "/projects/noted/revoke", url.Values{"role": {"phobos"}, "password": {password}})
	if agents := e.request("GET", "/access?project=noted", nil).Body.String(); strings.Contains(agents, `href="/agents/phobos"`) {
		t.Fatal("an agent without project access is listed under the project")
	}
}
