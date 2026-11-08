package dashboard

import (
	"bytes"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/requests"
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

// addAgent creates role "ops" with no access.
func (e *env) addOps() {
	e.t.Helper()
	access, _ := policy.LoadAccess(e.proxy.Config().AccessFile)
	access.Roles["ops"] = policy.Role{TokenSHA256: strings.Repeat("ab", 32), Access: map[string]policy.Access{}}
	cfg, err := policy.SaveAccess(e.proxy.Config().Rules, access)
	if err != nil {
		e.t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(cfg, keys)
}

// Giving an agent access to a project in one step: without "later" it is a
// grant per current service; with it, one grant that also covers services
// added later. Both carry the chosen limits and are audit-logged.
func TestGrantAgentAccessToProject(t *testing.T) {
	e := projectEnv(t)
	e.addOps()
	form := url.Values{"role": {"ops"}, "mode": {"read"}, "paths": {"/v1"}, "daily": {"50"}, "password": {password}}
	if w := e.request("POST", "/projects/noted/grant", url.Values{"role": {"ops"}, "mode": {"read"}, "paths": {"/"}, "password": {"wrong"}}); w.Code != http.StatusForbidden {
		t.Fatalf("wrong password: %d", w.Code)
	}
	if w := e.request("POST", "/projects/noted/grant", form); w.Header().Get("Location") != "/projects/noted?done=granted" {
		t.Fatalf("grant: %d %s", w.Code, w.Body.String())
	}
	ops := e.proxy.Config().Roles["ops"]
	for _, s := range []string{"api", "noted-stripe"} {
		acc, ok := ops.Access[s]
		if !ok || acc.DailyRequests != 50 || acc.Paths[0] != "/v1" || !slices.Equal(acc.Methods, []string{"GET", "HEAD"}) {
			t.Fatalf("%s: %+v %v", s, acc, ok)
		}
	}
	if _, ok := ops.Access["own"]; ok || len(ops.Projects) != 0 {
		t.Fatalf("grant went beyond the project's current services: %+v", ops)
	}
	if n := strings.Count(e.audit.String(), `"admin":"access_changed"`); n != 2 {
		t.Fatalf("%d access_changed audit lines, want 2", n)
	}

	// Whole project, services added later included.
	form.Set("later", "yes")
	form.Set("mode", "full")
	if w := e.request("POST", "/projects/noted/grant", form); w.Header().Get("Location") != "/projects/noted?done=granted" {
		t.Fatalf("whole-project grant: %d %s", w.Code, w.Body.String())
	}
	if acc, ok := e.proxy.Config().Roles["ops"].Projects["noted"]; !ok || acc.DailyRequests != 50 {
		t.Fatalf("whole-project grant not stored: %+v", e.proxy.Config().Roles["ops"])
	}
	if !strings.Contains(e.audit.String(), `"admin":"project_access_granted"`) {
		t.Fatal("whole-project grant not audit-logged")
	}
	page := e.request("GET", "/projects/noted", nil).Body.String()
	if !strings.Contains(page, "whole project, services added later included") {
		t.Fatalf("project page does not show the whole-project grant:\n%s", page)
	}
	// A new service in the project shows as reachable through the project.
	access, _ := policy.LoadAccess(e.proxy.Config().AccessFile)
	access.Services["noted-sendgrid"] = policy.Service{Base: access.Services["api"].Base, Key: "STRIPE_KEY", Auth: policy.AuthBearer, Project: "noted"}
	cfg, err := policy.SaveAccess(e.proxy.Config().Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(cfg, keys)
	agent := e.request("GET", "/agents/ops", nil).Body.String()
	if !strings.Contains(agent, "noted-sendgrid") || !strings.Contains(agent, "through project noted") || !strings.Contains(agent, `href="/projects/noted"`) {
		t.Fatalf("agent page does not show access through the project:\n%s", agent)
	}
	if cell := e.request("GET", "/access/ops/noted-sendgrid", nil).Body.String(); !strings.Contains(cell, "through its grant for the whole project") {
		t.Fatalf("cell page does not explain the project grant:\n%s", cell)
	}

	// Removing the agent from the project takes the whole-project grant too.
	if w := e.request("POST", "/projects/noted/revoke", url.Values{"role": {"ops"}, "password": {password}}); w.Header().Get("Location") != "/projects/noted?done=revoked" {
		t.Fatalf("revoke: %d", w.Code)
	}
	ops = e.proxy.Config().Roles["ops"]
	if len(ops.Projects) != 0 || len(ops.Access) != 0 {
		t.Fatalf("access left after removing the agent from the project: %+v", ops)
	}
	if !strings.Contains(e.audit.String(), `"admin":"project_access_revoked"`) {
		t.Fatal("whole-project revoke not audit-logged")
	}
}

func TestGrantRefusals(t *testing.T) {
	e := projectEnv(t)
	before := e.accessBytes()
	for label, form := range map[string]url.Values{
		"unknown agent": {"role": {"nobody"}, "mode": {"full"}, "paths": {"/"}},
		"no paths":      {"role": {"phobos"}, "mode": {"full"}, "paths": {""}},
		"no mode":       {"role": {"phobos"}, "paths": {"/"}},
	} {
		form.Set("password", password)
		if w := e.request("POST", "/projects/noted/grant", form); w.Code != http.StatusBadRequest || !bytes.Equal(e.accessBytes(), before) {
			t.Errorf("%s: %d, file changed %v", label, w.Code, !bytes.Equal(e.accessBytes(), before))
		}
	}
	if w := e.request("POST", "/projects/nope/grant", url.Values{"role": {"phobos"}, "mode": {"full"}, "paths": {"/"}, "password": {password}}); w.Code != http.StatusNotFound {
		t.Errorf("unknown project: %d", w.Code)
	}
}

// An agent asks for a whole project with keyring request --project; approving
// gives the whole-project grant (#111).
func TestApproveProjectRequest(t *testing.T) {
	e := projectEnv(t)
	reqs := requests.Open(filepath.Join(t.TempDir(), "requests.json"))
	e.backend.Requests = reqs
	if _, err := reqs.File(requests.Request{Role: "phobos", Projects: []string{"nope"}}, e.proxy.Config().AccessList, "127.0.0.1", time.Now()); err == nil || !strings.Contains(err.Error(), "unknown project") {
		t.Fatalf("unknown project accepted: %v", err)
	}
	filed, err := reqs.File(requests.Request{Role: "phobos", Projects: []string{"noted"}, Note: "client work"}, e.proxy.Config().AccessList, "127.0.0.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	page := e.request("GET", "/access", nil).Body.String()
	if !strings.Contains(page, "Full access to the whole project") || !strings.Contains(page, `href="/projects/noted"`) {
		t.Fatalf("request not shown as a whole-project request:\n%s", page)
	}
	if w := e.request("POST", "/requests/"+filed.ID, url.Values{"answer": {"approve"}, "password": {password}}); w.Header().Get("Location") != "/access?done=approved" {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	if _, ok := e.proxy.Config().Roles["phobos"].Projects["noted"]; !ok {
		t.Fatalf("approval did not give the whole-project grant: %+v", e.proxy.Config().Roles["phobos"])
	}
	if !strings.Contains(e.audit.String(), `"projects":["noted"]`) {
		t.Fatalf("approval audit lacks the project: %s", e.audit.String())
	}
}

// Moving a service out of a project takes it away from agents that reached it
// only through a whole-project grant, and the edit says so in the audit log;
// an agent's own grant for the service is unaffected.
func TestMovingAServiceChangesProjectGrantReach(t *testing.T) {
	e := projectEnv(t)
	e.addOps()
	e.request("POST", "/projects/noted/grant", url.Values{"role": {"ops"}, "mode": {"full"}, "paths": {"/"}, "later": {"yes"}, "password": {password}})
	if _, ok := e.proxy.Config().AccessFor(e.proxy.Config().Roles["ops"], "api"); !ok {
		t.Fatal("setup: ops should reach api through the project")
	}
	base := e.proxy.Config().Services["api"].Base
	if w := e.edit("api", url.Values{"base": {base}, "auth": {"bearer"}, "test_path": {"/v1/check"}, "project": {""}}); w.Header().Get("Location") != "/services/api?done=saved" {
		t.Fatalf("move out: %d %s", w.Code, w.Body.String())
	}
	if _, ok := e.proxy.Config().AccessFor(e.proxy.Config().Roles["ops"], "api"); ok {
		t.Fatal("ops still reaches api after it left the project")
	}
	if _, ok := e.proxy.Config().Roles["phobos"].Access["api"]; !ok {
		t.Fatal("phobos's own grant for api was touched")
	}
	if !strings.Contains(e.audit.String(), `"access_lost_by":["ops"]`) {
		t.Fatalf("audit does not name who lost access: %s", e.audit.String())
	}
	if w := e.edit("api", url.Values{"base": {base}, "auth": {"bearer"}, "test_path": {"/v1/check"}, "project": {"noted"}}); w.Header().Get("Location") != "/services/api?done=saved" {
		t.Fatalf("move back: %d", w.Code)
	}
	if !strings.Contains(e.audit.String(), `"access_gained_by":["ops"]`) {
		t.Fatalf("audit does not name who gained access: %s", e.audit.String())
	}
}

// Review of #114, F1: opening the editor for access that comes through a
// whole-project grant shows that grant's limits, and saving it unchanged
// keeps them instead of widening to full access.
func TestInheritedAccessEditorKeepsTheProjectLimits(t *testing.T) {
	e := projectEnv(t)
	e.addOps()
	ahead := time.Now().AddDate(0, 1, 0).UTC().Format(time.DateOnly)
	e.request("POST", "/projects/noted/grant", url.Values{"role": {"ops"}, "mode": {"read"}, "paths": {"/v1"}, "daily": {"10"}, "expires": {ahead}, "later": {"yes"}, "password": {password}})
	page := e.request("GET", "/access/ops/noted-stripe", nil).Body.String()
	for _, want := range []string{`value="read" checked`, `>/v1</textarea>`, `name="daily" inputmode="numeric" value="10"`, `name="expires" value="` + ahead + `"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("editor does not show the project grant's limit %q:\n%s", want, page)
		}
	}
	// Submit the rendered form unchanged.
	w := e.request("POST", "/access/ops/noted-stripe", url.Values{"on": {"yes"}, "mode": {"read"}, "paths": {"/v1"}, "daily": {"10"}, "expires": {ahead}, "password": {password}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	acc := e.proxy.Config().Roles["ops"].Access["noted-stripe"]
	if !slices.Equal(acc.Methods, []string{"GET", "HEAD"}) || acc.Paths[0] != "/v1" || acc.DailyRequests != 10 || acc.Expires == nil {
		t.Fatalf("saving unchanged widened the access: %+v", acc)
	}
}

// F2: a project referenced only by whole-project grants stays listed, has a
// page, and its grants can be removed.
func TestProjectWithOnlyGrantsLeftStaysManageable(t *testing.T) {
	e := projectEnv(t)
	e.addOps()
	e.request("POST", "/projects/noted/grant", url.Values{"role": {"ops"}, "mode": {"full"}, "paths": {"/"}, "later": {"yes"}, "password": {password}})
	base := e.proxy.Config().Services["api"].Base
	for _, s := range []string{"api", "noted-stripe"} {
		if w := e.edit(s, url.Values{"base": {base}, "auth": {"bearer"}, "project": {""}}); w.Header().Get("Location") != "/services/"+s+"?done=saved" {
			t.Fatalf("move %s out: %d", s, w.Code)
		}
	}
	if w := e.request("GET", "/projects/noted", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "whole project, services added later included") {
		t.Fatalf("project with only grants left: %d", w.Code)
	}
	if !strings.Contains(e.request("GET", "/projects", nil).Body.String(), `href="/projects/noted"`) {
		t.Fatal("project with only grants left is not listed")
	}
	if w := e.request("POST", "/projects/noted/revoke", url.Values{"role": {"ops"}, "password": {password}}); w.Header().Get("Location") != "/projects/noted?done=revoked" {
		t.Fatalf("revoke: %d", w.Code)
	}
	if len(e.proxy.Config().Roles["ops"].Projects) != 0 {
		t.Fatal("whole-project grant not removed")
	}
}

// F3: the service page lists agents that reach it through a project grant.
func TestServicePageListsProjectGrantedAgents(t *testing.T) {
	e := projectEnv(t)
	e.addOps()
	e.request("POST", "/projects/noted/grant", url.Values{"role": {"ops"}, "mode": {"full"}, "paths": {"/"}, "later": {"yes"}, "password": {password}})
	if page := e.request("GET", "/services/noted-stripe", nil).Body.String(); !strings.Contains(page, `href="/access/ops/noted-stripe"`) {
		t.Fatalf("service page does not list the project-granted agent:\n%s", page)
	}
}
