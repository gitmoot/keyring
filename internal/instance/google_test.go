package instance

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/googlelogin"
	"github.com/gitmoot/keyring/internal/server"
)

// Exercise the public admin transaction, not copies of the service definitions.
func TestContainerGoogleProvisioning(t *testing.T) {
	in, err := New(Options{AdminListen: freeAddr(t), AdminTokenSHA256: sha(adminToken), StatePath: filepath.Join(t.TempDir(), "sealed"), Container: true, Audit: io.Discard, AuditName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(in.Close)
	x := &inst{t: t, in: in, admin: in.AdminHandler()}
	listen := freeAddr(t)
	key := newKey(t)
	x.must("POST", "/create", map[string]any{"id": "person", "data_key": key, "listen": listen})
	x.must("PUT", "/services/other", map[string]any{"base": "https://example.com", "key": "OTHER", "auth": "bearer"})
	role := x.must("PUT", "/roles/router", map[string]any{"access": map[string]any{"other": map[string]any{"paths": []string{"/"}}}})
	token := role["token"].(string)
	// A real atomic-file commit failure must leave both live and sealed
	// grants unchanged, even when the router already has unrelated access.
	before := x.must("GET", "/state", nil)
	if err := os.Rename(in.opt.StatePath, in.opt.StatePath+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(in.opt.StatePath, 0700); err != nil {
		t.Fatal(err)
	}
	failed, _ := x.call("POST", "/google-drive", map[string]any{})
	if err := os.Remove(in.opt.StatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(in.opt.StatePath+".saved", in.opt.StatePath); err != nil {
		t.Fatal(err)
	}
	if failed != http.StatusInternalServerError {
		t.Fatalf("provisioning commit failure: %d", failed)
	}
	failedStatus := x.must("GET", "/status", nil)
	grants := failedStatus["roles"].(map[string]any)["router"].(map[string]any)["access"].(map[string]any)
	if len(grants) != 1 || grants["other"] == nil {
		t.Fatalf("failed provisioning mutated live grants: %v", grants)
	}
	unchanged := x.must("GET", "/state", nil)
	if before["state"] != unchanged["state"] || before["version"] != unchanged["version"] {
		t.Fatal("failed provisioning changed sealed state")
	}
	x.must("PUT", "/keys/other_fixture", map[string]any{"value": "fixture"})
	x.must("POST", "/google-drive", map[string]any{})
	x.must("POST", "/google-drive", map[string]any{})
	// The admin key namespace is independent of consent service names.
	x.must("PUT", "/keys/drive", map[string]any{"value": "unrelated-fixture-key"})
	x.must("DELETE", "/keys/drive", nil)
	if code, _ := x.call("DELETE", "/keys/drive", nil); code != http.StatusNotFound {
		t.Fatalf("raw key named drive was shadowed by Google disconnect: %d", code)
	}
	status := x.must("GET", "/status", nil)
	services := status["services"].(map[string]any)
	if services["other"] == nil || services["drive"] == nil {
		t.Fatalf("provisioning lost unrelated service or consent: %v", services)
	}
	// The original router token is still valid, but disconnected Google access
	// is refused before a command or upstream request can run.
	code, _ := proxyGet(t, listen, token, "/google-me-drive/about")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("disconnected access/token preservation: %d", code)
	}
	for _, path := range []string{"/google-me-upload/files", "/google-me-sheets/spreadsheets"} {
		code, _ := proxyGet(t, listen, token, path)
		want := http.StatusServiceUnavailable
		if path == "/google-me-upload/files" {
			want = http.StatusForbidden
		}
		if code != want {
			t.Fatalf("method boundary %s: %d", path, code)
		}
	}
	for _, body := range []any{nil, "{}", map[string]any{"overwrite": true}} {
		if code, _ := x.call("POST", "/google-drive", body); code != 400 {
			t.Fatalf("invalid provisioning body accepted: %d", code)
		}
	}
	// An incompatible pre-existing reserved grant must abort the entire change.
	x.must("PUT", "/roles/router", map[string]any{"access": map[string]any{"google-me-drive": map[string]any{"methods": []string{"DELETE"}, "paths": []string{"/"}}}})
	conflictState := x.must("GET", "/state", nil)
	if code, _ := x.call("POST", "/google-drive", map[string]any{}); code != 409 {
		t.Fatalf("reserved grant conflict: %d", code)
	}
	after := x.must("GET", "/state", nil)
	if conflictState["version"] != after["version"] || conflictState["state"] != after["state"] {
		t.Fatal("conflict partially changed sealed state")
	}
	raw, err := json.Marshal(status["google"])
	if err != nil {
		t.Fatal(err)
	}
	var view map[string]any
	if json.Unmarshal(raw, &view) != nil || view["phase"] != "disconnected" || view["account"] != nil || view["quota_project"] != nil {
		t.Fatalf("unsafe connection metadata: %s", raw)
	}
}

// The admin side may name an existing project for the retained sign-in's
// setup; that only chooses it and provisions nothing, so a refused choice
// changes nothing. {} stays the provisioning contract and unknown fields
// stay refused.
func TestContainerGoogleProvisioningChoosesProject(t *testing.T) {
	in, err := New(Options{AdminListen: freeAddr(t), AdminTokenSHA256: sha(adminToken), StatePath: filepath.Join(t.TempDir(), "sealed"), Container: true, Audit: io.Discard, AuditName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(in.Close)
	x := &inst{t: t, in: in, admin: in.AdminHandler()}
	x.must("POST", "/create", map[string]any{"id": "person", "data_key": newKey(t), "listen": freeAddr(t)})
	x.must("PUT", "/roles/router", map[string]any{"access": map[string]any{}})
	notProvisioned := func(what string) {
		t.Helper()
		if services := x.must("GET", "/status", nil)["services"].(map[string]any); services["drive"] != nil || services["google-me-drive"] != nil {
			t.Fatalf("%s provisioned Google services", what)
		}
	}
	before := x.must("GET", "/state", nil)
	for _, tc := range []struct {
		body any
		code int
	}{
		{map[string]any{"project": "Not_A_Project"}, http.StatusBadRequest},
		// Only an omitted project provisions; an explicit empty one is a
		// choice of nothing.
		{map[string]any{"project": ""}, http.StatusBadRequest},
		{map[string]any{"project": nil}, http.StatusBadRequest},
		{map[string]any{"project": 5}, http.StatusBadRequest},
		{map[string]any{"other": "field"}, http.StatusBadRequest},
		// No Google sign-in yet: nothing to set the project for.
		{map[string]any{"project": "owned-project-1"}, http.StatusConflict},
	} {
		if code, _ := x.call("POST", "/google-drive", tc.body); code != tc.code {
			t.Fatalf("%v: %d; want %d", tc.body, code, tc.code)
		}
		if after := x.must("GET", "/state", nil); after["version"] != before["version"] || after["state"] != before["state"] {
			t.Fatalf("refused %v changed the sealed state", tc.body)
		}
		notProvisioned("a refused request")
	}
	if google := x.must("GET", "/status", nil)["google"].(map[string]any); google["phase"] != "disconnected" {
		t.Fatalf("refused project choice changed the connection: %v", google)
	}
	x.must("POST", "/google-drive", map[string]any{})
	if services := x.must("GET", "/status", nil)["services"].(map[string]any); services["drive"] == nil {
		t.Fatal("{} did not provision Google services")
	}
	// Without the router's Google grants, a choice must not bring them back.
	x.must("PUT", "/roles/router", map[string]any{"access": map[string]any{}})
	// A sign-in whose setup failed (Google's project limit) is retained.
	signedIn := &googlelogin.Snapshot{Generation: strings.Repeat("a", 32), Account: "person@example.test", Project: "drivekey-aaaaaaaaaaaaaaaaaaaa",
		Files: map[string][]byte{"credentials.db": []byte("synthetic-credential")}}
	if err := in.saveGoogle(context.Background(), "", signedIn); err != nil {
		t.Fatal(err)
	}
	in.google.SetState(signedIn)
	x.must("POST", "/google-drive", map[string]any{"project": "owned-project-1"})
	in.mu.Lock()
	sealed := *in.state.Google
	in.mu.Unlock()
	if sealed.Project != "owned-project-1" || !sealed.ProjectChosen || sealed.Ready || sealed.Account != signedIn.Account {
		t.Fatalf("chosen project not sealed for setup: %+v", sealed)
	}
	if access, _ := x.must("GET", "/status", nil)["roles"].(map[string]any)["router"].(map[string]any)["access"].(map[string]any); len(access) != 0 {
		t.Fatalf("choosing a project provisioned grants: %v", access)
	}
	if google := x.must("GET", "/status", nil)["google"].(map[string]any); google["quota_project"] != nil {
		t.Fatalf("status exposed the project: %v", google)
	}
}

// Status reports the Google services as needing a reconnect from the
// controller's record of Google refusing the login: a refusal sealed with the
// login, even from a proxy that never saw the 401 (as after a container
// restart), and one whose seal failed (#184).
func TestContainerGoogleSealedRefusalStatus(t *testing.T) {
	in, err := New(Options{AdminListen: freeAddr(t), AdminTokenSHA256: sha(adminToken), StatePath: filepath.Join(t.TempDir(), "sealed"), Container: true, Audit: io.Discard, AuditName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(in.Close)
	x := &inst{t: t, in: in, admin: in.AdminHandler()}
	x.must("POST", "/create", map[string]any{"id": "person", "data_key": newKey(t), "listen": freeAddr(t)})
	x.must("PUT", "/roles/router", map[string]any{"access": map[string]any{}})
	x.must("POST", "/google-drive", map[string]any{})
	login := &googlelogin.Snapshot{Generation: strings.Repeat("b", 32), Account: "person@example.test", Project: "owned-project-1", Ready: true,
		Files: map[string][]byte{"credentials.db": []byte("synthetic-credential")}}
	check := func(step string, refused bool) {
		t.Helper()
		status := x.must("GET", "/status", nil)
		reconnect, _ := status["reconnect_required"].(map[string]any)
		failing, _ := status["failing"].(map[string]any)
		for _, name := range []string{"drive", "google-me-drive", "google-me-upload", "google-me-sheets"} {
			if (reconnect[name] == true) != refused || (failing[name] == server.GoogleRefusedContainer) != refused {
				t.Fatalf("%s %s: reconnect=%v failing=%v", step, name, reconnect[name], failing[name])
			}
		}
		want := map[bool]string{false: "connected", true: "reconnect_required"}[refused]
		if phase := status["google"].(map[string]any)["phase"]; phase != want {
			t.Fatalf("%s: phase %v", step, phase)
		}
	}
	expected := ""
	for _, refused := range []bool{false, true} {
		next := *login
		next.Refused = refused
		if err := in.saveGoogle(context.Background(), expected, &next); err != nil {
			t.Fatal(err)
		}
		expected = login.Generation
		check(map[bool]string{false: "sealed login", true: "sealed refusal"}[refused], refused)
	}
	in.google.RecordRefusal(context.Background(), login.Binding(), false, 1)
	check("accepted call", false)
	failed, cancel := context.WithCancel(context.Background())
	cancel()
	in.google.RecordRefusal(failed, login.Binding(), true, 2)
	in.mu.Lock()
	sealed := in.state.Google.Refused
	in.mu.Unlock()
	if sealed {
		t.Fatal("a canceled seal saved the refusal")
	}
	check("unsealed refusal", true)
}
