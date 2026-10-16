package instance

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
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
