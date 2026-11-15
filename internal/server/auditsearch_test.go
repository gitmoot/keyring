package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
)

// Owner, 2026-11-15: an agent the owner allows (audit_read) searches the
// audit log through the keyring; any other agent gets 403; the search is
// audited.
func TestAuditSearchOnlyForAllowedAgents(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.log")
	lines := `{"time":"2026-11-15T16:39:53Z","role":"phobos","service":"macserve","method":"POST","path":"/v1/jobs/j_ce4ce15b/cancel","status":202}
{"time":"2026-11-15T16:39:20Z","role":"tandem","service":"macserve","method":"GET","path":"/v1/jobs/j_ce4ce15b","status":200}
{"time":"2026-11-15T16:41:00Z","role":"phobos","service":"macserve","method":"POST","path":"/v1/jobs/j_ce4ce15b/cancel","status":202}
`
	if err := os.WriteFile(log, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	const reader, other = "reader-token-0123456789abcdef", "other-token-0123456789abcdef"
	cfg := &policy.Config{
		Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: log},
		AccessList: policy.AccessList{
			Services: map[string]policy.Service{"api": {Base: "https://api.example.com", Key: "API_KEY", Auth: policy.AuthBearer}},
			Roles: map[string]policy.Role{
				"jarvis": {TokenSHA256: tokenHash(reader), Access: map[string]policy.Access{}, AuditRead: true},
				"tandem": {TokenSHA256: tokenHash(other), Access: map[string]policy.Access{"api": allowAll}},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	audit := &bytes.Buffer{}
	h := New(cfg, map[string]string{"API_KEY": testKey}, audit)

	w := call(h, "GET", AuditPath+"?from=2026-11-15T16:39&to=2026-11-15T16:39&path=/cancel", reader, nil)
	var got struct {
		Rows []AuditRow `json:"rows"`
		More bool       `json:"more"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); w.Code != http.StatusOK || err != nil {
		t.Fatalf("allowed agent: %d %s", w.Code, w.Body)
	}
	if len(got.Rows) != 1 || got.Rows[0].Role != "phobos" || got.Rows[0].Time != "2026-11-15T16:39:53Z" {
		t.Fatalf("rows = %+v, want only phobos's 16:39:53 cancel", got.Rows)
	}
	if w := call(h, "GET", AuditPath+"?from=2026-11-15T16:39&to=2026-11-15T16:39", other, nil); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "j_ce4ce15b") {
		t.Fatalf("agent without audit_read: %d %s", w.Code, w.Body)
	}
	if w := call(h, "POST", AuditPath, reader, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
	if w := call(h, "GET", AuditPath+"?to=yesterday", reader, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("bad time: %d", w.Code)
	}
	if w := call(h, "GET", AuditPath, "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", w.Code)
	}
	if !strings.Contains(audit.String(), `"role":"jarvis"`) || !strings.Contains(audit.String(), `"note":"audit search"`) ||
		!strings.Contains(audit.String(), `"role":"tandem","method":"GET","path":"/_keyring/audit","status":403`) {
		t.Fatalf("searches not audited:\n%s", audit)
	}
}
