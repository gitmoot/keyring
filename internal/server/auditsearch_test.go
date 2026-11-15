package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	// The answer names the window as asked, fractions included, so it can be
	// sent again (#155 review).
	w = call(h, "GET", AuditPath+"?from=2026-11-15T16:39:53.1Z&to=2026-11-15T16:39:53.2Z", reader, nil)
	var win struct{ From, To string }
	if err := json.Unmarshal(w.Body.Bytes(), &win); w.Code != http.StatusOK || err != nil || win.From != "2026-11-15T16:39:53.1Z" || win.To != "2026-11-15T16:39:53.2Z" {
		t.Fatalf("window echoed as %+v (%d)", win, w.Code)
	}
	if w := call(h, "GET", AuditPath+"?from="+win.From+"&to="+win.To, reader, nil); w.Code != http.StatusOK {
		t.Fatalf("replaying the echoed window: %d", w.Code)
	}
	if !strings.Contains(audit.String(), `"role":"jarvis"`) || !strings.Contains(audit.String(), `"note":"audit search"`) ||
		!strings.Contains(audit.String(), `"role":"tandem","method":"GET","path":"/_keyring/audit","status":403`) {
		t.Fatalf("searches not audited:\n%s", audit)
	}
}

// #153 review: past the limit the newest by time are kept, even when an
// older, slow call was written last.
func TestSearchAuditKeepsNewestPastTheLimit(t *testing.T) {
	log := filepath.Join(t.TempDir(), "audit.log")
	var b strings.Builder
	base := time.Date(2026, 11, 15, 16, 0, 0, 0, time.UTC)
	for i := 1; i <= AuditLimit; i++ {
		fmt.Fprintf(&b, `{"time":%q,"role":"r","service":"s","method":"GET","path":"/x"}`+"\n", base.Add(time.Duration(i)*time.Second).Format(time.RFC3339))
	}
	// The oldest call, slow, is written last.
	fmt.Fprintf(&b, `{"time":%q,"role":"slow","service":"s","method":"GET","path":"/x"}`+"\n", base.Format(time.RFC3339))
	if err := os.WriteFile(log, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, more, err := SearchAudit(log, base, base.Add(time.Hour), AuditFilter{})
	if err != nil || !more || len(rows) != AuditLimit {
		t.Fatalf("rows %d more %v err %v", len(rows), more, err)
	}
	if want := base.Add(AuditLimit * time.Second).Format(time.RFC3339); rows[0].Time != want {
		t.Errorf("newest row %s, want %s", rows[0].Time, want)
	}
	for _, r := range rows {
		if r.Role == "slow" {
			t.Fatal("kept the oldest (slow, last-written) call over a newer one")
		}
	}
}

// #155 review: a window with fractional seconds matches exactly the
// whole-second records inside it.
func TestAuditWindowFractionalSeconds(t *testing.T) {
	log := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(log, []byte(`{"time":"2026-11-15T16:39:20Z","role":"r","service":"s","method":"GET","path":"/x"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		from, to string
		want     int
	}{
		{"2026-11-15T16:39:19.5Z", "2026-11-15T16:39:20.5Z", 1},
		{"2026-11-15T16:39:20.5Z", "2026-11-15T16:39:21.5Z", 0},
		{"2026-11-15T16:39:19Z", "2026-11-15T16:39:20Z", 0},
		{"2026-11-15T16:39:20Z", "2026-11-15T16:39:20.001Z", 1},
	} {
		from, to, err := AuditWindow(c.from, c.to, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		rows, _, err := SearchAudit(log, from, to, AuditFilter{})
		if err != nil || len(rows) != c.want {
			t.Errorf("[%s, %s): %d rows, want %d (%v)", c.from, c.to, len(rows), c.want, err)
		}
	}
}
