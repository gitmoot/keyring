package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

// projectHandler serves one service "api" in project "client" for role phobos,
// with the project settings given.
func projectHandler(t *testing.T, base string, project policy.Project, daily int) (*Handler, *bytes.Buffer) {
	t.Helper()
	svc := policy.Service{Auth: policy.AuthBearer, Project: "client", TestPath: "/v1/check"}
	h, audit := newHandler(t, base, svc, policy.Access{Paths: []string{"/"}, Methods: []string{"GET"}, DailyRequests: daily})
	cfg := *h.Config()
	cfg.Projects = map[string]policy.Project{"client": project}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h.Swap(&cfg, map[string]string{"API_KEY": testKey})
	return h, audit
}

func lastAudit(t *testing.T, audit *bytes.Buffer) auditRecord {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	var rec auditRecord
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// Pausing a project, or letting it expire, refuses every call to its services
// with a fixed code, before the key is used or any quota spent (#111).
func TestStoppedProjectRefusesCallsWithoutUsingTheKey(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	for _, tc := range []struct {
		name    string
		project policy.Project
		why     string
	}{
		{"paused", policy.Project{Paused: true}, "paused"},
		{"expired", policy.Project{Expires: &past}, "expired"},
		{"paused and expired", policy.Project{Paused: true, Expires: &past}, "paused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up, seen := upstream(t)
			h, audit := projectHandler(t, up.URL, tc.project, 1)
			for i := 0; i < 3; i++ {
				w := call(h, "GET", "/api/v1/x", testToken, nil)
				if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "project_paused: project client is "+tc.why) {
					t.Fatalf("call %d: %d %q", i, w.Code, w.Body.String())
				}
			}
			if seen.count() != 0 {
				t.Fatal("a call to a stopped project reached the service")
			}
			rec := lastAudit(t, audit)
			if rec.Project != "client" || rec.Service != "api" || rec.Role != "phobos" || rec.Status != 403 {
				t.Fatalf("audit = %+v", rec)
			}
			if strings.Contains(audit.String(), testKey) {
				t.Fatal("key in audit")
			}
			// Resuming restores everything, and the refusals spent nothing of
			// the daily limit of one.
			cfg := *h.Config()
			cfg.Projects = nil
			h.Swap(&cfg, map[string]string{"API_KEY": testKey})
			if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK {
				t.Fatalf("after resuming: %d %q", w.Code, w.Body.String())
			}
			if got := seen.last(t).Header.Get("Authorization"); got != "Bearer "+testKey {
				t.Fatalf("after resuming the key was not sent: %q", got)
			}
		})
	}
}

// A running project, a project whose expiry is still ahead, and a service with
// no project all work exactly as before, and the audit names the project.
func TestRunningProjectsAreUnchanged(t *testing.T) {
	future := time.Now().Add(time.Hour)
	for _, project := range []policy.Project{{}, {Expires: &future}, {ClientOwned: true}} {
		up, seen := upstream(t)
		h, audit := projectHandler(t, up.URL, project, 0)
		if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK || seen.count() != 1 {
			t.Fatalf("project %+v: %d, calls %d", project, w.Code, seen.count())
		}
		if rec := lastAudit(t, audit); rec.Project != "client" || rec.Status != 200 {
			t.Fatalf("audit = %+v", rec)
		}
	}
	up, _ := upstream(t)
	h, audit := newHandler(t, up.URL, bearer, allowAll)
	if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK || strings.Contains(audit.String(), `"project"`) {
		t.Fatalf("no-project service: %d, audit %s", w.Code, audit.String())
	}
}

// Pausing one project does not touch another project's services.
func TestPauseIsPerProject(t *testing.T) {
	up, seen := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	cfg := *h.Config()
	cfg.Services = map[string]policy.Service{}
	for name, svc := range h.Config().Services {
		cfg.Services[name] = svc
	}
	other := cfg.Services["api"]
	other.Project = "running"
	cfg.Services["api"] = other
	cfg.Projects = map[string]policy.Project{"client": {Paused: true}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h.Swap(&cfg, map[string]string{"API_KEY": testKey})
	if w := call(h, "GET", "/api/v1/x", testToken, nil); w.Code != http.StatusOK || seen.count() != 1 {
		t.Fatalf("another project's service was refused: %d", w.Code)
	}
}

// The dashboard Test button does not send a stopped project's key either.
func TestKeyTestRefusesAStoppedProject(t *testing.T) {
	up, seen := upstream(t)
	h, _ := projectHandler(t, up.URL, policy.Project{Paused: true}, 0)
	_, err := h.TestKey(context.Background(), h.Config().Services["api"], testKey)
	if err == nil || !strings.Contains(err.Error(), "project_paused: project client is paused") || seen.count() != 0 {
		t.Fatalf("TestKey on a paused project: err %v, calls %d", err, seen.count())
	}
}
