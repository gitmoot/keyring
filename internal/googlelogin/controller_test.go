package googlelogin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func controllerFixture(t *testing.T) (*Controller, func() *Snapshot, *bool) {
	t.Helper()
	var mu sync.Mutex
	var state *Snapshot
	failSave := new(bool)
	var c *Controller
	c = New(func(ctx context.Context, expected string, next *Snapshot) error {
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if *failSave {
			return errors.New("fixture save refused")
		}
		if expected != "*" && expected != generation(state) {
			return errors.New("stale generation")
		}
		state = next
		c.SetState(next)
		return nil
	})
	root := t.TempDir()
	c.root = filepath.Join(root, "google")
	c.executable = filepath.Join(root, "gcloud")
	script := `#!/bin/sh
set -eu
case "$1 $2" in
 "auth login")
  printf 'https://accounts.google.com/o/oauth2/auth?state=fixture\n'
  read -r code
  [ "$code" = fixture-code ] || exit 1
  printf 'PRIVATE-CREDENTIAL-FIXTURE' > "$CLOUDSDK_CONFIG/credentials.db"
  ;;
 "auth list") printf 'person@example.test\n' ;;
 "projects describe"|"projects create")
  # A test's own project answers, given "describe|create ID".
  if [ -f "$CLOUDSDK_CONFIG/../projects" ]; then . "$CLOUDSDK_CONFIG/../projects"; fi
  if [ "$2" = describe ]; then printf 'ACTIVE\n'; fi ;;
 "services enable")
  if [ -f "$CLOUDSDK_CONFIG/../terms" ]; then
   printf 'Callers must accept Terms of Service SECRET-CANARY\n' >&2
   exit 1
  fi ;;
 "auth print-access-token")
  if [ -f "$CLOUDSDK_CONFIG/../block" ]; then
   touch "$CLOUDSDK_CONFIG/../started"
   sleep 60
  fi
  if [ -f "$CLOUDSDK_CONFIG/../failure" ]; then
   cat "$CLOUDSDK_CONFIG/../failure" >&2
   exit 1
  fi
  printf 'r' >> "$CLOUDSDK_CONFIG/credentials.db"
  printf 'fixture-access-token\n' ;;
 "auth revoke") exit 1 ;;
 *) exit 1 ;;
esac
`
	if err := os.WriteFile(c.executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	c.client = &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Authorization") != "Bearer fixture-access-token" {
			t.Errorf("probe missing fixture token")
		}
		code, body := 404, "{}"
		if r.URL.Host == "www.googleapis.com" {
			code, body = 200, `{"user":{"emailAddress":"person@example.test"}}`
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	return c, func() *Snapshot { mu.Lock(); defer mu.Unlock(); return state }, failSave
}

func waitView(t *testing.T, c *Controller, id, phase string) View {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := c.View(id); ok {
			if v.Phase == phase {
				return v
			}
			if !v.Busy {
				t.Fatalf("flow finished before %s: %+v", phase, v)
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("flow did not reach %s", phase)
	return View{}
}

func TestLoginTermsRetryRefreshAndRestore(t *testing.T) {
	c, saved, failSave := controllerFixture(t)
	if err := os.Mkdir(c.root, 0700); err != nil {
		t.Fatal(err)
	}
	terms := filepath.Join(c.root, "terms")
	if err := os.WriteFile(terms, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Start("browser", c.Epoch()); err != nil {
		t.Fatal(err)
	}
	waitView(t, c, "browser", "awaiting_code")
	if err := c.Submit("different-browser", "fixture-code"); err == nil {
		t.Fatal("another flow supplied the code")
	}
	if err := c.Submit("browser", "fixture-code"); err != nil {
		t.Fatal(err)
	}
	failed := waitView(t, c, "browser", "failed")
	if failed.Error != string(errTerms) || strings.Contains(failed.Error, "SECRET") {
		t.Fatalf("unsafe terms diagnosis: %+v", failed)
	}
	checkpoint := saved()
	if checkpoint == nil || checkpoint.Ready || checkpoint.NeedsLogin || checkpoint.Account != "person@example.test" {
		t.Fatal("successful login was not retained for setup retry")
	}
	if err := os.Remove(terms); err != nil {
		t.Fatal(err)
	}
	if err := c.Start("browser", c.Epoch()); err != nil {
		t.Fatal(err)
	}
	waitView(t, c, "browser", "connected")
	connected := saved()
	if !connected.Ready || connected.Generation != checkpoint.Generation || connected.Project != checkpoint.Project {
		t.Fatal("retry replaced login/project instead of completing it")
	}
	token, err := c.Token(context.Background(), connected.Binding(), nil)
	if err != nil || token != "fixture-access-token" {
		t.Fatalf("token: %q %v", token, err)
	}
	refreshed := saved()
	if len(refreshed.Files["credentials.db"]) != len(connected.Files["credentials.db"])+1 {
		t.Fatal("refreshed credential not preserved before returning token")
	}
	*failSave = true
	if token, err := c.Token(context.Background(), refreshed.Binding(), nil); err == nil || token != "" {
		t.Fatal("access token escaped failed persistence")
	}
	*failSave = false
	restored, _, _ := controllerFixture(t)
	if err := restored.Restore(refreshed); err != nil {
		t.Fatal(err)
	}
	restored.SetState(refreshed)
	disk, err := os.ReadFile(filepath.Join(restored.root, refreshed.Generation, "credentials.db"))
	if err != nil || string(disk) != string(refreshed.Files["credentials.db"]) || restored.Status().Phase != "connected" {
		t.Fatal("restart failed to restore the committed credential")
	}
	failure := filepath.Join(c.root, "failure")
	if err := os.WriteFile(failure, []byte("Try signing in again: https://accounts.google.com/?error_subtype=rapt_required SECRET-CANARY"), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := c.Token(context.Background(), refreshed.Binding(), nil); token != "" || !errors.Is(err, errCommand) || !saved().Ready {
		t.Fatalf("ambiguous advice invented a login requirement: %v", err)
	}
	if err := os.WriteFile(failure, []byte(`{"error_subtype":"invalid_rapt"} SECRET-CANARY`), 0600); err != nil {
		t.Fatal(err)
	}
	if token, err := c.Token(context.Background(), refreshed.Binding(), nil); token != "" || !errors.Is(err, errLogin) || saved().Ready || !saved().NeedsLogin {
		t.Fatalf("proven reauthentication did not disable the binding: %v", err)
	}
}

func TestDisconnectCancelsRefreshAndRevokesOldFlows(t *testing.T) {
	c, saved, _ := controllerFixture(t)
	if err := c.Start("browser", c.Epoch()); err != nil {
		t.Fatal(err)
	}
	waitView(t, c, "browser", "awaiting_code")
	if err := c.Submit("browser", "fixture-code"); err != nil {
		t.Fatal(err)
	}
	waitView(t, c, "browser", "connected")
	binding, epoch := saved().Binding(), c.Epoch()
	if err := os.WriteFile(filepath.Join(c.root, "block"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	type tokenResult struct {
		token string
		err   error
	}
	result := make(chan tokenResult, 1)
	go func() { token, err := c.Token(context.Background(), binding, nil); result <- tokenResult{token, err} }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(c.root, "started")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh not started")
		}
		time.Sleep(time.Millisecond)
	}
	err := c.Disconnect(context.Background())
	if err == nil || !strings.Contains(err.Error(), "remote revocation could not be confirmed") {
		t.Fatalf("lost explicit remote-revocation failure: %v", err)
	}
	if saved() != nil || c.Status().Phase != "disconnected" {
		t.Fatal("disconnect left access enabled")
	}
	if _, err := os.Stat(filepath.Join(c.root, filepath.Base(binding.ConfigDir))); !os.IsNotExist(err) {
		t.Fatal("private credential directory survived disconnect")
	}
	if err := c.Start("old-link", epoch); err == nil {
		t.Fatal("pre-disconnect consent capability was reusable")
	}
	select {
	case result := <-result:
		if result.err == nil || result.token != "" {
			t.Fatal("refresh token escaped disconnect")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect did not join the canceled refresh")
	}
	if token, err := c.Token(context.Background(), binding, nil); err == nil || token != "" {
		t.Fatal("disconnected binding still mints tokens")
	}
}

// Google's real answers, with a canary that must never escape.
const projectAnswers = `id="$3"
log="$CLOUDSDK_CONFIG/../project-calls"
echo "$2 $id" >> "$log"
describes=$(grep -c '^describe ' "$log" || true)
creates=$(grep -c '^create ' "$log" || true)
hidden() { echo "ERROR: (gcloud.projects.describe) User [person@example.test] does not have permission to access projects instance [$id] (or it may not exist): The caller does not have permission SECRET-CANARY" >&2; exit 1; }
taken() { echo "ERROR: (gcloud.projects.create) Project creation failed. The project ID you specified is already in use by another project. Please try an alternative ID. SECRET-CANARY" >&2; exit 1; }
broken() { echo "ERROR: (gcloud.projects.$1) backend error SECRET-CANARY" >&2; exit 1; }
`

// connectWithProjects runs one connection (signing in first if needed)
// against the given project answers and returns the final view as the
// instance status shows it, and the project commands gcloud saw.
func connectWithProjects(t *testing.T, c *Controller, answers string, signIn bool) (map[string]any, []string) {
	t.Helper()
	if err := os.MkdirAll(c.root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.root, "projects"), []byte(projectAnswers+answers), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.Start("browser", c.Epoch()); err != nil {
		t.Fatal(err)
	}
	if signIn {
		waitView(t, c, "browser", "awaiting_code")
		if err := c.Submit("browser", "fixture-code"); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.Status().Busy {
		if time.Now().After(deadline) {
			t.Fatal("connection did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	raw, err := json.Marshal(c.Status())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET") {
		t.Fatalf("command output escaped: %s", raw)
	}
	var view map[string]any
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(filepath.Join(c.root, "project-calls"))
	if err != nil {
		t.Fatal(err)
	}
	return view, strings.Fields(strings.ReplaceAll(string(calls), "\n", " "))
}

// Google never reuses a project ID, and answers a project deleted for good
// exactly like one this account cannot reach. A retained ID that is gone must
// be replaced by a sealed fresh one, without looping, and a failed setup must
// say which command failed (#184).
func TestSetupReplacesProjectIDGoogleWillNotReuse(t *testing.T) {
	t.Run("deleted project gets a fresh sealed ID", func(t *testing.T) {
		c, saved, _ := controllerFixture(t)
		view, calls := connectWithProjects(t, c, `
if [ "$2" = describe ]; then
  if grep -qx "created $id" "$log"; then printf 'ACTIVE\n'; exit 0; fi
  hidden
fi
case $creates in 1) taken ;; 2) broken create ;; esac
echo "created $id" >> "$log"
exit 0
`, true)
		if view["phase"] != "setup_required" || view["error"] != "google_command_failed" || view["step"] != "project_create" {
			t.Fatalf("failed fresh create: %v", view)
		}
		retained, fresh := calls[1], saved().Project
		if want := []string{"describe", retained, "create", retained, "describe", retained, "create", fresh}; strings.Join(calls, " ") != strings.Join(want, " ") || fresh == retained {
			t.Fatalf("project commands %v; want %v", calls, want)
		}
		// The retry keeps the sealed fresh ID instead of picking another.
		view, calls = connectWithProjects(t, c, `
if [ "$2" = describe ]; then hidden; fi
exit 0
`, false)
		if view["phase"] != "connected" || !saved().Ready || saved().Project != fresh {
			t.Fatalf("retry: %v project=%s", view, saved().Project)
		}
		if got := strings.Join(calls[8:], " "); got != "describe "+fresh+" create "+fresh {
			t.Fatalf("retry project commands: %s", got)
		}
	})
	t.Run("a refused fresh ID is not retried", func(t *testing.T) {
		c, _, _ := controllerFixture(t)
		view, calls := connectWithProjects(t, c, `
if [ "$2" = describe ]; then hidden; fi
taken
`, true)
		if view["error"] != "project_not_accessible" || view["step"] != "project_create" || len(calls) != 8 {
			t.Fatalf("refused fresh ID: %v after %v", view, calls)
		}
	})
	t.Run("a passing describe failure keeps the project", func(t *testing.T) {
		c, saved, _ := controllerFixture(t)
		view, calls := connectWithProjects(t, c, `
if [ "$2" = describe ]; then
  if [ "$describes" = 1 ]; then broken describe; fi
  printf 'ACTIVE\n'; exit 0
fi
taken
`, true)
		if view["phase"] != "connected" || saved().Project != calls[1] || len(calls) != 6 {
			t.Fatalf("existing project replaced: %v after %v", view, calls)
		}
	})
}

// An account at Google's project limit cannot get a new project for 30 days
// even after deleting some; the owner names a project the account already
// owns, and setup uses it without trying to create anything (#184).
func TestProjectLimitUsesAnExistingProject(t *testing.T) {
	c, saved, _ := controllerFixture(t)
	answers := `
if [ "$2" = describe ]; then
  if [ "$id" = owned-project-1 ]; then printf 'ACTIVE\n'; exit 0; fi
  hidden
fi
echo "ERROR: (gcloud.projects.create) FAILED_PRECONDITION: You've reached your project limit. SECRET-CANARY" >&2
exit 1
`
	view, calls := connectWithProjects(t, c, answers, true)
	if view["error"] != "project_limit_reached" || view["step"] != "project_create" || len(calls) != 4 {
		t.Fatalf("project limit: %v after %v", view, calls)
	}
	ctx := context.Background()
	for _, bad := range []string{"Owned-project", "short", "1owned-project", "owned-project-", "owned_project", strings.Repeat("a", 31)} {
		if err := c.ChooseProject(ctx, bad); !errors.Is(err, ErrProjectID) {
			t.Fatalf("project ID %q accepted: %v", bad, err)
		}
	}
	if err := c.ChooseProject(ctx, "missing-project"); err != nil {
		t.Fatal(err)
	}
	view, calls = connectWithProjects(t, c, answers, false)
	if view["error"] != "project_not_found" || view["step"] != "project_describe" || strings.Join(calls[4:], " ") != "describe missing-project" {
		t.Fatalf("unreachable chosen project: %v after %v", view, calls)
	}
	if err := c.ChooseProject(ctx, "owned-project-1"); err != nil {
		t.Fatal(err)
	}
	view, calls = connectWithProjects(t, c, answers, false)
	connected := saved()
	if view["phase"] != "connected" || connected.Project != "owned-project-1" || !connected.ProjectChosen || strings.Join(calls[6:], " ") != "describe owned-project-1" {
		t.Fatalf("chosen project: %v project=%s after %v", view, connected.Project, calls)
	}
	if err := c.ChooseProject(ctx, "another-project"); !errors.Is(err, ErrProjectNotChoosable) {
		t.Fatalf("connected Drive changed project: %v", err)
	}
}
