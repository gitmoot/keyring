package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

// The optional assertion keeps the test executable on the previous production
// API too. Its assertion is the missing durable incident, not a missing method.
func openGoogleHistoryForTest(t *testing.T, h *Handler, path string) {
	t.Helper()
	if opener, ok := any(h).(interface{ OpenGoogleHistory(string) error }); ok {
		if err := opener.OpenGoogleHistory(path); err != nil {
			t.Fatal(err)
		}
	}
}

type recordedGoogleIncident struct {
	FirstFailure time.Time `json:"first_failure"`
	LastFailure  time.Time `json:"last_failure"`
	RecoveredAt  time.Time `json:"recovered_at"`
	Outcome      string    `json:"outcome"`
	Attempts     uint64    `json:"attempts"`
	Failure      struct {
		Category    string   `json:"category"`
		Stage       string   `json:"stage"`
		Evidence    []string `json:"evidence"`
		ExitCode    *int     `json:"exit_code"`
		TimedOut    bool     `json:"timed_out"`
		OutputLimit bool     `json:"output_limit"`
	} `json:"failure"`
}

type recordedGoogleAccount struct {
	Account     string                   `json:"account"`
	LastSuccess time.Time                `json:"last_success"`
	Incidents   []recordedGoogleIncident `json:"incidents"`
}

func readGoogleHistoryForTest(t *testing.T, path string) (map[string]recordedGoogleAccount, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("renewal did not retain its protected incident: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("history not private: %v %v", info, err)
	}
	var file struct {
		Accounts map[string]recordedGoogleAccount `json:"accounts"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	byLabel := make(map[string]recordedGoogleAccount, len(file.Accounts))
	for _, account := range file.Accounts {
		byLabel[account.Account] = account
	}
	return byLabel, data
}

func TestGoogleRenewalCauseAndSecrecy(t *testing.T) {
	for _, tc := range []struct{ name, stderr, cause, recovery string }{
		{"reauth", "There was a problem reauthenticating while refreshing your current auth tokens: Reauthentication failed. cannot prompt during non-interactive execution.", "reauth_required", "owner_reauth"},
		{"rapt", `{'error': 'invalid_grant', 'error_subtype': 'invalid_rapt'}`, "reauth_required", "owner_reauth"},
		{"revoked", "invalid_grant: Token has been expired or revoked.", "credentials_invalid", "owner_review_credentials"},
		{"permissions", "PermissionError: [Errno 13] Permission denied", "permission_denied", "repair_host"},
		{"configuration", "The configuration [default] does not exist.", "configuration_error", "repair_host"},
		{"runtime", "ModuleNotFoundError: No module named googlecloudsdk", "runtime_unavailable", "repair_host"},
		{"network", "ConnectionError: connection refused", "network_error", "check_connectivity"},
		{"provider", "HTTPError 503: Service Unavailable", "provider_error", "inspect_provider"},
		{"unknown_advice", "Unexpected failure; try gcloud auth login to sign in again", "unknown", "inspect_host"},
		{"opaque_codes", "Unknown failure https://accounts.google.com/?code=invalid_rapt&error=invalid_grant Bearer rapt_required", "unknown", "inspect_host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, audit, dirs, checks, _ := googleFixture(t)
			path := filepath.Join(t.TempDir(), "google-renewals.json")
			openGoogleHistoryForTest(t, h, path)
			const stdoutSecret = "synthetic-stdout-token-NEVER-RETAIN"
			const stderrSecret = "synthetic-stderr-bearer-NEVER-RETAIN"
			const codeSecret = "synthetic-auth-code-NEVER-RETAIN"
			script := fmt.Sprintf("#!/bin/sh\nprintf 'call\\n' >> \"$CLOUDSDK_CONFIG/calls\"\nif [ \"$3\" = business@example.com ]; then cat \"$CLOUDSDK_CONFIG/token\"; exit 0; fi\nprintf '%%s\\n' '%s'\ncat <<'DIAGNOSTIC' >&2\n%s\nBearer %s\nhttps://accounts.google.com/o/oauth2/auth?code=%s\nDIAGNOSTIC\nexit 1\n", stdoutSecret, tc.stderr, stderrSecret, codeSecret)
			if err := os.WriteFile(filepath.Join(filepath.Dir(dirs["personal"]), "gcloud"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				response := call(h, "GET", "/personal/files", "role-personal", nil)
				if response.Code != 502 || response.Header().Get("X-Keyring-Google-Cause") != tc.cause || response.Header().Get("X-Keyring-Google-Stage") != "command" || response.Header().Get("X-Keyring-Google-Recovery") != tc.recovery {
					t.Fatalf("wrong diagnosis: status=%d headers=%v", response.Code, response.Header())
				}
				if !strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain") {
					t.Fatal("diagnostic body changed transport")
				}
				status, _ := h.GoogleStatus("personal")
				_, persisted := readGoogleHistoryForTest(t, path)
				combined := response.Body.String() + fmt.Sprint(response.Header()) + audit.String() + status + string(persisted)
				for _, secret := range []string{stdoutSecret, stderrSecret, codeSecret, "https://accounts.google.com/", "access_token="} {
					if strings.Contains(combined, secret) {
						t.Fatalf("diagnosis retained secret material %q", secret)
					}
				}
			}
			if checks.Load() != 0 {
				t.Fatal("failed command triggered an extra token-validation request")
			}
			calls, err := os.ReadFile(filepath.Join(dirs["personal"], "calls"))
			if err != nil || string(calls) != "call\n" {
				t.Fatalf("diagnosis repeated the token command: %q %v", calls, err)
			}
			records, _ := readGoogleHistoryForTest(t, path)
			incidents := records["personal"].Incidents
			if len(incidents) != 1 || incidents[0].Attempts != 1 || incidents[0].Failure.Category != tc.cause || incidents[0].Failure.ExitCode == nil || *incidents[0].Failure.ExitCode != 1 {
				t.Fatalf("original failure evidence missing: %+v", incidents)
			}
			if response := call(h, "GET", "/personal/files", "role-business", nil); response.Code != 403 || response.Header().Get("X-Keyring-Google-Cause") != "" {
				t.Fatal("another role received this account's diagnosis")
			}
			if response := call(h, "GET", "/business/files", "role-business", nil); response.Code != 200 || response.Header().Get("X-Keyring-Google-Cause") != "" {
				t.Fatal("personal failure contaminated business")
			}
			records, _ = readGoogleHistoryForTest(t, path)
			if len(records["business"].Incidents) != 0 || records["business"].LastSuccess.IsZero() {
				t.Fatal("account-specific success/failure history was mixed")
			}
		})
	}
}

func TestGoogleRenewalHistorySurvivesRecoveryAndRestart(t *testing.T) {
	h, audit, dirs, _, _ := googleFixture(t)
	clock := time.Now().UTC()
	h.now = func() time.Time { return clock }
	path := filepath.Join(t.TempDir(), "google-renewals.json")
	openGoogleHistoryForTest(t, h, path)
	if response := call(h, "GET", "/personal/files", "role-personal", nil); response.Code != 200 {
		t.Fatal("initial renewal failed")
	}
	firstSuccess := clock
	clock = clock.Add(90 * time.Second)
	if err := os.WriteFile(filepath.Join(dirs["personal"], "fail"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if response := call(h, "GET", "/personal/files", "role-personal", nil); response.Code != 502 {
		t.Fatal("expected original renewal failure")
	}
	records, _ := readGoogleHistoryForTest(t, path)
	if len(records["personal"].Incidents) != 1 || !records["personal"].LastSuccess.Equal(firstSuccess) {
		t.Fatal("lost last success or original incident")
	}
	firstFailure := records["personal"].Incidents[0].FirstFailure
	// Restart with the same protected state and existing credentials. It must
	// update the open incident, not forget it or invent a successful recovery.
	restarted := New(h.Config(), nil, audit)
	restarted.client = h.client
	restarted.now = func() time.Time { return clock }
	openGoogleHistoryForTest(t, restarted, path)
	clock = clock.Add(time.Minute)
	if response := call(restarted, "GET", "/personal/files", "role-personal", nil); response.Code != 502 {
		t.Fatal("failure after restart was lost")
	}
	records, _ = readGoogleHistoryForTest(t, path)
	incident := records["personal"].Incidents[0]
	if len(records["personal"].Incidents) != 1 || incident.Attempts != 2 || !incident.FirstFailure.Equal(firstFailure) || !incident.LastFailure.Equal(clock) || incident.Outcome != "active" {
		t.Fatalf("restart lost original failure: %+v", incident)
	}
	if err := os.Remove(filepath.Join(dirs["personal"], "fail")); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(11 * time.Second)
	if response := call(restarted, "GET", "/personal/files", "role-personal", nil); response.Code != 200 || response.Header().Get("X-Keyring-Google-Cause") != "" {
		t.Fatal("successful renewal did not clear the active wire warning")
	}
	records, persisted := readGoogleHistoryForTest(t, path)
	incident = records["personal"].Incidents[0]
	if incident.Outcome != "renewed" || !incident.RecoveredAt.Equal(clock) || !records["personal"].LastSuccess.Equal(clock) || !incident.FirstFailure.Equal(firstFailure) {
		t.Fatalf("recovery erased failure history: %+v", incident)
	}
	if bytes.Contains(persisted, []byte("synthetic-personal")) || bytes.Contains(persisted, []byte("secret-stderr-sentinel")) {
		t.Fatal("restart history retained credentials/output")
	}
	last := New(h.Config(), nil, audit)
	last.client = h.client
	last.now = func() time.Time { return clock }
	openGoogleHistoryForTest(t, last, path)
	clock = clock.Add(time.Minute)
	if response := call(last, "GET", "/personal/files", "role-personal", nil); response.Code != 200 {
		t.Fatal("renewal after recovered restart failed")
	}
	records, _ = readGoogleHistoryForTest(t, path)
	if len(records["personal"].Incidents) != 1 || !records["personal"].Incidents[0].RecoveredAt.Equal(incident.RecoveredAt) {
		t.Fatal("recovered incident did not survive a second restart")
	}
}

func TestUpstreamCannotSpoofGoogleDiagnosis(t *testing.T) {
	for _, auth := range []string{policy.AuthGcloud, policy.AuthBearer} {
		t.Run(auth, func(t *testing.T) {
			h, _, _, _, _ := googleFixture(t)
			var status atomic.Int32
			status.Store(200)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/tokeninfo" {
					fmt.Fprint(w, `{"email":"personal@example.com","expires_in":120}`)
					return
				}
				w.Header()["x-kEyRiNg-gOoGlE-cAuSe"] = []string{"reauth_required"}
				w.Header()["X-KEYRING-GOOGLE-STAGE"] = []string{"command"}
				w.Header()["x-keyring-google-recovery"] = []string{"owner_reauth"}
				w.Header().Set("X-Fixture-Preserved", "yes")
				w.WriteHeader(int(status.Load()))
				fmt.Fprint(w, "ordinary upstream response")
			}))
			defer upstream.Close()
			target, _ := url.Parse(upstream.URL)
			h.client.Transport = googleTestTransport{target: target, transport: http.DefaultTransport}
			if auth == policy.AuthBearer {
				cfg := h.Config()
				service := cfg.Services["personal"]
				service.Auth, service.GoogleAccount, service.Key = auth, "", "FIXTURE_KEY"
				cfg.Services["personal"] = service
				if err := cfg.Validate(); err != nil {
					t.Fatal(err)
				}
				h.Swap(cfg, map[string]string{"FIXTURE_KEY": "synthetic-bearer"})
			}
			for _, code := range []int{200, 502} {
				status.Store(int32(code))
				response := call(h, "GET", "/personal/files", "role-personal", nil)
				if response.Code != code || response.Header().Get("X-Fixture-Preserved") != "yes" || response.Body.String() != "ordinary upstream response" {
					t.Fatalf("ordinary response changed: %d %s", response.Code, response.Body)
				}
				for _, header := range []string{"X-Keyring-Google-Cause", "X-Keyring-Google-Stage", "X-Keyring-Google-Recovery"} {
					if response.Header().Get(header) != "" {
						t.Fatalf("upstream impersonated provider via %s", header)
					}
				}
			}
		})
	}
}

func TestGoogleRenewalHistoryRetentionBounds(t *testing.T) {
	h, _, dirs, _, _ := googleFixture(t)
	clock := time.Now().UTC()
	h.now = func() time.Time { return clock }
	path := filepath.Join(t.TempDir(), "google-renewals.json")
	openGoogleHistoryForTest(t, h, path)
	var failures []time.Time
	for range 10 {
		clock = clock.Add(90 * time.Second)
		failures = append(failures, clock)
		if err := os.WriteFile(filepath.Join(dirs["personal"], "fail"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if response := call(h, "GET", "/personal/files", "role-personal", nil); response.Code != 502 {
			t.Fatal("failure fixture did not fail")
		}
		if err := os.Remove(filepath.Join(dirs["personal"], "fail")); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(11 * time.Second)
		if response := call(h, "GET", "/personal/files", "role-personal", nil); response.Code != 200 {
			t.Fatal("recovery fixture did not recover")
		}
	}
	records, _ := readGoogleHistoryForTest(t, path)
	incidents := records["personal"].Incidents
	if len(incidents) != 8 || !incidents[0].FirstFailure.Equal(failures[2]) || !incidents[7].FirstFailure.Equal(failures[9]) || incidents[7].Outcome != "renewed" {
		t.Fatalf("retention lost recent recovery or kept unbounded incidents: %+v", incidents)
	}
	// Reassigning a label must not merge the old binding's history into the
	// replacement. Bound the total retained bindings as configurations change.
	for i := range 66 {
		clock = clock.Add(time.Minute)
		cfg := h.Config()
		account := cfg.GoogleAccounts["personal"]
		account.Account = fmt.Sprintf("replacement-%d@example.com", i)
		cfg.GoogleAccounts["personal"] = account
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		h.Swap(cfg, nil)
		response := call(h, "GET", "/personal/files", "role-personal", nil)
		if response.Code != 502 || response.Header().Get("X-Keyring-Google-Cause") != "credentials_invalid" {
			t.Fatal("replacement identity was not independently checked")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Accounts map[string]recordedGoogleAccount `json:"accounts"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Accounts) != 64 || len(data) > 1<<20 {
		t.Fatal("binding history is not bounded")
	}
	for _, account := range file.Accounts {
		if len(account.Incidents) != 1 || account.Incidents[0].Attempts != 1 || account.Incidents[0].Failure.Category != "credentials_invalid" || !account.LastSuccess.IsZero() {
			t.Fatal("replacement inherited another binding's incidents or success")
		}
	}
	if bytes.Contains(data, []byte("replacement-")) {
		t.Fatal("history retained account emails rather than binding labels")
	}
}

func TestGoogleRuntimeStartFailures(t *testing.T) {
	for _, kind := range []string{"missing", "permission", "broken"} {
		t.Run(kind, func(t *testing.T) {
			h, _, dirs, checks, _ := googleFixture(t)
			executable := filepath.Join(filepath.Dir(dirs["personal"]), "gcloud")
			cause := "runtime_unavailable"
			var err error
			switch kind {
			case "missing":
				err = os.Remove(executable)
			case "permission":
				cause = "permission_denied"
				err = os.Chmod(executable, 0o600)
			case "broken":
				err = os.WriteFile(executable, []byte("not an executable image\n"), 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			response := call(h, "GET", "/personal/files", "role-personal", nil)
			if response.Code != 502 || response.Header().Get("X-Keyring-Google-Cause") != cause || response.Header().Get("X-Keyring-Google-Stage") != "command_start" || response.Header().Get("X-Keyring-Google-Recovery") != "repair_host" {
				t.Fatalf("runtime start error prescribed wrong repair: %d %v", response.Code, response.Header())
			}
			if checks.Load() != 0 {
				t.Fatal("start error issued a token validation probe")
			}
		})
	}
}

func TestGoogleUnsafeHistoryIsNotReadOrOverwritten(t *testing.T) {
	for _, kind := range []string{"public", "symlink", "unknown_field", "unknown_category", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			h, audit, dirs, _, _ := googleFixture(t)
			path := filepath.Join(t.TempDir(), "google-renewals.json")
			openGoogleHistoryForTest(t, h, path)
			if err := os.WriteFile(filepath.Join(dirs["personal"], "fail"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if response := call(h, "GET", "/personal/files", "role-personal", nil); response.Code != 502 {
				t.Fatal("fixture did not fail")
			}
			_, original := readGoogleHistoryForTest(t, path)
			const secret = "synthetic-history-poison-NEVER-RETAIN"
			switch kind {
			case "public":
				if err := os.Chmod(path, 0o644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(t.TempDir(), "private-target")
				if err := os.WriteFile(target, []byte(secret), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "unknown_field":
				poison := append([]byte(`{"`+secret+`":"unknown",`), original[1:]...)
				if err := os.WriteFile(path, poison, 0o600); err != nil {
					t.Fatal(err)
				}
			case "unknown_category":
				poison := bytes.Replace(original, []byte(`"category":"unknown"`), []byte(`"category":"`+secret+`"`), 1)
				if bytes.Equal(poison, original) {
					t.Fatal("fixture did not poison a diagnosis")
				}
				if err := os.WriteFile(path, poison, 0o600); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.WriteFile(path, bytes.Repeat([]byte("x"), (1<<20)+1), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			restarted := New(h.Config(), nil, audit)
			restarted.client = h.client
			if opener, ok := any(restarted).(interface{ OpenGoogleHistory(string) error }); ok {
				err := opener.OpenGoogleHistory(path)
				if err == nil || strings.Contains(err.Error(), secret) {
					t.Fatal("unsafe history accepted or echoed")
				}
			}
			response := call(restarted, "GET", "/personal/files", "role-personal", nil)
			if response.Code != 502 || response.Header().Get("X-Keyring-Google-Cause") != "unknown" {
				t.Fatal("unsafe history contaminated the new diagnosis")
			}
			if response := call(restarted, "GET", "/business/files", "role-business", nil); response.Code != 200 {
				t.Fatal("bad incident history disabled an unrelated account")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("unsafe history or symlink target was overwritten")
			}
			state, _ := restarted.GoogleStatus("personal")
			if strings.Contains(state+response.Body.String()+audit.String(), secret) {
				t.Fatal("unsafe history leaked through status/log/response")
			}
		})
	}
}

func TestGoogleAccountNameHistoryBoundary(t *testing.T) {
	for _, length := range []int{129, 128} {
		t.Run(fmt.Sprintf("length_%d", length), func(t *testing.T) {
			h, _, dirs, _, _ := googleFixture(t)
			cfg := h.Config()
			name := strings.Repeat("a", length)
			cfg.GoogleAccounts[name] = cfg.GoogleAccounts["personal"]
			delete(cfg.GoogleAccounts, "personal")
			service := cfg.Services["personal"]
			service.GoogleAccount = name
			cfg.Services["personal"] = service
			if length == 129 {
				if err := cfg.Validate(); err == nil {
					t.Fatal("accepted an account name whose incidents cannot be retained")
				}
				return
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("rejected supported boundary name: %v", err)
			}
			h.Swap(cfg, nil)
			path := filepath.Join(t.TempDir(), "google-renewals.json")
			openGoogleHistoryForTest(t, h, path)
			if err := os.WriteFile(filepath.Join(dirs["personal"], "fail"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			response := call(h, "GET", "/personal/files", "role-personal", nil)
			if response.Code != 502 || response.Header().Get("X-Keyring-Google-Cause") != "unknown" {
				t.Fatalf("boundary account did not use the renewal failure path: %d", response.Code)
			}
			records, _ := readGoogleHistoryForTest(t, path)
			incidents := records[name].Incidents
			if len(incidents) != 1 || incidents[0].Outcome != "active" || incidents[0].Failure.Category != "unknown" {
				t.Fatalf("accepted boundary account lost its incident: %+v", incidents)
			}
		})
	}
}
