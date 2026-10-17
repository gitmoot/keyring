package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/gcloudexec"
	"github.com/gitmoot/keyring/internal/policy"
)

// A real executable with gcloud's fixed argv contract, not a provider stub.
// Its only credentials are synthetic test strings in private temp directories.
func googleFixture(t *testing.T) (*Handler, *bytes.Buffer, map[string]string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	root := t.TempDir()
	executable := filepath.Join(root, "gcloud")
	script := `#!/bin/sh
[ "$1" = auth ] && [ "$2" = print-access-token ] && [ "$4" = "--account=$3" ] && [ "$5" = --configuration=default ] && [ "$6" = --quiet ] || exit 2
[ "$HOME" = "$CLOUDSDK_CONFIG" ] && [ -z "$CLOUDSDK_AUTH_ACCESS_TOKEN" ] || exit 3
printf 'call\n' >> "$CLOUDSDK_CONFIG/calls"
if [ -f "$CLOUDSDK_CONFIG/fail" ]; then echo 'secret-stderr-sentinel' >&2; exit 1; fi
cat "$CLOUDSDK_CONFIG/token"
`
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	dirs := map[string]string{}
	accounts := map[string]any{}
	services := map[string]any{}
	roles := map[string]any{}
	for _, name := range []string{"personal", "business"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		dirs[name] = dir
		if err := os.WriteFile(filepath.Join(dir, "token"), []byte("synthetic-"+name), 0600); err != nil {
			t.Fatal(err)
		}
		accounts[name] = map[string]any{"executable": executable, "config_dir": dir, "account": name + "@example.com", "quota_project": "quota-" + name}
		services[name] = map[string]any{"auth": "gcloud", "google_account": name, "base": "https://www.googleapis.com/drive/v3"}
		roles[name] = map[string]any{"token_sha256": tokenHash("role-" + name), "access": map[string]any{name: map[string]any{"paths": []string{"/files"}, "methods": []string{"GET", "POST"}}}}
	}
	blob, err := json.Marshal(map[string]any{"listen": "127.0.0.1:7701", "allow_sources": []string{caller}, "audit_log": "audit.log", "google_accounts": accounts, "services": services, "roles": roles})
	if err != nil {
		t.Fatal(err)
	}
	var cfg policy.Config
	if err := json.Unmarshal(blob, &cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	audit := &bytes.Buffer{}
	h := New(&cfg, nil, audit)
	checks, writes := &atomic.Int32{}, &atomic.Int32{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tokeninfo" {
			checks.Add(1)
			account := strings.TrimPrefix(r.URL.Query().Get("access_token"), "synthetic-")
			fmt.Fprintf(w, `{"email":%q,"expires_in":120}`, account+"@example.com")
			return
		}
		account := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer synthetic-")
		if account != "personal" && account != "business" {
			http.Error(w, "wrong identity", 401)
			return
		}
		if r.Header.Get("X-Goog-User-Project") != "quota-"+account || r.Header.Get("X-Goog-Api-Key") != "" || r.URL.Query().Get("access_token") != "" {
			http.Error(w, "caller overrode credentials or quota", 400)
			return
		}
		if r.Method == "POST" {
			writes.Add(1)
			http.Error(w, "rejected after an ambiguous write", 401)
			return
		}
		fmt.Fprintf(w, `{"owner":%q,"echo":%q}`, account, r.Header.Get("Authorization"))
	}))
	t.Cleanup(up.Close)
	target, _ := url.Parse(up.URL)
	h.client.Transport = googleTestTransport{target: target, transport: http.DefaultTransport}
	return h, audit, dirs, checks, writes
}

type googleTestTransport struct {
	target    *url.URL
	transport http.RoundTripper
}

func (t googleTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "oauth2.googleapis.com" && r.URL.Host != "www.googleapis.com" && r.URL.Host != "sheets.googleapis.com" {
		return nil, fmt.Errorf("unexpected upstream")
	}
	copy := r.Clone(r.Context())
	copy.URL.Scheme, copy.URL.Host = t.target.Scheme, t.target.Host
	return t.transport.RoundTrip(copy)
}

func TestGoogleAccountsProxy(t *testing.T) {
	h, audit, _, checks, writes := googleFixture(t)
	t.Setenv("CLOUDSDK_AUTH_ACCESS_TOKEN", "must-not-inherit")
	for range 3 {
		for _, name := range []string{"personal", "business"} {
			w := call(h, "GET", "/"+name+"/files?access_token=caller-token", "role-"+name, map[string]string{"X-Goog-User-Project": "caller-project", "X-Goog-Api-Key": "caller-key"})
			if w.Code != 200 || !strings.Contains(w.Body.String(), `"owner":"`+name+`"`) || strings.Contains(w.Body.String(), "synthetic-") {
				t.Fatalf("account %s: %d %s", name, w.Code, w.Body)
			}
		}
	}
	if checks.Load() != 2 {
		t.Fatalf("token validations = %d; want one per account", checks.Load())
	}
	for _, tc := range []struct{ method, path, token string }{
		{"GET", "/business/files", "role-personal"},
		{"GET", "/personal/files", "role-business"},
		{"DELETE", "/personal/files", "role-personal"},
		{"GET", "/personal/drives", "role-personal"},
		{"GET", "/personal/files", "revoked-role"},
	} {
		if w := call(h, tc.method, tc.path, tc.token, nil); w.Code != 403 && w.Code != 401 {
			t.Fatalf("grant violation %s %s: %d", tc.method, tc.path, w.Code)
		}
	}
	if checks.Load() != 2 {
		t.Fatal("denied calls reached credential provider")
	}
	if w := call(h, "POST", "/personal/files", "role-personal", nil); w.Code != 401 || writes.Load() != 1 {
		t.Fatalf("write status=%d effects=%d; must not replay", w.Code, writes.Load())
	}
	call(h, "GET", "/personal/files", "role-personal", nil)
	if checks.Load() != 3 {
		t.Fatal("401 did not invalidate the used credential")
	}
	if strings.Contains(audit.String(), "synthetic-") || strings.Contains(audit.String(), "caller-token") {
		t.Fatal("audit exposed a credential")
	}
}

func TestGoogleConcurrentRenewalAndFailures(t *testing.T) {
	h, audit, dirs, checks, _ := googleFixture(t)
	clock := time.Now()
	h.now = func() time.Time { return clock }
	for round := range 2 {
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if w := call(h, "GET", "/personal/files", "role-personal", nil); w.Code != 200 {
					t.Errorf("renewal: %d", w.Code)
				}
			}()
		}
		wg.Wait()
		if checks.Load() != int32(round+1) {
			t.Fatalf("renewal round %d: %d token checks", round, checks.Load())
		}
		clock = clock.Add(90 * time.Second)
	}
	if err := os.WriteFile(filepath.Join(dirs["personal"], "fail"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	w := call(h, "GET", "/personal/files", "role-personal", nil)
	if w.Code != 502 || strings.Contains(w.Body.String()+audit.String(), "secret-stderr-sentinel") {
		t.Fatalf("failed command: %d %s", w.Code, w.Body)
	}
	// One account failing must not break the other, or return a stale token.
	if w := call(h, "GET", "/business/files", "role-business", nil); w.Code != 200 {
		t.Fatalf("other account after failed command: %d", w.Code)
	}
	if err := os.Remove(filepath.Join(dirs["personal"], "fail")); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(11 * time.Second)
	if err := os.WriteFile(filepath.Join(dirs["personal"], "token"), []byte("synthetic-business"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := call(h, "GET", "/personal/files", "role-personal", nil); w.Code != 502 {
		t.Fatalf("mismatched Google identity: %d", w.Code)
	}
	// Role revocation blocks a cached account as well.
	cfg := h.Config()
	delete(cfg.Roles, "business")
	h.Swap(cfg, nil)
	if w := call(h, "GET", "/business/files", "role-business", nil); w.Code != 403 && w.Code != 401 {
		t.Fatalf("revoked role used cache: %d", w.Code)
	}
}

func TestGoogleCommandOutputAndTimeout(t *testing.T) {
	h, _, dirs, _, _ := googleFixture(t)
	clock := time.Now()
	h.now = func() time.Time { return clock }
	executable := filepath.Join(filepath.Dir(dirs["personal"]), "gcloud")
	if err := os.WriteFile(filepath.Join(dirs["personal"], "token"), bytes.Repeat([]byte("x"), 20000), 0600); err != nil {
		t.Fatal(err)
	}
	if w := call(h, "GET", "/personal/files", "role-personal", nil); w.Code != 502 || w.Header().Get("X-Keyring-Google-Cause") != "output_limit" || w.Header().Get("X-Keyring-Google-Recovery") != "repair_host" {
		t.Fatalf("oversized command output: %d", w.Code)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nsleep 60 &\nwait\n"), 0700); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(11 * time.Second)
	start := time.Now()
	if w := call(h, "GET", "/personal/files", "role-personal", nil); w.Code != 502 || w.Header().Get("X-Keyring-Google-Cause") != "timeout" || w.Header().Get("X-Keyring-Google-Stage") != "command" || time.Since(start) > 35*time.Second {
		t.Fatal("command process group was not bounded")
	}
	clock = clock.Add(11 * time.Second)
	if err := os.Chmod(dirs["personal"], 0755); err != nil {
		t.Fatal(err)
	}
	if w := call(h, "GET", "/personal/files", "role-personal", nil); w.Code != 502 || w.Header().Get("X-Keyring-Google-Cause") != "configuration_error" {
		t.Fatal("public gcloud directory was accepted")
	}
}

func TestGoogleSheetAppendSpacedRange(t *testing.T) {
	h, _, _, _, _ := googleFixture(t)
	cfg := h.Config()
	svc := cfg.Services["personal"]
	svc.Base = "https://sheets.googleapis.com/v4"
	cfg.Services["personal"] = svc
	role := cfg.Roles["personal"]
	role.Access["personal"] = policy.Access{Paths: []string{"/spreadsheets"}, Methods: []string{"POST"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h.Swap(cfg, nil)
	var appends atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tokeninfo" {
			fmt.Fprint(w, `{"email":"personal@example.com","expires_in":120}`)
			return
		}
		if r.URL.Path != "/v4/spreadsheets/sheet/values/'My Tab'!A1:append" ||
			!strings.Contains(r.URL.EscapedPath(), "My%20Tab") ||
			r.URL.Query().Get("valueInputOption") != "RAW" ||
			r.Method != "POST" || r.Header.Get("Authorization") != "Bearer synthetic-personal" {
			t.Errorf("incorrect append path/method/credential")
			http.Error(w, "bad append", 400)
			return
		}
		appends.Add(1)
		fmt.Fprint(w, `{"updates":{"updatedRows":1}}`)
	}))
	defer up.Close()
	target, _ := url.Parse(up.URL)
	h.client.Transport = googleTestTransport{target: target, transport: http.DefaultTransport}
	path := "/personal/spreadsheets/sheet/values/%27My%20Tab%27%21A1:append?valueInputOption=RAW"
	if w := call(h, "POST", path, "role-personal", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"updatedRows":1`) {
		t.Fatalf("append to tab with space: %d %s", w.Code, w.Body)
	}
	for _, escaped := range []string{"My%09Tab", "My%0aTab", "My%2520Tab", "My%2fTab", "%2e%2e", "My;Tab"} {
		if w := call(h, "POST", "/personal/spreadsheets/sheet/values/"+escaped+":append", "role-personal", nil); w.Code != 400 {
			t.Fatalf("ambiguous path %s: %d", escaped, w.Code)
		}
	}
	knownDenied := call(h, "POST", path, "role-business", nil)
	unknownDenied := call(h, "POST", strings.Replace(path, "/personal/", "/unknown/", 1), "role-business", nil)
	if knownDenied.Code < 400 || knownDenied.Code != unknownDenied.Code || knownDenied.Body.String() != unknownDenied.Body.String() {
		t.Fatal("a space probe reveals an ungranted Google service")
	}
	if appends.Load() != 1 {
		t.Fatalf("append effects=%d; rejected paths must not reach upstream", appends.Load())
	}
	legacy, _ := newHandler(t, up.URL, bearer, allowAll)
	if w := call(legacy, "GET", "/api/My%20Tab", testToken, nil); w.Code != 400 {
		t.Fatalf("non-Google path policy changed: %d", w.Code)
	}
}

type googleRenewalGate struct {
	base    http.RoundTripper
	entered chan struct{}
	release chan struct{}
}

func (g googleRenewalGate) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "oauth2.googleapis.com" {
		select {
		case g.entered <- struct{}{}:
		default:
		}
		select {
		case <-g.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	return g.base.RoundTrip(r)
}

func TestGoogleRenewalSurvivesConfigTransition(t *testing.T) {
	h, _, _, checks, _ := googleFixture(t)
	gate := googleRenewalGate{base: h.client.Transport, entered: make(chan struct{}, 1), release: make(chan struct{})}
	h.client.Transport = gate
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	t.Cleanup(release)
	results := make(chan int, 2)
	request := func() {
		results <- call(h, "GET", "/personal/files", "role-personal", nil).Code
	}
	go request()
	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("first renewal did not reach token validation")
	}
	cfg := h.Config()
	removed := *cfg
	removed.Services = map[string]policy.Service{}
	removed.Roles = map[string]policy.Role{}
	if err := removed.Validate(); err != nil {
		t.Fatal(err)
	}
	h.Swap(&removed, nil)
	h.Swap(cfg, nil)
	go request()
	release()
	for range 2 {
		if status := <-results; status != 200 {
			t.Fatalf("request across reload: %d", status)
		}
	}
	if checks.Load() != 1 {
		t.Fatalf("same binding renewed %d times across config transition; want one flight", checks.Load())
	}
}

func TestContainerGoogleRenewalBeyondHostBudget(t *testing.T) {
	t.Parallel()
	host, audit, dirs, _, _ := googleFixture(t)
	account := host.snap.Load().config.GoogleAccounts["personal"]
	// Model the measured lite-container SDK startup with a real, cancellable
	// command. Keep the host fixture's argv/environment and token validation.
	if err := os.Rename(account.Executable, account.Executable+".inner"); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nsleep 31\nexec \"$0.inner\" \"$@\"\n"
	if err := os.WriteFile(account.Executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg := *host.snap.Load().config
	cfg.ContainerMode = true
	cfg.AllowSources = nil
	binding := account
	binding.Executable = policy.ContainerGoogleExecutable
	binding.ConfigDir = policy.ContainerGoogleRoot + "/" + strings.Repeat("a", 32)
	cfg.GoogleAccounts = map[string]policy.GoogleAccount{"me": binding}
	cfg.Services = map[string]policy.Service{
		"google-me-drive": {Auth: policy.AuthGcloud, GoogleAccount: "me", Base: "https://www.googleapis.com/drive/v3"},
	}
	cfg.Roles = map[string]policy.Role{
		"router": {TokenSHA256: tokenHash("role-personal"), Access: map[string]policy.Access{
			"google-me-drive": {Methods: []string{"GET"}, Paths: []string{"/files"}},
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h := New(&cfg, nil, audit)
	h.client.Transport = host.client.Transport
	h.SetGoogleCommand(func(ctx context.Context, _ policy.GoogleAccount, trace *gcloudexec.RenewalTrace) (string, error) {
		token, _, err := host.fetchGoogleToken(ctx, account, trace)
		return token, err
	})
	proxy := httptest.NewServer(h)
	defer proxy.Close()
	// Match the existing caller's outer limit: a renewal may exceed the host
	// budget, but must still leave room for the actual upstream request.
	client := &http.Client{Timeout: time.Minute}
	for range 2 {
		req, err := http.NewRequest(http.MethodGet, proxy.URL+"/google-me-drive/files", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set(TokenHeader, "role-personal")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body struct{ Owner string }
		err = json.NewDecoder(res.Body).Decode(&body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK || err != nil || body.Owner != "personal" {
			t.Fatalf("slow container renewal did not reach the correct upstream: status=%d owner=%q err=%v", res.StatusCode, body.Owner, err)
		}
	}
	calls, err := os.ReadFile(filepath.Join(dirs["personal"], "calls"))
	if err != nil || string(calls) != "call\n" {
		t.Fatalf("cached request launched another SDK renewal: calls=%q err=%v", calls, err)
	}
}
