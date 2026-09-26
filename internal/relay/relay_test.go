package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
)

const (
	tokenPhobos = "phobos-token-0123456789abcdef"
	tokenJoltra = "joltra-token-0123456789abcdef"
	apiKey      = "sk-live-relay-test-key-0123456789"
)

type recorder struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (r *recorder) add(req *http.Request) {
	r.mu.Lock()
	r.reqs = append(r.reqs, req.Clone(req.Context()))
	r.mu.Unlock()
}

func (r *recorder) all() []*http.Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*http.Request(nil), r.reqs...)
}

func mustUpstream(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := CheckUpstream(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func do(h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader("body"))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRelayAddsTheRolesTokenAndStripsPrefix(t *testing.T) {
	seen := &recorder{}
	keyring := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.add(r)
		_, _ = io.WriteString(w, "answer")
	}))
	defer keyring.Close()
	rl := New(mustUpstream(t, keyring.URL), map[string]string{"phobos": tokenPhobos, "joltra": tokenJoltra})
	w := do(rl, "POST", "/joltra/openrouter/api/v1/chat?stream=1", map[string]string{TokenHeader: "caller-chosen", "X-Other": "kept"})
	if w.Code != 200 || w.Body.String() != "answer" {
		t.Fatalf("response %d %q", w.Code, w.Body.String())
	}
	got := seen.all()[0]
	if got.URL.Path != "/openrouter/api/v1/chat" || got.URL.RawQuery != "stream=1" {
		t.Fatalf("keyring saw %s?%s", got.URL.Path, got.URL.RawQuery)
	}
	if v := got.Header.Values(TokenHeader); len(v) != 1 || v[0] != tokenJoltra {
		t.Fatalf("token header %v, want only joltra's token", v)
	}
	if got.Header.Get("X-Other") != "kept" {
		t.Fatal("caller header dropped")
	}
}

func TestRelayRefusesUnknownRolesAndBadPaths(t *testing.T) {
	seen := &recorder{}
	keyring := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen.add(r) }))
	defer keyring.Close()
	rl := New(mustUpstream(t, keyring.URL), map[string]string{"phobos": tokenPhobos})
	for target, want := range map[string]int{
		"/nobody/openrouter/x": http.StatusForbidden,
		"/phobos":              http.StatusBadRequest,
		"/phobos/":             http.StatusBadRequest,
		"/..%2f/openrouter/x":  http.StatusBadRequest,
	} {
		if w := do(rl, "GET", target, nil); w.Code != want {
			t.Errorf("%s: status %d, want %d", target, w.Code, want)
		}
	}
	if n := len(seen.all()); n != 0 {
		t.Fatalf("keyring called %d times", n)
	}
}

func TestUnreachableKeyringGivesAClearError(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	base := dead.URL
	dead.Close()
	rl := New(mustUpstream(t, base), map[string]string{"phobos": tokenPhobos})
	w := do(rl, "GET", "/phobos/openrouter/x", nil)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "never fall back to local keys") {
		t.Fatalf("status %d %q", w.Code, w.Body.String())
	}
	if w := do(rl, "GET", HealthPath, nil); w.Code != http.StatusBadGateway {
		t.Fatalf("health with keyring down: %d", w.Code)
	}
}

func TestCheckUpstream(t *testing.T) {
	for raw, ok := range map[string]bool{
		"http://100.111.92.43:7701":   true,
		"http://127.0.0.1:7701":       true,
		"https://keyring.example":     true,
		"http://192.168.1.5:7701":     false, // LAN in clear
		"http://keyring.example":      false, // hostname in clear
		"http://100.111.92.43:7701/x": false,
		"ftp://100.111.92.43":         false,
	} {
		if _, err := CheckUpstream(raw); (err == nil) != ok {
			t.Errorf("CheckUpstream(%q) err = %v, want ok=%v", raw, err, ok)
		}
	}
}

func TestLoadTokensRequiresPrivateFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tokens")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "phobos.token"), []byte(tokenPhobos+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := LoadTokens(dir)
	if err != nil || tokens["phobos"] != tokenPhobos {
		t.Fatalf("tokens %v, err %v", tokens, err)
	}
	if err := os.Chmod(filepath.Join(dir, "phobos.token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokens(dir); err == nil {
		t.Fatal("token file readable by others accepted")
	} else if strings.Contains(err.Error(), tokenPhobos) {
		t.Fatal("error leaks the token")
	}
	_ = os.Chmod(filepath.Join(dir, "phobos.token"), 0o600)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokens(dir); err == nil {
		t.Fatal("token directory readable by others accepted")
	}
}

// The whole path: caller -> relay -> keyring -> API. The key exists only on
// the keyring side, and the caller sees the API's answer.
func TestRelayThroughRealKeyringEndToEnd(t *testing.T) {
	apiSeen := &recorder{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiSeen.add(r)
		_, _ = io.WriteString(w, "model says hi")
	}))
	defer api.Close()
	sum := sha256.Sum256([]byte(tokenPhobos))
	cfg := &policy.Config{
		Listen:       "127.0.0.1:7701",
		AllowSources: []string{"127.0.0.1"},
		AuditLog:     "audit.log",
		Services:     map[string]policy.Service{"openrouter": {Base: api.URL, Key: "OPENROUTER_API_KEY", Auth: policy.AuthBearer}},
		Roles: map[string]policy.Role{"phobos": {TokenSHA256: hex.EncodeToString(sum[:]),
			Access: map[string]policy.Access{"openrouter": {Paths: []string{"/api/v1"}}}}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	audit := &bytes.Buffer{}
	keyring := httptest.NewServer(server.New(cfg, map[string]string{"OPENROUTER_API_KEY": apiKey}, audit))
	defer keyring.Close()
	rl := httptest.NewServer(New(mustUpstream(t, keyring.URL), map[string]string{"phobos": tokenPhobos}))
	defer rl.Close()

	resp, err := http.Post(rl.URL+"/phobos/openrouter/api/v1/chat", "application/json", strings.NewReader(`{"q":1}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "model says hi" {
		t.Fatalf("response %d %q", resp.StatusCode, body)
	}
	got := apiSeen.all()[0]
	if got.URL.Path != "/api/v1/chat" || got.Header.Get("Authorization") != "Bearer "+apiKey || got.Header.Get(TokenHeader) != "" {
		t.Fatalf("API saw path %q auth %q token %q", got.URL.Path, got.Header.Get("Authorization"), got.Header.Get(TokenHeader))
	}
	if !strings.Contains(audit.String(), `"role":"phobos"`) {
		t.Fatalf("audit %q", audit.String())
	}
	resp, err = http.Get(rl.URL + "/phobos/openrouter/api/v2/other")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || len(apiSeen.all()) != 1 {
		t.Fatalf("path outside the role's rules: status %d, API calls %d", resp.StatusCode, len(apiSeen.all()))
	}
	resp, err = http.Get(rl.URL + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health %d", resp.StatusCode)
	}
}

func writeTokenDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tokens")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "phobos.token"), []byte(tokenPhobos+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadTokensRefusesSymlinks(t *testing.T) {
	dir := writeTokenDir(t)
	link := filepath.Join(t.TempDir(), "tokens-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokens(link); err == nil {
		t.Fatal("symlinked token directory accepted")
	}
	outside := filepath.Join(t.TempDir(), "elsewhere.token")
	if err := os.WriteFile(outside, []byte(tokenJoltra), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "joltra.token")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokens(dir); err == nil {
		t.Fatal("symlinked token file accepted")
	}
}

func TestLoadTokensRefusesADirectoryOwnedBySomeoneElse(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to hand the directory to another user")
	}
	dir := writeTokenDir(t)
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokens(dir); err == nil || !strings.Contains(err.Error(), "owned by uid 65534") {
		t.Fatalf("err = %v, want refusal naming the owner", err)
	}
}

func TestLoadTokensRefusesAFIFOWithoutHanging(t *testing.T) {
	dir := writeTokenDir(t)
	if err := syscall.Mkfifo(filepath.Join(dir, "joltra.token"), 0o600); err != nil {
		t.Skip("no mkfifo here:", err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadTokens(dir); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO token file accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("LoadTokens hung on a FIFO")
	}
}

func TestLoadTokensRefusesAParentOthersCanWrite(t *testing.T) {
	dir := writeTokenDir(t)
	if err := os.Chmod(filepath.Dir(dir), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTokens(dir); err == nil {
		t.Fatal("token directory under a world-writable parent accepted")
	}
}
