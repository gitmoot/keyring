package instance

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const adminToken = "supervisor-admin-token"

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newKey(t *testing.T) string {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k)
}

// freeAddr returns a loopback address nothing listens on right now.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type inst struct {
	t     *testing.T
	in    *Instance
	admin http.Handler
	audit *syncBuffer
	state string
}

func newInst(t *testing.T, statePath string) *inst {
	t.Helper()
	audit := &syncBuffer{}
	in, err := New(Options{AdminListen: freeAddr(t), AdminTokenSHA256: sha(adminToken), StatePath: statePath, Audit: audit, AuditName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(in.Close)
	return &inst{t: t, in: in, admin: in.AdminHandler(), audit: audit, state: statePath}
}

// call sends an admin request and decodes the JSON reply into a map.
func (x *inst) call(method, path string, body any) (int, map[string]any) {
	x.t.Helper()
	var r io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	x.admin.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (x *inst) must(method, path string, body any) map[string]any {
	x.t.Helper()
	code, out := x.call(method, path, body)
	if code/100 != 2 {
		x.t.Fatalf("%s %s: %d %v", method, path, code, out)
	}
	return out
}

// upstreamEcho answers with the Authorization header it got.
func upstreamEcho(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "auth="+r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// setUp creates an instance with one bearer service holding value and one
// role, and returns the proxy address and the role token.
func (x *inst) setUp(id, dataKey, upstream, value string) (string, string) {
	x.t.Helper()
	listen := freeAddr(x.t)
	x.must("POST", "/create", map[string]any{"id": id, "data_key": dataKey, "listen": listen, "allow_sources": []string{"127.0.0.1"}})
	x.must("PUT", "/services/api", map[string]any{"base": upstream, "key": "API_KEY", "auth": "bearer"})
	x.must("PUT", "/keys/API_KEY", map[string]any{"value": value})
	out := x.must("PUT", "/roles/agent", map[string]any{"access": map[string]any{"api": map[string]any{"paths": []string{"/"}}}})
	token, _ := out["token"].(string)
	if token == "" {
		x.t.Fatalf("new role: no token in %v", out)
	}
	return listen, token
}

func proxyGet(t *testing.T, listen, token, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+listen+path, nil)
	req.Header.Set("X-Keyring-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestCreateUseRotateDelete(t *testing.T) {
	up := upstreamEcho(t)
	statePath := filepath.Join(t.TempDir(), "state.sealed")
	x := newInst(t, statePath)
	key1 := newKey(t)
	listen, token := x.setUp("alice", key1, up.URL, "alice-secret-value")

	// Use: the agent's call gets the key added.
	if code, body := proxyGet(t, listen, token, "/api/v1/x"); code != 200 || body != "auth=Bearer [REDACTED]" {
		t.Fatalf("proxy call: %d %q", code, body)
	}
	// The state on disk is sealed: no value, no role token hash readable.
	disk, _ := os.ReadFile(statePath)
	if bytes.Contains(disk, []byte("alice-secret-value")) || bytes.Contains(disk, []byte(sha(token))) || bytes.Contains(disk, []byte("API_KEY")) {
		t.Fatal("state file holds plain text")
	}
	status := x.must("GET", "/status", nil)
	if strings.Contains(mustJSON(status), "alice-secret-value") || strings.Contains(mustJSON(status), sha(token)) {
		t.Fatalf("status shows a value or token hash: %v", status)
	}

	// Rotate the role token: the old one stops working.
	newToken, _ := x.must("POST", "/roles/agent/token", nil)["token"].(string)
	if code, _ := proxyGet(t, listen, token, "/api/v1/x"); code != http.StatusUnauthorized {
		t.Fatalf("old role token after rotation: %d", code)
	}
	if code, _ := proxyGet(t, listen, newToken, "/api/v1/x"); code != 200 {
		t.Fatalf("new role token: %d", code)
	}

	// Rotate the data key: the old key opens nothing written since.
	key2 := newKey(t)
	x.must("POST", "/rotate", map[string]any{"data_key": key2})
	sealed := stateBlob(t, x)
	if _, err := open(sealed, mustKey(t, key1)); err == nil {
		t.Fatal("the old data key opens the rotated state")
	}
	if disk, _ := os.ReadFile(statePath); !bytes.Equal(disk, sealed) {
		t.Fatal("state file is not the rotated state")
	}
	if s, err := open(sealed, mustKey(t, key2)); err != nil || s.Keys["API_KEY"] != "alice-secret-value" {
		t.Fatalf("new data key: %v", err)
	}

	// Delete: the state file is gone, the proxy stops, nothing is unlocked.
	x.must("DELETE", "/instance", nil)
	select {
	case <-x.in.Wiped():
	default:
		t.Fatal("Wiped not closed")
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state file after delete: %v", err)
	}
	if code, _ := proxyGet(t, listen, newToken, "/api/v1/x"); code != 0 {
		t.Fatalf("proxy still answers after delete: %d", code)
	}
	if code, out := x.call("GET", "/status", nil); code != 200 || out["unlocked"] != false {
		t.Fatalf("status after delete: %d %v", code, out)
	}
	if code, _ := x.call("GET", "/state", nil); code != http.StatusConflict {
		t.Fatalf("GET /state after delete: %d", code)
	}
	// The process takes no new state after a delete, not even the sealed
	// state the supervisor may still hold.
	if code, _ := x.call("POST", "/unlock", map[string]any{"data_key": key2, "state": base64.StdEncoding.EncodeToString(sealed)}); code != http.StatusGone {
		t.Fatalf("unlock after delete: %d", code)
	}
	if code, _ := x.call("POST", "/create", map[string]any{"id": "alice", "data_key": key2, "listen": freeAddr(t), "allow_sources": []string{"127.0.0.1"}}); code != http.StatusGone {
		t.Fatalf("create after delete: %d", code)
	}
	if code, _ := x.call("DELETE", "/instance", nil); code != http.StatusGone {
		t.Fatalf("second delete: %d", code)
	}
	for _, secret := range []string{"alice-secret-value", token, newToken, key1, key2} {
		if strings.Contains(x.audit.String(), secret) {
			t.Fatalf("audit log holds %q", secret)
		}
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func mustKey(t *testing.T, s string) []byte {
	k, err := decodeKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func stateBlob(t *testing.T, x *inst) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(x.must("GET", "/state", nil)["state"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRestartFromSealedState is the supervisor's path when the instance has
// no disk: it keeps the sealed state and data key, and hands both to a new
// process.
func TestRestartFromSealedState(t *testing.T) {
	up := upstreamEcho(t)
	x := newInst(t, "")
	key := newKey(t)
	listen, token := x.setUp("bob", key, up.URL, "bob-secret")
	blob := stateBlob(t, x)
	version := x.must("GET", "/state", nil)["version"]
	x.in.Close()

	y := newInst(t, "")
	if code, out := y.call("GET", "/status", nil); code != 200 || out["unlocked"] != false {
		t.Fatalf("new instance status: %d %v", code, out)
	}
	if code, out := y.call("POST", "/unlock", map[string]any{"data_key": newKey(t), "state": base64.StdEncoding.EncodeToString(blob)}); code != http.StatusForbidden {
		t.Fatalf("unlock with the wrong key: %d %v", code, out)
	}
	out := y.must("POST", "/unlock", map[string]any{"data_key": key, "state": base64.StdEncoding.EncodeToString(blob)})
	if out["version"] != version {
		t.Fatalf("version %v, want %v", out["version"], version)
	}
	if code, body := proxyGet(t, listen, token, "/api/v1/x"); code != 200 || !strings.HasPrefix(body, "auth=Bearer ") {
		t.Fatalf("proxy after restart: %d %q", code, body)
	}
	if code, _ := y.call("POST", "/unlock", map[string]any{"data_key": key, "state": base64.StdEncoding.EncodeToString(blob)}); code != http.StatusConflict {
		t.Fatalf("second unlock: %d", code)
	}
}

func TestTwoInstancesCannotUseEachOthersKeys(t *testing.T) {
	up := upstreamEcho(t)
	a, b := newInst(t, ""), newInst(t, "")
	keyA, keyB := newKey(t), newKey(t)
	listenA, tokenA := a.setUp("alice", keyA, up.URL, "alice-value")
	listenB, tokenB := b.setUp("bob", keyB, up.URL, "bob-value")

	// Same service and key names in both; each token works only on its own
	// instance and gets only its own value.
	if code, _ := proxyGet(t, listenB, tokenA, "/api/v1/x"); code != http.StatusUnauthorized {
		t.Fatalf("alice's token at bob's instance: %d", code)
	}
	if code, _ := proxyGet(t, listenA, tokenB, "/api/v1/x"); code != http.StatusUnauthorized {
		t.Fatalf("bob's token at alice's instance: %d", code)
	}
	// What each upstream call carried: redaction hides the echo from the
	// caller, so check at the upstream through a recording server.
	rec := &recorder{}
	recSrv := httptest.NewServer(rec)
	t.Cleanup(recSrv.Close)
	a.must("PUT", "/services/api", map[string]any{"base": recSrv.URL, "key": "API_KEY", "auth": "bearer"})
	b.must("PUT", "/services/api", map[string]any{"base": recSrv.URL, "key": "API_KEY", "auth": "bearer"})
	proxyGet(t, listenA, tokenA, "/api/a")
	proxyGet(t, listenB, tokenB, "/api/b")
	if got := rec.get("/a"); got != "Bearer alice-value" {
		t.Fatalf("alice's call carried %q", got)
	}
	if got := rec.get("/b"); got != "Bearer bob-value" {
		t.Fatalf("bob's call carried %q", got)
	}

	// Sealed states: neither key opens the other's state, and a state
	// cannot be passed off as another instance's even with its key.
	blobA, blobB := stateBlob(t, a), stateBlob(t, b)
	if _, err := open(blobA, mustKey(t, keyB)); err == nil {
		t.Fatal("bob's key opens alice's state")
	}
	if _, err := open(blobB, mustKey(t, keyA)); err == nil {
		t.Fatal("alice's key opens bob's state")
	}
	relabeled := bytes.Replace(blobA, []byte("\x05alice"), []byte("\x05bobby"), 1)
	if bytes.Equal(relabeled, blobA) {
		t.Fatal("test did not relabel the state")
	}
	if _, err := open(relabeled, mustKey(t, keyA)); err == nil {
		t.Fatal("a relabeled state opened")
	}
}

type recorder struct {
	mu  sync.Mutex
	got map[string]string
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.got == nil {
		r.got = map[string]string{}
	}
	r.got[req.URL.Path] = req.Header.Get("Authorization")
}

func (r *recorder) get(path string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got[path]
}

func TestAdminNeedsTheToken(t *testing.T) {
	x := newInst(t, "")
	for _, auth := range []string{"", "Bearer ", "Bearer wrong", "Basic " + adminToken, adminToken} {
		req := httptest.NewRequest("GET", "/status", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		x.admin.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("Authorization %q: %d", auth, w.Code)
		}
	}
	if _, err := New(Options{AdminListen: "0.0.0.0:7720", AdminTokenSHA256: sha(adminToken), Audit: io.Discard}); err == nil {
		t.Fatal("admin API on a wildcard address accepted")
	}
	if _, err := New(Options{AdminListen: freeAddr(t), AdminTokenSHA256: sha(adminToken)}); err == nil {
		t.Fatal("instance without an audit writer accepted")
	}
}

func TestRefusedChangesLeaveTheStateAlone(t *testing.T) {
	up := upstreamEcho(t)
	statePath := filepath.Join(t.TempDir(), "state.sealed")
	x := newInst(t, statePath)
	key := newKey(t)
	listen, token := x.setUp("carol", key, up.URL, "carol-value")
	before := stateBlob(t, x)
	version := x.must("GET", "/state", nil)["version"]

	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	refused := []struct {
		method, path string
		body         any
	}{
		{"PUT", "/services/bad", map[string]any{"base": "http://example.com", "key": "K", "auth": "bearer"}}, // plain http
		{"PUT", "/services/api2", map[string]any{"base": "https://x.example.com", "key": "K", "auth": "bearer", "extra": 1}},
		{"DELETE", "/services/api", nil}, // a role still uses it
		{"PUT", "/roles/agent", map[string]any{"access": map[string]any{"nope": map[string]any{"paths": []string{"/"}}}}},
		{"PUT", "/keys/bad-name", map[string]any{"value": "v"}},
		{"PUT", "/keys/K", map[string]any{"value": ""}},
		{"PUT", "/network", map[string]any{"listen": busy.Addr().String(), "allow_sources": []string{"127.0.0.1"}}},
		{"PUT", "/network", map[string]any{"listen": x.in.opt.AdminListen, "allow_sources": []string{"127.0.0.1"}}},
		{"PUT", "/network", map[string]any{"listen": "0.0.0.0:7799", "allow_sources": []string{"127.0.0.1"}}},
		{"POST", "/create", map[string]any{"id": "again", "data_key": newKey(t), "listen": freeAddr(t), "allow_sources": []string{"127.0.0.1"}}},
		{"POST", "/rotate", map[string]any{"data_key": "short"}},
	}
	for _, c := range refused {
		if code, out := x.call(c.method, c.path, c.body); code/100 == 2 {
			t.Errorf("%s %s accepted: %v", c.method, c.path, out)
		}
	}
	if v := x.must("GET", "/state", nil)["version"]; v != version {
		t.Fatalf("version moved from %v to %v", version, v)
	}
	if disk, _ := os.ReadFile(statePath); !bytes.Equal(disk, before) {
		t.Fatal("state file changed")
	}
	if code, _ := proxyGet(t, listen, token, "/api/v1/x"); code != 200 {
		t.Fatalf("proxy after refused changes: %d", code)
	}

	// A second process on the same state file cannot create over it; it
	// can only unlock it.
	x.in.Close()
	y := newInst(t, statePath)
	if code, out := y.call("POST", "/create", map[string]any{"id": "carol", "data_key": newKey(t), "listen": freeAddr(t), "allow_sources": []string{"127.0.0.1"}}); code != http.StatusConflict {
		t.Fatalf("create over an existing state file: %d %v", code, out)
	}
	if disk, _ := os.ReadFile(statePath); !bytes.Equal(disk, before) {
		t.Fatal("state file changed by a refused create")
	}
	y.must("POST", "/unlock", map[string]any{"data_key": key})
}

func TestNetworkMoveRebindsTheProxy(t *testing.T) {
	up := upstreamEcho(t)
	x := newInst(t, "")
	listen, token := x.setUp("dave", newKey(t), up.URL, "dave-value")
	moved := freeAddr(t)
	x.must("PUT", "/network", map[string]any{"listen": moved, "allow_sources": []string{"127.0.0.1"}})
	if code, _ := proxyGet(t, moved, token, "/api/v1/x"); code != 200 {
		t.Fatalf("proxy on the new address: %d", code)
	}
	if code, _ := proxyGet(t, listen, token, "/api/v1/x"); code != 0 {
		t.Fatalf("proxy still on the old address: %d", code)
	}
	// The old port is free as soon as the change returns, so moving back
	// works at once.
	for range 20 {
		x.must("PUT", "/network", map[string]any{"listen": listen, "allow_sources": []string{"127.0.0.1"}})
		x.must("PUT", "/network", map[string]any{"listen": moved, "allow_sources": []string{"127.0.0.1"}})
	}
	// Source check follows the new settings.
	x.must("PUT", "/network", map[string]any{"listen": moved, "allow_sources": []string{"10.9.9.9"}})
	if code, _ := proxyGet(t, moved, token, "/api/v1/x"); code != http.StatusForbidden {
		t.Fatalf("call from a source no longer allowed: %d", code)
	}
}

func TestConsentLinkStoresIntoTheSealedState(t *testing.T) {
	up := upstreamEcho(t)
	x := newInst(t, "")
	key := newKey(t)
	x.setUp("erin", key, up.URL, "erin-value")
	x.must("PUT", "/services/proxy", map[string]any{"base": up.URL, "key": "PROXY_KEY", "auth": "header", "header": "X-Api-Key"})
	pages, api := freeAddr(t), freeAddr(t)
	x.must("PUT", "/consent", map[string]any{"listen": pages, "public_url": "http://" + pages + "/p", "api_listen": api,
		"api_allow_sources": []string{"127.0.0.1"}, "api_token_sha256": sha("router-token")})
	if st := mustJSON(x.must("GET", "/status", nil)); strings.Contains(st, sha("router-token")) {
		t.Fatalf("status shows the consent API token hash: %s", st)
	}
	before := x.must("GET", "/state", nil)["version"].(float64)

	req, _ := http.NewRequest("POST", "http://"+api+"/links", strings.NewReader(`{"service":"proxy"}`))
	req.Header.Set("Authorization", "Bearer router-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var link struct{ URL string }
	_ = json.NewDecoder(resp.Body).Decode(&link)
	resp.Body.Close()
	form := url.Values{"value": {"person-pasted-value"}}
	post, _ := http.NewRequest("POST", link.URL, strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "http://"+pages)
	resp, err = http.DefaultClient.Do(post)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("consent post: %v %v", err, resp)
	}
	resp.Body.Close()

	after := x.must("GET", "/state", nil)["version"].(float64)
	if after != before+1 {
		t.Fatalf("version %v -> %v; want one change", before, after)
	}
	s, err := open(stateBlob(t, x), mustKey(t, key))
	if err != nil || s.Keys["PROXY_KEY"] != "person-pasted-value" {
		t.Fatalf("sealed state after consent: %v %v", err, s)
	}
	if strings.Contains(x.audit.String(), "person-pasted-value") {
		t.Fatal("audit log holds the pasted value")
	}
}

func TestContainerOption(t *testing.T) {
	if _, err := New(Options{AdminListen: "0.0.0.0:7720", AdminTokenSHA256: sha(adminToken), Audit: io.Discard}); err == nil {
		t.Fatal("wildcard admin accepted without --container")
	}
	_, port, _ := net.SplitHostPort(freeAddr(t))
	in, err := New(Options{AdminListen: "0.0.0.0:" + port, AdminTokenSHA256: sha(adminToken), Audit: io.Discard, Container: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(in.Close)
	x := &inst{t: t, in: in, admin: in.AdminHandler(), audit: &syncBuffer{}}
	_, proxyPort, _ := net.SplitHostPort(freeAddr(t))
	// The proxy cannot take the admin port, whatever the address.
	if code, _ := x.call("POST", "/create", map[string]any{"id": "c1", "data_key": newKey(t), "listen": "127.0.0.1:" + port}); code != http.StatusBadRequest {
		t.Fatalf("proxy on the admin port: %d", code)
	}
	if code, out := x.call("POST", "/create", map[string]any{"id": "c1", "data_key": newKey(t), "listen": "0.0.0.0:" + proxyPort, "allow_sources": []string{"10.0.0.1"}}); code != http.StatusBadRequest {
		t.Fatalf("allow_sources in container mode: %d %v", code, out)
	}
	up := upstreamEcho(t)
	x.must("POST", "/create", map[string]any{"id": "c1", "data_key": newKey(t), "listen": "0.0.0.0:" + proxyPort})
	x.must("PUT", "/services/api", map[string]any{"base": up.URL, "key": "API_KEY", "auth": "bearer"})
	x.must("PUT", "/keys/API_KEY", map[string]any{"value": "container-value"})
	token := x.must("PUT", "/roles/agent", map[string]any{"access": map[string]any{"api": map[string]any{"paths": []string{"/"}}}})["token"].(string)
	if code, _ := proxyGet(t, "127.0.0.1:"+proxyPort, token, "/api/x"); code != 200 {
		t.Fatalf("container proxy: %d", code)
	}
}

// TestDailyLimitSurvivesRestart: the supervisor keeps GET /usage while the
// process is stopped and hands it back on unlock, so a stop does not give a
// role a fresh daily limit.
func TestDailyLimitSurvivesRestart(t *testing.T) {
	up := upstreamEcho(t)
	x := newInst(t, "")
	key := newKey(t)
	listen := freeAddr(t)
	x.must("POST", "/create", map[string]any{"id": "frank", "data_key": key, "listen": listen, "allow_sources": []string{"127.0.0.1"}})
	x.must("PUT", "/services/api", map[string]any{"base": up.URL, "key": "API_KEY", "auth": "bearer"})
	x.must("PUT", "/keys/API_KEY", map[string]any{"value": "v"})
	token := x.must("PUT", "/roles/agent", map[string]any{"access": map[string]any{"api": map[string]any{"paths": []string{"/"}, "daily_requests": 2}}})["token"].(string)
	for range 2 {
		if code, _ := proxyGet(t, listen, token, "/api/x"); code != 200 {
			t.Fatalf("call within the limit: %d", code)
		}
	}
	usage := x.must("GET", "/usage", nil)
	if counts, _ := usage["counts"].([]any); len(counts) != 1 || mustJSON(counts[0]) != `{"count":2,"role":"agent","service":"api"}` {
		t.Fatalf("usage %v", usage)
	}
	blob := x.must("GET", "/state", nil)["state"]
	x.in.Close()

	y := newInst(t, "")
	y.must("POST", "/unlock", map[string]any{"data_key": key, "state": blob, "usage": usage})
	if code, _ := proxyGet(t, listen, token, "/api/x"); code != http.StatusTooManyRequests {
		t.Fatalf("after restart with kept usage: %d, want 429", code)
	}

	// Yesterday's counts are ignored; a restore never lowers a count.
	z := newInst(t, "")
	stale := map[string]any{"day": "2000-01-01", "counts": []map[string]any{{"role": "agent", "service": "api", "count": 2}}}
	listen2 := freeAddr(t)
	y.in.Close()
	z.must("POST", "/unlock", map[string]any{"data_key": key, "state": blob, "usage": stale})
	z.must("PUT", "/network", map[string]any{"listen": listen2, "allow_sources": []string{"127.0.0.1"}})
	if code, _ := proxyGet(t, listen2, token, "/api/x"); code != 200 {
		t.Fatalf("stale usage applied: %d", code)
	}
}
