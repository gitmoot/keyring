package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

// fakeAnthropic answers per key: what each sent key gets back.
type fakeAnthropic struct {
	mu     sync.Mutex
	answer map[string]func(w http.ResponseWriter)
	seen   []string
	bodies []string
}

func (f *fakeAnthropic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("x-api-key")
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, key)
	f.bodies = append(f.bodies, string(b))
	a := f.answer[key]
	f.mu.Unlock()
	if a == nil {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"key":"`+key+`"}`)
		return
	}
	a(w)
}

func status(code int, header map[string]string, body string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(code)
		io.WriteString(w, body)
	}
}

// anthropicBase is the base of a pool the Anthropic rules apply to; tests
// reach the fake through upstreamAt.
const anthropicBase = "https://api.anthropic.com"

// upstreamAt sends every request to target, whatever host it names.
type upstreamAt struct{ target *url.URL }

func (u upstreamAt) RoundTrip(r *http.Request) (*http.Response, error) {
	out := r.Clone(r.Context())
	out.URL.Scheme, out.URL.Host = u.target.Scheme, u.target.Host
	return http.DefaultTransport.RoundTrip(out)
}

// testClock is the handler's clock; the fake upstream may move it while a
// call is in flight.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func poolHandler(t *testing.T, base string, up *httptest.Server, keys map[string]string) (*Handler, *bytes.Buffer, *testClock) {
	t.Helper()
	svc := policy.Service{Base: base, Key: "CLAUDE_KEYS", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true}
	cfg := &policy.Config{
		Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: "audit.log"},
		AccessList: policy.AccessList{
			Services: map[string]policy.Service{"claude-api": svc},
			Roles:    map[string]policy.Role{"phobos": {TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"claude-api": allowAll}}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	audit := &bytes.Buffer{}
	h := New(cfg, keys, audit)
	h.SetValueOrder(map[string][]string{"CLAUDE_KEYS": {"main", "backup1", "backup2"}})
	target, _ := url.Parse(up.URL)
	h.client.Transport = upstreamAt{target}
	clock := &testClock{t: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	h.now = clock.now
	return h, audit, clock
}

var poolKeys = map[string]string{"CLAUDE_KEYS.main": "sk-ant-main-0000", "CLAUDE_KEYS.backup1": "sk-ant-b1-1111", "CLAUDE_KEYS.backup2": "sk-ant-b2-2222"}

func lastAuditRecord(t *testing.T, audit *bytes.Buffer) auditRecord {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	var rec auditRecord
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// Owner, 2026-11-22, P0: a dead or out-of-credit key never fails an agent's
// call while another key works. The refused key is set aside, the same
// request goes out again with the next, the answer never shows a key, and
// the audit names the key that answered.
func TestKeyPoolFailsOverAndSetsAside(t *testing.T) {
	fake := &fakeAnthropic{answer: map[string]func(http.ResponseWriter){
		"sk-ant-main-0000": status(401, nil, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`),
	}}
	up := httptest.NewServer(fake)
	defer up.Close()
	h, audit, clock := poolHandler(t, anthropicBase, up, poolKeys)
	w := call(h, "POST", "/claude-api/v1/messages", testToken, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"key":"[REDACTED]"`) {
		t.Fatalf("answer %d %s: want 200 from the next key, key masked", w.Code, w.Body)
	}
	if strings.Join(fake.seen, ",") != "sk-ant-main-0000,sk-ant-b1-1111" || fake.bodies[0] != "payload" || fake.bodies[1] != "payload" {
		t.Fatalf("sent %v with bodies %q", fake.seen, fake.bodies)
	}
	if rec := lastAuditRecord(t, audit); rec.Key != "CLAUDE_KEYS.backup1" || rec.Attempts != 2 || rec.Status != 200 || strings.Contains(audit.String(), "sk-ant") {
		t.Fatalf("audit %+v / %s", rec, audit)
	}
	// The next call skips the set-aside key.
	call(h, "POST", "/claude-api/v1/messages", testToken, nil)
	if got := fake.seen[len(fake.seen)-1]; got != "sk-ant-b1-1111" || len(fake.seen) != 3 {
		t.Fatalf("second call sent %v", fake.seen)
	}
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "failing" || st.Status != 401 || st.FailuresToday != 1 {
		t.Fatalf("main status %+v", st)
	}
	if st := h.PoolKeyStatus("CLAUDE_KEYS.backup1"); st.State != "working" {
		t.Fatalf("backup1 status %+v", st)
	}
	// After the set-aside time, main is tried first again; replacing a
	// value forgets what was known about the old one.
	clock.add(2 * time.Hour)
	fake.answer = nil
	call(h, "POST", "/claude-api/v1/messages", testToken, nil)
	if got := fake.seen[len(fake.seen)-1]; got != "sk-ant-main-0000" {
		t.Fatalf("after the set-aside time sent %s", got)
	}
}

// Answers that blame the request or the provider (other 400s, 5xx) are not
// key problems: no other key is tried and nothing is set aside. A 429 with
// retry-after sets the key aside for that long; a spend-limit 400 is a key
// problem; when every key is refused the caller gets the last answer.
func TestKeyPoolOnlySwitchesOnKeyProblems(t *testing.T) {
	cases := []struct {
		name     string
		answer   func(http.ResponseWriter)
		switches bool
		state    string
	}{
		{"bad request", status(400, nil, `{"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: field required"}}`), false, ""},
		{"overloaded", status(529, nil, `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`), false, ""},
		{"server error", status(500, nil, `{}`), false, ""},
		{"rate limit", status(429, map[string]string{"retry-after": "30"}, `{"type":"error","error":{"type":"rate_limit_error","message":"rate"}}`), true, "cooling"},
		{"spend cap", status(429, nil, `{"type":"error","error":{"type":"rate_limit_error","message":"cap"}}`), true, "failing"},
		{"spend limit", status(400, nil, `{"type":"error","error":{"type":"invalid_request_error","message":"You have reached your specified workspace API usage limits. Your spend limit will reset..."}}`), true, "failing"},
		{"credit", status(400, nil, `{"type":"error","error":{"type":"invalid_request_error","message":"Your credit balance is too low to access the Anthropic API."}}`), true, "failing"},
		{"billing", status(402, nil, `{"type":"error","error":{"type":"billing_error","message":"billing"}}`), true, "failing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fake := &fakeAnthropic{answer: map[string]func(http.ResponseWriter){"sk-ant-main-0000": c.answer}}
			up := httptest.NewServer(fake)
			defer up.Close()
			h, _, clock := poolHandler(t, anthropicBase, up, poolKeys)
			w := call(h, "POST", "/claude-api/v1/messages", testToken, nil)
			if switched := len(fake.seen) == 2; switched != c.switches {
				t.Fatalf("sent %v, switch %v", fake.seen, c.switches)
			}
			if !c.switches && w.Code == 200 {
				t.Fatal("the provider's error was not passed on")
			}
			if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != c.state {
				t.Fatalf("state %q, want %q", st.State, c.state)
			}
			if c.name == "rate limit" {
				clock.add(31 * time.Second)
				if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State == "cooling" {
					t.Fatal("still set aside after retry-after")
				}
			}
		})
	}
	// Every key refused: the caller gets the last refusal, after one try each.
	fake := &fakeAnthropic{answer: map[string]func(http.ResponseWriter){}}
	for _, k := range poolKeys {
		fake.answer[k] = status(401, nil, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
	}
	up := httptest.NewServer(fake)
	defer up.Close()
	h, _, _ := poolHandler(t, anthropicBase, up, poolKeys)
	if w := call(h, "POST", "/claude-api/v1/messages", testToken, nil); w.Code != 401 || len(fake.seen) != 3 {
		t.Fatalf("all refused: %d after %v", w.Code, fake.seen)
	}
}

// A pool's values may not double as another service's key: each of them may
// be sent upstream.
func TestKeyPoolValuesBelongToThePool(t *testing.T) {
	cfg := &policy.Config{
		Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: "audit.log"},
		AccessList: policy.AccessList{Services: map[string]policy.Service{
			"claude-api": {Base: "https://api.anthropic.com", Key: "CLAUDE_KEYS", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true},
			"other":      {Base: "https://example.com", Key: "CLAUDE_KEYS.backup1", Auth: policy.AuthBearer},
		}, Roles: map[string]policy.Role{}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "key pool") {
		t.Fatalf("err = %v", err)
	}
	bad := policy.Service{Base: "https://api.anthropic.com", Key: "CLAUDE_KEYS.main", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true}
	cfg.Services = map[string]policy.Service{"claude-api": bad}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "leave key_part out") {
		t.Fatalf("pool naming one value: %v", err)
	}
}

// A value that cannot go in a header (a line break pasted with it) is
// skipped, not sent: the call goes out with the next value and the key page
// shows the bad one failing. Only when no value can be sent is the call
// refused, and then nothing reaches the provider.
func TestKeyPoolSkipsUnsendableValues(t *testing.T) {
	fake := &fakeAnthropic{}
	up := httptest.NewServer(fake)
	defer up.Close()
	keys := map[string]string{"CLAUDE_KEYS.main": "sk-ant-main\n0000", "CLAUDE_KEYS.backup1": "sk-ant-b1-1111", "CLAUDE_KEYS.backup2": "sk-ant-b2-2222"}
	h, audit, _ := poolHandler(t, anthropicBase, up, keys)
	w := call(h, "POST", "/claude-api/v1/messages", testToken, nil)
	if w.Code != 200 || strings.Join(fake.seen, ",") != "sk-ant-b1-1111" {
		t.Fatalf("answer %d %s after sending %v: want 200 from backup1 only", w.Code, w.Body, fake.seen)
	}
	if rec := lastAuditRecord(t, audit); rec.Key != "CLAUDE_KEYS.backup1" || rec.Attempts != 1 {
		t.Fatalf("audit %+v", rec)
	}
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "failing" || !st.CannotSend || !strings.Contains(st.Reason, "cannot be sent") {
		t.Fatalf("main status %+v", st)
	}
	for name, v := range keys {
		keys[name] = v + "\r\n"
	}
	h, _, _ = poolHandler(t, anthropicBase, up, keys)
	if w := call(h, "POST", "/claude-api/v1/messages", testToken, nil); w.Code != 503 || len(fake.seen) != 1 || strings.Contains(w.Body.String(), "sk-ant") {
		t.Fatalf("no sendable value: %d %s after sending %v", w.Code, w.Body, fake.seen)
	}
}

// The Cloudflare asset upload carries the caller's upload token (#104): a
// pooled account token never goes with it, and its answer says nothing
// about the pool's values.
func TestKeyPoolLeavesCloudflareUploadAlone(t *testing.T) {
	cfg := &policy.Config{
		Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: "audit.log"},
		AccessList: policy.AccessList{
			Services: map[string]policy.Service{"api": {Base: cfBase, Key: "CF_TOKENS", Auth: policy.AuthBearer, KeyPool: true}},
			Roles:    map[string]policy.Role{"phobos": {TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"api": allowAll}}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h := New(cfg, map[string]string{"CF_TOKENS.main": "cf-main-0000", "CF_TOKENS.backup": "cf-backup-1111"}, &bytes.Buffer{})
	rec := &cfRecorder{}
	h.client = &http.Client{Transport: rec}
	if w := call(h, "POST", "/api"+cfUploadPath, testToken, map[string]string{"Authorization": "Bearer " + cfUploadJWT}); w.Code != 200 {
		t.Fatalf("upload: %d %s", w.Code, w.Body)
	}
	if out, _ := rec.last(t); out.Header.Get("Authorization") != "Bearer "+cfUploadJWT || rec.count() != 1 {
		t.Fatalf("upload sent Authorization %q in %d calls, want the caller's upload token once", out.Header.Get("Authorization"), rec.count())
	}
	if st := h.PoolKeyStatus("CF_TOKENS.main"); st.State != "" || !st.LastFailure.IsZero() {
		t.Fatalf("the upload's answer changed the pool: %+v", st)
	}
	// Any other call goes out with the pool.
	call(h, "GET", "/api/accounts/"+cfAccount+"/workers/scripts", testToken, nil)
	if out, _ := rec.last(t); out.Header.Get("Authorization") != "Bearer cf-main-0000" {
		t.Fatalf("pooled call sent %q", out.Header.Get("Authorization"))
	}
}

// Retry-After may be a date as well as seconds (RFC 9110 10.2.3); a date
// is a rate limit, not Anthropic's spend cap. The time set aside counts
// from when the refusal came back, not from when the call started.
func TestKeyPoolRetryAfter(t *testing.T) {
	fake := &fakeAnthropic{answer: map[string]func(http.ResponseWriter){}}
	up := httptest.NewServer(fake)
	defer up.Close()
	h, _, clock := poolHandler(t, anthropicBase, up, poolKeys)
	fake.mu.Lock()
	fake.answer["sk-ant-main-0000"] = func(w http.ResponseWriter) {
		status(429, map[string]string{"Retry-After": clock.now().Add(90 * time.Second).Format(http.TimeFormat)}, `{}`)(w)
	}
	fake.mu.Unlock()
	call(h, "POST", "/claude-api/v1/messages", testToken, nil)
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "cooling" || !st.Until.Equal(clock.now().Add(90*time.Second)) {
		t.Fatalf("Retry-After date: %+v", st)
	}
	// The provider answers ten minutes after the call started: the wait
	// counts from then.
	h, _, late := poolHandler(t, anthropicBase, up, poolKeys)
	fake.mu.Lock()
	fake.answer["sk-ant-main-0000"] = func(w http.ResponseWriter) {
		late.add(10 * time.Minute)
		status(429, map[string]string{"Retry-After": "30"}, `{}`)(w)
	}
	fake.mu.Unlock()
	call(h, "POST", "/claude-api/v1/messages", testToken, nil)
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "cooling" || !st.Until.Equal(late.now().Add(30*time.Second)) {
		t.Fatalf("set aside from the start of the call, not the refusal: %+v (now %s)", st, late.now())
	}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		value string
		wait  time.Duration
		ok    bool
	}{
		{"30", 30 * time.Second, true},
		{" 30 ", 30 * time.Second, true},
		{"0", time.Second, true},
		{"9300000000", time.Hour, true},              // seconds that overflow a Duration to negative
		{"18446744073709551615", time.Hour, true},    // the largest uint64
		{"99999999999999999999999", time.Hour, true}, // more than a uint64
		{now.Add(2 * time.Minute).Format(http.TimeFormat), 2 * time.Minute, true},
		{now.Add(-time.Minute).Format(http.TimeFormat), time.Second, true},
		{now.Add(48 * time.Hour).Format(http.TimeFormat), time.Hour, true},
		{"", 0, false},
		{"-5", 0, false},
		{"soon", 0, false},
	} {
		if wait, ok := retryAfter(c.value, now); wait != c.wait || ok != c.ok {
			t.Errorf("retryAfter(%q) = %s %v, want %s %v", c.value, wait, ok, c.wait, c.ok)
		}
	}
}

// An answer to a value that was replaced while the call was in flight says
// nothing about the new value: it neither clears nor overwrites what is
// known about it.
func TestKeyPoolIgnoresStaleOutcomes(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	fake := &fakeAnthropic{answer: map[string]func(http.ResponseWriter){
		"sk-ant-main-0000": func(w http.ResponseWriter) {
			close(entered)
			<-release
			io.WriteString(w, `{"ok":true}`)
		},
	}}
	up := httptest.NewServer(fake)
	// Cleanups run last first: the held request is let go before the
	// server waits for it, even when an assertion stops the test early.
	t.Cleanup(up.Close)
	var releaseOnce sync.Once
	let := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(let)
	h, _, _ := poolHandler(t, anthropicBase, up, poolKeys)
	done := make(chan int, 1)
	go func() { done <- call(h, "POST", "/claude-api/v1/messages", testToken, nil).Code }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the call with the old value never reached the provider")
	}
	keys := map[string]string{"CLAUDE_KEYS.main": "sk-ant-main-new0", "CLAUDE_KEYS.backup1": "sk-ant-b1-1111"}
	fake.mu.Lock()
	fake.answer["sk-ant-main-new0"] = status(401, nil, `{}`)
	fake.mu.Unlock()
	h.Swap(h.Config(), keys)
	if w := call(h, "POST", "/claude-api/v1/messages", testToken, nil); w.Code != 200 {
		t.Fatalf("call with the new value: %d", w.Code)
	}
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "failing" {
		t.Fatalf("new value status %+v", st)
	}
	let()
	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("call with the old value: %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call with the old value never finished")
	}
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "failing" || st.FailuresToday != 1 {
		t.Fatalf("the old value's answer changed the new value's status: %+v", st)
	}
}

// A call that loaded the keys before a value was replaced may order the
// pool after the new value was refused: ordering with the old value must
// not wipe out that refusal, and the new value stays set aside.
func TestKeyPoolOldOrderingKeepsCurrentRefusal(t *testing.T) {
	up := httptest.NewServer(&fakeAnthropic{})
	defer up.Close()
	h, _, clock := poolHandler(t, anthropicBase, up, poolKeys)
	old := h.snap.Load()
	members := []string{"CLAUDE_KEYS.main", "CLAUDE_KEYS.backup1", "CLAUDE_KEYS.backup2"}
	keys := map[string]string{"CLAUDE_KEYS.main": "sk-ant-main-new0", "CLAUDE_KEYS.backup1": "sk-ant-b1-1111", "CLAUDE_KEYS.backup2": "sk-ant-b2-2222"}
	h.Swap(h.Config(), keys)
	cur := h.snap.Load()
	h.poolFailed("CLAUDE_KEYS.main", cur.gens["CLAUDE_KEYS.main"], 401, verdict{true, true, time.Hour, "401 key rejected"}, clock.now())
	if got := h.pool.order(members, old.gens, clock.now()); got[0] != "CLAUDE_KEYS.main" {
		t.Fatalf("old snapshot order %v: its main value was never refused", got)
	}
	if got := h.pool.order(members, cur.gens, clock.now()); got[len(got)-1] != "CLAUDE_KEYS.main" {
		t.Fatalf("current order %v: the refused value is not last", got)
	}
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "failing" || st.FailuresToday != 1 {
		t.Fatalf("refusal of the current value lost: %+v", st)
	}
	// An answer to a value no longer stored is not recorded at all.
	h.poolWorked("CLAUDE_KEYS.main", old.gens["CLAUDE_KEYS.main"], clock.now())
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "failing" {
		t.Fatalf("an answer to the old value changed the current one: %+v", st)
	}
}

// Putting a value back (rotating A to B, then back to A) starts it over:
// A's old refusal does not come back with it, and an answer to A sent
// before the rotation does not count for A stored again.
func TestKeyPoolRollbackStartsOver(t *testing.T) {
	fake := &fakeAnthropic{answer: map[string]func(http.ResponseWriter){
		"sk-ant-main-0000": status(401, nil, `{}`),
		"sk-ant-main-new0": status(500, nil, `{}`),
		"sk-ant-b1-1111":   status(500, nil, `{}`),
	}}
	up := httptest.NewServer(fake)
	defer up.Close()
	h, _, clock := poolHandler(t, anthropicBase, up, poolKeys)
	call(h, "POST", "/claude-api/v1/messages", testToken, nil) // A refused, set aside
	first := h.snap.Load()
	rotated := map[string]string{"CLAUDE_KEYS.main": "sk-ant-main-new0", "CLAUDE_KEYS.backup1": "sk-ant-b1-1111", "CLAUDE_KEYS.backup2": "sk-ant-b2-2222"}
	h.Swap(h.Config(), rotated)
	call(h, "POST", "/claude-api/v1/messages", testToken, nil) // B: a 500, not a key problem
	h.Swap(h.Config(), poolKeys)
	fake.mu.Lock()
	fake.answer["sk-ant-main-0000"] = nil // A works again
	fake.mu.Unlock()
	if w := call(h, "POST", "/claude-api/v1/messages", testToken, nil); w.Code != 200 || fake.seen[len(fake.seen)-1] != "sk-ant-main-0000" {
		t.Fatalf("after the rollback: %d after %v, want A tried first", w.Code, fake.seen)
	}
	h.poolFailed("CLAUDE_KEYS.main", first.gens["CLAUDE_KEYS.main"], 401, verdict{true, true, time.Hour, "401 key rejected"}, clock.now())
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "working" {
		t.Fatalf("an answer to A before the rotation counted for A stored again: %+v", st)
	}
}

// Sendability belongs to the service: a value with a line break cannot go
// in a header, but a query pool on the same key sends it. Its health is
// what the query calls show, and the header service is named beside it.
func TestKeyPoolStatusPerServiceSendability(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"ok":true}`) }))
	defer up.Close()
	cfg := &policy.Config{
		Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: "audit.log"},
		AccessList: policy.AccessList{
			Services: map[string]policy.Service{
				"claude-api":   {Base: up.URL, Key: "CLAUDE_KEYS", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true},
				"claude-query": {Base: up.URL, Key: "CLAUDE_KEYS", Auth: policy.AuthQuery, Param: "key", KeyPool: true},
			},
			Roles: map[string]policy.Role{"phobos": {TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"claude-api": allowAll, "claude-query": allowAll}}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{"CLAUDE_KEYS.main": "sk-ant-main\n0000", "CLAUDE_KEYS.backup1": "sk-ant-b1-1111"}
	h := New(cfg, keys, &bytes.Buffer{})
	if w := call(h, "GET", "/claude-query/v1/models", testToken, nil); w.Code != 200 {
		t.Fatalf("query call: %d %s", w.Code, w.Body)
	}
	st := h.PoolKeyStatus("CLAUDE_KEYS.main")
	if st.State != "working" || st.CannotSend || strings.Join(st.Unsendable, ",") != "claude-api" {
		t.Fatalf("main status %+v: want working, not sendable by claude-api", st)
	}
}

// Outside Anthropic the generic rules hold: a 400 is the request's fault
// whatever it says and reaches the caller as sent, and a 429 without
// Retry-After is a short rate limit.
func TestKeyPoolGenericProvider(t *testing.T) {
	limit := `{"type":"error","error":{"type":"invalid_request_error","message":"Your credit balance is too low."}}`
	fake := &fakeAnthropic{answer: map[string]func(http.ResponseWriter){"sk-ant-main-0000": status(400, nil, limit)}}
	up := httptest.NewServer(fake)
	defer up.Close()
	h, _, clock := poolHandler(t, "https://api.example.com", up, poolKeys)
	if w := call(h, "POST", "/claude-api/v1/messages", testToken, nil); w.Code != 400 || w.Body.String() != limit || len(fake.seen) != 1 {
		t.Fatalf("400: %d %s after %v", w.Code, w.Body, fake.seen)
	}
	fake.mu.Lock()
	fake.answer["sk-ant-main-0000"] = status(429, nil, `{}`)
	fake.mu.Unlock()
	if w := call(h, "POST", "/claude-api/v1/messages", testToken, nil); w.Code != 200 {
		t.Fatalf("429 did not fail over: %d", w.Code)
	}
	if st := h.PoolKeyStatus("CLAUDE_KEYS.main"); st.State != "cooling" || !st.Until.Equal(clock.now().Add(time.Minute)) {
		t.Fatalf("generic 429: %+v", st)
	}
}
