package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

func poolHandler(t *testing.T, up *httptest.Server, keys map[string]string) (*Handler, *bytes.Buffer, *time.Time) {
	t.Helper()
	old := isAnthropic
	isAnthropic = func(policy.Service) bool { return true }
	t.Cleanup(func() { isAnthropic = old })
	svc := policy.Service{Base: up.URL, Key: "CLAUDE_KEYS.main", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true}
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
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	return h, audit, &now
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
	h, audit, now := poolHandler(t, up, poolKeys)
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
	*now = now.Add(2 * time.Hour)
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
			h, _, now := poolHandler(t, up, poolKeys)
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
				*now = now.Add(31 * time.Second)
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
	h, _, _ := poolHandler(t, up, poolKeys)
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
			"claude-api": {Base: "https://api.anthropic.com", Key: "CLAUDE_KEYS.main", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true},
			"other":      {Base: "https://example.com", Key: "CLAUDE_KEYS.backup1", Auth: policy.AuthBearer},
		}, Roles: map[string]policy.Role{}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "key pool") {
		t.Fatalf("err = %v", err)
	}
	bad := policy.Service{Base: "https://api.anthropic.com", Key: "CLAUDE_KEY", Auth: policy.AuthHeader, Header: "x-api-key", KeyPool: true}
	cfg.Services = map[string]policy.Service{"claude-api": bad}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "several values") {
		t.Fatalf("pool on a single-value key: %v", err)
	}
}
