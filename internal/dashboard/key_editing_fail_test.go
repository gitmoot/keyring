package dashboard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/store"
)

// Test on a pooled key moves on to the next value only when a call would:
// the service refused the value (401, 403, 402, 429). A 503 for the first
// value stops a call, so Test stops there too and records the key failing.
func TestPoolTestMovesOnOnlyWhenACallWould(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("x-api-key")
		mu.Lock()
		seen = append(seen, key)
		mu.Unlock()
		if key == "sk-ant-a-0000" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(up.Close)
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-a-0000", "sk-ant-b-1111"}, "password": {password}})
	pasted := `{"service":"claude-api","base":"` + up.URL + `","auth":"header","header":"x-api-key","test_path":"/v1/models","key_pool":true}`
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {pasted}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=connected" {
		t.Fatalf("connect: %s", loc)
	}
	e.request("POST", "/keys/CLAUDE_KEYS/test", url.Values{})
	meta, err := e.backend.loadMeta()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if meta["CLAUDE_KEYS"].Status != "failing" || !slices.Equal(seen, []string{"sk-ant-a-0000"}) {
		t.Fatalf("Test recorded %q after %d calls; a call stops at the 503", meta["CLAUDE_KEYS"].Status, len(seen))
	}
}

// Test closes a refused answer, like a call, instead of reading it to the
// end: a 403 whose body never finishes does not use up Test's time limit,
// and the next value is tried and works.
func TestPoolTestMovesOnPastASlowRefusal(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	var mu sync.Mutex
	var seen []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("x-api-key")
		mu.Lock()
		seen = append(seen, key)
		mu.Unlock()
		switch key {
		case "sk-ant-a-0000":
			w.WriteHeader(http.StatusForbidden)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-release:
			}
		case "sk-ant-b-1111":
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(up.Close)
	t.Cleanup(func() { close(release) })
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-a-0000", "sk-ant-b-1111"}, "password": {password}})
	pasted := `{"service":"claude-api","base":"` + up.URL + `","auth":"header","header":"x-api-key","test_path":"/v1/models","key_pool":true}`
	if loc := e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {pasted}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=connected" {
		t.Fatalf("connect: %s", loc)
	}
	e.request("POST", "/keys/CLAUDE_KEYS/test", url.Values{})
	meta, err := e.backend.loadMeta()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if m := meta["CLAUDE_KEYS"]; m.Status != "working" || !slices.Equal(seen, []string{"sk-ant-a-0000", "sk-ant-b-1111"}) {
		t.Fatalf("Test recorded %q (%s) after %d calls; it tries the stalled primary, then the backup that works", m.Status, m.Reason, len(seen))
	}
}

// A pool Test result describes every value that set its order, tried or
// not: its credential, its generation and its place in the list. The
// primary is set aside after a refusal, so Test sends only the backup.
// Replacing the primary meanwhile puts the replacement first; setting the
// original back clears its refusal, so it is first again; keyring set
// changes it on disk before the proxy reloads; Move up reorders the list.
// In each case the backup's late 200 says nothing about the pool now, so it
// is not recorded.
func TestPoolTestIgnoresAnAnswerOrderedByAReplacedValue(t *testing.T) {
	replace := func(values ...string) func(t *testing.T, e *env) {
		return func(t *testing.T, e *env) {
			for _, v := range values {
				if loc := e.request("POST", "/keys/CLAUDE_KEYS/replace", url.Values{"part": {"1"}, "value": {v}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=replaced" {
					t.Fatalf("replace: %s", loc)
				}
			}
		}
	}
	for _, c := range []struct {
		name   string
		change func(t *testing.T, e *env) // made while Test waits for the backup
	}{
		{"replaced", replace("sk-ant-c-2222")},
		{"replaced and set back", replace("sk-ant-c-2222", "sk-ant-a-0000")},
		{"set on disk before a reload", func(t *testing.T, e *env) {
			if err := store.Set(e.backend.StorePath, "CLAUDE_KEYS.1", "sk-ant-c-2222"); err != nil {
				t.Fatal(err)
			}
		}},
		{"moved", func(t *testing.T, e *env) {
			if loc := e.request("POST", "/keys/CLAUDE_KEYS/move-up", url.Values{"part": {"2"}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=value-moved" {
				t.Fatalf("move up: %s", loc)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			started, proceed := make(chan struct{}), make(chan struct{})
			var startOnce, proceedOnce sync.Once
			release := func() { proceedOnce.Do(func() { close(proceed) }) }
			var mu sync.Mutex
			var tested []string
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				key := r.Header.Get("x-api-key")
				if r.Header.Get("User-Agent") == "keyring-test" {
					mu.Lock()
					tested = append(tested, key)
					mu.Unlock()
				}
				switch key {
				case "sk-ant-a-0000":
					w.WriteHeader(http.StatusForbidden)
				case "sk-ant-b-1111":
					if r.Header.Get("User-Agent") == "keyring-test" {
						startOnce.Do(func() { close(started) })
						<-proceed
					}
				default:
					w.WriteHeader(http.StatusServiceUnavailable)
				}
			}))
			t.Cleanup(up.Close)
			t.Cleanup(release)
			e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-a-0000", "sk-ant-b-1111"}, "password": {password}})
			pasted := `{"service":"claude-api","base":"` + up.URL + `","auth":"header","header":"x-api-key","test_path":"/v1/models","key_pool":true}`
			if loc := e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {pasted}, "password": {password}}).Header().Get("Location"); loc != "/keys/CLAUDE_KEYS?done=connected" {
				t.Fatalf("connect: %s", loc)
			}
			grantPhobos(t, e, "claude-api")
			if code := e.call("POST", "/claude-api/v1/messages", token); code != http.StatusOK {
				t.Fatalf("call: %d", code)
			}
			done := make(chan string, 1)
			go func() {
				done <- e.request("POST", "/keys/CLAUDE_KEYS/test", url.Values{}).Header().Get("Location")
			}()
			select {
			case <-started:
			case loc := <-done:
				t.Fatalf("Test answered %s without trying the backup", loc)
			case <-time.After(10 * time.Second):
				t.Fatal("Test never reached the backup")
			}
			c.change(t, e)
			release()
			var loc string
			select {
			case loc = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Test did not finish")
			}
			meta, err := e.backend.loadMeta()
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(tested, []string{"sk-ant-b-1111"}) {
				t.Fatalf("Test sent %d values; the primary was set aside, so only the backup", len(tested))
			}
			if m := meta["CLAUDE_KEYS"]; m.Status == "working" || loc != "/keys/CLAUDE_KEYS?error=changed" {
				t.Fatalf("Test answered %s and recorded %q although the pool changed while it ran", loc, m.Status)
			}
		})
	}
}

// Add key writes the key's value order (what a key pool follows) before it
// stores the values: when the order cannot be saved, Add fails and stores
// nothing, instead of reporting the key added with its order lost.
func TestAddKeyFailsWhenItsOrderCannotBeSaved(t *testing.T) {
	e := newEnv(t)
	metaPath := e.backend.MetaPath
	e.backend.MetaPath = filepath.Join(t.TempDir(), "missing", "keymeta.json")
	loc := e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-z-0000", "sk-ant-a-1111"}, "part": {"z", "a"}, "password": {password}}).Header().Get("Location")
	e.backend.MetaPath = metaPath
	if loc == "/keys/CLAUDE_KEYS?done=added" {
		t.Fatal("Add key reported success without saving the value order")
	}
	for name := range mustKeys(t, e) {
		if name == "CLAUDE_KEYS.z" || name == "CLAUDE_KEYS.a" {
			t.Fatalf("a failed Add stored %s", name)
		}
	}
}
