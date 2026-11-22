package dashboard

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"sync"
	"testing"
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
