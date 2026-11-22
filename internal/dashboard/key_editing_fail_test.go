package dashboard

import (
	"net/url"
	"path/filepath"
	"testing"
)

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
