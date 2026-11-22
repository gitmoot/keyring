package dashboard

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// A key rename that cannot finish must leave the store and the access file
// in step: every key a service names is still stored, so the next start
// works, and the store is as it was. A file-size limit makes one write fail
// (Go ignores SIGXFSZ, so the write gets EFBIG):
//   - store: the limit admits the store under the new, shorter names but
//     not under the old ones, nor the larger access file;
//   - access: the limit admits the store holding both names but not the
//     renamed access file, so the access write itself fails.
func TestFailedRenameKeepsStoreAndAccessInStep(t *testing.T) {
	for _, c := range []struct {
		name string
		// limit picks the file-size limit from the store's size under the
		// old names, under the new ones, with both, and the renamed access
		// file's size.
		limit func(old, renamed, both, access int64) int64
	}{
		{"store", func(old, renamed, both, access int64) int64 { return (old + renamed) / 2 }},
		{"access", func(old, renamed, both, access int64) int64 { return (both + access) / 2 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			long := "CLAUDE_KEYS_" + strings.Repeat("X", 120)
			values := make([]string, 12)
			for i := range values {
				values[i] = fmt.Sprintf("sk-ant-%c-0000", 'a'+i)
			}
			e.request("POST", "/keys", url.Values{"name": {long}, "value": values, "password": {password}})
			// Many pools on the key make the access file the largest file.
			for i := range 30 {
				pasted := fmt.Sprintf(`{"service":"claude-%d","base":"https://api.anthropic.com","auth":"header","header":"x-api-key","key_pool":true}`, i)
				if loc := e.request("POST", "/keys/"+long+"/connect", url.Values{"pasted": {pasted}, "password": {password}}).Header().Get("Location"); loc != "/keys/"+long+"?done=connected" {
					t.Fatalf("connect %d: %s", i, loc)
				}
			}
			rules := e.proxy.Config().Rules
			keys, err := store.Load(e.backend.StorePath)
			if err != nil {
				t.Fatal(err)
			}
			access, err := policy.LoadAccess(rules.AccessFile)
			if err != nil {
				t.Fatal(err)
			}
			before, err := policy.LoadAccess(rules.AccessFile)
			if err != nil {
				t.Fatal(err)
			}
			renamed, both := map[string]string{}, map[string]string{}
			moves := map[string]string{long: "K"}
			for name, value := range keys {
				both[name] = value
				if base, part := store.SplitPart(name); base == long {
					renamed["K."+part] = value
					both["K."+part] = value
					moves[name] = "K." + part
				} else {
					renamed[name] = value
				}
			}
			renameRefs(&access, moves)
			jsonSize := func(v any) int64 {
				raw, err := json.MarshalIndent(v, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				return int64(len(raw) + 1)
			}
			sizes := [4]int64{jsonSize(keys), jsonSize(renamed), jsonSize(both), jsonSize(access)}
			limit := c.limit(sizes[0], sizes[1], sizes[2], sizes[3])
			others := []string{e.backend.MetaPath, rules.AuditLog}
			ok := sizes[1] < limit && sizes[3] > limit
			if c.name == "store" {
				ok = ok && sizes[0] > limit
			} else {
				ok = ok && sizes[2] < limit
			}
			for _, path := range others {
				if info, err := os.Stat(path); err == nil && info.Size()+200 >= limit {
					ok = false
				}
			}
			if !ok {
				t.Fatalf("sizes old/renamed/both/access %v leave no limit that fails the %s write only", sizes, c.name)
			}
			var old syscall.Rlimit
			if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: uint64(limit), Max: old.Max}); err != nil {
				t.Skipf("cannot set a file-size limit: %v", err)
			}
			res := e.request("POST", "/keys/"+long+"/rename", url.Values{"new_name": {"K"}, "password": {password}})
			if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
				t.Fatal(err)
			}
			// The intended write failed, and the rename said so.
			intended := map[string]string{"store": e.backend.StorePath, "access": rules.AccessFile}[c.name]
			if body := res.Body.String(); res.Code != http.StatusInternalServerError || !strings.Contains(body, "file too large") || !strings.Contains(body, filepath.Base(intended)) {
				t.Fatalf("rename answered %d %q, want 500 for the failed %s write", res.Code, res.Header().Get("Location"), c.name)
			}
			// What the next start loads: every key a service names is
			// stored, and the store is as it was.
			after, err := policy.LoadAccess(rules.AccessFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := (&policy.Config{Rules: rules, AccessList: after}).Validate(); err != nil {
				t.Fatal(err)
			}
			now, err := store.Load(e.backend.StorePath)
			if err != nil {
				t.Fatal(err)
			}
			if members := policy.PoolMembers(after.Services["claude-0"], now, nil); len(members) != len(values) {
				t.Fatalf("after the failed rename the pool on %s has %d of %d values stored", after.Services["claude-0"].Key, len(members), len(values))
			}
			if !maps.Equal(now, keys) {
				t.Fatal("after the failed rename the store differs from before")
			}
			refs := func(a policy.AccessList) map[string][]string {
				out := map[string][]string{}
				for name, svc := range a.Services {
					out[name] = svc.KeyNames()
				}
				return out
			}
			if !maps.EqualFunc(refs(after), refs(before), slices.Equal) {
				t.Fatalf("after the failed rename the services name %v, were %v", refs(after), refs(before))
			}
		})
	}
}

// Renaming a pooled value moves no service reference: the store changes in
// one atomic write, so a failed rename never leaves the value under two
// names, which a pool would send twice.
func TestFailedValueRenameNeverStoresAValueTwice(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"CLAUDE_KEYS"}, "value": {"sk-ant-a-" + strings.Repeat("0", 600), "sk-ant-b-" + strings.Repeat("1", 600)}, "password": {password}})
	pasted := `{"service":"claude-api","base":"https://api.anthropic.com","auth":"header","header":"x-api-key","key_pool":true}`
	e.request("POST", "/keys/CLAUDE_KEYS/connect", url.Values{"pasted": {pasted}, "password": {password}})
	keys, err := store.Load(e.backend.StorePath)
	if err != nil {
		t.Fatal(err)
	}
	both := maps.Clone(keys)
	both["CLAUDE_KEYS.a_much_longer_value_name"] = keys["CLAUDE_KEYS.1"]
	raw, _ := json.MarshalIndent(both, "", "  ")
	limit := int64(len(raw)) // admits the store with the value renamed, not with both names
	if info, err := os.Stat(e.backend.MetaPath); err != nil || info.Size()+200 >= limit {
		t.Fatalf("key notes too large for the limit %d", limit)
	}
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: uint64(limit), Max: old.Max}); err != nil {
		t.Skipf("cannot set a file-size limit: %v", err)
	}
	loc := e.request("POST", "/keys/CLAUDE_KEYS/rename-value", url.Values{"part": {"1"}, "new_part": {"a_much_longer_value_name"}, "password": {password}}).Header().Get("Location")
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	if loc != "/keys/CLAUDE_KEYS?done=value-renamed" {
		t.Fatalf("rename value: %s", loc)
	}
	now, err := store.Load(e.backend.StorePath)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, name := range policy.PoolMembers(e.proxy.Config().Services["claude-api"], now, nil) {
		if seen[now[name]] {
			t.Fatalf("the pool sends one value twice: %s", name)
		}
		seen[now[name]] = true
	}
}
