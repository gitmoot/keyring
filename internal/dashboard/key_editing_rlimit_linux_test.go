package dashboard

import (
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// A rename that cannot save the access file must leave the store and the
// access file in step: every key a service names is still stored, so the
// next start works. The file-size limit lets the renamed (shorter) store be
// written but not the larger access file, nor the store under its old,
// longer names. Go ignores SIGXFSZ, so such a write fails with EFBIG.
func TestFailedRenameKeepsStoreAndAccessInStep(t *testing.T) {
	e := newEnv(t)
	long := "CLAUDE_KEYS_" + strings.Repeat("X", 48)
	values := make([]string, 12)
	for i := range values {
		values[i] = "sk-ant-" + string(rune('a'+i)) + "-0000"
	}
	e.request("POST", "/keys", url.Values{"name": {long}, "value": values, "password": {password}})
	// Several pools on the key make the access file the larger file.
	for _, svc := range []string{"claude-api", "claude-a", "claude-b", "claude-c", "claude-d", "claude-e"} {
		pasted := `{"service":"` + svc + `","base":"https://api.anthropic.com","auth":"header","header":"x-api-key","key_pool":true}`
		if loc := e.request("POST", "/keys/"+long+"/connect", url.Values{"pasted": {pasted}, "password": {password}}).Header().Get("Location"); loc != "/keys/"+long+"?done=connected" {
			t.Fatalf("connect %s: %s", svc, loc)
		}
	}
	size := func(path string) int64 {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			return 0
		}
		if err != nil {
			t.Fatal(err)
		}
		return info.Size()
	}
	rules := e.proxy.Config().Rules
	storeSize, accessSize, metaSize := size(e.backend.StorePath), size(rules.AccessFile), size(e.backend.MetaPath)
	limit := storeSize - 100 // the renamed store is ~12*48 bytes shorter
	if metaSize >= limit || accessSize <= limit || size(rules.AuditLog) >= limit {
		t.Fatalf("sizes: store %d access %d notes %d audit %d", storeSize, accessSize, metaSize, size(rules.AuditLog))
	}
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: uint64(limit), Max: old.Max}); err != nil {
		t.Skipf("cannot set a file-size limit: %v", err)
	}
	loc := e.request("POST", "/keys/"+long+"/rename", url.Values{"new_name": {"K"}, "password": {password}}).Header().Get("Location")
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	if loc == "/keys/K?done=renamed" {
		t.Fatal("the rename succeeded although the access file could not be written")
	}
	// What the next start loads: every key a service names is stored.
	access, err := policy.LoadAccess(rules.AccessFile)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.Load(e.backend.StorePath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &policy.Config{Rules: rules, AccessList: access}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if members := policy.PoolMembers(access.Services["claude-api"], keys, nil); len(members) != len(values) {
		t.Fatalf("after the failed rename the pool on %s has %d of %d values stored", access.Services["claude-api"].Key, len(members), len(values))
	}
}
