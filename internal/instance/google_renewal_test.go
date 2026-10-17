package instance

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoogleRenewalReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.sealed")
	x := newInst(t, path)
	x.in.opt.Container = true
	request := httptest.NewRequest(http.MethodGet, "/google-renewal", nil)
	response := httptest.NewRecorder()
	x.admin.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatal("diagnostic read bypassed admin authentication")
	}
	locked := x.must("GET", "/google-renewal", nil)
	if locked["available"] != false || locked["reason"] != "locked" {
		t.Fatal(locked)
	}
	if x.in.state != nil {
		t.Fatal("diagnostic read unlocked the instance")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("diagnostic read created a state file")
	}
	x.must("POST", "/create", map[string]any{"id": strings.Repeat("a", 32), "data_key": newKey(t), "listen": freeAddr(t)})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	version := x.in.state.Version
	audit := x.audit.String()
	for range 3 {
		view := x.must("GET", "/google-renewal", nil)
		if view["available"] != false || view["reason"] != "no_attempt" || view["process_started_at"] == nil {
			t.Fatal(view)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || version != x.in.state.Version || audit != x.audit.String() {
		t.Fatal("diagnostic reads changed sealed state, version or audit")
	}
}
