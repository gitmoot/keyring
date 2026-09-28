package requests

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

var (
	fpA = strings.Repeat("a", 64)
	fpB = strings.Repeat("b", 64)
	now = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
)

func access() policy.AccessList {
	return policy.AccessList{
		Services: map[string]policy.Service{"api": {}, "other": {}},
		Roles:    map[string]policy.Role{"phobos": {TokenSHA256: fpB}},
	}
}

func TestCheckAcceptsOnlyWellFormedRequests(t *testing.T) {
	ok := []Request{
		{Role: "adstudio", Fingerprint: fpA, Services: []string{"api"}},
		{Role: "phobos", Services: []string{"api", "other"}},
	}
	for _, r := range ok {
		if err := Check(r, access()); err != nil {
			t.Errorf("%+v refused: %v", r, err)
		}
	}
	bad := map[string]Request{
		"new agent without fingerprint": {Role: "adstudio", Services: []string{"api"}},
		"short fingerprint":             {Role: "adstudio", Fingerprint: fpA[:63], Services: []string{"api"}},
		"upper-case fingerprint":        {Role: "adstudio", Fingerprint: strings.ToUpper(fpA), Services: []string{"api"}},
		"existing agent, new token":     {Role: "phobos", Fingerprint: fpA, Services: []string{"api"}},
		"token of another agent":        {Role: "adstudio", Fingerprint: fpB, Services: []string{"api"}},
		"unknown service":               {Role: "phobos", Services: []string{"nope"}},
		"no services":                   {Role: "phobos"},
		"service twice":                 {Role: "phobos", Services: []string{"api", "api"}},
		"bad role name":                 {Role: "-x", Fingerprint: fpA, Services: []string{"api"}},
		"note too long":                 {Role: "phobos", Services: []string{"api"}, Note: strings.Repeat("x", maxNote+1)},
	}
	for name, r := range bad {
		if err := Check(r, access()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFileDedupesBoundsAndTakes(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "requests.json"))
	a, err := s.File(Request{Role: "phobos", Services: []string{"other", "api"}}, access(), "100.64.0.20", now)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == "" || a.From != "100.64.0.20" || strings.Join(a.Services, ",") != "api,other" {
		t.Fatalf("filed: %+v", a)
	}
	again, err := s.File(Request{Role: "phobos", Services: []string{"api", "other"}}, access(), "100.64.0.20", now)
	if err != nil || again.ID != a.ID {
		t.Fatalf("the same request was filed twice: %v %v", again.ID, err)
	}
	if _, err := s.File(Request{Role: "phobos", Services: []string{"nope"}}, access(), "x", now); err == nil {
		t.Fatal("an invalid request was filed")
	}
	for i := 1; i < MaxPending; i++ {
		if _, err := s.File(Request{Role: "agent" + string(rune('a'+i)), Fingerprint: strings.Repeat(string("0123456789abcdef"[i%16]), 63) + string("0123456789abcdef"[i/16]), Services: []string{"api"}}, access(), "x", now); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if _, err := s.File(Request{Role: "late", Fingerprint: fpA, Services: []string{"api"}}, access(), "x", now); err == nil {
		t.Fatalf("more than %d requests pending", MaxPending)
	}
	got, ok, err := s.Take(a.ID)
	if err != nil || !ok || got.ID != a.ID {
		t.Fatalf("take: %v %v", ok, err)
	}
	if _, ok, _ := s.Take(a.ID); ok {
		t.Fatal("taken twice")
	}
	if err := s.Put(got); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Pending()
	if len(list) != MaxPending || list[0].ID != a.ID {
		t.Fatalf("after put back: %d, first %s", len(list), list[0].ID)
	}
}
