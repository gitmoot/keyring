package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
)

func catalogHandler(t *testing.T) *Handler {
	t.Helper()
	const other = "other-token-0123456789abcdef"
	cfg := &policy.Config{
		Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: "audit.log"},
		AccessList: policy.AccessList{
			Services: map[string]policy.Service{
				"cloudflare-vcf": {Base: "https://api.cloudflare.com/client/v4", Key: "CF", Auth: policy.AuthBearer},
				"openrouter":     {Base: "https://openrouter.ai/api/v1", Key: "OR", Auth: policy.AuthBearer},
				"gmail-send":     {Base: "https://gmail.googleapis.com", Key: "GM", Auth: policy.AuthBearer},
				"acme-stripe":    {Base: "https://api.stripe.com", Key: "ST", Auth: policy.AuthBearer, Project: "acme"},
			},
			Projects: map[string]policy.Project{"acme": {ClientOwned: true}},
			Roles: map[string]policy.Role{
				"phobos": {TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"openrouter": {Paths: []string{"/models"}, Methods: []string{"GET"}}}},
				"acme":   {TokenSHA256: tokenHash(other), Access: map[string]policy.Access{}, Projects: map[string]policy.Access{"acme": {Paths: []string{"/"}}}},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return New(cfg, map[string]string{"CF": "k1", "OR": "k2", "GM": "k3", "ST": "k4"}, &bytes.Buffer{})
}

type listing struct {
	Services []ServiceEntry `json:"services"`
}

func list(t *testing.T, h http.Handler, query, token string) listing {
	t.Helper()
	w := call(h, "GET", ServicesPath+query, token, nil)
	var l listing
	if err := json.Unmarshal(w.Body.Bytes(), &l); w.Code != http.StatusOK || err != nil {
		t.Fatalf("GET %s: %d %s", query, w.Code, w.Body)
	}
	return l
}

func names(l listing) []string {
	var out []string
	for _, s := range l.Services {
		out = append(out, s.Name)
	}
	return out
}

// Owner, 2026-11-22: an agent looked for "cloudflare-workers-ai", found
// nothing, and concluded the keyring had no Cloudflare service although
// cloudflare-vcf existed. Agents can now list and search the services.
func TestAgentsFindServicesBySearch(t *testing.T) {
	h := catalogHandler(t)
	got := list(t, h, "?search=cloudflare-workers-ai", testToken)
	if n := names(got); len(n) != 1 || n[0] != "cloudflare-vcf" {
		t.Fatalf("search cloudflare-workers-ai found %v, want [cloudflare-vcf]", n)
	}
	if n := names(list(t, h, "?search=googleapis", testToken)); len(n) != 1 || n[0] != "gmail-send" {
		t.Fatalf("search by provider found %v", n)
	}
	all := list(t, h, "", testToken)
	if n := strings.Join(names(all), ","); n != "cloudflare-vcf,gmail-send,openrouter" {
		t.Fatalf("phobos sees %s; a client-owned project's service must stay hidden from it", n)
	}
	for _, s := range all.Services {
		if s.Name == "openrouter" && (!s.Granted || s.Call != "/openrouter/<path>" || strings.Join(s.Methods, ",") != "GET" || s.Provider != "openrouter.ai") {
			t.Errorf("openrouter entry %+v", s)
		}
		if s.Name == "cloudflare-vcf" && s.Granted {
			t.Error("cloudflare-vcf shown as granted")
		}
	}
	// The project's own agent sees its project's service; a caller without a
	// token (a new agent) sees only the open ones.
	if n := strings.Join(names(list(t, h, "?search=stripe", "other-token-0123456789abcdef")), ","); n != "acme-stripe" {
		t.Fatalf("acme agent search stripe: %s", n)
	}
	if n := strings.Join(names(list(t, h, "", "")), ","); n != "cloudflare-vcf,gmail-send,openrouter" {
		t.Fatalf("no token: %s", n)
	}
	if w := call(h, "GET", ServicesPath, "not-a-token", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown token: %d", w.Code)
	}
	if w := call(h, "POST", ServicesPath, testToken, nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
}

// A wrong service name gets "did you mean"; a client-owned project's service
// the role may not see gets exactly the answer of a name that does not exist.
func TestWrongServiceNameSuggestsWithoutLeaking(t *testing.T) {
	h := catalogHandler(t)
	w := call(h, "GET", "/cloudflare-workers-ai/accounts", testToken, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "no service named cloudflare-workers-ai (did you mean cloudflare-vcf?); list them with: keyring services --role phobos") {
		t.Fatalf("wrong name: %d %s", w.Code, w.Body)
	}
	hidden := call(h, "GET", "/acme-stripe/v1/charges", testToken, nil).Body.String()
	absent := call(h, "GET", "/acme-stripx/v1/charges", testToken, nil).Body.String()
	if strings.Replace(hidden, "acme-stripe", "X", 1) != strings.Replace(absent, "acme-stripx", "X", 1) {
		t.Fatalf("hidden and absent answers differ:\n%s\n%s", hidden, absent)
	}
	// A visible service the role may not use says how to ask for it.
	if body := call(h, "GET", "/gmail-send/x", testToken, nil).Body.String(); !strings.Contains(body, "keyring request --role phobos --service gmail-send") {
		t.Fatalf("not-granted answer: %s", body)
	}
}
