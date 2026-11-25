package server

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

// ServicesPath lists and searches the services (owner, 2026-11-22): GET,
// optional ?search=. With a role token (through a relay:
// /<role>/_keyring/services) the answer says which services the role may use
// and how; without one (a new agent, like RequestsPath) it lists the services
// any agent may ask for. Services in a client-owned project are listed only
// to roles with access to them.
const ServicesPath = "/_keyring/services"

// ServiceEntry is one service as an agent sees it. It never holds a key, a
// key name or any setting that names one.
type ServiceEntry struct {
	Name     string `json:"name"`
	Provider string `json:"provider,omitempty"`
	Auth     string `json:"auth"`
	// Kind is proxy (call the API through it), sign (get a signature or
	// short-lived token), tunnel (egress proxy) or login (connected by the
	// owner, not called).
	Kind    string `json:"kind"`
	Project string `json:"project,omitempty"`
	// Granted: the calling role may use it now.
	Granted bool     `json:"granted"`
	Methods []string `json:"methods,omitempty"`
	Paths   []string `json:"paths,omitempty"`
	// Call is the path to call after the relay's /<role>, when granted. A
	// tunnel has none: its WebSocket upgrade does not pass the relay.
	Call string `json:"call,omitempty"`
}

// askHint is how an agent asks the owner for a service it may not use.
func askHint(role, service string) string {
	if role == "" {
		role = "<role>"
	}
	if service == "" {
		service = "<name>"
	}
	return "ask the owner with: keyring request --upstream <keyring URL> --role " + role + " --service " + service
}

func serviceKind(s policy.Service) string {
	switch {
	case s.SignOnly():
		return "sign"
	case s.Auth == policy.AuthEgressProxy:
		return "tunnel"
	case s.Auth == policy.AuthGcloudLogin:
		return "login"
	}
	return "proxy"
}

func serviceCall(name string, s policy.Service) string {
	switch s.Auth {
	case policy.AuthAppleAdsSign:
		return "POST " + appleAdsSignPath
	case policy.AuthAppStoreConnectSign:
		return "POST " + appStoreConnectSignPath
	case policy.AuthEd25519Sign, policy.AuthSignInWithAppleSign:
		return "POST " + ed25519SignPrefix + name
	case policy.AuthMinisignSign:
		return "POST " + minisignPrefix + name
	case policy.AuthBitcoinPSBTSign:
		return "POST " + bitcoinPrefix + name + "/" + bitcoinSignAction
	case policy.AuthEgressProxy, policy.AuthGcloudLogin:
		return ""
	}
	return "/" + name + "/<path>"
}

func (h *Handler) listServices(w http.ResponseWriter, r *http.Request, snap *snapshot, from string, now time.Time) {
	rec := auditRecord{Time: now.UTC().Format(time.RFC3339), Source: from, Method: r.Method, Path: ServicesPath}
	defer func() { h.writeAudit(rec) }()
	fail := func(status int, msg string) {
		rec.Status, rec.Note = status, msg
		http.Error(w, http.StatusText(status)+": "+msg, status)
	}
	if r.Method != http.MethodGet {
		fail(http.StatusMethodNotAllowed, "the service list is GET only")
		return
	}
	var role *policy.Role
	if token := r.Header.Get(TokenHeader); token != "" {
		name, rl, ok := snap.config.RoleForToken(token)
		if !ok {
			fail(http.StatusUnauthorized, "unknown role token")
			return
		}
		rec.Role = name
		if rl.Expired(now) {
			fail(http.StatusUnauthorized, "role expired")
			return
		}
		role = &rl
	}
	search := r.URL.Query().Get("search")
	cfg := snap.config
	entries := []ServiceEntry{}
	for _, name := range cfg.SearchServices(role, search, now) {
		svc := cfg.Services[name]
		e := ServiceEntry{Name: name, Provider: svc.Provider(), Auth: svc.Auth, Kind: serviceKind(svc), Project: svc.Project}
		if role != nil {
			if acc, ok := cfg.AccessFor(*role, name); ok && !acc.Expired(now) && cfg.ProjectStopped(svc, now) == "" {
				e.Granted, e.Methods, e.Paths, e.Call = true, acc.EffectiveMethods(), slices.Clone(acc.Paths), serviceCall(name, svc)
			}
		}
		entries = append(entries, e)
	}
	rec.Status = http.StatusOK
	rec.Note = "services list"
	if search != "" {
		rec.Note += ": " + strings.TrimSpace(truncate(search, 80))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"role": rec.Role, "search": search, "services": entries,
		"ask": "for a service you may not use yet, " + askHint(rec.Role, ""),
	})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
