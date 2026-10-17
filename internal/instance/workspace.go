package instance

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/workspace"
)

// Account mutations take workspaceMu, then the affected dispatch gates, then
// mu. Proxy requests hold only their account's read gate across network I/O;
// they take mu briefly to select the immutable credentials and current grants.
type workspaceBoundary struct{ in *Instance }

func accountID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read cannot fail on supported Go versions.
	return hex.EncodeToString(b[:])
}

type workspaceGate struct {
	sync.RWMutex
	identity sync.Mutex
}

func (in *Instance) accountGate(id string) *workspaceGate {
	if gate, ok := in.workspaceGates.Load(id); ok {
		return gate.(*workspaceGate)
	}
	gate, _ := in.workspaceGates.LoadOrStore(id, new(workspaceGate))
	return gate.(*workspaceGate)
}

// changeBindings also covers the pre-existing admin key/service/role writers.
// It prevents an old credential lease crossing dispatch after a replacement.
// Empty key means policy/client configuration: every account is affected.
func (in *Instance) changeBindings(key string, fn func(*State) error) (uint64, error) {
	in.workspaceMu.Lock()
	defer in.workspaceMu.Unlock()
	in.mu.Lock()
	var ids []string
	if in.state != nil {
		for id, a := range in.state.WorkspaceAccounts {
			affected := key == "" || key == a.Key
			for _, name := range []string{"gmail", "calendar"} {
				svc := in.state.Services[name]
				affected = affected || svc.OAuth2 != nil && svc.OAuth2.ClientSecretKey == key
			}
			if affected {
				if in.workspaceRevoking[id] {
					in.mu.Unlock()
					return 0, workspace.Failure(409, "account_revoking")
				}
				ids = append(ids, id)
			}
		}
	}
	in.mu.Unlock()
	slices.Sort(ids)
	for _, id := range ids {
		in.accountGate(id).Lock()
	}
	defer func() {
		for i := len(ids) - 1; i >= 0; i-- {
			in.accountGate(ids[i]).Unlock()
		}
	}()
	return in.change(fn)
}

func (s *State) validateWorkspace(container bool) error {
	if len(s.WorkspaceAccounts) == 0 && s.DefaultWorkspaceAccountID == "" {
		return nil
	}
	if !container {
		return errors.New("Workspace accounts require container mode")
	}
	aliases, keys := map[string]bool{}, map[string]bool{}
	for id, a := range s.WorkspaceAccounts {
		if id != a.ID || !workspace.ValidID(id) || !workspace.ValidID(a.Generation) || !workspace.ValidAlias(a.Alias) || a.Key == "" || aliases[a.Alias] || keys[a.Key] {
			return errors.New("invalid Workspace account registry")
		}
		if (a.Email == "") != (a.VerifiedAt == nil) {
			return errors.New("invalid Workspace identity")
		}
		aliases[a.Alias], keys[a.Key] = true, true
		for _, grants := range a.Grants {
			for service := range grants {
				if !workspace.Service(service) {
					return errors.New("invalid Workspace account grant")
				}
			}
		}
	}
	a, ok := s.WorkspaceAccounts[s.DefaultWorkspaceAccountID]
	if !ok || a.Alias != "personal" {
		return errors.New("invalid default Workspace account")
	}
	for _, name := range []string{"gmail", "calendar"} {
		if svc, exists := s.Services[name]; exists && svc.Key != a.Key {
			return errors.New("Workspace default refresh key is immutable after migration")
		}
	}
	return nil
}

// reconcileWorkspace invalidates approvals when an existing admin writer
// replaces credentials or client settings. Refreshing an access token is not a
// state mutation and never changes this generation.
func reconcileWorkspace(old, next *State) {
	for id, a := range next.WorkspaceAccounts {
		previous, ok := old.WorkspaceAccounts[id]
		if !ok || previous.Generation != a.Generation {
			continue
		}
		changed := previous.Key != a.Key || old.Keys[previous.Key] != next.Keys[a.Key]
		for _, service := range []string{"gmail", "calendar"} {
			before, after := old.Services[service], next.Services[service]
			changed = changed || before.Auth != after.Auth || before.Key != after.Key || !before.OAuth2.Equal(after.OAuth2)
			if before.OAuth2 != nil {
				changed = changed || old.Keys[before.OAuth2.ClientSecretKey] != next.Keys[before.OAuth2.ClientSecretKey]
			}
		}
		if changed {
			a.Generation = accountID()
			if next.Keys[a.Key] != "" {
				a.Email, a.VerifiedAt = "", nil
			}
			next.WorkspaceAccounts[id] = a
		}
	}
}

func workspaceServices(s *State) (policy.Service, error) {
	gmail, gok := s.Services["gmail"]
	calendar, cok := s.Services["calendar"]
	if !gok || !cok || gmail.Auth != policy.AuthOAuth2 || calendar.Auth != policy.AuthOAuth2 || gmail.OAuth2 == nil || !gmail.OAuth2.Equal(calendar.OAuth2) || gmail.Key != calendar.Key || gmail.OAuth2.TokenURL != "https://oauth2.googleapis.com/token" || gmail.OAuth2.AuthURL != "https://accounts.google.com/o/oauth2/v2/auth" {
		return policy.Service{}, workspace.Failure(409, "workspace_not_configured")
	}
	for name, service := range s.Services {
		if !workspace.Service(name) && service.Key == gmail.Key {
			return policy.Service{}, workspace.Failure(409, "workspace_not_configured")
		}
	}
	if s.DefaultWorkspaceAccountID != "" && s.WorkspaceAccounts[s.DefaultWorkspaceAccountID].Key != gmail.Key {
		return policy.Service{}, workspace.Failure(409, "account_binding_changed")
	}
	return gmail, nil
}

func accountGrants(s *State, routerOnly bool) map[string]map[string]policy.Access {
	grants := make(map[string]map[string]policy.Access)
	for name, role := range s.Roles {
		if routerOnly && name != "router" {
			continue
		}
		allowed := make(map[string]policy.Access)
		for _, service := range []string{"gmail", "calendar"} {
			if a, ok := role.Access[service]; ok {
				a.Paths, a.Methods = slices.Clone(a.Paths), slices.Clone(a.Methods)
				if role.Expires != nil && (a.Expires == nil || role.Expires.Before(*a.Expires)) {
					a.Expires = role.Expires
				}
				allowed[service] = a
			}
		}
		if len(allowed) != 0 {
			grants[name] = allowed
		}
	}
	return grants
}

// viewLocked is observational: no refresh, provider request or state write.
func (in *Instance) viewLocked(a workspace.Record) workspace.View {
	s := in.state
	connected := s.Keys[a.Key] != ""
	v := workspace.View{ID: a.ID, Alias: a.Alias, Default: a.ID == s.DefaultWorkspaceAccountID, Provider: "google", Generation: a.Generation, VerifiedAt: a.VerifiedAt, IdentityState: "unknown", Connected: connected, Status: "disconnected", AffectedServices: []string{"gmail", "calendar"}, Services: make(map[string]workspace.ServiceStatus, 2)}
	if a.Email != "" {
		email := a.Email
		v.Email = &email
		v.IdentityState = "verified"
	}
	if connected {
		v.Status = "connected"
		if a.Email == "" {
			v.Status = "identity_pending"
		}
	}
	for _, name := range v.AffectedServices {
		svc := s.Services[name]
		svc.Key = a.Key
		failure := ""
		if connected && svc.OAuth2 != nil && in.proxy.WorkspaceRejected(svc, s.Keys[a.Key], s.Keys[svc.OAuth2.ClientSecretKey]) {
			failure = "account_reconnect_required"
			v.Status = "reconnect_required"
			v.Connected = false
		}
		v.Services[name] = workspace.ServiceStatus{Connected: connected && failure == "", Failing: failure}
	}
	if in.workspaceRevoking[a.ID] {
		v.Status = "revoking"
		v.Connected = false
	}
	return v
}

func (in *Instance) accounts(w http.ResponseWriter, r *http.Request) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if !in.opt.Container || in.state == nil {
		workspace.WriteError(w, workspace.Failure(409, "accounts_unavailable"))
		return
	}
	views := make([]workspace.View, 0, len(in.state.WorkspaceAccounts))
	for _, a := range in.state.WorkspaceAccounts {
		views = append(views, in.viewLocked(a))
	}
	slices.SortFunc(views, func(a, b workspace.View) int {
		if a.Default != b.Default {
			if a.Default {
				return -1
			}
			return 1
		}
		if a.Alias < b.Alias {
			return -1
		}
		if a.Alias > b.Alias {
			return 1
		}
		return 0
	})
	writeJSON(w, 200, map[string]any{"accounts": views, "default_account_id": in.state.DefaultWorkspaceAccountID, "migration_required": in.state.DefaultWorkspaceAccountID == ""})
}

func (in *Instance) migrateAccounts(w http.ResponseWriter, r *http.Request) {
	in.workspaceMu.Lock()
	defer in.workspaceMu.Unlock()
	in.mu.Lock()
	if in.state != nil && in.state.DefaultWorkspaceAccountID != "" {
		view := in.viewLocked(in.state.WorkspaceAccounts[in.state.DefaultWorkspaceAccountID])
		in.mu.Unlock()
		writeJSON(w, 200, map[string]any{"account": view})
		return
	}
	in.mu.Unlock()
	var id string
	_, err := in.change(func(s *State) error {
		if !in.opt.Container {
			return workspace.Failure(409, "accounts_unavailable")
		}
		svc, err := workspaceServices(s)
		if err != nil {
			return err
		}
		id = accountID()
		s.DefaultWorkspaceAccountID = id
		s.WorkspaceAccounts = map[string]workspace.Record{id: {ID: id, Alias: "personal", Generation: accountID(), Key: svc.Key, Grants: accountGrants(s, false)}}
		return nil
	})
	in.accountResult(w, id, err)
}

func (in *Instance) createAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Alias string `json:"alias"`
	}
	if err := decode(r, &req); err != nil || !workspace.ValidAlias(req.Alias) {
		workspace.WriteError(w, workspace.Failure(400, "invalid_account_alias"))
		return
	}
	in.workspaceMu.Lock()
	defer in.workspaceMu.Unlock()
	id := accountID()
	_, err := in.change(func(s *State) error {
		if !in.opt.Container || s.DefaultWorkspaceAccountID == "" {
			return workspace.Failure(409, "account_migration_required")
		}
		if _, err := workspaceServices(s); err != nil {
			return err
		}
		for _, a := range s.WorkspaceAccounts {
			if a.Alias == req.Alias {
				return workspace.Failure(409, "account_alias_exists")
			}
			if s.Keys[a.Key] != "" && a.Email == "" {
				return workspace.Failure(409, "account_identity_unverified")
			}
		}
		grants := accountGrants(s, true)
		if len(grants["router"]) == 0 {
			return workspace.Failure(403, "account_not_allowed")
		}
		s.WorkspaceAccounts[id] = workspace.Record{ID: id, Alias: req.Alias, Generation: accountID(), Key: workspace.AccountKeyPrefix + id, Grants: grants}
		return nil
	})
	in.accountResult(w, id, err)
}

func (in *Instance) accountResult(w http.ResponseWriter, id string, err error) {
	if err != nil {
		workspace.WriteError(w, err)
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.state == nil {
		workspace.WriteError(w, workspace.Failure(409, "accounts_unavailable"))
		return
	}
	writeJSON(w, 200, map[string]any{"account": in.viewLocked(in.state.WorkspaceAccounts[id])})
}

func (in *Instance) recordLocked(id, generation string, legacy bool) (workspace.Record, error) {
	if in.state == nil || !in.opt.Container {
		return workspace.Record{}, workspace.Failure(409, "accounts_unavailable")
	}
	if legacy {
		id = in.state.DefaultWorkspaceAccountID
	}
	a, ok := in.state.WorkspaceAccounts[id]
	if !ok || !workspace.ValidID(id) {
		return a, workspace.Failure(404, "account_not_found")
	}
	if !legacy && generation == "" {
		return a, workspace.Failure(428, "account_generation_required")
	}
	if !legacy && generation != a.Generation {
		return a, workspace.Failure(409, "account_binding_changed")
	}
	if in.workspaceRevoking[id] {
		return a, workspace.Failure(409, "account_revoking")
	}
	return a, nil
}

func (b workspaceBoundary) Acquire(ctx context.Context, id, generation, role, token, service, method, path string) (*workspace.Selection, error) {
	in := b.in
	if !workspace.Service(service) {
		return nil, workspace.Failure(403, "account_not_allowed")
	}
	legacy := id == ""
	in.mu.Lock()
	if legacy && in.state != nil {
		id = in.state.DefaultWorkspaceAccountID
	}
	known := false
	if in.state != nil {
		_, known = in.state.WorkspaceAccounts[id]
	}
	in.mu.Unlock()
	if legacy && id == "" {
		return nil, nil
	}
	if !known {
		return nil, workspace.Failure(404, "account_not_found")
	}
	gate := in.accountGate(id)
	gate.RLock()
	release := gate.RUnlock
	fail := func(err error) (*workspace.Selection, error) { release(); return nil, err }
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	a, err := in.recordLocked(id, generation, legacy)
	if err != nil {
		return fail(err)
	}
	s := in.state
	if s.Keys[a.Key] == "" {
		return fail(workspace.Failure(409, "account_disconnected"))
	}
	if !legacy && a.Email == "" {
		return fail(workspace.Failure(409, "account_identity_unverified"))
	}
	current, ok := s.Roles[role]
	sum := sha256.Sum256([]byte(token))
	want, _ := hex.DecodeString(current.TokenSHA256)
	if !ok || subtle.ConstantTimeCompare(sum[:], want) != 1 || current.Expired(time.Now()) {
		return fail(workspace.Failure(403, "account_not_allowed"))
	}
	grant, gok := a.Grants[role][service]
	ceiling, cok := current.Access[service]
	if !gok || !cok || grant.Expired(time.Now()) || ceiling.Expired(time.Now()) || !grant.AllowsMethod(method) || !grant.AllowsPath(path) || !ceiling.AllowsMethod(method) || !ceiling.AllowsPath(path) {
		return fail(workspace.Failure(403, "account_not_allowed"))
	}
	if _, err := workspaceServices(s); err != nil {
		return fail(err)
	}
	svc := in.proxy.Config().Services[service]
	svc.Key = a.Key
	limit := ceiling.DailyRequests
	if grant.DailyRequests > 0 && (limit == 0 || grant.DailyRequests < limit) {
		limit = grant.DailyRequests
	}
	return &workspace.Selection{ID: a.ID, Generation: a.Generation, Service: svc, Refresh: s.Keys[a.Key], Secret: s.Keys[svc.OAuth2.ClientSecretKey], DailyRequests: limit, Release: release}, nil
}

func (b workspaceBoundary) Revalidate(ctx context.Context, selected *workspace.Selection) error {
	in := b.in
	in.mu.Lock()
	defer in.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	a, err := in.recordLocked(selected.ID, selected.Generation, false)
	if err != nil {
		return err
	}
	if in.state.Keys[a.Key] != selected.Refresh || selected.Service.OAuth2 == nil ||
		in.state.Keys[selected.Service.OAuth2.ClientSecretKey] != selected.Secret {
		return workspace.Failure(409, "account_binding_changed")
	}
	return nil
}

func (b workspaceBoundary) PrepareConsent(id, generation, service string) (*workspace.ConsentBinding, error) {
	in := b.in
	in.mu.Lock()
	defer in.mu.Unlock()
	if !workspace.Service(service) {
		return nil, workspace.Failure(403, "account_not_allowed")
	}
	legacy := id == ""
	if legacy && in.state != nil && in.state.DefaultWorkspaceAccountID == "" {
		return nil, nil
	}
	a, err := in.recordLocked(id, generation, legacy)
	if err != nil {
		return nil, err
	}
	if _, err := workspaceServices(in.state); err != nil {
		return nil, err
	}
	for otherID, other := range in.state.WorkspaceAccounts {
		if otherID != a.ID && in.state.Keys[other.Key] != "" && other.Email == "" {
			return nil, workspace.Failure(409, "account_identity_unverified")
		}
	}
	svc := in.state.Services[service]
	svc.Key = a.Key
	return &workspace.ConsentBinding{ID: a.ID, Generation: a.Generation, ServiceName: service, Service: svc, View: in.viewLocked(a)}, nil
}

func duplicateIdentity(s *State, id, email string) bool {
	for otherID, other := range s.WorkspaceAccounts {
		if otherID != id && s.Keys[other.Key] != "" && other.Email == email {
			return true
		}
	}
	return false
}

func (b workspaceBoundary) CommitConsent(ctx context.Context, binding workspace.ConsentBinding, refresh, email string) error {
	in := b.in
	in.workspaceMu.Lock()
	defer in.workspaceMu.Unlock()
	gate := in.accountGate(binding.ID)
	gate.Lock()
	defer gate.Unlock()
	_, err := in.change(func(s *State) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, err := in.recordLocked(binding.ID, binding.Generation, false)
		if err != nil {
			return err
		}
		if _, err := workspaceServices(s); err != nil {
			return err
		}
		svc := s.Services[binding.ServiceName]
		if !svc.OAuth2.Equal(binding.Service.OAuth2) {
			return workspace.Failure(409, "account_binding_changed")
		}
		if s.Keys[a.Key] != "" && a.Email != "" && a.Email != email {
			return workspace.Failure(409, "account_identity_changed")
		}
		if duplicateIdentity(s, a.ID, email) {
			return workspace.Failure(409, "account_identity_exists")
		}
		for otherID, other := range s.WorkspaceAccounts {
			if otherID != a.ID && s.Keys[other.Key] != "" && other.Email == "" {
				return workspace.Failure(409, "account_identity_unverified")
			}
		}
		now := time.Now().UTC()
		a.Email = email
		a.VerifiedAt = &now
		a.Generation = accountID()
		s.Keys[a.Key] = refresh
		s.WorkspaceAccounts[a.ID] = a
		return nil
	})
	return err
}

func (in *Instance) hydrateAccount(w http.ResponseWriter, r *http.Request) {
	id, generation := r.PathValue("account"), r.Header.Get(workspace.GenerationHeader)
	if !workspace.ValidID(id) {
		workspace.WriteError(w, workspace.Failure(404, "account_not_found"))
		return
	}
	gate := in.accountGate(id)
	gate.identity.Lock()
	defer gate.identity.Unlock()
	gate.RLock()
	in.mu.Lock()
	a, err := in.recordLocked(id, generation, false)
	if err == nil && in.state.Keys[a.Key] == "" {
		err = workspace.Failure(409, "account_disconnected")
	}
	if err == nil && a.Email != "" {
		v := in.viewLocked(a)
		in.mu.Unlock()
		gate.RUnlock()
		writeJSON(w, 200, map[string]any{"account": v})
		return
	}
	var selected workspace.Selection
	if err == nil {
		svc, e := workspaceServices(in.state)
		err = e
		if err == nil {
			svc.Key = a.Key
			selected = workspace.Selection{Service: svc, Refresh: in.state.Keys[a.Key], Secret: in.state.Keys[svc.OAuth2.ClientSecretKey]}
		}
	}
	in.mu.Unlock()
	if err != nil {
		gate.RUnlock()
		workspace.WriteError(w, err)
		return
	}
	email, err := in.proxy.WorkspaceIdentity(r.Context(), selected)
	gate.RUnlock()
	if err != nil {
		workspace.WriteError(w, err)
		return
	}
	in.workspaceMu.Lock()
	defer in.workspaceMu.Unlock()
	gate.Lock()
	defer gate.Unlock()
	_, err = in.change(func(s *State) error {
		a, err := in.recordLocked(id, generation, false)
		if err != nil {
			return err
		}
		if err := r.Context().Err(); err != nil {
			return err
		}
		if duplicateIdentity(s, id, email) {
			return workspace.Failure(409, "account_identity_exists")
		}
		now := time.Now().UTC()
		a.Email = email
		a.VerifiedAt = &now
		s.WorkspaceAccounts[id] = a
		return nil
	})
	in.accountResult(w, id, err)
}

// Detach invalidates the local binding before remote revocation. While the
// provider call runs, revoking prevents a new consent from reusing that grant.
func (b workspaceBoundary) Detach(ctx context.Context, id, generation string) (workspace.View, *workspace.Selection, error) {
	in := b.in
	in.workspaceMu.Lock()
	defer in.workspaceMu.Unlock()
	legacy := id == ""
	if legacy {
		in.mu.Lock()
		if in.state != nil {
			id = in.state.DefaultWorkspaceAccountID
		}
		in.mu.Unlock()
		if id == "" {
			return workspace.View{}, nil, nil
		}
	}
	gate := in.accountGate(id)
	gate.Lock()
	defer gate.Unlock()
	var selected *workspace.Selection
	_, err := in.change(func(s *State) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		a, err := in.recordLocked(id, generation, legacy)
		if err != nil {
			return err
		}
		svc, err := workspaceServices(s)
		if err != nil {
			return err
		}
		svc.Key = a.Key
		selected = &workspace.Selection{ID: id, Generation: a.Generation, Service: svc, Refresh: s.Keys[a.Key], Secret: s.Keys[svc.OAuth2.ClientSecretKey]}
		delete(s.Keys, a.Key)
		a.Generation = accountID()
		s.WorkspaceAccounts[id] = a
		return nil
	})
	if err != nil {
		return workspace.View{}, nil, err
	}
	in.mu.Lock()
	v := in.viewLocked(in.state.WorkspaceAccounts[id])
	if in.workspaceRevoking == nil {
		in.workspaceRevoking = map[string]bool{}
	}
	in.workspaceRevoking[id] = true
	in.mu.Unlock()
	selected.Release = func() { in.mu.Lock(); delete(in.workspaceRevoking, id); in.mu.Unlock() }
	return v, selected, nil
}

func (in *Instance) accountLink(w http.ResponseWriter, r *http.Request) {
	in.mu.Lock()
	s := in.consent
	in.mu.Unlock()
	if s == nil {
		workspace.WriteError(w, workspace.Failure(409, "accounts_unavailable"))
		return
	}
	s.AccountLink(w, r)
}
func (in *Instance) disconnectAccount(w http.ResponseWriter, r *http.Request) {
	in.mu.Lock()
	s := in.consent
	in.mu.Unlock()
	if s == nil {
		workspace.WriteError(w, workspace.Failure(409, "accounts_unavailable"))
		return
	}
	s.DisconnectAccount(w, r)
}
