package instance

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/consent"
	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/googlelogin"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// Options configure an instance. Only the admin token's hash is kept.
type Options struct {
	// AdminListen is the admin API's address; no other listener may use it.
	AdminListen string
	// AdminTokenSHA256 is the hex SHA-256 of the supervisor's admin token.
	AdminTokenSHA256 string
	// StatePath, when set, keeps the sealed state in this file (mode 600).
	// When empty, the sealed state exists only in memory and through
	// GET /state; the supervisor stores it.
	StatePath string
	// Audit receives one JSON line per proxied call and admin change,
	// never a value. AuditName names it in the rules (e.g. its path).
	Audit     io.Writer
	AuditName string
	// Log receives operational messages (listeners started and stopped).
	Log io.Writer
	// Container runs the instance inside a container that only its
	// supervisor can reach (policy.Config.ContainerMode): listeners may use
	// a wildcard address and no source address is checked. Off by default.
	Container bool
}

// Instance is one person's keyring.
type Instance struct {
	opt   Options
	admin netip.AddrPort

	auditMu sync.Mutex

	// mu serializes every change and guards the fields below.
	mu        sync.Mutex
	state     *State // nil until created or unlocked, and after wipe
	key       []byte
	sealed    []byte
	proxy     *server.Handler
	consent   *consent.Server
	google    *googlelogin.Controller // fixed at construction for container mode
	listeners map[string]*running
	wiped     chan struct{}
}

type running struct {
	addr string
	srv  *http.Server
	// l is closed by us as well: srv.Close only closes listeners its
	// Serve goroutine has already registered.
	l net.Listener
}

// New prepares a locked instance. It serves nothing but the admin API (see
// AdminHandler) until it is created or unlocked.
func New(opt Options) (*Instance, error) {
	admin, err := netip.ParseAddrPort(opt.AdminListen)
	if opt.Container {
		// The supervisor reaches the container over its own network
		// interface, not loopback; the admin token still guards every call.
		if err != nil || admin.Port() == 0 {
			return nil, fmt.Errorf("admin listen %q: want IP:port", opt.AdminListen)
		}
	} else if err != nil || !admin.Addr().IsLoopback() || admin.Port() == 0 {
		return nil, fmt.Errorf("admin listen %q: must be a loopback IP:port", opt.AdminListen)
	}
	if len(opt.AdminTokenSHA256) != 64 || strings.Trim(opt.AdminTokenSHA256, "0123456789abcdef") != "" {
		return nil, errors.New("admin token hash must be 64 lowercase hex characters")
	}
	if opt.Audit == nil {
		return nil, errors.New("an audit writer is required")
	}
	if opt.AuditName == "" {
		opt.AuditName = "audit"
	}
	if opt.Log == nil {
		opt.Log = io.Discard
	}
	in := &Instance{opt: opt, admin: admin, listeners: map[string]*running{}, wiped: make(chan struct{})}
	if opt.Container {
		in.google = googlelogin.New(in.saveGoogle)
	}
	return in, nil
}

// Wiped is closed when the instance was deleted through the API.
func (in *Instance) Wiped() <-chan struct{} { return in.wiped }

// Close stops the proxy and consent listeners.
func (in *Instance) Close() {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.closeListeners(nil)
	if in.google != nil {
		in.google.Close()
	}
}

func (in *Instance) writeAudit(event string, fields map[string]any) {
	rec := map[string]any{"time": time.Now().UTC().Format(time.RFC3339), "admin": event}
	maps.Copy(rec, fields)
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	in.auditMu.Lock()
	defer in.auditMu.Unlock()
	_, _ = in.opt.Audit.Write(append(line, '\n'))
}

// ---- listeners ----

type listenerSpec struct {
	name, addr string
	handler    http.Handler
}

func (in *Instance) wanted(cfg *policy.Config) []listenerSpec {
	specs := []listenerSpec{{"proxy", cfg.Listen, in.proxy}}
	if k := cfg.Consent; k != nil {
		specs = append(specs,
			listenerSpec{"consent pages", k.Listen, in.consent.PagesHandler()},
			listenerSpec{"consent API", k.APIListen, in.consent.APIHandler()})
	}
	return specs
}

// bind opens the listeners cfg needs that are not already open at the same
// address. On failure nothing stays open. Callers hold in.mu.
func (in *Instance) bind(cfg *policy.Config) (map[string]net.Listener, error) {
	opened := map[string]net.Listener{}
	for _, s := range in.wanted(cfg) {
		if addr, err := netip.ParseAddrPort(s.addr); err == nil && addr.Port() == in.admin.Port() &&
			(addr.Addr() == in.admin.Addr() || addr.Addr().IsUnspecified() || in.admin.Addr().IsUnspecified()) {
			closeAll(opened)
			return nil, fmt.Errorf("%s cannot use the admin address", s.name)
		}
		if r, ok := in.listeners[s.name]; ok && r.addr == s.addr {
			continue
		}
		l, err := net.Listen("tcp", s.addr)
		if err != nil {
			closeAll(opened)
			return nil, fmt.Errorf("%s on %s: %w", s.name, s.addr, err)
		}
		opened[s.name] = l
	}
	return opened, nil
}

func closeAll(ls map[string]net.Listener) {
	for _, l := range ls {
		l.Close()
	}
}

// serve starts the newly opened listeners and closes those cfg no longer
// wants or that moved. Callers hold in.mu.
func (in *Instance) serve(cfg *policy.Config, opened map[string]net.Listener) {
	want := map[string]listenerSpec{}
	for _, s := range in.wanted(cfg) {
		want[s.name] = s
	}
	in.closeListeners(func(name, addr string) bool {
		s, ok := want[name]
		return ok && s.addr == addr
	})
	for name, l := range opened {
		srv := &http.Server{
			Handler:           want[name].handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       5 * time.Minute,
			IdleTimeout:       2 * time.Minute,
		}
		in.listeners[name] = &running{addr: want[name].addr, srv: srv, l: l}
		go func() { _ = srv.Serve(l) }()
		fmt.Fprintf(in.opt.Log, "%s on %s\n", name, want[name].addr)
	}
}

// closeListeners stops every listener keep does not keep (nil keeps none).
// Callers hold in.mu.
func (in *Instance) closeListeners(keep func(name, addr string) bool) {
	for name, r := range in.listeners {
		if keep != nil && keep(name, r.addr) {
			continue
		}
		// Closing the listener first frees the port now, even if Serve has
		// not started; Serve then returns at once.
		_ = r.l.Close()
		_ = r.srv.Close()
		delete(in.listeners, name)
		fmt.Fprintf(in.opt.Log, "%s on %s stopped\n", name, r.addr)
	}
}

// ---- state changes ----

// errLocked: no state yet (create or unlock first), or wiped.
var errLocked = errors.New("the instance is locked: create or unlock it first")

// errWipedHTTP: the instance was deleted; this process takes no new state.
var errWipedHTTP = &httpError{http.StatusGone, "the instance was deleted; start a new process"}

// isWiped reports whether DELETE /instance ran. Callers hold in.mu.
func (in *Instance) isWiped() bool {
	select {
	case <-in.wiped:
		return true
	default:
		return false
	}
}

type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return &httpError{http.StatusBadRequest, fmt.Sprintf(format, args...)}
}

// commit makes next the state in use, sealed with key: it validates next,
// opens any new listeners, writes the sealed state, swaps it into the proxy
// and closes listeners no longer used. On any error nothing changes.
// Callers hold in.mu.
func (in *Instance) commit(next *State, key []byte) error {
	cfg, err := next.config(in.opt.AuditName, in.opt.Container)
	if err != nil {
		return badRequest("%v", err)
	}
	sealed, err := seal(next, key)
	if err != nil {
		return err
	}
	if in.proxy == nil {
		in.proxy = server.New(cfg, next.Keys, in.opt.Audit)
		in.consent = consent.New(in.proxy.Config, instanceKeys{in}, in.opt.Audit)
		if in.google != nil {
			in.proxy.SetGoogleCommand(in.google.Token)
			in.consent.SetGoogle(in.google)
		}
	}
	opened, err := in.bind(cfg)
	if err != nil {
		if in.state == nil {
			in.proxy, in.consent = nil, nil
		}
		return badRequest("%v", err)
	}
	if in.opt.StatePath != "" {
		if err := fileutil.WriteAtomic(in.opt.StatePath, sealed, 0o600); err != nil {
			closeAll(opened)
			if in.state == nil {
				in.proxy, in.consent = nil, nil
			}
			return err
		}
	}
	in.state, in.key, in.sealed = next, key, sealed
	in.proxy.Swap(cfg, next.Keys)
	if in.google != nil {
		in.google.SetState(next.Google)
	}
	in.serve(cfg, opened)
	return nil
}

// change applies fn to a copy of the state and commits it as the next
// version.
func (in *Instance) change(fn func(*State) error) (uint64, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.state == nil {
		return 0, &httpError{http.StatusConflict, errLocked.Error()}
	}
	next := in.state.clone()
	if err := fn(next); err != nil {
		return 0, err
	}
	next.Version++
	if err := in.commit(next, in.key); err != nil {
		return 0, err
	}
	return next.Version, nil
}

// instanceKeys lets consent links store keys through the instance's state.
type instanceKeys struct{ in *Instance }

func (k instanceKeys) Load() (map[string]string, error) {
	k.in.mu.Lock()
	defer k.in.mu.Unlock()
	if k.in.state == nil {
		return nil, errLocked
	}
	return maps.Clone(k.in.state.Keys), nil
}

func (k instanceKeys) Set(name, value string) error {
	_, err := k.in.change(func(s *State) error { s.Keys[name] = value; return nil })
	return err
}

func (k instanceKeys) Delete(name string) error {
	_, err := k.in.change(func(s *State) error { delete(s.Keys, name); return nil })
	return err
}

// ---- admin API ----

// AdminHandler serves the admin API. Every request needs the admin token.
func (in *Instance) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /create", in.create)
	mux.HandleFunc("POST /unlock", in.unlock)
	mux.HandleFunc("GET /status", in.status)
	mux.HandleFunc("GET /state", in.getState)
	mux.HandleFunc("GET /usage", in.getUsage)
	mux.HandleFunc("PUT /network", in.putNetwork)
	mux.HandleFunc("PUT /consent", in.putConsent)
	mux.HandleFunc("DELETE /consent", in.deleteConsent)
	mux.HandleFunc("PUT /services/{name}", in.putService)
	mux.HandleFunc("DELETE /services/{name}", in.deleteService)
	mux.HandleFunc("POST /google-drive", in.provisionGoogle)
	mux.HandleFunc("PUT /roles/{name}", in.putRole)
	mux.HandleFunc("POST /roles/{name}/token", in.newRoleToken)
	mux.HandleFunc("DELETE /roles/{name}", in.deleteRole)
	mux.HandleFunc("PUT /keys/{name}", in.putKey)
	mux.HandleFunc("DELETE /keys/{name}", in.deleteKey)
	mux.HandleFunc("POST /rotate", in.rotate)
	mux.HandleFunc("DELETE /instance", in.wipe)
	want, _ := hex.DecodeString(in.opt.AdminTokenSHA256)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(token))
		if !ok || token == "" || subtle.ConstantTimeCompare(sum[:], want) != 1 {
			writeError(w, &httpError{http.StatusUnauthorized, "admin token required"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, err error) {
	var he *httpError
	if errors.As(err, &he) {
		writeJSON(w, he.status, map[string]string{"error": he.msg})
		return
	}
	// Other errors are internal (disk, randomness); their text names no
	// value but may name paths, so it stays generic.
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}

// decode reads one JSON value with no unknown fields and nothing after it.
func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return badRequest("invalid JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return badRequest("invalid JSON: data after the value")
	}
	return nil
}

func (in *Instance) changed(w http.ResponseWriter, event string, fields map[string]any, version uint64, err error, extra map[string]any) {
	if err != nil {
		writeError(w, err)
		return
	}
	if fields == nil {
		fields = map[string]any{}
	}
	fields["version"] = version
	in.writeAudit(event, fields)
	out := map[string]any{"version": version}
	maps.Copy(out, extra)
	writeJSON(w, http.StatusOK, out)
}

func (in *Instance) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID           string   `json:"id"`
		DataKey      string   `json:"data_key"`
		Listen       string   `json:"listen"`
		AllowSources []string `json:"allow_sources"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if !ValidID(req.ID) {
		writeError(w, badRequest("id: 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit"))
		return
	}
	key, err := decodeKey(req.DataKey)
	if err != nil {
		writeError(w, badRequest("%v", err))
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.isWiped() {
		writeError(w, errWipedHTTP)
		return
	}
	if in.state != nil {
		writeError(w, &httpError{http.StatusConflict, "the instance already has a state"})
		return
	}
	if in.opt.StatePath != "" {
		if _, err := os.Lstat(in.opt.StatePath); err == nil {
			writeError(w, &httpError{http.StatusConflict, "a state file exists: unlock it, or delete it through the API first"})
			return
		}
	}
	s := &State{ID: req.ID, Version: 1, Listen: req.Listen, AllowSources: req.AllowSources,
		Services: map[string]policy.Service{}, Roles: map[string]policy.Role{}, Keys: map[string]string{}}
	if err := in.commit(s, key); err != nil {
		writeError(w, err)
		return
	}
	in.writeAudit("created", map[string]any{"id": s.ID, "version": s.Version})
	writeJSON(w, http.StatusCreated, map[string]any{"version": s.Version})
}

func (in *Instance) unlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DataKey string `json:"data_key"`
		State   string `json:"state"`
		// Usage is what GET /usage returned before the last stop; counts of
		// another day are ignored.
		Usage *usageReply `json:"usage"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	key, err := decodeKey(req.DataKey)
	if err != nil {
		writeError(w, badRequest("%v", err))
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.isWiped() {
		writeError(w, errWipedHTTP)
		return
	}
	if in.state != nil {
		writeError(w, &httpError{http.StatusConflict, "the instance is already unlocked"})
		return
	}
	var blob []byte
	switch {
	case req.State != "":
		if blob, err = base64.StdEncoding.DecodeString(req.State); err != nil {
			writeError(w, badRequest("state must be base64"))
			return
		}
	case in.opt.StatePath != "":
		if blob, err = os.ReadFile(in.opt.StatePath); err != nil {
			writeError(w, &httpError{http.StatusNotFound, "no state: create the instance, or pass its sealed state"})
			return
		}
	default:
		writeError(w, badRequest("pass the sealed state"))
		return
	}
	s, err := open(blob, key)
	if err != nil {
		in.writeAudit("unlock_refused", nil)
		writeError(w, &httpError{http.StatusForbidden, err.Error()})
		return
	}
	if in.google != nil {
		if err := in.google.Restore(s.Google); err != nil {
			writeError(w, badRequest("cannot restore private Google login"))
			return
		}
	}
	if err := in.commit(s, key); err != nil {
		writeError(w, err)
		return
	}
	if req.Usage != nil {
		in.proxy.RestoreDailyCounts(req.Usage.Day, req.Usage.Counts, time.Now())
	}
	in.writeAudit("unlocked", map[string]any{"id": s.ID, "version": s.Version})
	writeJSON(w, http.StatusOK, map[string]any{"version": s.Version})
}

func (in *Instance) status(w http.ResponseWriter, _ *http.Request) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.state == nil {
		writeJSON(w, http.StatusOK, map[string]any{"unlocked": false})
		return
	}
	s := in.state
	type roleView struct {
		Expires *time.Time               `json:"expires,omitempty"`
		Access  map[string]policy.Access `json:"access"`
	}
	roles := map[string]roleView{}
	for n, role := range s.Roles {
		roles[n] = roleView{role.Expires, role.Access}
	}
	keys := slices.Sorted(maps.Keys(s.Keys))
	var consentView *policy.Consent
	if s.Consent != nil {
		c := *s.Consent
		c.APITokenSHA256 = "" // a token hash, like the roles' hashes, is not shown
		consentView = &c
	}
	// Why a service's refresh failed, for oauth2 services whose last
	// refresh failed (never a token).
	failing := map[string]string{}
	reconnect := map[string]bool{}
	for name, svc := range s.Services {
		if svc.Auth == policy.AuthOAuth2 {
			why, rejected := in.proxy.OAuthFailure(svc.Key)
			if why != "" {
				failing[name] = why
			}
			if rejected {
				reconnect[name] = true
			}
		} else if svc.Auth == policy.AuthGcloud || svc.Auth == policy.AuthGcloudLogin {
			why, _ := in.proxy.GoogleStatus(svc.GoogleAccount)
			switch why {
			case "not configured", "not checked", "renewing", "renewal required", "ready":
			default:
				failing[name] = why
			}
		}
	}
	var googleView *googlelogin.View
	if in.google != nil {
		view := in.google.Status()
		view.Account, view.Project = "", ""
		googleView = &view
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"unlocked": true, "id": s.ID, "version": s.Version,
		"listen": s.Listen, "allow_sources": s.AllowSources, "consent": consentView,
		"services": s.Services, "roles": roles, "keys": keys, "failing": failing,
		"reconnect_required": reconnect,
		"google":             googleView,
	})
}

func (in *Instance) getState(w http.ResponseWriter, _ *http.Request) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.state == nil {
		writeError(w, &httpError{http.StatusConflict, errLocked.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": in.state.Version, "state": base64.StdEncoding.EncodeToString(in.sealed)})
}

// usageReply is today's daily-limit counts. They are not secret and not
// sealed: the supervisor keeps them while the process is stopped and passes
// them back to POST /unlock.
type usageReply struct {
	Day    string              `json:"day"`
	Counts []server.DailyCount `json:"counts"`
}

func (in *Instance) getUsage(w http.ResponseWriter, _ *http.Request) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.state == nil {
		writeError(w, &httpError{http.StatusConflict, errLocked.Error()})
		return
	}
	day, counts := in.proxy.DailyCounts(time.Now())
	writeJSON(w, http.StatusOK, usageReply{Day: day, Counts: counts})
}

func (in *Instance) putNetwork(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Listen       string   `json:"listen"`
		AllowSources []string `json:"allow_sources"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	v, err := in.change(func(s *State) error {
		s.Listen, s.AllowSources = req.Listen, req.AllowSources
		return nil
	})
	in.changed(w, "network_set", nil, v, err, nil)
}

func (in *Instance) putConsent(w http.ResponseWriter, r *http.Request) {
	var req policy.Consent
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	v, err := in.change(func(s *State) error { s.Consent = &req; return nil })
	in.changed(w, "consent_set", nil, v, err, nil)
}

func (in *Instance) deleteConsent(w http.ResponseWriter, _ *http.Request) {
	v, err := in.change(func(s *State) error { s.Consent = nil; return nil })
	in.changed(w, "consent_deleted", nil, v, err, nil)
}

func (in *Instance) putService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var svc policy.Service
	if err := decode(r, &svc); err != nil {
		writeError(w, err)
		return
	}
	v, err := in.change(func(s *State) error { s.Services[name] = svc; return nil })
	in.changed(w, "service_set", map[string]any{"service": name}, v, err, nil)
}

func (in *Instance) deleteService(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v, err := in.change(func(s *State) error {
		if _, ok := s.Services[name]; !ok {
			return &httpError{http.StatusNotFound, "no such service"}
		}
		delete(s.Services, name)
		return nil
	})
	in.changed(w, "service_deleted", map[string]any{"service": name}, v, err, nil)
}

func (in *Instance) putRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Expires *time.Time               `json:"expires"`
		Access  map[string]policy.Access `json:"access"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	var token string
	v, err := in.change(func(s *State) error {
		role, exists := s.Roles[name]
		if !exists {
			t, sha, err := policy.NewToken()
			if err != nil {
				return err
			}
			token, role.TokenSHA256 = t, sha
		}
		role.Expires, role.Access = req.Expires, req.Access
		s.Roles[name] = role
		return nil
	})
	extra := map[string]any{}
	if token != "" && err == nil {
		// The only time the token is shown; only its hash is kept.
		extra["token"] = token
	}
	in.changed(w, "role_set", map[string]any{"role": name, "new_token": token != ""}, v, err, extra)
}

func (in *Instance) newRoleToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var token string
	v, err := in.change(func(s *State) error {
		role, ok := s.Roles[name]
		if !ok {
			return &httpError{http.StatusNotFound, "no such role"}
		}
		t, sha, err := policy.NewToken()
		if err != nil {
			return err
		}
		token, role.TokenSHA256 = t, sha
		s.Roles[name] = role
		return nil
	})
	in.changed(w, "role_token_rotated", map[string]any{"role": name}, v, err, map[string]any{"token": token})
}

func (in *Instance) deleteRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v, err := in.change(func(s *State) error {
		if _, ok := s.Roles[name]; !ok {
			return &httpError{http.StatusNotFound, "no such role"}
		}
		delete(s.Roles, name)
		return nil
	})
	in.changed(w, "role_deleted", map[string]any{"role": name}, v, err, nil)
}

func (in *Instance) putKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Value string `json:"value"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if !store.ValidName(name) {
		writeError(w, badRequest("key name: letters, digits and _"))
		return
	}
	if req.Value == "" || len(req.Value) > 64<<10 {
		writeError(w, badRequest("value: 1 byte to 64 KiB"))
		return
	}
	v, err := in.change(func(s *State) error { s.Keys[name] = req.Value; return nil })
	in.changed(w, "key_set", map[string]any{"key": name}, v, err, nil)
}

func (in *Instance) deleteKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v, err := in.change(func(s *State) error {
		if _, ok := s.Keys[name]; !ok {
			return &httpError{http.StatusNotFound, "no such key"}
		}
		delete(s.Keys, name)
		return nil
	})
	in.changed(w, "key_deleted", map[string]any{"key": name}, v, err, nil)
}

// rotate seals the state with a new data key. The old key no longer opens
// anything the instance writes from now on.
func (in *Instance) rotate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DataKey string `json:"data_key"`
	}
	if err := decode(r, &req); err != nil {
		writeError(w, err)
		return
	}
	key, err := decodeKey(req.DataKey)
	if err != nil {
		writeError(w, badRequest("%v", err))
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.state == nil {
		writeError(w, &httpError{http.StatusConflict, errLocked.Error()})
		return
	}
	next := in.state.clone()
	next.Version++
	old := in.key
	if err := in.commit(next, key); err != nil {
		writeError(w, err)
		return
	}
	clear(old)
	in.writeAudit("data_key_rotated", map[string]any{"version": next.Version})
	writeJSON(w, http.StatusOK, map[string]any{"version": next.Version})
}

// wipe deletes the instance: the state file is overwritten and removed, the
// state and data key are dropped from memory and the listeners stop. Once
// the supervisor drops its copy of the data key, no copy of the sealed state
// it may still hold can be opened.
func (in *Instance) wipe(w http.ResponseWriter, _ *http.Request) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.isWiped() {
		writeError(w, errWipedHTTP)
		return
	}
	if in.opt.StatePath != "" {
		if err := shred(in.opt.StatePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			writeError(w, err)
			return
		}
	}
	in.closeListeners(nil)
	if in.google != nil {
		in.google.Close()
	}
	// The proxy may still be reading the keys map; only drop references.
	clear(in.key)
	in.state, in.key, in.sealed = nil, nil, nil
	in.proxy, in.consent = nil, nil
	in.writeAudit("deleted", nil)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
	close(in.wiped)
}

// shred overwrites a file with random bytes before removing it, so the
// sealed state is gone even from a disk that keeps old blocks in place.
func shred(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err == nil {
		noise := make([]byte, info.Size())
		_, _ = rand.Read(noise)
		_, err = f.WriteAt(noise, 0)
		if err == nil {
			err = f.Sync()
		}
	}
	f.Close()
	if err != nil {
		return err
	}
	return os.Remove(path)
}
