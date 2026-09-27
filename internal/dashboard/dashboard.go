// Package dashboard is the keyring's management pages: keys and access. It
// runs behind internal/admin, which has already checked the Host, Origin,
// session and CSRF token of every request. Key values go one way only: a form
// posts a value once, and no page or response ever contains one.
package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/admin"
	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// Backend is what the pages read and change.
type Backend struct {
	// Mu serializes changes, here and in the SIGHUP reload.
	Mu        *sync.Mutex
	StorePath string
	MetaPath  string // key status and leaked flags; never values
	// Proxy holds the running config; its rules (which only root and SIGHUP
	// change) are the ones every change is checked against.
	Proxy *server.Handler
	Admin *admin.Server
	Now   func() time.Time
}

// KeyMeta is what the dashboard remembers about a key besides its value.
type KeyMeta struct {
	Status    string     `json:"status"` // "working", "failing" or "" (not tested)
	Reason    string     `json:"reason,omitempty"`
	CheckedAt time.Time  `json:"checked_at,omitzero"`
	LeakedAt  *time.Time `json:"leaked_at,omitempty"`
}

// rules are the running rules: a SIGHUP may have changed allow_sources since
// the start, and a dashboard change must not roll that back.
func (b *Backend) rules() policy.Rules { return b.Proxy.Config().Rules }

// Register adds the pages to the admin server.
func Register(b *Backend) {
	if b.Now == nil {
		b.Now = time.Now
	}
	a := b.Admin
	a.SetHome("/keys")
	a.Handle("GET /keys", b.keysPage)
	a.Handle("GET /new/key", b.newKeyPage) // not under /keys/: a key may be named "new"
	a.Handle("POST /keys", b.addKey)
	a.Handle("GET /keys/{name}", b.keyPage)
	a.Handle("POST /keys/{name}/test", b.testKey)
	a.Handle("POST /keys/{name}/replace", b.replaceKey)
	a.Handle("POST /keys/{name}/leaked", b.markLeaked)
	a.Handle("POST /keys/{name}/delete", b.deleteKey)
	registerAccess(b)
}

// keyRow is one line of the keys table.
type keyRow struct {
	Name, Status, StatusClass string
	Services, UsedBy          []string
	LastUsed                  string
	CallsToday                int
	HasValue                  bool
}

func (b *Backend) loadMeta() (map[string]KeyMeta, error) {
	raw, err := os.ReadFile(b.MetaPath)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]KeyMeta{}, nil
	}
	if err != nil {
		return nil, err
	}
	meta := map[string]KeyMeta{}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, fmt.Errorf("%s: %w", b.MetaPath, err)
	}
	return meta, nil
}

func (b *Backend) saveMeta(meta map[string]KeyMeta) error {
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(b.MetaPath, append(raw, '\n'), 0o600)
}

// rows builds the keys table: every stored key, plus any key a service names
// that has no value.
func (b *Backend) rows() ([]keyRow, error) {
	names, err := store.Names(b.StorePath)
	if err != nil {
		return nil, err
	}
	meta, err := b.loadMeta()
	if err != nil {
		return nil, err
	}
	cfg := b.Proxy.Config()
	usage := b.Proxy.Usage()
	has := map[string]bool{}
	for _, n := range names {
		has[n] = true
	}
	all := append([]string(nil), names...)
	for _, svc := range cfg.Services {
		if !has[svc.Key] {
			has[svc.Key] = false
			all = append(all, svc.Key)
		}
	}
	sort.Strings(all)
	all = compact(all)
	rows := make([]keyRow, 0, len(all))
	for _, name := range all {
		row := keyRow{Name: name, HasValue: has[name]}
		services := map[string]bool{}
		for sname, svc := range cfg.Services {
			if svc.Key == name {
				services[sname] = true
				row.Services = append(row.Services, sname)
			}
		}
		sort.Strings(row.Services)
		users := map[string]bool{}
		for role, r := range cfg.Roles {
			for sname := range r.Access {
				if services[sname] {
					users[role] = true
				}
			}
		}
		for role := range users {
			row.UsedBy = append(row.UsedBy, role)
		}
		sort.Strings(row.UsedBy)
		var last time.Time
		for _, u := range usage {
			if services[u.Service] {
				row.CallsToday += u.Calls
				if u.LastUsed.After(last) {
					last = u.LastUsed
				}
			}
		}
		if !last.IsZero() {
			row.LastUsed = ago(b.Now(), last)
		}
		row.Status, row.StatusClass = describe(has[name], meta[name])
		rows = append(rows, row)
	}
	return rows, nil
}

func compact(sorted []string) []string {
	out := sorted[:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func describe(hasValue bool, m KeyMeta) (string, string) {
	switch {
	case !hasValue:
		return "No value stored", "bad"
	case m.LeakedAt != nil:
		return "Leaked — replace", "warn"
	case m.Status == "working":
		return "Working", "ok"
	case m.Status == "failing":
		return "Failing: " + m.Reason, "bad"
	}
	return "Not tested", ""
}

func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return t.UTC().Format("2006-01-02")
}

func (b *Backend) keysPage(w http.ResponseWriter, r *http.Request, sid string) {
	rows, err := b.rows()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if q != "" {
		kept := rows[:0]
		for _, row := range rows {
			if strings.Contains(strings.ToLower(row.Name), q) || strings.Contains(strings.ToLower(strings.Join(row.Services, " ")), q) {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	b.render(w, http.StatusOK, "keys", sid, map[string]any{"Rows": rows, "Query": q, "Notice": r.URL.Query().Get("done")})
}

type newKeyForm struct {
	Name, Mode, Existing, SvcName, Base, Auth, Header, Param, TestMethod, TestPath string
}

func (b *Backend) newKeyPage(w http.ResponseWriter, r *http.Request, sid string) {
	b.renderNewKey(w, sid, http.StatusOK, newKeyForm{Mode: "new", Auth: policy.AuthBearer, TestMethod: "GET"}, "")
}

func (b *Backend) renderNewKey(w http.ResponseWriter, sid string, status int, f newKeyForm, msg string) {
	cfg := b.Proxy.Config()
	services := make([]string, 0, len(cfg.Services))
	for name := range cfg.Services {
		services = append(services, name)
	}
	sort.Strings(services)
	b.render(w, status, "newkey", sid, map[string]any{"Form": f, "Services": services, "Error": msg})
}

// readValue takes the posted value. Only surrounding line breaks are removed.
func readValue(r *http.Request) (string, error) {
	v := strings.TrimRight(r.PostFormValue("value"), "\r\n")
	if v == "" {
		return "", errors.New("paste the key value")
	}
	if strings.ContainsAny(v, "\r\n") {
		return "", errors.New("the value must be on one line")
	}
	return v, nil
}

func (b *Backend) addKey(w http.ResponseWriter, r *http.Request, sid string) {
	f := newKeyForm{
		Name: strings.TrimSpace(r.PostFormValue("name")), Mode: r.PostFormValue("mode"), Existing: r.PostFormValue("existing"),
		SvcName: strings.TrimSpace(r.PostFormValue("svc_name")), Base: strings.TrimSpace(r.PostFormValue("base")), Auth: r.PostFormValue("auth"),
		Header: strings.TrimSpace(r.PostFormValue("header")), Param: strings.TrimSpace(r.PostFormValue("param")),
		TestMethod: r.PostFormValue("test_method"), TestPath: strings.TrimSpace(r.PostFormValue("test_path")),
	}
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		b.renderNewKey(w, sid, http.StatusForbidden, f, "Enter your dashboard password to add a key.")
		return
	}
	if !store.ValidName(f.Name) {
		b.renderNewKey(w, sid, http.StatusBadRequest, f, "The name must be letters, digits and _, not starting with a digit.")
		return
	}
	value, err := readValue(r)
	if err != nil {
		b.renderNewKey(w, sid, http.StatusBadRequest, f, err.Error())
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if _, taken := keys[f.Name]; taken {
		b.renderNewKey(w, sid, http.StatusConflict, f, "A key with this name exists. Open it and use Replace.")
		return
	}
	// Edit the file, not the running copy: hand edits not yet reloaded stay.
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	switch f.Mode {
	case "existing":
		svc, ok := next.Services[f.Existing]
		if !ok {
			b.renderNewKey(w, sid, http.StatusBadRequest, f, "Pick a service.")
			return
		}
		svc.Key = f.Name
		next.Services[f.Existing] = svc
	case "new":
		if _, taken := next.Services[f.SvcName]; taken {
			b.renderNewKey(w, sid, http.StatusConflict, f, "A service with this name exists. Pick it under “existing service”.")
			return
		}
		next.Services[f.SvcName] = policy.Service{Base: f.Base, Key: f.Name, Auth: f.Auth, Header: f.Header, Param: f.Param, TestMethod: f.TestMethod, TestPath: f.TestPath}
	case "none":
	default:
		b.renderNewKey(w, sid, http.StatusBadRequest, f, "Choose how the key is used.")
		return
	}
	// Check the whole change before writing, so a refused form leaves nothing
	// behind; after that only the two writes can fail, and a failed access
	// write takes the value back out. The running config is swapped last,
	// from what was checked, as in saveAndApply.
	cfg := &policy.Config{Rules: b.rules(), AccessList: next}
	if err := cfg.Validate(); err != nil {
		b.renderNewKey(w, sid, http.StatusBadRequest, f, err.Error())
		return
	}
	if err := store.Set(b.StorePath, f.Name, value); err != nil {
		b.fail(w, sid, err)
		return
	}
	if f.Mode != "none" {
		if cfg, err = policy.SaveAccess(b.rules(), next); err != nil {
			if undo := store.Delete(b.StorePath, f.Name); undo != nil {
				err = errors.Join(err, undo)
			}
			b.fail(w, sid, err)
			return
		}
	}
	keys[f.Name] = value
	b.Proxy.Swap(cfg, keys)
	service := f.Existing
	if f.Mode == "new" {
		service = f.SvcName
	}
	b.Admin.Audit("key_added", sid, map[string]any{"key": f.Name, "service": service})
	http.Redirect(w, r, "/keys/"+f.Name+"?done=added", http.StatusSeeOther)
}

// apply loads the saved access file and keys and swaps them into the proxy,
// with the running rules. Callers hold b.Mu.
func (b *Backend) apply() error {
	access, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		return err
	}
	cfg := &policy.Config{Rules: b.rules(), AccessList: access}
	if err := cfg.Validate(); err != nil {
		return err
	}
	keys, err := store.Load(b.StorePath)
	if err != nil {
		return err
	}
	b.Proxy.Swap(cfg, keys)
	return nil
}

func (b *Backend) keyPage(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	rows, err := b.rows()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	for _, row := range rows {
		if row.Name == name {
			meta, _ := b.loadMeta()
			b.render(w, http.StatusOK, "key", sid, map[string]any{
				"Row": row, "Meta": meta[name], "Testable": b.testService(name) != "",
				"Notice": r.URL.Query().Get("done"), "Error": r.URL.Query().Get("error"),
			})
			return
		}
	}
	http.NotFound(w, r)
}

// known reports whether the keys page lists name: it is stored or an
// access-file service names it. Changes to any other name are refused, so
// they cannot leave entries for keys that exist nowhere.
func (b *Backend) known(name string) (bool, error) {
	rows, err := b.rows()
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if row.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// testService is the first service (by name) that uses the key and has a
// test request.
func (b *Backend) testService(name string) string {
	cfg := b.Proxy.Config()
	var names []string
	for sname, svc := range cfg.Services {
		if svc.Key == name && svc.TestPath != "" {
			names = append(names, sname)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func (b *Backend) testKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	sname := b.testService(name)
	if sname == "" {
		http.Redirect(w, r, "/keys/"+name+"?error=no-test", http.StatusSeeOther)
		return
	}
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	value, ok := keys[name]
	if !ok {
		http.Redirect(w, r, "/keys/"+name+"?error=no-value", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	status, testErr := b.Proxy.TestKey(ctx, b.Proxy.Config().Services[sname], value)
	m := KeyMeta{CheckedAt: b.Now().UTC()}
	switch {
	case testErr != nil:
		m.Status, m.Reason = "failing", testErr.Error()
	case status >= 200 && status < 300:
		m.Status = "working"
	default:
		m.Status, m.Reason = "failing", fmt.Sprintf("%d %s", status, http.StatusText(status))
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	// The result belongs to the value that was sent: if a replace or delete
	// happened meanwhile, it says nothing about the key now stored.
	now, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if cur, ok := now[name]; !ok || cur != value {
		http.Redirect(w, r, "/keys/"+name+"?error=changed", http.StatusSeeOther)
		return
	}
	meta, err := b.loadMeta()
	if err == nil {
		m.LeakedAt = meta[name].LeakedAt
		meta[name] = m
		err = b.saveMeta(meta)
	}
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("key_tested", sid, map[string]any{"key": name, "service": sname, "status": status})
	http.Redirect(w, r, "/keys/"+name+"?done=tested", http.StatusSeeOther)
}

func (b *Backend) replaceKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	if !store.ValidName(name) {
		http.NotFound(w, r)
		return
	}
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		http.Redirect(w, r, "/keys/"+name+"?error=password", http.StatusSeeOther)
		return
	}
	value, err := readValue(r)
	if err != nil {
		http.Redirect(w, r, "/keys/"+name+"?error=value", http.StatusSeeOther)
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	if ok, err := b.known(name); err != nil || !ok {
		b.unknownKey(w, r, sid, err)
		return
	}
	if err := store.Set(b.StorePath, name, value); err != nil {
		b.fail(w, sid, err)
		return
	}
	meta, err := b.loadMeta()
	if err == nil {
		meta[name] = KeyMeta{} // new value: not tested, no longer leaked
		err = b.saveMeta(meta)
	}
	if err == nil {
		err = b.apply()
	}
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("key_replaced", sid, map[string]any{"key": name})
	http.Redirect(w, r, "/keys/"+name+"?done=replaced", http.StatusSeeOther)
}

func (b *Backend) markLeaked(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		http.Redirect(w, r, "/keys/"+name+"?error=password", http.StatusSeeOther)
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	if ok, err := b.known(name); err != nil || !ok {
		b.unknownKey(w, r, sid, err)
		return
	}
	meta, err := b.loadMeta()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	m := meta[name]
	now := b.Now().UTC()
	m.LeakedAt = &now
	meta[name] = m
	if err := b.saveMeta(meta); err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("key_marked_leaked", sid, map[string]any{"key": name})
	http.Redirect(w, r, "/keys/"+name+"?done=leaked", http.StatusSeeOther)
}

func (b *Backend) deleteKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		http.Redirect(w, r, "/keys/"+name+"?error=password", http.StatusSeeOther)
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	rows, err := b.rows()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	for _, row := range rows {
		if row.Name == name && len(row.UsedBy) > 0 && r.PostFormValue("confirm_in_use") != "yes" {
			http.Redirect(w, r, "/keys/"+name+"?error=in-use", http.StatusSeeOther)
			return
		}
	}
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if _, ok := keys[name]; !ok {
		http.Redirect(w, r, "/keys/"+name+"?error=no-value", http.StatusSeeOther)
		return
	}
	if err := store.Delete(b.StorePath, name); err != nil {
		b.fail(w, sid, err)
		return
	}
	meta, err := b.loadMeta()
	if err == nil {
		delete(meta, name)
		err = b.saveMeta(meta)
	}
	if err == nil {
		err = b.apply()
	}
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("key_deleted", sid, map[string]any{"key": name})
	http.Redirect(w, r, "/keys?done=deleted", http.StatusSeeOther)
}

func (b *Backend) fail(w http.ResponseWriter, sid string, err error) {
	b.render(w, http.StatusInternalServerError, "error", sid, map[string]any{"Error": err.Error()})
}

func (b *Backend) render(w http.ResponseWriter, status int, page, sid string, data map[string]any) {
	data["CSRF"] = b.Admin.CSRF(sid)
	data["Page"] = page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pages.ExecuteTemplate(w, page, data)
}

func (b *Backend) unknownKey(w http.ResponseWriter, r *http.Request, sid string, err error) {
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	http.NotFound(w, r)
}
