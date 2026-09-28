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
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/admin"
	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/requests"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// Backend is what the pages read and change.
type Backend struct {
	// Mu serializes changes, here and in the SIGHUP reload.
	Mu        *sync.Mutex
	StorePath string
	MetaPath  string // key status and leaked flags; never values
	// Requests holds agents' access requests; nil turns them off.
	Requests *requests.Store
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
	// UpdatedAt is when the value was last added or replaced here (nil for
	// keys stored before the dashboard kept this).
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
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
	a.Handle("POST /keys/{name}/connect", b.connectKey)
	registerAccess(b)
}

// keyRow is one line of the keys table.
type keyRow struct {
	Name, Status, StatusClass string
	// State is the status filter: working, failing, untested, leaked or
	// novalue.
	State      string
	Services   []string
	Provider   string // e.g. "Apify", from the service's base URL
	UsedBy     []string
	Grants     []grant // UsedBy with each agent's kind of access
	LastUsed   string
	lastUsedAt time.Time
	CallsToday int
	Week       [7]int
	Updated    string
	HasValue   bool
}

// grant is an agent's access to a key, for the chips in the keys table.
type grant struct {
	Role string
	Full bool
}

// Spark returns the 7-day bar heights in pixels (2 to 18).
func (r keyRow) Spark() []int { return spark(r.Week) }

// WeekTotal is the calls of the last 7 days, for the chart's tooltip.
func (r keyRow) WeekTotal() int {
	n := 0
	for _, c := range r.Week {
		n += c
	}
	return n
}

func spark(week [7]int) []int {
	top := 0
	for _, c := range week {
		top = max(top, c)
	}
	out := make([]int, len(week))
	for i, c := range week {
		out[i] = 2
		if top > 0 && c > 0 {
			out[i] = max(3, c*18/top)
		}
	}
	return out
}

// isFull reports whether an access is what "give this agent this API"
// gives: every method and path, no limit, no end.
func isFull(a policy.Access) bool {
	return sameSet(a.Methods, fullMethods) && len(a.Paths) == 1 && a.Paths[0] == "/" && a.DailyRequests == 0 && a.Expires == nil
}

// providerOf names the API a service calls, from the built-in presets.
func providerOf(svc policy.Service) string {
	for _, p := range presets {
		if strings.TrimSuffix(svc.Base, "/") == strings.TrimSuffix(p.Base, "/") {
			return p.Label
		}
	}
	host := strings.TrimPrefix(strings.TrimPrefix(svc.Base, "https://"), "http://")
	host, _, _ = strings.Cut(host, "/")
	return strings.TrimPrefix(host, "api.")
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
		for _, sname := range row.Services {
			if row.Provider == "" {
				row.Provider = providerOf(cfg.Services[sname])
			}
		}
		full := map[string]bool{}
		for role, r := range cfg.Roles {
			for sname, acc := range r.Access {
				if services[sname] {
					if _, seen := full[role]; !seen {
						full[role] = true
					}
					full[role] = full[role] && isFull(acc)
				}
			}
		}
		for role := range full {
			row.UsedBy = append(row.UsedBy, role)
		}
		sort.Strings(row.UsedBy)
		for _, role := range row.UsedBy {
			row.Grants = append(row.Grants, grant{Role: role, Full: full[role]})
		}
		for _, u := range usage {
			if services[u.Service] {
				row.CallsToday += u.Calls
				for i, c := range u.Week() {
					row.Week[i] += c
				}
				if u.LastUsed.After(row.lastUsedAt) {
					row.lastUsedAt = u.LastUsed
				}
			}
		}
		if !row.lastUsedAt.IsZero() {
			row.LastUsed = ago(b.Now(), row.lastUsedAt)
		}
		if at := meta[name].UpdatedAt; at != nil {
			row.Updated = at.UTC().Format("2 Jan 2006")
		}
		row.Status, row.StatusClass = describe(has[name], meta[name])
		row.State = state(has[name], meta[name])
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

// state is the filter group of a key; it follows describe.
func state(hasValue bool, m KeyMeta) string {
	switch {
	case !hasValue:
		return "novalue"
	case m.LeakedAt != nil:
		return "leaked"
	case m.Status == "working":
		return "working"
	case m.Status == "failing":
		return "failing"
	}
	return "untested"
}

type keyFilter struct {
	ID, Label, Class string
	Count            int
	On               bool
}

// keyFilters are the chips above the keys table, with counts. "unused" are
// keys no agent may use.
func keyFilters(rows []keyRow, on string) []keyFilter {
	list := []keyFilter{{ID: "", Label: "All"}, {ID: "working", Label: "Working"}, {ID: "failing", Label: "Failing", Class: "bad"},
		{ID: "untested", Label: "Not tested"}, {ID: "leaked", Label: "Leaked", Class: "warn"}, {ID: "novalue", Label: "No value", Class: "bad"},
		{ID: "unused", Label: "Unused"}}
	out := list[:0]
	for _, f := range list {
		for _, r := range rows {
			if keyMatches(r, f.ID) {
				f.Count++
			}
		}
		f.On = f.ID == on
		if f.ID == "" || f.Count > 0 || f.On {
			out = append(out, f)
		}
	}
	return out
}

func keyMatches(r keyRow, filter string) bool {
	switch filter {
	case "":
		return true
	case "unused":
		return len(r.UsedBy) == 0
	}
	return r.State == filter
}

// sortKeys orders the table by a column; unknown columns sort by name.
func sortKeys(rows []keyRow, by string, desc bool) {
	rank := map[string]int{"novalue": 0, "failing": 1, "leaked": 2, "untested": 3, "working": 4}
	less := func(a, b keyRow) int {
		switch by {
		case "api":
			return strings.Compare(strings.ToLower(a.Provider), strings.ToLower(b.Provider))
		case "status":
			return rank[a.State] - rank[b.State]
		case "agents":
			return len(a.UsedBy) - len(b.UsedBy)
		case "last":
			return a.lastUsedAt.Compare(b.lastUsedAt)
		case "today":
			return a.CallsToday - b.CallsToday
		}
		return 0
	}
	sort.SliceStable(rows, func(i, j int) bool {
		c := less(rows[i], rows[j])
		if c == 0 {
			c = strings.Compare(strings.ToLower(rows[i].Name), strings.ToLower(rows[j].Name))
		}
		if desc {
			return c > 0
		}
		return c < 0
	})
}

// column is a sortable table header.
type column struct {
	ID, Label, Class, Href, Arrow string
}

// columns builds the header links: a click sorts by that column, a second
// click reverses it. Number and time columns start with the largest.
func columns(base string, q url.Values, by string, desc bool, cols [][3]string) []column {
	out := make([]column, 0, len(cols))
	for _, c := range cols {
		col := column{ID: c[0], Label: c[1], Class: c[2]}
		if col.ID != "" {
			v := url.Values{}
			for _, k := range []string{"q", "show"} { // not done= or error=: a notice shows once
				if q.Get(k) != "" {
					v.Set(k, q.Get(k))
				}
			}
			v.Set("sort", col.ID)
			numeric := col.Class == "num" || col.ID == "last" || col.ID == "agents" || col.ID == "apis"
			nextDesc := numeric
			if by == col.ID {
				nextDesc = !desc
				col.Arrow = "▲"
				if desc {
					col.Arrow = "▼"
				}
			}
			if nextDesc {
				v.Set("desc", "1")
			}
			col.Href = base + "?" + v.Encode()
		}
		out = append(out, col)
	}
	return out
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
	query := r.URL.Query()
	q := strings.ToLower(strings.TrimSpace(query.Get("q")))
	if q != "" {
		kept := rows[:0]
		for _, row := range rows {
			if strings.Contains(strings.ToLower(row.Name), q) || strings.Contains(strings.ToLower(row.Provider+" "+strings.Join(row.Services, " ")), q) {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	show := query.Get("show")
	filters := keyFilters(rows, show)
	kept := rows[:0]
	for _, row := range rows {
		if keyMatches(row, show) {
			kept = append(kept, row)
		}
	}
	rows = kept
	by, desc := query.Get("sort"), query.Get("desc") == "1"
	sortKeys(rows, by, desc)
	cols := columns("/keys", query, by, desc, [][3]string{{"name", "Key", ""}, {"api", "API", ""}, {"status", "Status", ""},
		{"agents", "Agents with access", ""}, {"last", "Last used", ""}, {"today", "Calls today", "num"}, {"", "7 days", ""}, {"", "Updated", ""}})
	b.render(w, http.StatusOK, "keys", sid, map[string]any{"Rows": rows, "Query": q, "Show": show, "Sort": by, "Desc": desc,
		"Filters": filters, "Columns": cols, "Notice": query.Get("done")})
}

func (b *Backend) newKeyPage(w http.ResponseWriter, r *http.Request, sid string) {
	b.renderNewKey(w, sid, http.StatusOK, "", "")
}

func (b *Backend) renderNewKey(w http.ResponseWriter, sid string, status int, name, msg string) {
	b.render(w, status, "newkey", sid, map[string]any{"Name": name, "Error": msg})
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

// addKey stores a new key: a name and a value, nothing else. Which API it is
// for is set later on the key's page ("Connect to a service").
func (b *Backend) addKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		b.renderNewKey(w, sid, http.StatusForbidden, name, "Enter your dashboard password to add a key.")
		return
	}
	if !store.ValidName(name) {
		b.renderNewKey(w, sid, http.StatusBadRequest, name, "The name must be letters, digits and _, not starting with a digit.")
		return
	}
	value, err := readValue(r)
	if err != nil {
		b.renderNewKey(w, sid, http.StatusBadRequest, name, "Paste the value, on one line.")
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if _, taken := keys[name]; taken {
		b.renderNewKey(w, sid, http.StatusConflict, name, "A key with this name exists. Open it and use Replace.")
		return
	}
	if err := store.Set(b.StorePath, name, value); err != nil {
		b.fail(w, sid, err)
		return
	}
	keys[name] = value
	b.Proxy.Swap(b.Proxy.Config(), keys)
	// Only the date: a failure here leaves the key stored and working.
	if meta, err := b.loadMeta(); err == nil {
		now := b.Now().UTC()
		meta[name] = KeyMeta{UpdatedAt: &now}
		_ = b.saveMeta(meta)
	}
	b.Admin.Audit("key_added", sid, map[string]any{"key": name})
	http.Redirect(w, r, "/keys/"+name+"?done=added", http.StatusSeeOther)
}

// connectForm is "Connect to a service" on a key's page.
type connectForm struct {
	Preset, Service, Base, Auth, Header, Param, TestPath, Pasted string
}

// agentSettings is what an agent may hand the owner to paste: the same
// fields as the form, as JSON.
type agentSettings struct {
	Service  string `json:"service"`
	Base     string `json:"base"`
	Auth     string `json:"auth"`
	Header   string `json:"header,omitempty"`
	Param    string `json:"param,omitempty"`
	TestPath string `json:"test_path,omitempty"`
}

// connectFormFor fills the form from a preset for key name.
func (b *Backend) connectFormFor(name, id string) connectForm {
	f := connectForm{Preset: id, Auth: policy.AuthBearer}
	if p, ok := presetByID(id); ok {
		f.Service = serviceName(p.ID, name, b.Proxy.Config().Services)
		f.Base, f.Auth, f.Header, f.Param, f.TestPath = p.Base, p.Auth, p.Header, p.Param, p.TestPath
	}
	return f
}

// connectKey adds a service that uses this key: from a preset, typed fields,
// or settings an agent wrote as JSON. The whole access list is checked before
// anything is written.
func (b *Backend) connectKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	f := connectForm{
		Preset: r.PostFormValue("preset"), Service: strings.TrimSpace(r.PostFormValue("service")),
		Base: strings.TrimSpace(r.PostFormValue("base")), Auth: r.PostFormValue("auth"),
		Header: strings.TrimSpace(r.PostFormValue("header")), Param: strings.TrimSpace(r.PostFormValue("param")),
		TestPath: strings.TrimSpace(r.PostFormValue("test_path")), Pasted: strings.TrimSpace(r.PostFormValue("pasted")),
	}
	again := func(status int, msg string) { b.renderKey(w, r, sid, status, name, f, msg) }
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		again(http.StatusForbidden, "Enter your dashboard password to connect the key.")
		return
	}
	if f.Pasted != "" {
		var a agentSettings
		dec := json.NewDecoder(strings.NewReader(f.Pasted))
		dec.DisallowUnknownFields()
		err := dec.Decode(&a)
		if err == nil {
			if _, extra := dec.Token(); extra != io.EOF {
				err = errors.New("text after the settings")
			}
		}
		if err != nil {
			again(http.StatusBadRequest, "The pasted settings are not valid: "+err.Error())
			return
		}
		f.Service, f.Base, f.Auth, f.Header, f.Param, f.TestPath = a.Service, a.Base, a.Auth, a.Header, a.Param, a.TestPath
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	if ok, err := b.known(name); err != nil || !ok {
		b.unknownKey(w, r, sid, err)
		return
	}
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if _, taken := next.Services[f.Service]; taken {
		again(http.StatusConflict, "A service named "+f.Service+" exists already. Pick another name.")
		return
	}
	next.Services[f.Service] = policy.Service{Base: f.Base, Key: name, Auth: f.Auth, Header: f.Header, Param: f.Param, TestPath: f.TestPath}
	if err := (&policy.Config{Rules: b.rules(), AccessList: next}).Validate(); err != nil {
		again(http.StatusBadRequest, err.Error())
		return
	}
	if err := b.saveAndApply(next); err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("key_connected", sid, map[string]any{"key": name, "service": f.Service, "base": f.Base})
	http.Redirect(w, r, "/keys/"+name+"?done=connected", http.StatusSeeOther)
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
	id := r.URL.Query().Get("preset")
	if id == "" {
		id = suggestPreset(name)
	}
	b.renderKey(w, r, sid, http.StatusOK, name, b.connectFormFor(name, id), "")
}

func (b *Backend) renderKey(w http.ResponseWriter, r *http.Request, sid string, status int, name string, f connectForm, msg string) {
	rows, err := b.rows()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	for _, row := range rows {
		if row.Name == name {
			meta, _ := b.loadMeta()
			errCode := r.URL.Query().Get("error")
			b.render(w, status, "key", sid, map[string]any{
				"Row": row, "Meta": meta[name], "Testable": b.testService(name) != "",
				"Notice": r.URL.Query().Get("done"), "Error": errCode, "ConnectError": msg,
				"Connect": f, "Presets": presetOptions(),
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
		m.LeakedAt, m.UpdatedAt = meta[name].LeakedAt, meta[name].UpdatedAt
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
		now := b.Now().UTC()
		meta[name] = KeyMeta{UpdatedAt: &now} // new value: not tested, no longer leaked
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
	pending, _ := b.pendingRequests()
	data["PendingCount"] = len(pending)
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
