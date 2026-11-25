// Package dashboard is the keyring's management pages: keys and access. It
// runs behind internal/admin, which has already checked the Host, Origin,
// session and CSRF token of every request. Key values go one way only: a form
// posts a value once, and no page or response ever contains one.
package dashboard

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

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
	// Version is the running release, shown in the sidebar.
	Version string
}

// navProject is one project in the sidebar.
type navProject struct {
	Name     string
	Dot      string // "ok" running, "warn" paused or ended
	Services int
}

// nav is what the sidebar on every page shows.
type nav struct {
	Keys, Agents, Projects int
	ProjectList            []navProject
	Version                string
}

func (b *Backend) nav() nav {
	cfg := b.Proxy.Config()
	n := nav{Agents: len(cfg.Roles), Version: b.Version}
	// The same set the Keys page lists: stored values plus keys a service
	// names that have none yet.
	if names, err := store.Names(b.StorePath); err == nil {
		set := map[string]bool{}
		for _, svc := range cfg.Services {
			names = append(names, svc.KeyNames()...)
		}
		for _, name := range names {
			base, _ := store.SplitPart(name)
			set[base] = true
		}
		n.Keys = len(set)
	}
	now := b.Now()
	for _, p := range projectNames(cfg) {
		dot := "ok"
		if projectState(cfg, p, now) != "running" {
			dot = "warn"
		}
		n.ProjectList = append(n.ProjectList, navProject{Name: p, Dot: dot, Services: len(projectServices(cfg, p))})
	}
	n.Projects = len(n.ProjectList)
	return n
}

// keyStats is the numbers strip above the keys table, over every key.
type keyStats struct {
	Keys, CallsToday, Failing, NoValue int
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
	// CreatedAt is when the key was added in the dashboard (nil for keys
	// added before it kept this, or with keyring set). It survives a replace.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// Kind and Fingerprint describe a value uploaded as a key file (#126):
	// e.g. "EC P-256 private key" and the first 16 hex of the SHA-256 of its
	// public key. Never the value. Cleared when the value is replaced by hand.
	Kind        string `json:"kind,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Values are the key's values in list order, with their labels (owner,
	// 2026-11-22): a key pool tries them in this order. Never values.
	Values []ValueNote `json:"values,omitempty"`
	// LastNumber is the highest number a value of the key was named with;
	// a value added without a name gets the next, so none is given twice.
	LastNumber int `json:"last_number,omitempty"`
}

// ValueNote is one value of a key in its list: its value name (the part of
// KEY.part; "" for the one plain value of KEY) and an optional label, free
// text the owner chose ("Jerry's Max account"). Not secret; never routes.
type ValueNote struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
}

// renewed is m after a new value: not tested and not leaked, with the dates
// and the value list kept.
func (m KeyMeta) renewed(now time.Time) KeyMeta {
	return KeyMeta{UpdatedAt: &now, CreatedAt: m.CreatedAt, Values: m.Values, LastNumber: m.LastNumber}
}

// order is the key's value names in list order.
func (m KeyMeta) order() []string {
	out := make([]string, 0, len(m.Values))
	for _, v := range m.Values {
		out = append(out, v.Name)
	}
	return out
}

// label is the label of value name, or "".
func (m KeyMeta) label(name string) string {
	for _, v := range m.Values {
		if v.Name == name {
			return v.Label
		}
	}
	return ""
}

// ValueOrder reads each key's list order of its value names from the key
// notes at metaPath, for the proxy's key pools (server.SetValueOrder).
func ValueOrder(metaPath string) (map[string][]string, error) {
	meta, err := readMeta(metaPath)
	if err != nil {
		return nil, err
	}
	return valueOrder(meta), nil
}

// PutValueOrder puts, for each key, the listed value names (key -> names)
// at the front of the key's list in the key notes at metaPath, in that
// order, keeping labels; values not listed follow as they were. Used when a
// v0.14.18 pool that named one value is converted to name the key
// (policy.ConvertNamedValuePools), so the pool keeps its whole order.
func PutValueOrder(metaPath string, order map[string][]string) error {
	meta, err := readMeta(metaPath)
	if err != nil {
		return err
	}
	for key, names := range order {
		m := meta[key]
		values := make([]ValueNote, 0, len(names)+len(m.Values))
		for _, name := range names {
			values = append(values, ValueNote{Name: name, Label: m.label(name)})
		}
		for _, v := range m.Values {
			if !slices.Contains(names, v.Name) {
				values = append(values, v)
			}
		}
		m.Values = values
		meta[key] = m
	}
	return writeMeta(metaPath, meta)
}

func valueOrder(meta map[string]KeyMeta) map[string][]string {
	out := map[string][]string{}
	for key, m := range meta {
		for _, v := range m.Values {
			if v.Name != "" {
				out[key] = append(out[key], v.Name)
			}
		}
	}
	return out
}

// rules are the running rules: a SIGHUP may have changed allow_sources since
// the start, and a dashboard change must not roll that back.
func (b *Backend) rules() policy.Rules { return b.Proxy.Config().Rules }

// diskConfig is the settings a reload would load: the running rules and the
// access file on disk, validated. Validate stores parsed forms in the
// consent settings, so they get their own copy: the running ones are read
// by consent requests without b.Mu.
func (b *Backend) diskConfig() (*policy.Config, error) {
	access, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		return nil, err
	}
	rules := b.rules()
	if rules.Consent != nil {
		consent := *rules.Consent
		rules.Consent = &consent
	}
	cfg := &policy.Config{Rules: rules, AccessList: access}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

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
	a.Handle("POST /new/key/upload", b.uploadKey)
	a.Handle("GET /keys/{name}", b.keyPage)
	a.Handle("POST /keys/{name}/test", b.testKey)
	a.Handle("POST /keys/{name}/reveal", b.revealKey)
	a.Handle("POST /keys/{name}/replace", b.replaceKey)
	a.Handle("POST /keys/{name}/leaked", b.markLeaked)
	a.Handle("POST /keys/{name}/delete", b.deleteKey)
	a.Handle("POST /keys/{name}/connect", b.connectKey)
	a.Handle("GET /keys/{name}/connect", b.connectRedirect)
	a.Handle("POST /keys/{name}/rename", b.renameKey)
	a.Handle("POST /keys/{name}/rename-value", b.renameValue)
	a.Handle("POST /keys/{name}/remove-value", b.removeValue)
	a.Handle("POST /keys/{name}/add-value", b.addValue)
	a.Handle("POST /keys/{name}/label", b.labelValue)
	a.Handle("POST /keys/{name}/move-up", b.moveValueUp)
	registerServices(b)
	registerProjects(b)
	registerActivity(b)
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
	// Projects are the projects of the key's services (#111).
	Projects []string
	// Parts are the named values of a key (MODAL.id, MODAL.secret;
	// CLAUDE_KEYS.1), in the key's list order; empty for a key with one
	// plain value.
	Parts []keyPart
	// Label is the label of a key's one plain value.
	Label string
	// AnyValue: at least one of the key's values is stored (HasValue needs
	// all of them).
	AnyValue bool
	// baseStored: the plain name has a stored value too (the CLI can store
	// API_KEY next to API_KEY.id); it is one of the row's values.
	baseStored bool
}

// keyPart is one named value of a key.
type keyPart struct {
	Name     string // "id"
	Full     string // "MODAL.id", the name services use
	Label    string // the owner's label, if any
	HasValue bool
	// Pooled: a key_pool service sends this value (owner, 2026-11-22).
	// PoolStatus and PoolClass say whether it is working or set aside;
	// the counts are its calls through the pool.
	Pooled                bool
	PoolStatus, PoolClass string
	CallsToday, CallsWeek int
	FailuresToday         int
	LastUsed              string
}

// valueNames are the stored names behind a key row: its parts, or itself.
func (r keyRow) valueNames() []string {
	if len(r.Parts) == 0 {
		return []string{r.Name}
	}
	out := make([]string, 0, len(r.Parts)+1)
	if r.baseStored {
		out = append(out, r.Name)
	}
	for _, p := range r.Parts {
		out = append(out, p.Full)
	}
	return out
}

// soleValue is the stored name (KEY, or KEY.part) of row's one stored value;
// ok is false when it has none or several. Connect's page and its
// submission both use it: settings that leave the value out mean it.
func (r keyRow) soleValue() (name string, ok bool) {
	var stored []string
	if r.baseStored {
		stored = append(stored, r.Name)
	}
	for _, p := range r.Parts {
		if p.HasValue {
			stored = append(stored, p.Full)
		}
	}
	if len(stored) != 1 {
		return "", false
	}
	return stored[0], true
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
	return sameSet(a.Methods, fullMethods) && len(a.Paths) == 1 && a.Paths[0] == "/" && a.DailyRequests == 0 && a.Expires == nil &&
		a.BitcoinMaxSatsPerTx == 0 && a.BitcoinMaxSatsPerDay == 0
}

// providerOf names the API a service calls, from the built-in presets.
func providerOf(svc policy.Service) string {
	if svc.Auth == policy.AuthAppleAdsSign {
		return "Apple Ads (sign only)"
	}
	if svc.Auth == policy.AuthAppStoreConnectSign {
		return "App Store Connect (sign only)"
	}
	if svc.Auth == policy.AuthSignInWithAppleSign {
		return "Sign in with Apple (sign only)"
	}
	if svc.Auth == policy.AuthMinisignSign {
		return "minisign (sign only)"
	}
	if svc.Auth == policy.AuthBitcoinPSBTSign {
		return "Bitcoin PSBT (sign only)"
	}
	for _, p := range presets {
		if strings.TrimSuffix(svc.Base, "/") == strings.TrimSuffix(p.Base, "/") {
			return p.Label
		}
	}
	host := strings.TrimPrefix(strings.TrimPrefix(svc.Base, "https://"), "http://")
	host, _, _ = strings.Cut(host, "/")
	return strings.TrimPrefix(host, "api.")
}

func (b *Backend) loadMeta() (map[string]KeyMeta, error) { return readMeta(b.MetaPath) }

// readMeta reads the key notes at path; none when the file does not exist.
func readMeta(path string) (map[string]KeyMeta, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]KeyMeta{}, nil
	}
	if err != nil {
		return nil, err
	}
	meta := map[string]KeyMeta{}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return meta, nil
}

// saveMeta writes the key notes and gives the proxy the value order in them.
func (b *Backend) saveMeta(meta map[string]KeyMeta) error {
	if err := writeMeta(b.MetaPath, meta); err != nil {
		return err
	}
	b.Proxy.SetValueOrder(valueOrder(meta))
	return nil
}

// writeMeta writes the key notes at path, replacing the file atomically.
func writeMeta(path string, meta map[string]KeyMeta) error {
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(path, append(raw, '\n'), 0o600)
}

// NoteKeyChange records in the key notes at metaPath that a key was set or
// deleted outside the dashboard (a consent link): a new value is not tested
// and not leaked, as after Replace; a deleted key has no notes. Callers hold
// the lock the dashboard's changes use.
func NoteKeyChange(metaPath, name string, deleted bool, now time.Time) error {
	meta, err := readMeta(metaPath)
	if err != nil {
		return err
	}
	if deleted {
		if _, ok := meta[name]; !ok {
			return nil
		}
		delete(meta, name)
	} else {
		at := now.UTC()
		meta[name] = meta[name].renewed(at)
	}
	return writeMeta(metaPath, meta)
}

// rows builds the keys table: every stored key, plus any key a service names
// that has no value.
func (b *Backend) rows() ([]keyRow, error) {
	keys, err := store.Load(b.StorePath)
	if err != nil {
		return nil, err
	}
	return b.rowsOf(keys)
}

// rowsOf builds the keys table from keys, one loaded store.
func (b *Backend) rowsOf(keys map[string]string) ([]keyRow, error) {
	names := slices.Sorted(maps.Keys(keys))
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
		for _, kn := range svc.KeyNames() {
			if !has[kn] {
				has[kn] = false
				all = append(all, kn)
			}
		}
	}
	sort.Strings(all)
	all = compact(all)
	// One row per key: MODAL.id and MODAL.secret are the parts of MODAL.
	parts := map[string][]keyPart{}
	var bases []string
	for _, name := range all {
		base, part := store.SplitPart(name)
		if len(bases) == 0 || bases[len(bases)-1] != base {
			bases = append(bases, base)
		}
		if part != "" {
			parts[base] = append(parts[base], keyPart{Name: part, Full: name, HasValue: has[name]})
		}
	}
	bases = compact(bases)
	rows := make([]keyRow, 0, len(bases))
	for _, name := range bases {
		row := keyRow{Name: name, HasValue: has[name], Parts: parts[name], baseStored: has[name], Label: meta[name].label("")}
		orderParts(row.Parts, meta[name])
		row.AnyValue = row.HasValue
		named := false // a named value is stored (MODAL.id)
		for _, p := range row.Parts {
			named = named || p.HasValue
		}
		row.AnyValue = row.AnyValue || named
		pooled := poolsKey(cfg, name)
		switch {
		case pooled:
			// A pool sends its key's named values while any is stored, or
			// the key's one plain value while it has no named ones; a value
			// under the bare name next to named ones is not sent
			// (policy.PoolMembers).
			row.HasValue = named || len(row.Parts) == 0 && has[name]
		case len(row.Parts) > 0:
			row.HasValue = true
			for _, p := range row.Parts {
				row.HasValue = row.HasValue && p.HasValue
			}
		}
		services := map[string]bool{}
		for sname, svc := range cfg.Services {
			if slices.ContainsFunc(svc.KeyNames(), func(k string) bool { b, _ := store.SplitPart(k); return b == name }) {
				services[sname] = true
				row.Services = append(row.Services, sname)
			}
		}
		sort.Strings(row.Services)
		for _, sname := range row.Services {
			if row.Provider == "" {
				row.Provider = providerOf(cfg.Services[sname])
			}
			if p := cfg.Services[sname].Project; p != "" && !slices.Contains(row.Projects, p) {
				row.Projects = append(row.Projects, p)
			}
		}
		sort.Strings(row.Projects)
		full := map[string]bool{}
		for role, r := range cfg.Roles {
			for sname, acc := range cfg.Grants(r) {
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
		m := meta[name]
		// A live refresh failure outranks an older test result. Each value is
		// checked: an oauth2 service may use one value of a key with several
		// (GMAIL_LENSCALE.refresh).
		for _, value := range row.valueNames() {
			if failure, _ := b.Proxy.OAuthFailure(value); failure != "" {
				m.Status, m.Reason = "failing", failure
				break
			}
		}
		row.Status, row.StatusClass = describe(row.HasValue, m)
		row.State = state(row.HasValue, m)
		if pooled {
			b.describePool(&row, usage)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// poolsKey reports whether a key_pool service sends the values of key.
func poolsKey(cfg *policy.Config, key string) bool {
	for _, svc := range cfg.Services {
		if svc.KeyPool && svc.Key == key {
			return true
		}
	}
	return false
}

// orderParts puts a key's values in its list order and gives each its label.
func orderParts(parts []keyPart, m KeyMeta) {
	byName := make(map[string]keyPart, len(parts))
	names := make([]string, len(parts))
	for i, p := range parts {
		byName[p.Name], names[i] = p, p.Name
	}
	store.OrderParts(names, m.order())
	for i, n := range names {
		parts[i] = byName[n]
		parts[i].Label = m.label(n)
	}
}

// notes are the key's values in list order with their labels, as the
// dashboard stores them.
func (r keyRow) notes() []ValueNote {
	if len(r.Parts) == 0 {
		return []ValueNote{{Name: "", Label: r.Label}}
	}
	out := make([]ValueNote, len(r.Parts))
	for i, p := range r.Parts {
		out[i] = ValueNote{Name: p.Name, Label: p.Label}
	}
	return out
}

// describePool fills in each pooled value of row and, when values are set
// aside, says so in the row's status: a pool keeps working while one value
// does, so some set aside is a warning and all set aside is a failure.
func (b *Backend) describePool(row *keyRow, usage []server.Usage) {
	now := b.Now()
	var members, away int
	var firstAway string
	for i := range row.Parts {
		p := &row.Parts[i]
		if !p.HasValue {
			continue
		}
		p.Pooled = true
		members++
		var last time.Time
		for _, u := range usage {
			if u.Key == p.Full {
				p.CallsToday += u.Calls
				for _, c := range u.Week() {
					p.CallsWeek += c
				}
				if u.LastUsed.After(last) {
					last = u.LastUsed
				}
			}
		}
		if !last.IsZero() {
			p.LastUsed = ago(now, last)
		}
		st := b.Proxy.PoolKeyStatus(p.Full)
		p.FailuresToday = st.FailuresToday
		switch st.State {
		case "failing":
			p.PoolStatus, p.PoolClass = "Failing: "+st.Reason, "bad"
			if !st.Until.IsZero() {
				p.PoolStatus += "; set aside, tried again " + inTime(now, st.Until)
			}
		case "cooling":
			p.PoolStatus, p.PoolClass = "Busy: "+st.Reason+"; set aside, back "+inTime(now, st.Until), "warn"
		case "working":
			p.PoolStatus, p.PoolClass = "Working", "ok"
		default:
			p.PoolStatus = "Ready"
			if !st.LastFailure.IsZero() {
				p.PoolStatus = "Ready again (last failure " + st.Reason + ", " + ago(now, st.LastFailure) + ")"
			}
		}
		// Another service pooling the value can still send it; the ones
		// that cannot are named beside its health.
		if len(st.Unsendable) > 0 && !st.CannotSend {
			p.PoolStatus += "; cannot be sent by " + strings.Join(st.Unsendable, ", ") + " (line break or control character)"
			if p.PoolClass == "" || p.PoolClass == "ok" {
				p.PoolClass = "warn"
			}
		}
		if st.State == "failing" || st.State == "cooling" {
			away++
			if firstAway == "" {
				firstAway = p.Name + ": " + st.Reason
			}
		}
	}
	switch {
	case members > 0 && away == members:
		row.Status, row.StatusClass, row.State = fmt.Sprintf("All %d values set aside (%s)", members, firstAway), "bad", "failing"
	case away > 0:
		row.Status, row.StatusClass = fmt.Sprintf("%s · %d of %d values set aside (%s)", row.Status, away, members, firstAway), "warn"
	}
}

// inTime says when t comes, from now: "in 12 min".
func inTime(now, t time.Time) string {
	d := t.Sub(now)
	switch {
	case d < time.Minute:
		return "in under a minute"
	case d < time.Hour:
		return fmt.Sprintf("in %d min", int(d.Minutes())+1)
	}
	return fmt.Sprintf("in %d h %d min", int(d.Hours()), int(d.Minutes())%60)
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
			for _, k := range []string{"q", "show", "project"} { // not done= or error=: a notice shows once
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
	stats := keyStats{Keys: len(rows)}
	// Once per usage record: a row's count covers every service using that
	// key, so a service with two keys would be counted twice.
	keyed := b.Proxy.Config()
	for _, u := range b.Proxy.Usage() {
		if svc, ok := keyed.Services[u.Service]; ok && len(svc.KeyNames()) > 0 {
			stats.CallsToday += u.Calls
		}
	}
	for _, row := range rows {
		if row.StatusClass == "bad" {
			if row.HasValue {
				stats.Failing++
			} else {
				stats.NoValue++
			}
		}
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
	project := query.Get("project")
	projectChips := projectFilters(b.Proxy.Config(), "/keys", query, project, func(p string) int {
		n := 0
		for _, row := range rows {
			if keyInProject(row, p) {
				n++
			}
		}
		return n
	})
	if project != "" {
		kept := rows[:0]
		for _, row := range rows {
			if keyInProject(row, project) {
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
	type googleRow struct {
		Name, Account, Status, Expires string
		Services                       []string
		LastSuccess                    string
		History                        []server.GoogleIncident
		HistoryUnavailable             bool
	}
	var accounts []googleRow
	cfg := b.Proxy.Config()
	for name, a := range cfg.GoogleAccounts {
		google := b.Proxy.GoogleStatus(name)
		row := googleRow{Name: name, Account: a.Account, Status: google.Text(cfg.ContainerMode)}
		history := b.Proxy.GoogleHistory(name)
		row.History, row.HistoryUnavailable = history.Incidents, history.Unavailable
		if !history.LastSuccess.IsZero() {
			row.LastSuccess = history.LastSuccess.UTC().Format(time.RFC3339)
		}
		if n := len(history.Incidents); google.Mint == server.GoogleNotChecked && n != 0 && history.Incidents[n-1].Outcome == "active" {
			row.Status = "Last recorded failure: " + history.Incidents[n-1].Failure.Error()
		}
		if !google.Expires.IsZero() && !google.Refused {
			row.Expires = google.Expires.UTC().Format(time.RFC3339)
		}
		for service, svc := range cfg.Services {
			if svc.Auth == policy.AuthGcloud && svc.GoogleAccount == name {
				row.Services = append(row.Services, service)
			}
		}
		sort.Strings(row.Services)
		accounts = append(accounts, row)
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Name < accounts[j].Name })
	b.render(w, http.StatusOK, "keys", sid, map[string]any{"Rows": rows, "Query": q, "Show": show, "Sort": by, "Desc": desc,
		"GoogleAccounts": accounts, "Filters": filters, "Columns": cols, "Notice": query.Get("done"),
		"Project": project, "ProjectFilters": projectChips, "Stats": stats})
}

func (b *Backend) newKeyPage(w http.ResponseWriter, r *http.Request, sid string) {
	b.renderNewKey(w, sid, http.StatusOK, "", "")
}

// renderNewKeyUpload shows the add-key page with an upload error.
func (b *Backend) renderNewKeyUpload(w http.ResponseWriter, sid string, status int, name, msg string) {
	b.render(w, status, "newkey", sid, map[string]any{"UploadName": name, "UploadError": msg, "MaxParts": maxParts})
}

func (b *Backend) renderNewKey(w http.ResponseWriter, sid string, status int, name, msg string) {
	b.render(w, status, "newkey", sid, map[string]any{"Name": name, "Error": msg, "MaxParts": maxParts})
}

// errValueControl: the value has a line break or control character inside it.
// Such a value cannot go in an HTTP header, so storing it would make every
// call fail (#109).
var errValueControl = errors.New("the value has a line break or control character")

// readValue takes the posted value. Whitespace around it (a stray space, tab or
// line break from copying) is removed; a value with a line break or control
// character inside is refused.
func readValue(r *http.Request) (string, error) {
	return checkValue(r.PostFormValue("value"))
}

func checkValue(raw string) (string, error) {
	v := strings.Trim(raw, " \t\r\n")
	if v == "" {
		return "", errors.New("paste the key value")
	}
	if !server.HeaderSafe(v) {
		return "", errValueControl
	}
	return v, nil
}

// maxParts bounds the values of one key (owner, 2026-11-22: four was too few
// for a key pool).
const maxParts = 32

// maxLabel bounds a value's label, in characters.
const maxLabel = 80

// checkLabel trims a value's label and refuses a long one or one with a
// line break or control character; it returns the message to show.
func checkLabel(raw string) (string, string) {
	label := strings.TrimSpace(raw)
	if utf8.RuneCountInString(label) > maxLabel || strings.ContainsFunc(label, unicode.IsControl) {
		return "", fmt.Sprintf("A label is at most %d characters, on one line.", maxLabel)
	}
	return label, ""
}

// valueRow is one value on the add-key form: the value, and an optional
// value name and label.
type valueRow struct{ Name, Value, Label string }

// readRows reads the rows of the add-key form ("value", "part" and "label"
// fields, one of each per row); empty rows are skipped. It returns the
// message to show if a row is wrong.
func readRows(r *http.Request) ([]valueRow, string) {
	values, names, labels := r.PostForm["value"], r.PostForm["part"], r.PostForm["label"]
	at := func(list []string, i int) string {
		if i < len(list) {
			return list[i]
		}
		return ""
	}
	var rows []valueRow
	named := map[string]bool{}
	for i := range max(len(values), len(names), len(labels)) {
		raw, rawLabel := at(values, i), at(labels, i)
		part := strings.ToLower(strings.TrimSpace(at(names, i)))
		if strings.TrimSpace(raw) == "" && part == "" && strings.TrimSpace(rawLabel) == "" {
			continue // an empty extra row
		}
		if part != "" && !store.ValidPart(part) {
			return nil, "Name a value with lowercase letters, digits or _ (e.g. id), or leave the name empty."
		}
		if named[part] {
			return nil, "Two values have the name " + part + "."
		}
		named[part] = part != ""
		label, msg := checkLabel(rawLabel)
		if msg != "" {
			return nil, msg
		}
		v, err := checkValue(raw)
		if err != nil {
			what := "the value"
			if part != "" {
				what = "the value for " + part
			}
			if errors.Is(err, errValueControl) {
				return nil, "The" + strings.TrimPrefix(what, "the") + " has a line break or control character inside it. Paste only the key itself."
			}
			return nil, "Paste " + what + ", on one line."
		}
		rows = append(rows, valueRow{Name: part, Value: v, Label: label})
	}
	if len(rows) == 0 {
		return nil, "Paste the value, on one line."
	}
	if len(rows) > maxParts {
		return nil, fmt.Sprintf("At most %d values per key.", maxParts)
	}
	return rows, ""
}

// nextNumber names a value added without a name: one more than the highest
// number the key has had (*last), skipping taken names. Numbers are never
// given twice.
func nextNumber(last *int, taken map[string]bool) string {
	for {
		*last++
		if n := strconv.Itoa(*last); !taken[n] {
			taken[n] = true
			return n
		}
	}
}

// maxNumber bounds automatic numbering: a value named with a larger number
// (a valid name of up to 32 digits) is just a name and does not move the
// counter, so the next number never overflows. nextNumber skips taken names.
const maxNumber = 1_000_000

// noteNumber raises *last to a value name that is a number, so that number
// is not given again.
func noteNumber(last *int, name string) {
	if n, err := strconv.Atoi(name); err == nil && n < maxNumber && n > *last {
		*last = n
	}
}

// addKey stores a new key: a name and one value, or several values (MODAL
// with id and secret, stored as MODAL.id and MODAL.secret; CLAUDE_KEYS with
// three values without names, stored as CLAUDE_KEYS.1, .2 and .3), each with
// an optional label. Which API it is for is set later on the key's page
// ("Connect to a service").
func (b *Backend) addKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		b.renderNewKey(w, sid, http.StatusForbidden, name, "Enter your dashboard password to add a key.")
		return
	}
	if base, part := store.SplitPart(name); part != "" || !store.ValidName(base) {
		b.renderNewKey(w, sid, http.StatusBadRequest, name, "The name must be letters, digits and _, not starting with a digit.")
		return
	}
	rows, msg := readRows(r)
	if msg != "" {
		b.renderNewKey(w, sid, http.StatusBadRequest, name, msg)
		return
	}
	values := map[string]string{}
	var notes []ValueNote
	last := 0
	if len(rows) == 1 && rows[0].Name == "" {
		// One value without a name: a plain key. Adding a second value
		// later gives both numbers.
		values[name] = rows[0].Value
		if rows[0].Label != "" {
			notes = []ValueNote{{Label: rows[0].Label}}
		}
	} else {
		taken := map[string]bool{}
		for _, row := range rows {
			taken[row.Name] = row.Name != ""
			noteNumber(&last, row.Name)
		}
		for _, row := range rows {
			if row.Name == "" {
				row.Name = nextNumber(&last, taken)
			}
			values[name+"."+row.Name] = row.Value
			notes = append(notes, ValueNote{Name: row.Name, Label: row.Label})
		}
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	// Taken if any value of it is stored. A name a service waits for, with
	// nothing stored yet, can be added.
	for stored := range keys {
		if base, _ := store.SplitPart(stored); base == name {
			b.renderNewKey(w, sid, http.StatusConflict, name, "A key with this name exists. Open it and use Replace.")
			return
		}
	}
	// A service may wait for this name already: no service but a Bitcoin
	// signing service may get a Bitcoin key.
	maps.Copy(keys, values)
	if err := b.Proxy.CheckBitcoinChange(b.Proxy.Config().AccessList, keys); err != nil {
		b.renderNewKey(w, sid, http.StatusBadRequest, name, err.Error())
		return
	}
	// The key notes hold the value order a key pool follows: they are
	// written before the values are stored, so a pool never sends the new
	// values in another order, and put back if storing fails.
	before, err := b.loadMeta()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	meta := maps.Clone(before)
	now := b.Now().UTC()
	meta[name] = KeyMeta{UpdatedAt: &now, CreatedAt: &now, Values: notes, LastNumber: last}
	if err := writeMeta(b.MetaPath, meta); err != nil {
		b.fail(w, sid, err)
		return
	}
	if err := store.Move(b.StorePath, nil, values); err != nil {
		if metaErr := writeMeta(b.MetaPath, before); metaErr != nil {
			err = errors.Join(err, fmt.Errorf("putting the key notes back failed too: %w", metaErr))
		}
		b.fail(w, sid, err)
		return
	}
	b.Proxy.SwapWithOrder(b.Proxy.Config(), keys, valueOrder(meta))
	fields := map[string]any{"key": name}
	if _, plain := values[name]; !plain {
		var parts []string
		for _, n := range notes {
			parts = append(parts, n.Name)
		}
		fields["parts"] = parts // names only, never values
	}
	b.Admin.Audit("key_added", sid, fields)
	http.Redirect(w, r, "/keys/"+name+"?done=added", http.StatusSeeOther)
}

// connectForm is "Connect to a service" on a key's page.
type connectForm struct {
	Preset, Service, Base, Auth, Scheme, Header, Param, TestPath, TLSPin, Project, Pasted string
	FixedHeaders, ExtraHeaders                                                            map[string]string
	APNs                                                                                  *policy.APNs
	SignInWithApple                                                                       *policy.SignInWithApple
	// KeyPart and PartHeaders: for a key with several values, the part sent
	// as the main credential, and header names for the others.
	KeyPart     string
	PartHeaders map[string]string
	OAuth2      *policy.OAuth2
	ForwardRole bool
	KeyPool     bool
	// Bitcoin: the settings of a bitcoin-psbt-sign service (#201).
	Bitcoin *policy.Bitcoin
}

// agentSettings is what an agent may hand the owner to paste: the same
// fields as the form, as JSON.
type agentSettings struct {
	Service      string            `json:"service"`
	Base         string            `json:"base"`
	Auth         string            `json:"auth"`
	Scheme       string            `json:"scheme,omitempty"`
	Header       string            `json:"header,omitempty"`
	Param        string            `json:"param,omitempty"`
	TestPath     string            `json:"test_path,omitempty"`
	TLSPin       string            `json:"tls_pin_sha256,omitempty"`
	FixedHeaders map[string]string `json:"fixed_headers,omitempty"`
	Project      string            `json:"project,omitempty"`
	// ForwardRole sends the calling agent's name upstream (X-Keyring-Role).
	ForwardRole bool `json:"forward_role,omitempty"`
	// KeyPool uses every value of the key in turn, in the key's list order.
	// A pointer, so an edit can tell "left out" (keep) from false (off).
	KeyPool *bool `json:"key_pool,omitempty"`
	// ExtraHeaders sends more secret values with each call: header name ->
	// name of another stored key, never a value. A pointer, so an edit can
	// tell "left out" (keep) from {} (remove).
	ExtraHeaders *map[string]string `json:"extra_headers,omitempty"`
	// APNs is the key and team ID of an Apple push key (auth "apns").
	APNs *policy.APNs `json:"apns,omitempty"`
	// SignInWithApple is the identity of a Sign in with Apple client-secret
	// signer (auth "sign-in-with-apple-sign").
	SignInWithApple *policy.SignInWithApple `json:"sign_in_with_apple,omitempty"`
	// KeyPart picks which value of a key with several is the service's main
	// credential (sent as auth/header/param); extra_headers may then name the
	// key's other values by their part names.
	KeyPart string `json:"key_part,omitempty"`
	// OAuth2 makes an "oauth2" service: the key is the refresh token, and
	// client_secret_key names another stored key (never a value).
	OAuth2 *policy.OAuth2 `json:"oauth2,omitempty"`
	// Key names the key as access.json does. Pasted on a key's page it must
	// be that key (or one of its values); on a service's page, the key
	// chosen there.
	Key string `json:"key,omitempty"`
	// Bitcoin makes a "bitcoin-psbt-sign" service: network, paths or
	// script, sighash (#201).
	Bitcoin *policy.Bitcoin `json:"bitcoin,omitempty"`
	// TestMethod is taken so a service copied from access.json pastes as
	// it is; the dashboard does not change it (see testMethodKept).
	TestMethod string `json:"test_method,omitempty"`
}

// pasteHelp is what a refused paste is told the settings look like.
const pasteHelp = `Paste one service's settings as JSON, like {"service":"name","auth":"bearer","base":"https://…"}; for a Bitcoin key: {"service":"name","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","paths":["m/86'/1'/0'/0/*","m/86'/1'/0'/1/*"]}}.`

var errTextAfter = errors.New("text after the settings")

// hasAuth reports whether the JSON object has an "auth" member, its name
// matched as encoding/json matches field names (case-insensitively).
func hasAuth(object json.RawMessage) bool {
	var members map[string]json.RawMessage
	if json.Unmarshal(object, &members) != nil {
		return false
	}
	for name := range members {
		if strings.EqualFold(name, "auth") {
			return true
		}
	}
	return false
}

// decodeSettings reads pasted settings. Besides the settings themselves it
// takes one service the way access.json writes it, {"name":{...}} or the
// line "name": {...} copied from the file, and the name is then the
// service's. A refused paste gets plain text naming at most a field, never
// a value: a secret pasted by mistake is not repeated.
func decodeSettings(pasted string) (agentSettings, string) {
	a, err := decodeStrict(pasted)
	if err == nil {
		return a, ""
	}
	copied := strings.HasPrefix(pasted, `"`)
	outer := pasted
	if copied {
		outer = "{" + strings.TrimSuffix(pasted, ",") + "}"
	}
	var named map[string]json.RawMessage
	if json.Unmarshal([]byte(outer), &named) == nil && len(named) == 1 {
		for name, inner := range named {
			if !bytes.HasPrefix(bytes.TrimSpace(inner), []byte("{")) {
				break
			}
			a, innerErr := decodeStrict(string(inner))
			if innerErr != nil {
				// A braced member named like a settings field (a service
				// called "bitcoin") may be flat settings with a bad field
				// instead: it is a service entry when it has the "auth"
				// every service has (matched as the decoder matches), and
				// copied lines always are.
				if !copied && settingsField(name) && !hasAuth(inner) {
					break // flat settings: their error says which field
				}
				return agentSettings{}, pasteProblem(innerErr)
			}
			if a.Service != "" && a.Service != name {
				return agentSettings{}, "The pasted settings name two services. Paste one service's settings."
			}
			a.Service = name
			return a, ""
		}
	}
	return agentSettings{}, pasteProblem(err)
}

// testMethodKept returns the message for a pasted test_method other than
// the one the service keeps (have; "" is GET): it is set in access.json.
func testMethodKept(pasted, have string) string {
	if pasted == "" || strings.EqualFold(pasted, cmp.Or(have, http.MethodGet)) {
		return ""
	}
	return "The test method is set in access.json, not here: leave \"test_method\" out, or give the one shown on the service's page."
}

func decodeStrict(text string) (agentSettings, error) {
	var a agentSettings
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return a, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return a, errTextAfter
	}
	return a, nil
}

// settingsField reports whether name is a field of agentSettings, matched
// as encoding/json does (case-insensitively).
func settingsField(name string) bool {
	t := reflect.TypeFor[agentSettings]()
	for i := range t.NumField() {
		if tag, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); strings.EqualFold(tag, name) {
			return true
		}
	}
	return false
}

// pasteProblem is the plain text for a paste that does not decode.
func pasteProblem(err error) string {
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.Is(err, errTextAfter):
		return "There is text after the pasted settings. " + pasteHelp
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return "The pasted settings have an " + strings.TrimPrefix(err.Error(), "json: ") + ". " + pasteHelp
	case errors.As(err, &typeErr) && typeErr.Field != "":
		return "In the pasted settings, " + strconv.Quote(typeErr.Field) + " has the wrong type. " + pasteHelp
	}
	return "The pasted settings are not valid. " + pasteHelp
}

// extraHeaderKeys checks that every key named in extra (header -> key name)
// has a stored value, and returns the message to show if one does not.
func (b *Backend) extraHeaderKeys(extra map[string]string) (string, error) {
	if len(extra) == 0 {
		return "", nil
	}
	stored, err := b.storedNames()
	if err != nil {
		return "", err
	}
	for _, header := range sortedNames(extra) {
		if msg := storedKeyRef(stored, "extra_headers: "+header, extra[header]); msg != "" {
			return msg, nil
		}
	}
	return "", nil
}

// storedKeyRef checks that key names a stored key and returns the message to
// show if not, naming field and never key: a secret pasted by mistake must
// not be repeated, and an identifier-shaped secret can pass as a name.
func storedKeyRef(stored map[string]bool, field, key string) string {
	if !store.ValidName(key) {
		return field + " must name a stored key (letters, digits and _), never a value. Add the value under Keys first, then name that key here."
	}
	if !stored[key] {
		return field + " must name a key with a stored value. Add the value under Keys first, then name that key here."
	}
	return ""
}

// clientIDProblem returns the message to show if an OAuth client ID is a
// template placeholder left in (Jarvis 447635: a saved "PASTE_YOUR_CLIENT_ID_HERE"
// made Google answer invalid_client), or, for Google's token endpoint, not a
// Google client ID. Only whole template shapes count, so an opaque ID that
// merely contains such a word (REPORTING_CLIENT_ID) passes. Checked on
// connect and on an edit that changes the ID, never on load, so a running
// config still starts.
func clientIDProblem(o *policy.OAuth2) string {
	if placeholderID.MatchString(o.ClientID) {
		return "The OAuth client ID looks like a placeholder. Copy the real one from the provider (Google: Clients > your client > Client ID)."
	}
	if u, err := url.Parse(o.TokenURL); err == nil && (u.Hostname() == "oauth2.googleapis.com" || u.Hostname() == "accounts.google.com") &&
		!strings.HasSuffix(o.ClientID, ".apps.googleusercontent.com") {
		return "A Google OAuth client ID ends in .apps.googleusercontent.com. Copy it from Google Cloud: Clients > your client > Client ID."
	}
	return ""
}

// placeholderID is a complete template value for the field itself, such as
// PASTE_YOUR_CLIENT_ID_HERE, YOUR_CLIENT_ID or client_id, or explicit
// placeholder syntax: <...>, {{...}} or ${...}. Nothing else, so an opaque ID
// (REPORTING_CLIENT_ID, enter_47f9e2) is never refused.
var placeholderID = regexp.MustCompile(`(?i)^((paste|enter|insert|put|replace)[_-])?(your[_-])?((oauth2?|google)[_-])?client[_-]?id([_-]here)?$|<[^<>]+>|\{\{|\$\{`)

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
		Base: strings.TrimSpace(r.PostFormValue("base")), Auth: r.PostFormValue("auth"), Scheme: strings.TrimSpace(r.PostFormValue("scheme")),
		Header: strings.TrimSpace(r.PostFormValue("header")), Param: strings.TrimSpace(r.PostFormValue("param")),
		TestPath: strings.TrimSpace(r.PostFormValue("test_path")), TLSPin: strings.TrimSpace(r.PostFormValue("tls_pin_sha256")), Pasted: strings.TrimSpace(r.PostFormValue("pasted")),
		KeyPart: strings.TrimSpace(r.PostFormValue("key_part")), PartHeaders: map[string]string{},
	}
	if f.Auth != policy.AuthBearer {
		f.Scheme = "" // the form's scheme box belongs to the bearer choice
	}
	for field, values := range r.PostForm {
		if part, ok := strings.CutPrefix(field, "part_header_"); ok && len(values) == 1 && strings.TrimSpace(values[0]) != "" {
			f.PartHeaders[part] = strings.TrimSpace(values[0])
		}
	}
	formProblem := ""
	if f.Auth == policy.AuthBitcoinPSBTSign {
		f.Bitcoin, formProblem = bitcoinFromForm(r)
	}
	again := func(status int, msg string) {
		if f.Pasted != "" {
			// A refused paste is one unit: none of it fills the form, and
			// no preset either, so sending the form again saves nothing
			// until it is filled in or a paste is accepted.
			f = b.connectFormFor(name, "")
		}
		b.renderKey(w, r, sid, status, name, f, msg)
	}
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		again(http.StatusForbidden, "Enter your dashboard password to connect the key.")
		return
	}
	if f.Pasted != "" {
		a, msg := decodeSettings(f.Pasted)
		if msg != "" {
			again(http.StatusBadRequest, msg)
			return
		}
		// The pasted key, as access.json names it, must be this page's key;
		// "NAME.part" picks the value, like key_part. It is never repeated:
		// it may be a value pasted by mistake.
		if a.Key != "" {
			base, part := store.SplitPart(a.Key)
			switch {
			case base != name:
				again(http.StatusBadRequest, "The pasted settings name another key in \"key\". Connect them from that key's page, or leave \"key\" out to connect "+name+".")
				return
			case part != "" && a.KeyPart != "" && part != a.KeyPart:
				again(http.StatusBadRequest, "The pasted \"key\" and \"key_part\" name different values. Leave one of them out.")
				return
			case part != "":
				a.KeyPart = part
			}
		}
		if msg := testMethodKept(a.TestMethod, ""); msg != "" {
			again(http.StatusBadRequest, msg)
			return
		}
		f.Service, f.Base, f.Auth, f.Scheme, f.Header, f.Param, f.TestPath, f.TLSPin = a.Service, a.Base, a.Auth, a.Scheme, a.Header, a.Param, a.TestPath, a.TLSPin
		f.FixedHeaders, f.Project, f.ForwardRole, f.KeyPool = a.FixedHeaders, a.Project, a.ForwardRole, a.KeyPool != nil && *a.KeyPool
		if a.ExtraHeaders != nil {
			f.ExtraHeaders = *a.ExtraHeaders
		}
		f.APNs, f.SignInWithApple, f.KeyPart, f.OAuth2, f.Bitcoin = a.APNs, a.SignInWithApple, a.KeyPart, a.OAuth2, a.Bitcoin
		f.PartHeaders = nil
	} else if formProblem != "" {
		again(http.StatusBadRequest, formProblem)
		return
	}
	if f.Service == "" {
		again(http.StatusBadRequest, "Name the service.")
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, ok, err := b.row(name)
	if err != nil || !ok {
		b.unknownKey(w, r, sid, err)
		return
	}
	keyName := name
	sole, hasSole := row.soleValue()
	_, solePart := store.SplitPart(sole)
	switch {
	case f.KeyPool && f.KeyPart != "":
		again(http.StatusBadRequest, "Leave key_part out: a key pool uses the values of "+name+" in list order.")
		return
	case f.KeyPool:
		// The pool names the key itself; its values are tried in list order.
	case f.KeyPart == "" && hasSole && solePart == "":
		// The plain value is the one stored value (services may name values
		// not stored yet): settings that leave the value out mean it, as the
		// page that offers them does.
	case len(row.Parts) > 0:
		// Settings that leave the value out mean the one stored value.
		if f.KeyPart == "" && hasSole {
			f.KeyPart = solePart
		}
		has := map[string]bool{}
		for _, p := range row.Parts {
			has[p.Name] = true
		}
		if !has[f.KeyPart] {
			again(http.StatusBadRequest, "Pick which value of "+name+" is sent as the key.")
			return
		}
		keyName = name + "." + f.KeyPart
		// The other values go in headers: from the form's per-value header
		// names, or pasted extra_headers naming a part ("secret").
		if f.ExtraHeaders == nil {
			f.ExtraHeaders = map[string]string{}
		}
		for part, header := range f.PartHeaders {
			if !has[part] || part == f.KeyPart {
				again(http.StatusBadRequest, "Only the other values of "+name+" can be sent as extra headers.")
				return
			}
			f.ExtraHeaders[header] = part
		}
		for header, ref := range f.ExtraHeaders {
			if has[ref] {
				f.ExtraHeaders[header] = name + "." + ref
			}
		}
	case f.KeyPart != "":
		again(http.StatusBadRequest, name+" has one value; leave key_part out.")
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
	if msg, err := b.extraHeaderKeys(f.ExtraHeaders); err != nil {
		b.fail(w, sid, err)
		return
	} else if msg != "" {
		again(http.StatusBadRequest, msg)
		return
	}
	if f.OAuth2 != nil {
		if msg := clientIDProblem(f.OAuth2); msg != "" {
			again(http.StatusBadRequest, msg)
			return
		}
	}
	if f.OAuth2 != nil && f.OAuth2.ClientSecretKey != "" {
		// Same rule as extra headers: a stored key's name, never a value,
		// and never repeated in the message.
		stored, err := b.storedNames()
		if err != nil {
			b.fail(w, sid, err)
			return
		}
		if msg := storedKeyRef(stored, "oauth2.client_secret_key", f.OAuth2.ClientSecretKey); msg != "" {
			again(http.StatusBadRequest, msg)
			return
		}
	}
	var extra map[string]string
	if len(f.ExtraHeaders) > 0 {
		extra = f.ExtraHeaders
	}
	svc := policy.Service{Base: f.Base, Key: keyName, Auth: f.Auth, Scheme: f.Scheme, Header: f.Header, Param: f.Param, TestPath: f.TestPath, TLSPinSHA256: f.TLSPin, FixedHeaders: f.FixedHeaders, ExtraHeaders: extra, Project: f.Project, ForwardRole: f.ForwardRole, KeyPool: f.KeyPool, APNs: f.APNs, SignInWithApple: f.SignInWithApple, OAuth2: f.OAuth2, Bitcoin: f.Bitcoin}
	next.Services[f.Service] = svc
	if err := (&policy.Config{Rules: b.rules(), AccessList: next}).Validate(); err != nil {
		again(http.StatusBadRequest, err.Error())
		return
	}
	msg, err := b.saveChecked(next, f.Service)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if msg != "" {
		again(http.StatusBadRequest, msg)
		return
	}
	fields := map[string]any{"key": keyName, "service": f.Service, "base": f.Base}
	if len(extra) > 0 {
		fields["extra_headers"] = extra // header and key names only, never values
	}
	b.Admin.Audit("key_connected", sid, fields)
	http.Redirect(w, r, "/keys/"+name+"?done=connected", http.StatusSeeOther)
}

// apply loads the saved access file and keys and swaps them into the proxy,
// with the running rules, as a reload does: a stored Bitcoin key a proxy
// service would use is refused at request time. Callers hold b.Mu.
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
	// Links built from a service's key name (MODAL.id) open the key, MODAL.
	if base, part := store.SplitPart(name); part != "" {
		http.Redirect(w, r, "/keys/"+base, http.StatusSeeOther)
		return
	}
	id := r.URL.Query().Get("preset")
	if id == "" {
		id = suggestPreset(name)
	}
	b.renderKey(w, r, sid, http.StatusOK, name, b.connectFormFor(name, id), "")
}

func (b *Backend) renderKey(w http.ResponseWriter, r *http.Request, sid string, status int, name string, f connectForm, msg string) {
	row, values, ok, err := b.storedRow(name)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	meta, _ := b.loadMeta()
	info, never := neverShown(b.Proxy.Config(), row, values)
	// A key with one stored value that is a Bitcoin key connects to a
	// bitcoin-psbt-sign service only, so its page offers that form instead
	// of the API one (#201), sending that value's name when it has one. A
	// key with several values keeps the API form, whatever its values are;
	// Bitcoin settings for one of them are pasted. With one stored value,
	// info describes it.
	var btc *bitcoinForm
	btcPart := ""
	if sole, ok := row.soleValue(); ok && info != nil {
		btc = bitcoinFormOf(f.Bitcoin, info.WIF)
		_, btcPart = store.SplitPart(sole)
	}
	b.render(w, status, "key", sid, map[string]any{
		"Row": row, "Meta": meta[name], "Testable": b.testService(b.Proxy.Config(), name) != "",
		"Notice": r.URL.Query().Get("done"), "Error": r.URL.Query().Get("error"), "EditError": b.keyEditError(r.URL.Query()), "ConnectError": msg,
		"Connect": f, "Presets": presetOptions(), "Bitcoin": info, "NeverShown": never, "BitcoinForm": btc, "BitcoinKeyPart": btcPart,
	})
}

// known reports whether the keys page lists name: it is stored or an
// access-file service names it. Changes to any other name are refused, so
// they cannot leave entries for keys that exist nowhere.
func (b *Backend) known(name string) (bool, error) {
	_, ok, err := b.row(name)
	return ok, err
}

// row is the keys page row of name.
func (b *Backend) row(name string) (keyRow, bool, error) {
	row, _, ok, err := b.storedRow(name)
	return row, ok, err
}

// storedRow is the keys page row of name and the store it was built from,
// so the row and its values come from one read.
func (b *Backend) storedRow(name string) (keyRow, map[string]string, bool, error) {
	keys, err := store.Load(b.StorePath)
	if err != nil {
		return keyRow{}, nil, false, err
	}
	rows, err := b.rowsOf(keys)
	if err != nil {
		return keyRow{}, nil, false, err
	}
	for _, row := range rows {
		if row.Name == name {
			return row, keys, true, nil
		}
	}
	return keyRow{}, nil, false, nil
}

// testService is the first service (by name) in cfg that uses the key and
// has a test request.
func (b *Backend) testService(cfg *policy.Config, name string) string {
	var names []string
	for sname, svc := range cfg.Services {
		if base, _ := store.SplitPart(svc.Key); base == name && !svc.SignOnly() && svc.TestPath != "" {
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
	cfg := b.Proxy.Config()
	sname := b.testService(cfg, name)
	if sname == "" {
		http.Redirect(w, r, "/keys/"+name+"?error=no-test", http.StatusSeeOther)
		return
	}
	svc := cfg.Services[sname]
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	var status int
	var sent map[string]string
	var pool server.PoolValues
	var testErr error
	if svc.KeyPool {
		// A pool is tested as a call goes (server.TestPool): the proxy
		// checks the service still pools the key chosen here, takes its
		// values and their order from one snapshot and moves on only when
		// the service refused one the way a call moves on, so the key
		// works if a call through the pool would.
		status, pool, testErr = b.Proxy.TestPool(ctx, sname, svc.Key)
		switch {
		case errors.Is(testErr, server.ErrNoPoolValue):
			http.Redirect(w, r, "/keys/"+name+"?error=no-value", http.StatusSeeOther)
			return
		case errors.Is(testErr, server.ErrPoolChanged):
			http.Redirect(w, r, "/keys/"+name+"?error=changed", http.StatusSeeOther)
			return
		}
	} else {
		keys, err := store.Load(b.StorePath)
		if err != nil {
			b.fail(w, sid, err)
			return
		}
		names := svc.KeyNames()
		if len(names) == 0 {
			http.Redirect(w, r, "/keys/"+name+"?error=no-value", http.StatusSeeOther)
			return
		}
		sent = map[string]string{}
		for _, kn := range names {
			v, ok := keys[kn]
			if !ok {
				http.Redirect(w, r, "/keys/"+name+"?error=no-value", http.StatusSeeOther)
				return
			}
			sent[kn] = v
		}
		status, testErr = b.Proxy.TestKey(ctx, svc, sent[names[0]])
	}
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
	// The result belongs to the values that were tested: if one was
	// replaced, deleted, added or moved meanwhile, it says nothing about the
	// key now. The store on disk can change without the dashboard (keyring
	// set) before the proxy reloads it. A pool is checked once, by
	// PoolCurrent, against the settings, store and value order on disk and
	// against the proxy's pool now.
	now, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	meta, err := b.loadMeta()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	fresh := true
	if svc.KeyPool {
		disk, err := b.diskConfig()
		if err != nil {
			b.fail(w, sid, err)
			return
		}
		fresh = b.Proxy.PoolCurrent(pool, disk, now, valueOrder(meta))
	} else {
		for kn, v := range sent {
			if cur, ok := now[kn]; !ok || cur != v {
				fresh = false
			}
		}
	}
	if !fresh {
		http.Redirect(w, r, "/keys/"+name+"?error=changed", http.StatusSeeOther)
		return
	}
	m.LeakedAt, m.UpdatedAt, m.CreatedAt = meta[name].LeakedAt, meta[name].UpdatedAt, meta[name].CreatedAt
	m.Kind, m.Fingerprint = meta[name].Kind, meta[name].Fingerprint
	m.Values, m.LastNumber = meta[name].Values, meta[name].LastNumber
	meta[name] = m
	err = b.saveMeta(meta)
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
		code := "value"
		if errors.Is(err, errValueControl) {
			code = "value-control"
		}
		http.Redirect(w, r, "/keys/"+name+"?error="+code, http.StatusSeeOther)
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, ok, err := b.row(name)
	if err != nil || !ok {
		b.unknownKey(w, r, sid, err)
		return
	}
	// A key with several values replaces one of them; Add a value adds one.
	target := name
	if part := strings.TrimSpace(r.PostFormValue("part")); part != "" || len(row.Parts) > 0 {
		if !slices.ContainsFunc(row.Parts, func(p keyPart) bool { return p.Name == part }) {
			http.Redirect(w, r, "/keys/"+name+"?error=part", http.StatusSeeOther)
			return
		}
		target = name + "." + part
	}
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	keys[target] = value
	if refusedBitcoinKey(w, r, name, b.Proxy.CheckBitcoinChange(b.Proxy.Config().AccessList, keys)) {
		return
	}
	if err := store.Set(b.StorePath, target, value); err != nil {
		b.fail(w, sid, err)
		return
	}
	// Live at once with the running config, as upload does: nothing can fail
	// after the value is stored, so the store and the keyring agree (#128).
	b.Proxy.Swap(b.Proxy.Config(), keys)
	if meta, err := b.loadMeta(); err == nil {
		now := b.Now().UTC()
		meta[name] = meta[name].renewed(now) // new value: not tested, no longer leaked
		_ = b.saveMeta(meta)
	}
	b.Admin.Audit("key_replaced", sid, map[string]any{"key": target})
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
	complete := r.PostFormValue("remove_services") == "yes"
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
	row, _, err := b.row(name)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	stored := []string{}
	for _, kn := range row.valueNames() {
		if _, ok := keys[kn]; ok {
			stored = append(stored, kn)
		}
	}
	if len(stored) == 0 && !complete {
		http.Redirect(w, r, "/keys/"+name+"?error=no-value", http.StatusSeeOther)
		return
	}
	ofKey := func(k string) bool { b, _ := store.SplitPart(k); return b == name }
	var removed []string
	if complete {
		next, err := policy.LoadAccess(b.rules().AccessFile)
		if err != nil {
			b.fail(w, sid, err)
			return
		}
		for service, svc := range next.Services {
			if slices.ContainsFunc(svc.KeyNames(), ofKey) {
				removed = append(removed, service)
				delete(next.Services, service)
				for _, role := range next.Roles {
					delete(role.Access, service)
				}
			}
		}
		sort.Strings(removed)
		if len(stored) == 0 && len(removed) == 0 {
			b.notFound(w, sid)
			return
		}
		// Remove and apply access first. If deleting the value fails, no
		// removed service can still use it; the remaining key can be retried.
		if err := b.saveAndApply(next); err != nil {
			b.fail(w, sid, err)
			return
		}
		b.Admin.Audit("services_removed", sid, map[string]any{"key": name, "services": removed})
	}
	for _, kn := range stored {
		if err := store.Delete(b.StorePath, kn); err != nil {
			b.fail(w, sid, err)
			return
		}
		delete(keys, kn)
	}
	// Dropping metadata must not keep the deleted value live in the proxy.
	b.Proxy.Swap(b.Proxy.Config(), keys)
	meta, err := b.loadMeta()
	if err == nil {
		delete(meta, name)
		for _, kn := range stored {
			delete(meta, kn)
		}
		err = b.saveMeta(meta)
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
	data["Nav"] = b.nav()
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

// keyInProject reports whether a key belongs in a project filter: "-" is the
// keys with no project (personal), otherwise keys a service of that project uses.
func keyInProject(row keyRow, project string) bool {
	if project == "-" {
		return len(row.Projects) == 0
	}
	return slices.Contains(row.Projects, project)
}

// projectFilter is one chip of the project filter row.
type projectFilter struct {
	Label, Href string
	Count       int
	On          bool
}

// projectFilters builds the project chips: All, Personal (no project) and one
// per project, each keeping the page's other filters and sort.
func projectFilters(cfg *policy.Config, base string, q url.Values, on string, count func(string) int) []projectFilter {
	names := projectNames(cfg)
	if len(names) == 0 {
		return nil
	}
	link := func(project string) string {
		v := url.Values{}
		for _, k := range []string{"q", "show", "sort", "desc"} {
			if q.Get(k) != "" {
				v.Set(k, q.Get(k))
			}
		}
		if project != "" {
			v.Set("project", project)
		}
		if len(v) == 0 {
			return base
		}
		return base + "?" + v.Encode()
	}
	out := []projectFilter{{Label: "All projects", Href: link(""), On: on == "", Count: -1}, {Label: "Personal", Href: link("-"), On: on == "-", Count: count("-")}}
	for _, name := range names {
		out = append(out, projectFilter{Label: name, Href: link(name), On: on == name, Count: count(name)})
	}
	return out
}
