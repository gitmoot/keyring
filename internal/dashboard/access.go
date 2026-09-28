package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// The access grid: rows are roles (agents), columns are services. A token is
// made here and shown in the one response that made it; only its SHA-256 is
// kept.

var (
	readMethods = []string{"GET", "HEAD"}
	fullMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
	// tokenDir is where the relay on the calling machine reads role tokens.
	tokenDir = "/etc/keyring/tokens"
)

func registerAccess(b *Backend) {
	a := b.Admin
	a.Handle("GET /access", b.accessPage)
	a.Handle("POST /requests/{id}", b.answerRequest)
	a.Handle("GET /access/{role}/{service}", b.cellPage)
	a.Handle("POST /access/{role}/{service}", b.saveCell)
	a.Handle("GET /new/agent", b.newAgentPage) // not under /agents/: a role may be named "new"
	a.Handle("POST /agents", b.addAgent)
	a.Handle("GET /agents/{role}", b.agentPage)
	a.Handle("POST /agents/{role}/token", b.newAgentToken)
	a.Handle("POST /agents/{role}/revoke", b.revokeAgent)
}

type gridCell struct {
	Role, Service string
	On, Ended     bool
	Label, Detail string
}

// gridRow is one agent's card: the services it may use (Cells) and the ones
// it may not (Off), for "Add a service".
type gridRow struct {
	Role       string
	Ended      bool
	Cells      []gridCell
	Off        []string
	CallsToday int
}

// methodsLabel names a method list the way the cell form offers it.
func methodsLabel(m []string) string {
	switch {
	case len(m) == 0:
		return "GET, HEAD, POST"
	case sameSet(m, readMethods):
		return "Read only"
	case sameSet(m, fullMethods):
		return "Full"
	}
	return strings.Join(inOrder(m), ", ")
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			return false
		}
	}
	return true
}

// inOrder sorts methods as fullMethods lists them.
func inOrder(m []string) []string {
	out := make([]string, 0, len(m))
	for _, x := range fullMethods {
		if slices.Contains(m, x) {
			out = append(out, x)
		}
	}
	return out
}

func calls(n int) string {
	if n == 1 {
		return "1 call"
	}
	return strconv.Itoa(n) + " calls"
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var accessErrors = map[string]string{
	"password": "Enter your dashboard password to answer a request.",
	"gone":     "That request was already answered.",
}

var accessNotices = map[string]string{
	"saved":   "Access saved. It applies to the next call.",
	"revoked": "Agent revoked. Its token no longer works.",
}

func (b *Backend) accessPage(w http.ResponseWriter, r *http.Request, sid string) {
	cfg := b.Proxy.Config()
	now := b.Now()
	count := map[[2]string]int{}
	for _, u := range b.Proxy.Usage() {
		count[[2]string{u.Role, u.Service}] += u.Calls
	}
	services := sortedNames(cfg.Services)
	var rows []gridRow
	for _, role := range sortedNames(cfg.Roles) {
		rl := cfg.Roles[role]
		row := gridRow{Role: role, Ended: rl.Expired(now)}
		for _, svc := range services {
			c := gridCell{Role: role, Service: svc}
			if acc, ok := rl.Access[svc]; ok {
				c.On, c.Ended = true, row.Ended || acc.Expired(now)
				c.Label = methodsLabel(acc.Methods)
				n := count[[2]string{role, svc}]
				row.CallsToday += n
				switch {
				case c.Ended:
					c.Detail = "ended"
				// Calls counts attempts, refused ones too; the limit counts
				// only calls that went out, so the two are shown apart.
				case acc.DailyRequests > 0:
					c.Detail = fmt.Sprintf("%s today · limit %d", calls(n), acc.DailyRequests)
				default:
					c.Detail = calls(n) + " today · no limit"
				}
			}
			if c.On {
				row.Cells = append(row.Cells, c)
			} else {
				row.Off = append(row.Off, svc)
			}
		}
		rows = append(rows, row)
	}
	notice := accessNotices[r.URL.Query().Get("done")]
	if notice == "" {
		notice = requestNotices[r.URL.Query().Get("done")]
	}
	pending, err := b.pendingRequests()
	errMsg := accessErrors[r.URL.Query().Get("error")]
	if err != nil {
		errMsg = "Access requests cannot be read: " + err.Error()
	}
	b.render(w, http.StatusOK, "access", sid, map[string]any{
		"Services": services, "Rows": rows, "Notice": notice, "Requests": pending, "Error": errMsg,
	})
}

// cellForm is the cell editor's state, as shown and as posted.
type cellForm struct {
	Role, Service string
	On            bool
	Mode          string // read, full or custom
	Methods       []string
	Paths         string // one per line
	Daily         string
	Expires       string // YYYY-MM-DD, UTC
}

func (f cellForm) Has(method string) bool { return slices.Contains(f.Methods, method) }

func formFromAccess(role, service string, acc policy.Access, on bool) cellForm {
	// A service not granted yet opens ready for full access: switched on,
	// every method, every path, no limit. Saving is all it takes.
	f := cellForm{Role: role, Service: service, On: true, Mode: "full", Paths: "/"}
	if !on {
		return f
	}
	f.Paths = strings.Join(acc.Paths, "\n")
	if acc.DailyRequests > 0 {
		f.Daily = strconv.Itoa(acc.DailyRequests)
	}
	if acc.Expires != nil {
		f.Expires = acc.Expires.UTC().Format(time.DateOnly)
	}
	switch {
	case len(acc.Methods) == 0:
		f.Mode, f.Methods = "custom", []string{"GET", "HEAD", "POST"}
	case sameSet(acc.Methods, readMethods):
		f.Mode = "read"
	case sameSet(acc.Methods, fullMethods):
		f.Mode = "full"
	default:
		f.Mode, f.Methods = "custom", inOrder(acc.Methods)
	}
	return f
}

// access turns the posted form into an Access. The policy checks the rest
// (path shapes) when the whole access list is validated.
func (f cellForm) access(now time.Time) (policy.Access, error) {
	var acc policy.Access
	switch f.Mode {
	case "read":
		acc.Methods = slices.Clone(readMethods)
	case "full":
		acc.Methods = slices.Clone(fullMethods)
	case "custom":
		acc.Methods = inOrder(f.Methods)
		if len(acc.Methods) != len(f.Methods) || len(acc.Methods) == 0 {
			return acc, errors.New("Pick at least one method from the list.")
		}
	default:
		return acc, errors.New("Choose read only, full or custom methods.")
	}
	for _, line := range strings.Split(f.Paths, "\n") {
		if p := strings.TrimSpace(line); p != "" {
			acc.Paths = append(acc.Paths, p)
		}
	}
	if len(acc.Paths) == 0 {
		return acc, errors.New("Give at least one path; / allows every path.")
	}
	if d := strings.TrimSpace(f.Daily); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 0 {
			return acc, errors.New("The daily limit must be a whole number, 0 or more (0 or empty: no limit).")
		}
		acc.DailyRequests = n
	}
	if e := strings.TrimSpace(f.Expires); e != "" {
		t, err := time.Parse(time.DateOnly, e)
		if err != nil {
			return acc, errors.New("The end date must look like 2026-12-31.")
		}
		if !t.After(now) {
			return acc, errors.New("The end date must be after today (UTC).")
		}
		acc.Expires = &t
	}
	return acc, nil
}

func (b *Backend) cellPage(w http.ResponseWriter, r *http.Request, sid string) {
	role, service := r.PathValue("role"), r.PathValue("service")
	if service == "-" { // "Add a service" without JavaScript: ?service=NAME
		http.Redirect(w, r, "/access/"+url.PathEscape(role)+"/"+url.PathEscape(r.URL.Query().Get("service")), http.StatusSeeOther)
		return
	}
	cfg := b.Proxy.Config()
	rl, ok := cfg.Roles[role]
	if _, known := cfg.Services[service]; !ok || !known {
		b.notFound(w, sid)
		return
	}
	acc, on := rl.Access[service]
	b.renderCell(w, sid, http.StatusOK, formFromAccess(role, service, acc, on), "")
}

func (b *Backend) renderCell(w http.ResponseWriter, sid string, status int, f cellForm, msg string) {
	b.render(w, status, "cell", sid, map[string]any{"Form": f, "Error": msg, "AllMethods": fullMethods})
}

func (b *Backend) saveCell(w http.ResponseWriter, r *http.Request, sid string) {
	f := cellForm{
		Role: r.PathValue("role"), Service: r.PathValue("service"), On: r.PostFormValue("on") == "yes",
		Mode: r.PostFormValue("mode"), Methods: r.PostForm["method"], Paths: r.PostFormValue("paths"),
		Daily: r.PostFormValue("daily"), Expires: r.PostFormValue("expires"),
	}
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		b.renderCell(w, sid, http.StatusForbidden, f, "Enter your dashboard password to change access.")
		return
	}
	var acc policy.Access
	if f.On {
		var err error
		if acc, err = f.access(b.Now()); err != nil {
			b.renderCell(w, sid, http.StatusBadRequest, f, err.Error())
			return
		}
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	rl, ok := next.Roles[f.Role]
	if _, known := next.Services[f.Service]; !ok || !known {
		b.notFound(w, sid)
		return
	}
	if rl.Access == nil {
		rl.Access = map[string]policy.Access{}
	}
	if f.On {
		rl.Access[f.Service] = acc
	} else {
		delete(rl.Access, f.Service)
	}
	next.Roles[f.Role] = rl
	if err := (&policy.Config{Rules: b.rules(), AccessList: next}).Validate(); err != nil {
		b.renderCell(w, sid, http.StatusBadRequest, f, err.Error())
		return
	}
	if err := b.saveAndApply(next); err != nil {
		b.fail(w, sid, err)
		return
	}
	fields := map[string]any{"role": f.Role, "service": f.Service, "on": f.On}
	if f.On {
		fields["methods"], fields["paths"], fields["daily_requests"] = acc.Methods, acc.Paths, acc.DailyRequests
		if acc.Expires != nil {
			fields["expires"] = acc.Expires.Format(time.DateOnly)
		}
	}
	b.Admin.Audit("access_changed", sid, fields)
	http.Redirect(w, r, "/access?done=saved", http.StatusSeeOther)
}

// saveAndApply writes the access file and swaps it into the proxy. The keys
// are read first: once the file is written nothing can fail, so the file and
// the running config never disagree, and a token shown after a rotation is
// the one in force. Callers hold b.Mu.
func (b *Backend) saveAndApply(next policy.AccessList) error {
	keys, err := store.Load(b.StorePath)
	if err != nil {
		return err
	}
	cfg, err := policy.SaveAccess(b.rules(), next)
	if err != nil {
		return err
	}
	b.Proxy.Swap(cfg, keys)
	return nil
}

func (b *Backend) newAgentPage(w http.ResponseWriter, r *http.Request, sid string) {
	b.render(w, http.StatusOK, "newagent", sid, map[string]any{})
}

func (b *Backend) addAgent(w http.ResponseWriter, r *http.Request, sid string) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	// fingerprint: the SHA-256 of a token made on the calling machine
	// (keyring new-token). Then no token is shown here or ever leaves it.
	fingerprint := strings.ToLower(strings.TrimSpace(r.PostFormValue("fingerprint")))
	again := func(status int, msg string) {
		b.render(w, status, "newagent", sid, map[string]any{"Name": name, "Fingerprint": fingerprint, "Error": msg})
	}
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		again(http.StatusForbidden, "Enter your dashboard password to add an agent.")
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if _, taken := next.Roles[name]; taken {
		again(http.StatusConflict, "An agent with this name exists. Open it to make a new token.")
		return
	}
	token, sha := "", fingerprint
	if sha == "" {
		if token, sha, err = policy.NewToken(); err != nil {
			b.fail(w, sid, err)
			return
		}
	} else if !fingerprintShape.MatchString(sha) {
		again(http.StatusBadRequest, "The fingerprint must be the 64-character sha256 that keyring new-token prints.")
		return
	}
	next.Roles[name] = policy.Role{TokenSHA256: sha, Access: map[string]policy.Access{}}
	if !policy.ValidRoleName(name) {
		again(http.StatusBadRequest, "The name must be letters, digits, dot, dash or underscore, starting with a letter or digit.")
		return
	}
	for other, rl := range next.Roles {
		if other != name && rl.TokenSHA256 == sha {
			again(http.StatusConflict, "Agent "+other+" already uses this token. Make a new token with keyring new-token.")
			return
		}
	}
	if err := (&policy.Config{Rules: b.rules(), AccessList: next}).Validate(); err != nil {
		again(http.StatusBadRequest, err.Error())
		return
	}
	if err := b.saveAndApply(next); err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("agent_added", sid, map[string]any{"role": name, "own_token": token == ""})
	if token == "" {
		http.Redirect(w, r, "/agents/"+url.PathEscape(name)+"?done=added", http.StatusSeeOther)
		return
	}
	b.showToken(w, sid, name, token, false)
}

var fingerprintShape = regexp.MustCompile(`^[0-9a-f]{64}$`)

// showToken is the only response that ever contains the token.
func (b *Backend) showToken(w http.ResponseWriter, sid, role, token string, replaced bool) {
	b.render(w, http.StatusOK, "token", sid, map[string]any{
		"Role": role, "Token": token, "Replaced": replaced, "File": tokenDir + "/" + role + ".token",
	})
}

var agentErrors = map[string]string{
	"password": "Enter your dashboard password.",
	"confirm":  "Tick the box to revoke the agent.",
	"stale":    "The token was already replaced (was the page sent twice?). Nothing changed; make a new one if you need it.",
}

func (b *Backend) agentPage(w http.ResponseWriter, r *http.Request, sid string) {
	role := r.PathValue("role")
	cfg := b.Proxy.Config()
	rl, ok := cfg.Roles[role]
	if !ok {
		b.notFound(w, sid)
		return
	}
	type svcRow struct{ Service, Label string }
	var services []svcRow
	for _, s := range sortedNames(rl.Access) {
		services = append(services, svcRow{s, methodsLabel(rl.Access[s].Methods)})
	}
	var off []string
	for _, s := range sortedNames(cfg.Services) {
		if _, on := rl.Access[s]; !on {
			off = append(off, s)
		}
	}
	expires := ""
	if rl.Expires != nil {
		expires = rl.Expires.UTC().Format(time.DateOnly)
	}
	b.render(w, http.StatusOK, "agent", sid, map[string]any{
		"Role": role, "Services": services, "Off": off, "Expires": expires, "Ended": rl.Expired(b.Now()),
		"File": tokenDir + "/" + role + ".token", "Current": rl.TokenSHA256[:12],
		"Error": agentErrors[r.URL.Query().Get("error")], "Added": r.URL.Query().Get("done") == "added",
	})
}

func (b *Backend) newAgentToken(w http.ResponseWriter, r *http.Request, sid string) {
	role := r.PathValue("role")
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		http.Redirect(w, r, "/agents/"+role+"?error=password", http.StatusSeeOther)
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	rl, ok := next.Roles[role]
	if !ok {
		b.notFound(w, sid)
		return
	}
	// The form names the token it replaces, so a form sent twice (a reload
	// of the result page) cannot silently replace the token just shown.
	if cur := r.PostFormValue("current"); len(cur) != 12 || !strings.HasPrefix(rl.TokenSHA256, cur) {
		http.Redirect(w, r, "/agents/"+role+"?error=stale", http.StatusSeeOther)
		return
	}
	token, sha, err := policy.NewToken()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	rl.TokenSHA256 = sha
	next.Roles[role] = rl
	if err := b.saveAndApply(next); err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("token_replaced", sid, map[string]any{"role": role})
	b.showToken(w, sid, role, token, true)
}

func (b *Backend) revokeAgent(w http.ResponseWriter, r *http.Request, sid string) {
	role := r.PathValue("role")
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		http.Redirect(w, r, "/agents/"+role+"?error=password", http.StatusSeeOther)
		return
	}
	if r.PostFormValue("confirm") != "yes" {
		http.Redirect(w, r, "/agents/"+role+"?error=confirm", http.StatusSeeOther)
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if _, ok := next.Roles[role]; !ok {
		b.notFound(w, sid)
		return
	}
	delete(next.Roles, role)
	if err := b.saveAndApply(next); err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("agent_revoked", sid, map[string]any{"role": role})
	http.Redirect(w, r, "/access?done=revoked", http.StatusSeeOther)
}

func (b *Backend) notFound(w http.ResponseWriter, sid string) {
	b.render(w, http.StatusNotFound, "error", sid, map[string]any{"Error": "Not found."})
}
