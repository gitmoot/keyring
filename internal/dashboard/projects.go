package dashboard

import (
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// Projects (gitmoot/keyring#111, step 2): a page per project to see what it
// holds, pause it, set its end date, mark its keys client-owned, list them for
// handover, and take an agent's access to all of it away in one step.

func registerProjects(b *Backend) {
	b.Admin.Handle("GET /projects", b.projectsPage)
	b.Admin.Handle("GET /projects/{name}", b.projectPage)
	b.Admin.Handle("POST /projects/{name}", b.saveProject)
	b.Admin.Handle("POST /projects/{name}/revoke", b.revokeProject)
	b.Admin.Handle("POST /projects/{name}/grant", b.grantProject)
}

// projectNames lists every project: those services name and those with
// settings (a project whose last service was removed can still be cleared).
func projectNames(cfg *policy.Config) []string {
	seen := map[string]bool{}
	for _, svc := range cfg.Services {
		if svc.Project != "" {
			seen[svc.Project] = true
		}
	}
	for name := range cfg.Projects {
		seen[name] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// projectServices lists the services in project, sorted.
func projectServices(cfg *policy.Config, project string) []string {
	var names []string
	for name, svc := range cfg.Services {
		if svc.Project == project {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// projectState is "paused", "expired" or "running".
func projectState(cfg *policy.Config, project string, now time.Time) string {
	if why := cfg.ProjectStopped(policy.Service{Project: project}, now); why != "" {
		return why
	}
	return "running"
}

type projectSummary struct {
	Name, State string
	Services    int
	ClientOwned bool
	Expires     string
}

func (b *Backend) projectsPage(w http.ResponseWriter, r *http.Request, sid string) {
	cfg := b.Proxy.Config()
	now := b.Now()
	var list []projectSummary
	for _, name := range projectNames(cfg) {
		p := cfg.Projects[name]
		s := projectSummary{Name: name, State: projectState(cfg, name, now), Services: len(projectServices(cfg, name)), ClientOwned: p.ClientOwned}
		if p.Expires != nil {
			s.Expires = p.Expires.UTC().Format("2 Jan 2006")
		}
		list = append(list, s)
	}
	b.render(w, http.StatusOK, "projects", sid, map[string]any{"Projects": list})
}

type projectService struct {
	Name, Key, Provider, LastUsed string
	CallsToday                    int
}

type projectAgent struct {
	Role     string
	Services []string
	// Whole: the agent has a grant for the whole project, services added
	// later included.
	Whole bool
}

type handoverKey struct {
	Name, Created, Replaced string
	HasValue                bool
}

func (b *Backend) projectPage(w http.ResponseWriter, r *http.Request, sid string) {
	b.renderProject(w, r, sid, http.StatusOK, r.PathValue("name"), "")
}

func (b *Backend) renderProject(w http.ResponseWriter, r *http.Request, sid string, status int, name, msg string) {
	cfg := b.Proxy.Config()
	if !slices.Contains(projectNames(cfg), name) {
		b.notFound(w, sid)
		return
	}
	now := b.Now()
	services := projectServices(cfg, name)
	in := map[string]bool{}
	keyNames := map[string]bool{}
	var rows []projectService
	usage := b.Proxy.Usage()
	for _, sname := range services {
		in[sname] = true
		svc := cfg.Services[sname]
		for _, k := range svc.KeyNames() {
			keyNames[k] = true
		}
		row := projectService{Name: sname, Key: svc.Key, Provider: providerOf(svc)}
		var last time.Time
		for _, u := range usage {
			if u.Service == sname {
				row.CallsToday += u.Calls
				if u.LastUsed.After(last) {
					last = u.LastUsed
				}
			}
		}
		if !last.IsZero() {
			row.LastUsed = ago(now, last)
		}
		rows = append(rows, row)
	}
	var agents []projectAgent
	for _, role := range sortedNames(cfg.Roles) {
		a := projectAgent{Role: role}
		for _, sname := range services {
			if _, ok := cfg.AccessFor(cfg.Roles[role], sname); ok {
				a.Services = append(a.Services, sname)
			}
		}
		_, a.Whole = cfg.Roles[role].Projects[name]
		if len(a.Services) > 0 || a.Whole {
			agents = append(agents, a)
		}
	}
	meta, _ := b.loadMeta()
	stored, _ := b.storedNames()
	var handover []handoverKey
	for _, k := range sortedKeys(keyNames) {
		h := handoverKey{Name: k, Created: "unknown", Replaced: "unknown", HasValue: stored[k]}
		if at := meta[k].CreatedAt; at != nil {
			h.Created = at.UTC().Format("2 Jan 2006")
		}
		if at := meta[k].UpdatedAt; at != nil {
			h.Replaced = at.UTC().Format("2 Jan 2006")
		}
		handover = append(handover, h)
	}
	p := cfg.Projects[name]
	expires := ""
	if p.Expires != nil {
		expires = p.Expires.UTC().Format("2006-01-02")
	}
	b.render(w, status, "project", sid, map[string]any{
		"Name": name, "State": projectState(cfg, name, now), "P": p, "ExpiresDate": expires,
		"Roles": sortedNames(cfg.Roles), "AllMethods": fullMethods,
		"Services": rows, "Agents": agents, "Handover": handover,
		"Notice": r.URL.Query().Get("done"), "ProjectError": msg,
	})
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// saveProject sets the project's pause, end date and client ownership.
func (b *Backend) saveProject(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		b.renderProject(w, r, sid, http.StatusForbidden, name, "Enter your dashboard password to change the project.")
		return
	}
	next := policy.Project{Paused: r.PostFormValue("paused") == "yes", ClientOwned: r.PostFormValue("client_owned") == "yes"}
	if date := strings.TrimSpace(r.PostFormValue("expires")); date != "" {
		at, err := time.Parse("2006-01-02", date)
		if err != nil {
			b.renderProject(w, r, sid, http.StatusBadRequest, name, "The end date must be a date like 2027-03-31.")
			return
		}
		// The project stops at the start of that day, UTC.
		next.Expires = &at
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	access, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if !slices.Contains(projectNames(&policy.Config{AccessList: access}), name) {
		b.notFound(w, sid)
		return
	}
	cur := access.Projects[name]
	changed := []string{}
	if cur.Paused != next.Paused {
		changed = append(changed, "paused")
	}
	if (cur.Expires == nil) != (next.Expires == nil) || cur.Expires != nil && !cur.Expires.Equal(*next.Expires) {
		changed = append(changed, "expires")
	}
	if cur.ClientOwned != next.ClientOwned {
		changed = append(changed, "client_owned")
	}
	if access.Projects == nil {
		access.Projects = map[string]policy.Project{}
	}
	if next == (policy.Project{}) {
		// No settings left: the project is simply running.
		delete(access.Projects, name)
	} else {
		access.Projects[name] = next
	}
	if err := b.saveAndApply(access); err != nil {
		b.renderProject(w, r, sid, http.StatusBadRequest, name, err.Error())
		return
	}
	fields := map[string]any{"project": name, "changed": changed, "paused": next.Paused, "client_owned": next.ClientOwned}
	if next.Expires != nil {
		fields["expires"] = next.Expires.UTC().Format(time.RFC3339)
	}
	b.Admin.Audit("project_changed", sid, fields)
	http.Redirect(w, r, "/projects/"+name+"?done=saved", http.StatusSeeOther)
}

// revokeProject removes one agent's access to every service in the project.
// Its access elsewhere, and the services and keys, stay as they are.
func (b *Backend) revokeProject(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	role := r.PostFormValue("role")
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		b.renderProject(w, r, sid, http.StatusForbidden, name, "Enter your dashboard password to remove access.")
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	access, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	cfg := &policy.Config{AccessList: access}
	if !slices.Contains(projectNames(cfg), name) {
		b.notFound(w, sid)
		return
	}
	rl, ok := access.Roles[role]
	if !ok {
		b.renderProject(w, r, sid, http.StatusBadRequest, name, "There is no agent named "+role+".")
		return
	}
	var removed []string
	for _, sname := range projectServices(cfg, name) {
		if _, granted := rl.Access[sname]; granted {
			delete(rl.Access, sname)
			removed = append(removed, sname)
		}
	}
	_, whole := rl.Projects[name]
	if whole {
		delete(rl.Projects, name)
		if len(rl.Projects) == 0 {
			rl.Projects = nil
		}
	}
	if len(removed) == 0 && !whole {
		b.renderProject(w, r, sid, http.StatusBadRequest, name, role+" has no access to this project.")
		return
	}
	access.Roles[role] = rl
	if err := b.saveAndApply(access); err != nil {
		b.fail(w, sid, err)
		return
	}
	for _, sname := range removed {
		b.Admin.Audit("access_revoked", sid, map[string]any{"project": name, "service": sname, "role": role})
	}
	if whole {
		b.Admin.Audit("project_access_revoked", sid, map[string]any{"project": name, "role": role})
	}
	http.Redirect(w, r, "/projects/"+name+"?done=revoked", http.StatusSeeOther)
}

// storedNames reports which key names have a value in the store.
func (b *Backend) storedNames() (map[string]bool, error) {
	names, err := store.Names(b.StorePath)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out, nil
}

// grantProject gives one agent access to every service in the project in one
// step, with the same limits. With "later" it is a single grant for the whole
// project, which also covers services added to it later; without, it writes
// an ordinary grant for each service the project has now.
func (b *Backend) grantProject(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	role := r.PostFormValue("role")
	later := r.PostFormValue("later") == "yes"
	f := cellForm{Role: role, On: true, Mode: r.PostFormValue("mode"), Methods: r.PostForm["method"],
		Paths: r.PostFormValue("paths"), Daily: r.PostFormValue("daily"), Expires: r.PostFormValue("expires")}
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		b.renderProject(w, r, sid, http.StatusForbidden, name, "Enter your dashboard password to give access.")
		return
	}
	acc, err := f.access(b.Now())
	if err != nil {
		b.renderProject(w, r, sid, http.StatusBadRequest, name, err.Error())
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	access, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	cfg := &policy.Config{Rules: b.rules(), AccessList: access}
	if !slices.Contains(projectNames(cfg), name) {
		b.notFound(w, sid)
		return
	}
	rl, ok := access.Roles[role]
	if !ok {
		b.renderProject(w, r, sid, http.StatusBadRequest, name, "There is no agent named "+role+". Add it under Agents first.")
		return
	}
	services := projectServices(cfg, name)
	if !later && len(services) == 0 {
		b.renderProject(w, r, sid, http.StatusBadRequest, name, "This project has no services yet. Tick \"services added later\" to give access to the whole project.")
		return
	}
	if later {
		if rl.Projects == nil {
			rl.Projects = map[string]policy.Access{}
		}
		rl.Projects[name] = acc
	} else {
		if rl.Access == nil {
			rl.Access = map[string]policy.Access{}
		}
		for _, sname := range services {
			rl.Access[sname] = acc
		}
	}
	access.Roles[role] = rl
	if err := cfg.Validate(); err != nil {
		b.renderProject(w, r, sid, http.StatusBadRequest, name, err.Error())
		return
	}
	if err := b.saveAndApply(access); err != nil {
		b.fail(w, sid, err)
		return
	}
	fields := map[string]any{"project": name, "role": role, "methods": acc.Methods, "paths": acc.Paths, "daily_requests": acc.DailyRequests}
	if acc.Expires != nil {
		fields["expires"] = acc.Expires.Format(time.DateOnly)
	}
	if later {
		b.Admin.Audit("project_access_granted", sid, fields)
	} else {
		for _, sname := range services {
			f := maps.Clone(fields)
			f["service"] = sname
			b.Admin.Audit("access_changed", sid, f)
		}
	}
	http.Redirect(w, r, "/projects/"+name+"?done=granted", http.StatusSeeOther)
}
