package dashboard

import (
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/gitmoot/keyring/internal/policy"
)

// Editing a service in place (gitmoot/keyring#107). Deleting a service to fix
// a wrong base URL or key also deletes every agent's grant on it; an edit
// changes only the service's own settings, so the roles stay as they are.

func registerServices(b *Backend) {
	b.Admin.Handle("GET /services/{name}", b.servicePage)
	b.Admin.Handle("POST /services/{name}", b.saveService)
}

// editableService reports whether the dashboard form can change the service
// without losing settings it does not show. Static and OAuth services can;
// sign-only, Google and egress-proxy services carry their own fields and stay
// in access.json.
func editableService(svc policy.Service) bool {
	switch svc.Auth {
	case policy.AuthBearer, policy.AuthHeader, policy.AuthQuery:
		if svc.OAuth2 != nil {
			return false
		}
	case policy.AuthOAuth2:
	default:
		return false
	}
	return svc.EgressProxy == nil && svc.GoogleAccount == "" &&
		svc.AppleAds == nil && svc.AppStoreConnect == nil && svc.Minisign == nil
}

// serviceForm is the edit page's fields. Extra holds what the form shows but
// does not change: fixed headers (changed by pasting JSON) and the names of
// the extra credential headers (never their values).
type serviceForm struct {
	Name, Key, Base, Auth, Header, Param, TestPath, TLSPin, Project, Pasted string
	FixedHeaders                                                            map[string]string
	ExtraHeaders                                                            []string
	// OAuth client settings of an oauth2 service (#142): the secret is a key
	// name, never a value.
	ClientID, TokenURL, ClientSecretKey string
}

func formOf(name string, svc policy.Service) serviceForm {
	f := serviceForm{Name: name, Key: svc.Key, Base: svc.Base, Auth: svc.Auth, Header: svc.Header, Param: svc.Param,
		TestPath: svc.TestPath, TLSPin: svc.TLSPinSHA256, Project: svc.Project, FixedHeaders: svc.FixedHeaders}
	if o := svc.OAuth2; o != nil {
		f.ClientID, f.TokenURL, f.ClientSecretKey = o.ClientID, o.TokenURL, o.ClientSecretKey
	}
	for header, key := range svc.ExtraHeaders {
		f.ExtraHeaders = append(f.ExtraHeaders, header+" ← "+key)
	}
	slices.Sort(f.ExtraHeaders)
	return f
}

// keyChoices are the key names the service may use: those the keys page lists.
func (b *Backend) keyChoices() ([]string, error) {
	rows, err := b.rows()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, row.valueNames()...)
	}
	return names, nil
}

func (b *Backend) servicePage(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	svc, ok := b.Proxy.Config().Services[name]
	if !ok {
		b.notFound(w, sid)
		return
	}
	b.renderService(w, sid, http.StatusOK, formOf(name, svc), r.URL.Query().Get("done"), "")
}

func (b *Backend) renderService(w http.ResponseWriter, sid string, status int, f serviceForm, notice, msg string) {
	cfg := b.Proxy.Config()
	svc := cfg.Services[f.Name]
	keys, err := b.keyChoices()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	var agents []string
	for role, rl := range cfg.Roles {
		if _, granted := cfg.AccessFor(rl, f.Name); granted {
			agents = append(agents, role)
		}
	}
	slices.Sort(agents)
	// OAuth settings are shown so the owner can compare them with Google's
	// console (an "invalid_client" means the ID or secret does not match).
	// The secret is named, never shown.
	secretStored := false
	if svc.OAuth2 != nil && svc.OAuth2.ClientSecretKey != "" {
		stored, err := b.storedNames()
		if err != nil {
			b.fail(w, sid, err)
			return
		}
		secretStored = stored[svc.OAuth2.ClientSecretKey]
	}
	method := svc.TestMethod
	if method == "" {
		method = http.MethodGet
	}
	b.render(w, status, "service", sid, map[string]any{
		"OAuth2": svc.OAuth2, "SecretStored": secretStored,
		"Name": f.Name, "F": f, "Editable": editableService(svc), "Kind": svc.Auth,
		"Keys": keys, "Agents": agents, "Notice": notice, "EditError": msg, "TestMethod": method, "ProjectStopped": cfg.ProjectStopped(svc, b.Now()),
	})
}

func (b *Backend) saveService(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	f := serviceForm{
		Name: name, Key: strings.TrimSpace(r.PostFormValue("key")), Base: strings.TrimSpace(r.PostFormValue("base")),
		Auth: r.PostFormValue("auth"), Header: strings.TrimSpace(r.PostFormValue("header")), Param: strings.TrimSpace(r.PostFormValue("param")),
		TestPath: strings.TrimSpace(r.PostFormValue("test_path")), TLSPin: strings.TrimSpace(r.PostFormValue("tls_pin_sha256")),
		Project:  strings.TrimSpace(r.PostFormValue("project")),
		Pasted:   strings.TrimSpace(r.PostFormValue("pasted")),
		ClientID: strings.TrimSpace(r.PostFormValue("client_id")), TokenURL: strings.TrimSpace(r.PostFormValue("token_url")),
		ClientSecretKey: strings.TrimSpace(r.PostFormValue("client_secret_key")),
	}
	again := func(status int, msg string) {
		// Refused pasted settings are not shown again: they may hold a value
		// pasted by mistake (as Connect already does).
		f.Pasted = ""
		if svc, ok := b.Proxy.Config().Services[name]; ok {
			f.FixedHeaders, f.ExtraHeaders = svc.FixedHeaders, formOf(name, svc).ExtraHeaders
		}
		b.renderService(w, sid, status, f, "", msg)
	}
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		again(http.StatusForbidden, "Enter your dashboard password to save the changes.")
		return
	}
	pasted := f.Pasted != ""
	var fixed map[string]string
	var extra *map[string]string // nil: keep the stored extra headers
	var oauth *policy.OAuth2     // pasted: replaces the OAuth settings
	if pasted {
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
		if a.Service != "" && a.Service != name {
			again(http.StatusBadRequest, "The pasted settings name another service. A service cannot be renamed here; leave \"service\" out or use "+name+".")
			return
		}
		f.Base, f.Auth, f.Header, f.Param, f.TestPath, f.TLSPin, f.Project = a.Base, a.Auth, a.Header, a.Param, a.TestPath, a.TLSPin, a.Project
		fixed, extra, oauth = a.FixedHeaders, a.ExtraHeaders, a.OAuth2
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	cur, exists := next.Services[name]
	if !exists {
		b.notFound(w, sid)
		return
	}
	if !editableService(cur) {
		again(http.StatusConflict, "This kind of service is not edited here; change it in access.json.")
		return
	}
	if f.Key == "" {
		f.Key = cur.Key
	}
	// The kind of an OAuth service does not change here: it would lose its
	// OAuth settings. A static service does not become OAuth either.
	if (cur.Auth == policy.AuthOAuth2) != (f.Auth == policy.AuthOAuth2) {
		again(http.StatusBadRequest, "An OAuth service stays OAuth, and a static one stays static. Connect a new service for the other kind.")
		return
	}
	if f.Key != cur.Key {
		if ok, err := b.knownValue(f.Key); err != nil {
			b.fail(w, sid, err)
			return
		} else if !ok {
			again(http.StatusBadRequest, "There is no key named "+f.Key+". Add it under Keys first.")
			return
		}
	}
	// Start from what is stored: only the fields this form owns change, so
	// the settings it does not show (extra credential headers) survive.
	updated := cur
	updated.Base, updated.Key, updated.Auth, updated.Header, updated.Param = f.Base, f.Key, f.Auth, f.Header, f.Param
	updated.TestPath, updated.TLSPinSHA256, updated.Project = f.TestPath, f.TLSPin, f.Project
	if pasted {
		updated.FixedHeaders = fixed
	}
	if cur.Auth == policy.AuthOAuth2 {
		next := *cur.OAuth2
		switch {
		case oauth != nil:
			next = *oauth
		case !pasted:
			next.ClientID, next.TokenURL, next.ClientSecretKey = f.ClientID, f.TokenURL, f.ClientSecretKey
		}
		if msg := clientIDProblem(&next); msg != "" {
			again(http.StatusBadRequest, msg)
			return
		}
		if next.ClientSecretKey != "" {
			stored, err := b.storedNames()
			if err != nil {
				b.fail(w, sid, err)
				return
			}
			if msg := storedKeyRef(stored, "client secret", next.ClientSecretKey); msg != "" {
				again(http.StatusBadRequest, msg)
				return
			}
		}
		updated.OAuth2 = &next
	} else if oauth != nil {
		again(http.StatusBadRequest, "oauth2 settings belong to an OAuth service; connect a new service for that.")
		return
	}
	if extra != nil {
		if msg, err := b.extraHeaderKeys(*extra); err != nil {
			b.fail(w, sid, err)
			return
		} else if msg != "" {
			again(http.StatusBadRequest, msg)
			return
		}
		updated.ExtraHeaders = nil
		if len(*extra) > 0 {
			updated.ExtraHeaders = *extra
		}
	}
	changed := changedFields(cur, updated)
	// Moving a service between projects changes which whole-project grants
	// reach it: name the agents that gain or lose access that way (#111).
	var gained, lost []string
	if cur.Project != updated.Project {
		for _, role := range sortedNames(next.Roles) {
			rl := next.Roles[role]
			if _, own := rl.Access[name]; own {
				continue
			}
			_, before := rl.Projects[cur.Project]
			_, after := rl.Projects[updated.Project]
			before, after = before && cur.Project != "", after && updated.Project != ""
			switch {
			case after && !before:
				gained = append(gained, role)
			case before && !after:
				lost = append(lost, role)
			}
		}
	}
	next.Services[name] = updated
	if err := (&policy.Config{Rules: b.rules(), AccessList: next}).Validate(); err != nil {
		again(http.StatusBadRequest, err.Error())
		return
	}
	if err := b.saveAndApply(next); err != nil {
		b.fail(w, sid, err)
		return
	}
	fields := map[string]any{"service": name, "key": updated.Key, "changed": changed}
	if len(gained) > 0 {
		fields["access_gained_by"] = gained
	}
	if len(lost) > 0 {
		fields["access_lost_by"] = lost
	}
	b.Admin.Audit("service_edited", sid, fields)
	http.Redirect(w, r, "/services/"+name+"?done=saved", http.StatusSeeOther)
}

// changedFields names the settings an edit changed, never their values.
func changedFields(old, now policy.Service) []string {
	changed := []string{}
	for _, c := range []struct {
		name string
		diff bool
	}{
		{"base", old.Base != now.Base}, {"key", old.Key != now.Key}, {"auth", old.Auth != now.Auth},
		{"header", old.Header != now.Header}, {"param", old.Param != now.Param}, {"test_path", old.TestPath != now.TestPath},
		{"tls_pin_sha256", old.TLSPinSHA256 != now.TLSPinSHA256}, {"project", old.Project != now.Project}, {"fixed_headers", !maps.Equal(old.FixedHeaders, now.FixedHeaders)},
		{"extra_headers", !maps.Equal(old.ExtraHeaders, now.ExtraHeaders)},
		{"oauth2", !old.OAuth2.Equal(now.OAuth2)},
	} {
		if c.diff {
			changed = append(changed, c.name)
		}
	}
	return changed
}
