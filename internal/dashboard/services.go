package dashboard

import (
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// Editing a service in place (gitmoot/keyring#107). Deleting a service to fix
// a wrong base URL or key also deletes every agent's grant on it; an edit
// changes only the service's own settings, so the roles stay as they are.

func registerServices(b *Backend) {
	b.Admin.Handle("GET /services/{name}", b.servicePage)
	b.Admin.Handle("POST /services/{name}", b.saveService)
}

// editableService reports whether the dashboard form can change the service
// without losing settings it does not show. Static, OAuth and Bitcoin signing
// services (#201) can; the other sign-only, Google and egress-proxy services
// carry their own fields and stay in access.json.
func editableService(svc policy.Service) bool {
	switch svc.Auth {
	case policy.AuthBearer, policy.AuthHeader, policy.AuthQuery:
		if svc.OAuth2 != nil {
			return false
		}
	case policy.AuthOAuth2:
	case policy.AuthBitcoinPSBTSign:
		if svc.Bitcoin == nil {
			return false
		}
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
	Name, Key, Base, Auth, Scheme, Header, Param, TestPath, TLSPin, Project, Pasted string
	FixedHeaders                                                                    map[string]string
	ExtraHeaders                                                                    []string
	// OAuth client settings of an oauth2 service (#142): the secret is a key
	// name, never a value.
	ClientID, TokenURL, ClientSecretKey string
	// ForwardRole: the form's checkbox, or forward_role in pasted settings.
	ForwardRole bool
	// KeyPool is shown; set by pasted settings. KeyBase is the key without
	// its value name, for the link to the key's page.
	KeyPool bool
	KeyBase string
	// Bitcoin: a bitcoin-psbt-sign service's network, paths or script and
	// sighash, from the form or pasted.
	Bitcoin *policy.Bitcoin
}

func formOf(name string, svc policy.Service) serviceForm {
	f := serviceForm{Name: name, Key: svc.Key, Base: svc.Base, Auth: svc.Auth, Scheme: svc.Scheme, Header: svc.Header, Param: svc.Param,
		TestPath: svc.TestPath, TLSPin: svc.TLSPinSHA256, Project: svc.Project, FixedHeaders: svc.FixedHeaders, ForwardRole: svc.ForwardRole, KeyPool: svc.KeyPool, Bitcoin: svc.Bitcoin}
	f.KeyBase, _ = store.SplitPart(svc.Key)
	if o := svc.OAuth2; o != nil {
		f.ClientID, f.TokenURL, f.ClientSecretKey = o.ClientID, o.TokenURL, o.ClientSecretKey
	}
	for header, key := range svc.ExtraHeaders {
		f.ExtraHeaders = append(f.ExtraHeaders, header+" ← "+key)
	}
	slices.Sort(f.ExtraHeaders)
	return f
}

// keyChoices are the key names a service may use, in the keys page's order:
// pools, the keys a key pool may name (CLAUDE_KEYS), and values, the names
// any other service may send (API_KEY, MODAL.id). menu is both, for the
// edit form, so a paste that turns key_pool on or off can pick its key too.
func (b *Backend) keyChoices() (pools, values, menu []string, err error) {
	rows, err := b.rows()
	if err != nil {
		return nil, nil, nil, err
	}
	for _, row := range rows {
		names := row.valueNames()
		pools = append(pools, row.Name)
		values = append(values, names...)
		if !slices.Contains(names, row.Name) {
			menu = append(menu, row.Name)
		}
		menu = append(menu, names...)
	}
	return pools, values, menu, nil
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
	_, _, keys, err := b.keyChoices()
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
	sentAs := "" // from the stored service, never a refused edit
	if svc.Auth == policy.AuthBearer {
		sentAs = svc.AuthorizationScheme()
	}
	data := map[string]any{
		"OAuth2": svc.OAuth2, "SecretStored": secretStored, "SentAs": sentAs,
		"Name": f.Name, "F": f, "Editable": editableService(svc), "Kind": svc.Auth,
		"Keys": keys, "Agents": agents, "Notice": notice, "EditError": msg, "TestMethod": method, "ProjectStopped": cfg.ProjectStopped(svc, b.Now()),
	}
	if svc.Auth == policy.AuthBitcoinPSBTSign {
		maps.Copy(data, b.bitcoinPage(f.Name, svc))
		shown := f.Bitcoin
		if shown == nil {
			shown = svc.Bitcoin
		}
		// The stored service tells a WIF key (script) from an extended one.
		data["BitcoinForm"] = bitcoinFormOf(shown, svc.Bitcoin != nil && svc.Bitcoin.Script != "")
	}
	b.render(w, status, "service", sid, data)
}

func (b *Backend) saveService(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	f := serviceForm{
		Name: name, Key: strings.TrimSpace(r.PostFormValue("key")), Base: strings.TrimSpace(r.PostFormValue("base")),
		Auth: r.PostFormValue("auth"), Scheme: strings.TrimSpace(r.PostFormValue("scheme")), Header: strings.TrimSpace(r.PostFormValue("header")), Param: strings.TrimSpace(r.PostFormValue("param")),
		TestPath: strings.TrimSpace(r.PostFormValue("test_path")), TLSPin: strings.TrimSpace(r.PostFormValue("tls_pin_sha256")),
		Project:  strings.TrimSpace(r.PostFormValue("project")),
		Pasted:   strings.TrimSpace(r.PostFormValue("pasted")),
		ClientID: strings.TrimSpace(r.PostFormValue("client_id")), TokenURL: strings.TrimSpace(r.PostFormValue("token_url")),
		ClientSecretKey: strings.TrimSpace(r.PostFormValue("client_secret_key")),
		ForwardRole:     r.PostFormValue("forward_role") == "yes",
	}
	formProblem := ""
	if f.Auth == policy.AuthBitcoinPSBTSign {
		f.Bitcoin, formProblem = bitcoinFromForm(r)
	}
	again := func(status int, msg string) {
		svc, ok := b.Proxy.Config().Services[name]
		switch {
		case ok && f.Pasted != "":
			// A refused paste is one unit: none of it fills the form, which
			// shows the stored settings again, so sending the form does not
			// save part of the paste.
			f = formOf(name, svc)
		case ok:
			f.FixedHeaders, f.ExtraHeaders = svc.FixedHeaders, formOf(name, svc).ExtraHeaders
		}
		// Refused pasted settings are not shown again: they may hold a value
		// pasted by mistake (as Connect already does).
		f.Pasted = ""
		b.renderService(w, sid, status, f, "", msg)
	}
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		again(http.StatusForbidden, "Enter your dashboard password to save the changes.")
		return
	}
	pasted := f.Pasted != ""
	var fixed map[string]string
	var forwardRole bool
	var keyPool *bool            // nil: keep the stored key_pool
	var extra *map[string]string // nil: keep the stored extra headers
	var oauth *policy.OAuth2     // pasted: replaces the OAuth settings
	pastedKey, pastedMethod := "", ""
	if pasted {
		a, msg := decodeSettings(f.Pasted)
		if msg != "" {
			again(http.StatusBadRequest, msg)
			return
		}
		if a.Service != "" && a.Service != name {
			again(http.StatusBadRequest, "The pasted settings name another service. A service cannot be renamed here; leave \"service\" out or use "+name+".")
			return
		}
		f.Base, f.Auth, f.Scheme, f.Header, f.Param, f.TestPath, f.TLSPin, f.Project = a.Base, a.Auth, a.Scheme, a.Header, a.Param, a.TestPath, a.TLSPin, a.Project
		fixed, extra, oauth, forwardRole, keyPool = a.FixedHeaders, a.ExtraHeaders, a.OAuth2, a.ForwardRole, a.KeyPool
		f.Bitcoin, pastedKey, pastedMethod = a.Bitcoin, a.Key, a.TestMethod
	} else if formProblem != "" {
		again(http.StatusBadRequest, formProblem)
		return
	} else if f.Auth != policy.AuthBearer {
		f.Scheme = "" // the form's scheme box belongs to the bearer choice
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
	// A Bitcoin signing service stays one: the other kinds forward calls
	// with the key, and this key is never sent anywhere.
	if (cur.Auth == policy.AuthBitcoinPSBTSign) != (f.Auth == policy.AuthBitcoinPSBTSign) {
		again(http.StatusBadRequest, "A Bitcoin signing service stays one, and another service does not become one. Connect a new service for the other kind.")
		return
	}
	pool := cur.KeyPool
	if keyPool != nil {
		pool = *keyPool
	}
	if pool {
		// A pool names the key itself; one of its values offered by the
		// menu stands for its key.
		f.Key, _ = store.SplitPart(f.Key)
	}
	// A pasted "key" (as access.json names it) must be the key chosen
	// above; it is not repeated, as it may be a value pasted by mistake.
	if pastedKey != "" && pastedKey != f.Key {
		again(http.StatusBadRequest, "The pasted settings name another key in \"key\" than "+f.Key+". Pick the key under Key, or leave \"key\" out.")
		return
	}
	if msg := testMethodKept(pastedMethod, cur.TestMethod); msg != "" {
		again(http.StatusBadRequest, msg)
		return
	}
	if f.Key != cur.Key || pool != cur.KeyPool {
		pools, values, _, err := b.keyChoices()
		if err != nil {
			b.fail(w, sid, err)
			return
		}
		switch {
		case pool && !slices.Contains(pools, f.Key), !pool && !slices.Contains(pools, f.Key) && !slices.Contains(values, f.Key):
			again(http.StatusBadRequest, "There is no key named "+f.Key+". Add it under Keys first.")
			return
		case !pool && !slices.Contains(values, f.Key):
			again(http.StatusBadRequest, f.Key+" has several values, and a service that is not a key pool sends one of them: pick it under Key (for example "+f.Key+".1), or keep key_pool on.")
			return
		}
	}
	// Start from what is stored: only the fields this form owns change, so
	// the settings it does not show (extra credential headers) survive.
	updated := cur
	updated.Base, updated.Key, updated.Auth, updated.Scheme, updated.Header, updated.Param = f.Base, f.Key, f.Auth, f.Scheme, f.Header, f.Param
	updated.TestPath, updated.TLSPinSHA256, updated.Project = f.TestPath, f.TLSPin, f.Project
	updated.ForwardRole = f.ForwardRole
	if pasted {
		updated.FixedHeaders, updated.ForwardRole = fixed, forwardRole
		if keyPool != nil {
			updated.KeyPool = *keyPool
		}
	}
	if pasted || cur.Auth == policy.AuthBitcoinPSBTSign {
		// Pasted settings without "bitcoin" remove it, so validation
		// refuses a Bitcoin service left without its settings.
		updated.Bitcoin = f.Bitcoin
	}
	if cur.Auth == policy.AuthOAuth2 {
		next := *cur.OAuth2
		switch {
		case oauth != nil:
			next = *oauth
		case !pasted:
			next.ClientID, next.TokenURL, next.ClientSecretKey = f.ClientID, f.TokenURL, f.ClientSecretKey
		}
		if next.ClientID == cur.OAuth2.ClientID && next.TokenURL == cur.OAuth2.TokenURL {
			// Unchanged: an edit of another field is not refused for it.
		} else if msg := clientIDProblem(&next); msg != "" {
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
	msg := ""
	if updated.Auth == policy.AuthBitcoinPSBTSign {
		msg, err = b.saveBitcoinChecked(next, name)
	} else {
		err = b.saveAndApply(next)
	}
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if msg != "" {
		again(http.StatusBadRequest, msg)
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
		{"base", old.Base != now.Base}, {"key", old.Key != now.Key}, {"auth", old.Auth != now.Auth}, {"scheme", old.Scheme != now.Scheme},
		{"header", old.Header != now.Header}, {"param", old.Param != now.Param}, {"test_path", old.TestPath != now.TestPath},
		{"tls_pin_sha256", old.TLSPinSHA256 != now.TLSPinSHA256}, {"project", old.Project != now.Project}, {"fixed_headers", !maps.Equal(old.FixedHeaders, now.FixedHeaders)}, {"key_pool", old.KeyPool != now.KeyPool}, {"forward_role", old.ForwardRole != now.ForwardRole},
		{"extra_headers", !maps.Equal(old.ExtraHeaders, now.ExtraHeaders)},
		{"oauth2", !old.OAuth2.Equal(now.OAuth2)},
	} {
		if c.diff {
			changed = append(changed, c.name)
		}
	}
	return append(changed, bitcoinChanges(old.Bitcoin, now.Bitcoin)...)
}
