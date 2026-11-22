package dashboard

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// Renaming a key or one of its values, and removing one value of a key with
// several (owner, 2026-11-22). Every service that names a moved value is
// changed with it, so it keeps working; values never appear in a page, a
// message or the audit log.

// keyEditErrors are the messages for the ?error= codes of these forms.
// {service} is replaced by the service named in ?service=.
var keyEditErrors = map[string]string{
	"name":             "The new name must be letters, digits and _, not starting with a digit.",
	"name-taken":       "A key with that name exists already. Pick another name.",
	"value-name":       "Name the value with lowercase letters, digits or _ (at most 32), e.g. main.",
	"value-taken":      "This key has a value with that name already. Pick another name.",
	"value-unknown":    "This key has no stored value with that name.",
	"value-plain":      "This key has one value without a name. To remove it, use Delete below.",
	"value-only":       "This is the key's only value. To remove it, use Delete below.",
	"value-used":       "{service} sends this value. Change or remove that service first, then remove the value.",
	"value-pool-first": "{service} is a key pool that tries this value first. Pick another value as its key on the service's page, then remove this one.",
	"too-many":         fmt.Sprintf("A key has at most %d values. Remove one first.", maxParts),
}

// keyEditError is the message for an error code of these forms, or "".
func (b *Backend) keyEditError(q url.Values) string {
	msg := keyEditErrors[q.Get("error")]
	if !strings.Contains(msg, "{service}") {
		return msg
	}
	svc := "A service"
	if name := q.Get("service"); name != "" {
		if _, ok := b.Proxy.Config().Services[name]; ok {
			svc = "Service " + name
		}
	}
	return strings.ReplaceAll(msg, "{service}", svc)
}

// connectRedirect sends a browser that opened the connect form's address
// (a GET of /keys/{name}/connect) to the key's page, where the form is.
func (b *Backend) connectRedirect(w http.ResponseWriter, r *http.Request, _ string) {
	http.Redirect(w, r, "/keys/"+url.PathEscape(r.PathValue("name")), http.StatusSeeOther)
}

// renameRefs points every key reference of the services in access (key,
// extra_headers, oauth2.client_secret_key) that moves to its new name, and
// returns the services it changed, sorted.
func renameRefs(access *policy.AccessList, moves map[string]string) []string {
	var changed []string
	for name, svc := range access.Services {
		if len(svc.KeyNames()) == 0 {
			continue // gcloud: no stored key
		}
		touched := false
		if to, ok := moves[svc.Key]; ok {
			svc.Key, touched = to, true
		}
		if len(svc.ExtraHeaders) > 0 {
			extra := maps.Clone(svc.ExtraHeaders)
			for header, ref := range extra {
				if to, ok := moves[ref]; ok {
					extra[header], touched = to, true
				}
			}
			svc.ExtraHeaders = extra
		}
		if svc.OAuth2 != nil {
			if to, ok := moves[svc.OAuth2.ClientSecretKey]; ok && svc.OAuth2.ClientSecretKey != "" {
				o := *svc.OAuth2
				o.ClientSecretKey, touched = to, true
				svc.OAuth2 = &o
			}
		}
		if touched {
			access.Services[name] = svc
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	return changed
}

// moveValues renames stored values (old name -> new name) and every service
// reference to them, and returns the services changed. The new access list is
// checked before anything is written; if saving it fails after the store
// changed, the store change is undone, so no service is left naming a missing
// value. Callers hold b.Mu.
func (b *Backend) moveValues(moves map[string]string) ([]string, error) {
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err != nil {
		return nil, err
	}
	services := renameRefs(&next, moves)
	if len(services) > 0 {
		if err := (&policy.Config{Rules: b.rules(), AccessList: next}).Validate(); err != nil {
			return nil, err
		}
	}
	keys, err := store.Load(b.StorePath)
	if err != nil {
		return nil, err
	}
	stored := map[string]string{}
	for from, to := range moves {
		if _, ok := keys[from]; ok {
			stored[from] = to
		}
	}
	if len(stored) > 0 {
		if err := store.Rename(b.StorePath, stored); err != nil {
			return nil, err
		}
	}
	cfg := b.Proxy.Config()
	if len(services) > 0 {
		saved, err := policy.SaveAccess(b.rules(), next)
		if err != nil {
			if len(stored) > 0 {
				back := make(map[string]string, len(stored))
				for from, to := range stored {
					back[to] = from
				}
				if undo := store.Rename(b.StorePath, back); undo != nil {
					return nil, fmt.Errorf("%w; putting the values back under their old names failed too: %v", err, undo)
				}
			}
			return nil, err
		}
		cfg = saved
	}
	for from, to := range stored {
		keys[to] = keys[from]
		delete(keys, from)
	}
	b.Proxy.Swap(cfg, keys)
	return services, nil
}

// moveMeta moves the dashboard's notes (status, dates, file kind) with
// renamed names. A failure here leaves the rename done; only notes are lost.
func (b *Backend) moveMeta(moves map[string]string) {
	meta, err := b.loadMeta()
	if err != nil {
		return
	}
	changed := false
	for from, to := range moves {
		if m, ok := meta[from]; ok {
			delete(meta, from)
			meta[to] = m
			changed = true
		}
	}
	if changed {
		_ = b.saveMeta(meta)
	}
}

// renameKey gives a key a new name: all its values move (MODAL.id becomes
// NEW.id) and every service that uses them follows.
func (b *Backend) renameKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	newName := strings.TrimSpace(r.PostFormValue("new_name"))
	back := func(code string) { http.Redirect(w, r, "/keys/"+name+"?error="+code, http.StatusSeeOther) }
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		back("password")
		return
	}
	if base, part := store.SplitPart(newName); part != "" || !store.ValidName(base) {
		back("name")
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, ok, err := b.row(name)
	if err != nil || !ok {
		b.unknownKey(w, r, sid, err)
		return
	}
	if _, taken, err := b.row(newName); err != nil {
		b.fail(w, sid, err)
		return
	} else if taken {
		back("name-taken")
		return
	}
	moves := map[string]string{name: newName}
	for _, p := range row.Parts {
		moves[p.Full] = newName + "." + p.Name
	}
	services, err := b.moveValues(moves)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	b.moveMeta(moves)
	b.Admin.Audit("key_renamed", sid, map[string]any{"key": name, "new_name": newName, "services": services})
	http.Redirect(w, r, "/keys/"+newName+"?done=renamed", http.StatusSeeOther)
}

// renameValue renames one value of a key with several (KEY.a to KEY.b), or
// gives the one value of a plain key a name (KEY to KEY.main), so more
// values can be added. Services that use the value follow.
func (b *Backend) renameValue(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	part := strings.TrimSpace(r.PostFormValue("part"))
	newPart := strings.ToLower(strings.TrimSpace(r.PostFormValue("new_part")))
	back := func(code string) { http.Redirect(w, r, "/keys/"+name+"?error="+code, http.StatusSeeOther) }
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		back("password")
		return
	}
	if !store.ValidPart(newPart) {
		back("value-name")
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, ok, err := b.row(name)
	if err != nil || !ok {
		b.unknownKey(w, r, sid, err)
		return
	}
	hasPart := func(p string) bool {
		return slices.ContainsFunc(row.Parts, func(k keyPart) bool { return k.Name == p })
	}
	from := name
	switch {
	case part == "" && len(row.Parts) > 0:
		back("part")
		return
	case part != "" && !hasPart(part):
		back("value-unknown")
		return
	case part != "":
		from = name + "." + part
	}
	if hasPart(newPart) {
		back("value-taken")
		return
	}
	moves := map[string]string{from: name + "." + newPart}
	services, err := b.moveValues(moves)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	done := "value-named"
	if part != "" {
		// The key's own notes stay under its name; a value's move with it.
		b.moveMeta(moves)
		done = "value-renamed"
	}
	b.Admin.Audit("key_value_renamed", sid, map[string]any{"key": from, "new_name": moves[from], "services": services})
	http.Redirect(w, r, "/keys/"+name+"?done="+done, http.StatusSeeOther)
}

// removeValue deletes one value of a key with several. A value a service
// sends is kept: its key or an extra header, or the value a key pool tries
// first. Any other pooled value just leaves the pool.
func (b *Backend) removeValue(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	part := strings.TrimSpace(r.PostFormValue("part"))
	back := func(code string) { http.Redirect(w, r, "/keys/"+name+"?error="+code, http.StatusSeeOther) }
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		back("password")
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, ok, err := b.row(name)
	if err != nil || !ok {
		b.unknownKey(w, r, sid, err)
		return
	}
	if len(row.Parts) == 0 {
		back("value-plain")
		return
	}
	full := name + "." + part
	stored := 0
	found := false
	for _, p := range row.Parts {
		if p.HasValue {
			stored++
			found = found || p.Name == part
		}
	}
	if !found {
		back("value-unknown")
		return
	}
	if stored == 1 {
		back("value-only")
		return
	}
	cfg := b.Proxy.Config()
	for _, sname := range sortedNames(cfg.Services) {
		svc := cfg.Services[sname]
		if !slices.Contains(svc.KeyNames(), full) {
			continue
		}
		code := "value-used"
		if svc.KeyPool && svc.Key == full {
			code = "value-pool-first"
		}
		http.Redirect(w, r, "/keys/"+name+"?"+url.Values{"error": {code}, "service": {sname}}.Encode(), http.StatusSeeOther)
		return
	}
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if err := store.Delete(b.StorePath, full); err != nil {
		b.fail(w, sid, err)
		return
	}
	delete(keys, full)
	b.Proxy.Swap(cfg, keys)
	if meta, err := b.loadMeta(); err == nil {
		if _, ok := meta[full]; ok {
			delete(meta, full)
			_ = b.saveMeta(meta)
		}
	}
	b.Admin.Audit("key_value_removed", sid, map[string]any{"key": full})
	http.Redirect(w, r, "/keys/"+name+"?done=value-removed", http.StatusSeeOther)
}
