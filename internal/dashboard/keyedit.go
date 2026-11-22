package dashboard

import (
	"errors"
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

// Editing a key's values on its page (owner, 2026-11-22): add a value (names
// are optional: one added without a name gets the key's next number), label
// it, move it up the list (a key pool tries the values in list order),
// rename the key or a value, and remove a value. Every service that names a
// moved value is changed with it, so it keeps working; values never appear in
// a page, a message, the key notes or the audit log.

// keyEditErrors are the messages for the ?error= codes of these forms.
// {service} is replaced by the service named in ?service=.
var keyEditErrors = map[string]string{
	"name":          "The new name must be letters, digits and _, not starting with a digit.",
	"name-taken":    "A key with that name exists already. Pick another name.",
	"value-name":    "Name the value with lowercase letters, digits or _ (at most 32), or leave the name empty.",
	"value-taken":   "This key has a value with that name already. Pick another name.",
	"value-unknown": "This key has no value with that name.",
	"value-plain":   "This key has one value without a name. Add a second value to give both numbers.",
	"value-only":    "This is the key's only value. To remove it, use Delete below.",
	"value-used":    "{service} sends this value. Change or remove that service first, then remove the value.",
	"label":         fmt.Sprintf("A label is at most %d characters, on one line.", maxLabel),
	"too-many":      fmt.Sprintf("A key has at most %d values. Remove one first.", maxParts),
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
// returns the services it changed, sorted. A key pool names the key itself,
// so it follows a renamed key but not its plain value becoming KEY.1.
func renameRefs(access *policy.AccessList, moves map[string]string) []string {
	var changed []string
	for name, svc := range access.Services {
		if len(svc.KeyNames()) == 0 {
			continue // gcloud: no stored key
		}
		touched := false
		if to, ok := moves[svc.Key]; ok && !(svc.KeyPool && strings.Contains(to, ".")) {
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

// moveValues renames stored values (old name -> new name), adds new ones
// (name -> value), points every service reference at the new names and
// applies notes to the key notes, which hold each key's value order; it
// returns the services changed. The new access list is checked before
// anything is written. The key notes are written first, then the store in
// one write, then the access list; a failure undoes what was written before
// it, so no service is left naming a missing value and no pool loses its
// order. The proxy then gets the new settings, keys and order together.
// Callers hold b.Mu.
func (b *Backend) moveValues(moves, add map[string]string, notes func(meta map[string]KeyMeta)) ([]string, error) {
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
	before, err := b.loadMeta()
	if err != nil {
		return nil, err
	}
	meta := maps.Clone(before)
	notes(meta)
	if err := b.writeMeta(meta); err != nil {
		return nil, err
	}
	undo := func(err error) error {
		if metaErr := b.writeMeta(before); metaErr != nil {
			err = errors.Join(err, fmt.Errorf("putting the key notes back failed too: %w", metaErr))
		}
		return err
	}
	stored := map[string]string{}
	for from, to := range moves {
		if _, ok := keys[from]; ok {
			stored[from] = to
		}
	}
	if len(stored) > 0 || len(add) > 0 {
		if err := store.Move(b.StorePath, stored, add); err != nil {
			return nil, undo(err)
		}
	}
	cfg := b.Proxy.Config()
	if len(services) > 0 {
		saved, err := policy.SaveAccess(b.rules(), next)
		if err != nil {
			return nil, undo(errors.Join(err, b.undoMove(stored, add)))
		}
		cfg = saved
	}
	for from, to := range stored {
		keys[to] = keys[from]
		delete(keys, from)
	}
	maps.Copy(keys, add)
	b.Proxy.SwapWithOrder(cfg, keys, valueOrder(meta))
	return services, nil
}

// undoMove puts the store back as it was before store.Move(stored, add).
func (b *Backend) undoMove(stored, add map[string]string) error {
	if len(add) > 0 {
		if err := store.DeleteAll(b.StorePath, slices.Collect(maps.Keys(add))); err != nil {
			return fmt.Errorf("removing the added values failed too: %w", err)
		}
	}
	if len(stored) == 0 {
		return nil
	}
	back := make(map[string]string, len(stored))
	for from, to := range stored {
		back[to] = from
	}
	if err := store.Move(b.StorePath, back, nil); err != nil {
		return fmt.Errorf("putting the values back under their old names failed too: %w", err)
	}
	return nil
}

// moveNotes moves the dashboard's notes (status, dates, file kind, value
// list) in meta with renamed names.
func moveNotes(meta map[string]KeyMeta, moves map[string]string) {
	moved := map[string]KeyMeta{}
	for from, to := range moves {
		if m, ok := meta[from]; ok {
			delete(meta, from)
			moved[to] = m
		}
	}
	maps.Copy(meta, moved)
}

// setNotes sets the key's value list (and highest number) in meta.
func setNotes(meta map[string]KeyMeta, key string, notes []ValueNote, last int) {
	m := meta[key]
	m.Values = notes
	m.LastNumber = max(m.LastNumber, last)
	meta[key] = m
}

// saveNotes stores the key's value list (and highest number) in its notes.
func (b *Backend) saveNotes(key string, notes []ValueNote, last int) error {
	meta, err := b.loadMeta()
	if err != nil {
		return err
	}
	setNotes(meta, key, notes, last)
	return b.saveMeta(meta)
}

// editStart is the common start of these forms, called with b.Mu held: the
// password, then the key's row. ok is false when a response was written.
func (b *Backend) editStart(w http.ResponseWriter, r *http.Request, sid string) (row keyRow, back func(code string), ok bool) {
	name := r.PathValue("name")
	back = func(code string) { http.Redirect(w, r, "/keys/"+name+"?error="+code, http.StatusSeeOther) }
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		back("password")
		return row, back, false
	}
	row, found, err := b.row(name)
	if err != nil || !found {
		b.unknownKey(w, r, sid, err)
		return row, back, false
	}
	return row, back, true
}

// partIndex is the position of value part in the row's list, or -1.
func partIndex(row keyRow, part string) int {
	return slices.IndexFunc(row.Parts, func(p keyPart) bool { return p.Name == part })
}

// addValue adds one value to a key, last in its list. Without a name it gets
// the key's next number. A key's one plain value becomes a numbered value
// first (KEY becomes KEY.1, the new one KEY.2), and every service that sent
// KEY sends KEY.1, in the same step.
func (b *Backend) addValue(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	value, err := readValue(r)
	part := strings.ToLower(strings.TrimSpace(r.PostFormValue("part")))
	label, labelMsg := checkLabel(r.PostFormValue("label"))
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, back, ok := b.editStart(w, r, sid)
	if !ok {
		return
	}
	switch {
	case errors.Is(err, errValueControl):
		back("value-control")
		return
	case err != nil:
		back("value")
		return
	case part != "" && !store.ValidPart(part):
		back("value-name")
		return
	case labelMsg != "":
		back("label")
		return
	case partIndex(row, part) >= 0:
		back("value-taken")
		return
	case len(row.Parts) >= maxParts:
		back("too-many")
		return
	}
	meta, err := b.loadMeta()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	last := meta[name].LastNumber
	taken := map[string]bool{part: part != ""}
	for _, p := range row.Parts {
		taken[p.Name] = true
		noteNumber(&last, p.Name)
	}
	noteNumber(&last, part)
	moves := map[string]string{}
	var notes []ValueNote
	target := ""
	switch {
	case len(row.Parts) > 0:
		notes = row.notes()
	case row.baseStored:
		// The plain value becomes the first numbered value.
		first := nextNumber(&last, taken)
		moves[name] = name + "." + first
		notes = []ValueNote{{Name: first, Label: row.Label}}
	case part == "":
		// A key with no value yet: its first one is a plain value, as on Add.
		target = name
	}
	if target == "" {
		if part == "" {
			part = nextNumber(&last, taken)
		}
		target = name + "." + part
	}
	notes = append(notes, ValueNote{Name: part, Label: label})
	services, err := b.moveValues(moves, map[string]string{target: value}, func(meta map[string]KeyMeta) { setNotes(meta, name, notes, last) })
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("key_value_added", sid, map[string]any{"key": target, "moved": moves, "services": services})
	http.Redirect(w, r, "/keys/"+name+"?done=value-added", http.StatusSeeOther)
}

// labelValue sets or clears the label of one value of a key.
func (b *Backend) labelValue(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	part := strings.TrimSpace(r.PostFormValue("part"))
	label, msg := checkLabel(r.PostFormValue("label"))
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, back, ok := b.editStart(w, r, sid)
	if !ok {
		return
	}
	if msg != "" {
		back("label")
		return
	}
	notes := row.notes()
	i := slices.IndexFunc(notes, func(n ValueNote) bool { return n.Name == part })
	if i < 0 {
		back("value-unknown")
		return
	}
	notes[i].Label = label
	if err := b.saveNotes(name, notes, 0); err != nil {
		b.fail(w, sid, err)
		return
	}
	full := name
	if part != "" {
		full += "." + part
	}
	b.Admin.Audit("key_value_labelled", sid, map[string]any{"key": full})
	http.Redirect(w, r, "/keys/"+name+"?done=value-labelled", http.StatusSeeOther)
}

// moveValueUp moves one value of a key a place up its list: a key pool
// tries it before the value it passes.
func (b *Backend) moveValueUp(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	part := strings.TrimSpace(r.PostFormValue("part"))
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, back, ok := b.editStart(w, r, sid)
	if !ok {
		return
	}
	i := partIndex(row, part)
	switch {
	case len(row.Parts) == 0:
		back("value-plain")
		return
	case i < 0:
		back("value-unknown")
		return
	}
	if i > 0 {
		notes := row.notes()
		notes[i-1], notes[i] = notes[i], notes[i-1]
		if err := b.saveNotes(name, notes, 0); err != nil {
			b.fail(w, sid, err)
			return
		}
		b.Admin.Audit("key_value_moved", sid, map[string]any{"key": name + "." + part, "position": i})
	}
	http.Redirect(w, r, "/keys/"+name+"?done=value-moved", http.StatusSeeOther)
}

// renameKey gives a key a new name: all its values move (MODAL.id becomes
// NEW.id) and every service that uses them follows.
func (b *Backend) renameKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	newName := strings.TrimSpace(r.PostFormValue("new_name"))
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, back, ok := b.editStart(w, r, sid)
	if !ok {
		return
	}
	if base, part := store.SplitPart(newName); part != "" || !store.ValidName(base) {
		back("name")
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
	services, err := b.moveValues(moves, nil, func(meta map[string]KeyMeta) { moveNotes(meta, moves) })
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("key_renamed", sid, map[string]any{"key": name, "new_name": newName, "services": services})
	http.Redirect(w, r, "/keys/"+newName+"?done=renamed", http.StatusSeeOther)
}

// renameValue renames one value of a key (KEY.a to KEY.b); it keeps its
// place in the list and services that use it follow.
func (b *Backend) renameValue(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	part := strings.TrimSpace(r.PostFormValue("part"))
	newPart := strings.ToLower(strings.TrimSpace(r.PostFormValue("new_part")))
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, back, ok := b.editStart(w, r, sid)
	if !ok {
		return
	}
	i := partIndex(row, part)
	switch {
	case len(row.Parts) == 0:
		back("value-plain")
		return
	case i < 0:
		back("value-unknown")
		return
	case !store.ValidPart(newPart):
		back("value-name")
		return
	case partIndex(row, newPart) >= 0:
		back("value-taken")
		return
	}
	from := name + "." + part
	moves := map[string]string{from: name + "." + newPart}
	notes := row.notes()
	notes[i].Name = newPart
	last := 0
	noteNumber(&last, newPart)
	services, err := b.moveValues(moves, nil, func(meta map[string]KeyMeta) {
		moveNotes(meta, moves)
		setNotes(meta, name, notes, last)
	})
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	b.Admin.Audit("key_value_renamed", sid, map[string]any{"key": from, "new_name": moves[from], "services": services})
	http.Redirect(w, r, "/keys/"+name+"?done=value-renamed", http.StatusSeeOther)
}

// removeValue deletes one value of a key with several. A value a service
// names is kept: its key, an extra header or an OAuth client secret. A key
// pool names the key, so a pooled value just leaves the pool. The key's last
// value goes with Delete.
func (b *Backend) removeValue(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	part := strings.TrimSpace(r.PostFormValue("part"))
	b.Mu.Lock()
	defer b.Mu.Unlock()
	row, back, ok := b.editStart(w, r, sid)
	if !ok {
		return
	}
	if len(row.Parts) == 0 {
		back("value-only")
		return
	}
	i := partIndex(row, part)
	if i < 0 || !row.Parts[i].HasValue {
		back("value-unknown")
		return
	}
	stored := 0
	for _, p := range row.Parts {
		if p.HasValue {
			stored++
		}
	}
	if stored+btoi(row.baseStored) <= 1 {
		back("value-only")
		return
	}
	full := name + "." + part
	cfg := b.Proxy.Config()
	for _, sname := range sortedNames(cfg.Services) {
		if slices.Contains(cfg.Services[sname].KeyNames(), full) {
			http.Redirect(w, r, "/keys/"+name+"?"+url.Values{"error": {"value-used"}, "service": {sname}}.Encode(), http.StatusSeeOther)
			return
		}
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
		delete(meta, full)
		m := meta[name]
		m.Values = slices.DeleteFunc(row.notes(), func(n ValueNote) bool { return n.Name == part })
		meta[name] = m
		_ = b.saveMeta(meta)
	}
	b.Admin.Audit("key_value_removed", sid, map[string]any{"key": full})
	http.Redirect(w, r, "/keys/"+name+"?done=value-removed", http.StatusSeeOther)
}

func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}
