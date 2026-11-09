package dashboard

import (
	"encoding/base64"
	"net/http"

	"github.com/gitmoot/keyring/internal/store"
)

// Showing a key's value to the owner (owner request, 9 Nov). Only on request,
// one key at a time, after the dashboard password, as the answer to a POST: the
// value is never in a URL, a GET page, a log or the audit (which names the key
// only), and every dashboard response is Cache-Control: no-store.

// revealedValue is one value on the reveal page.
type revealedValue struct {
	ID, Label, Value string
	// Exact is the value in base64: Copy uses it, because a text box
	// normalizes line endings and drops a leading newline.
	Exact     string
	Multiline bool
}

func (b *Backend) revealKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := r.PathValue("name")
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		http.Redirect(w, r, "/keys/"+name+"?error=password", http.StatusSeeOther)
		return
	}
	row, ok, err := b.row(name)
	if err != nil || !ok {
		b.unknownKey(w, r, sid, err)
		return
	}
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	var values []revealedValue
	var shown []string
	for i, full := range row.valueNames() {
		v, stored := keys[full]
		if !stored {
			continue
		}
		label := "Value"
		if _, part := store.SplitPart(full); part != "" {
			label = part
		}
		values = append(values, revealedValue{ID: "value-" + string(rune('a'+i)), Label: label, Value: v, Exact: base64.StdEncoding.EncodeToString([]byte(v)),
			Multiline: len(v) > 120 || containsNewline(v)})
		shown = append(shown, full)
	}
	if len(values) == 0 {
		http.Redirect(w, r, "/keys/"+name+"?error=no-value", http.StatusSeeOther)
		return
	}
	b.Admin.Audit("key_revealed", sid, map[string]any{"key": name, "values": shown})
	b.render(w, http.StatusOK, "reveal", sid, map[string]any{"Name": name, "Values": values})
}

func containsNewline(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return true
		}
	}
	return false
}
