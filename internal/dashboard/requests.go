package dashboard

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/requests"
)

// Access requests: agents file them at the keyring (server.RequestsPath);
// the owner approves or declines each here. Approving gives the agent full
// access to the services it named, creating it (with its own token's
// fingerprint) when it is new.

// fullAccess is what "give this agent this API" means: every method, every
// path, no daily limit.
func fullAccess() policy.Access {
	return policy.Access{Methods: slices.Clone(fullMethods), Paths: []string{"/"}}
}

// pendingRequests is shown on the Agents page; nil when requests are off. A
// requests file that cannot be read is reported, not shown as empty.
func (b *Backend) pendingRequests() ([]requests.Request, error) {
	if b.Requests == nil {
		return nil, nil
	}
	return b.Requests.Pending()
}

var requestNotices = map[string]string{
	"approved": "Approved. The agent can call those APIs now.",
	"declined": "Request declined.",
}

func (b *Backend) answerRequest(w http.ResponseWriter, r *http.Request, sid string) {
	id := r.PathValue("id")
	if b.Requests == nil {
		http.NotFound(w, r)
		return
	}
	approve := r.PostFormValue("answer") == "approve"
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		http.Redirect(w, r, "/access?error=password", http.StatusSeeOther)
		return
	}
	b.Mu.Lock()
	defer b.Mu.Unlock()
	// The request stays pending until it is answered: a refused approval
	// (a mistyped mainnet confirmation, a changed access list) leaves it
	// where it was, and only a decline or a saved approval takes it.
	pending, err := b.Requests.Pending()
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	i := slices.IndexFunc(pending, func(p requests.Request) bool { return p.ID == id })
	if i < 0 {
		http.Redirect(w, r, "/access?error=gone", http.StatusSeeOther)
		return
	}
	req := pending[i]
	take := func() bool {
		_, ok, err := b.Requests.Take(id)
		if err != nil {
			b.fail(w, sid, err)
			return false
		}
		if !ok {
			http.Redirect(w, r, "/access?error=gone", http.StatusSeeOther)
		}
		return ok
	}
	fields := map[string]any{"request": req.ID, "role": req.Role, "from": req.From}
	if len(req.Services) > 0 {
		fields["services"] = req.Services
	}
	if len(req.Projects) > 0 {
		fields["projects"] = req.Projects
	}
	if !approve {
		if !take() {
			return
		}
		b.Admin.Audit("request_declined", sid, fields)
		http.Redirect(w, r, "/access?done=declined", http.StatusSeeOther)
		return
	}
	refuse := func(msg string) {
		b.render(w, http.StatusConflict, "error", sid, map[string]any{"Error": "Cannot approve: " + msg})
	}
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err == nil {
		// The access list may have changed since it was filed.
		err = requests.Check(req, next)
	}
	if err != nil {
		refuse(err.Error())
		return
	}
	role, exists := next.Roles[req.Role]
	if !exists {
		role = policy.Role{TokenSHA256: req.Fingerprint, Access: map[string]policy.Access{}}
	}
	if role.Access == nil {
		role.Access = map[string]policy.Access{}
	}
	// A mainnet Bitcoin service gets the sats limits posted for it, which
	// its typed name and daily limit confirm (owner, 2026-11-26).
	limits := map[string][2]int64{}
	for _, svc := range req.Services {
		acc := fullAccess()
		if next.Services[svc].BitcoinMainnet() {
			var msg string
			if acc, msg = mainnetGrantFromForm(r, svc); msg != "" {
				refuse(msg)
				return
			}
			limits[svc] = [2]int64{acc.BitcoinMaxSatsPerTx, acc.BitcoinMaxSatsPerDay}
		}
		role.Access[svc] = acc
	}
	for _, p := range req.Projects {
		if role.Projects == nil {
			role.Projects = map[string]policy.Access{}
		}
		role.Projects[p] = fullAccess()
	}
	next.Roles[req.Role] = role
	if err := (&policy.Config{Rules: b.rules(), AccessList: next}).Validate(); err != nil {
		refuse(err.Error())
		return
	}
	// Saved first, so a failed save leaves the request pending as it was.
	if err := b.saveAndApply(next); err != nil {
		b.fail(w, sid, err)
		return
	}
	if len(limits) > 0 {
		fields["bitcoin_limits"] = limits
	}
	fields["new_agent"] = !exists
	b.Admin.Audit("request_approved", sid, fields)
	if _, _, err := b.Requests.Take(id); err != nil {
		b.fail(w, sid, fmt.Errorf("the access was granted, but the request could not be removed from the queue: %w", err))
		return
	}
	http.Redirect(w, r, "/access?done=approved", http.StatusSeeOther)
}
