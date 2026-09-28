package dashboard

import (
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
	req, ok, err := b.Requests.Take(id)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	if !ok {
		http.Redirect(w, r, "/access?error=gone", http.StatusSeeOther)
		return
	}
	fields := map[string]any{"request": req.ID, "role": req.Role, "services": req.Services, "from": req.From}
	if !approve {
		b.Admin.Audit("request_declined", sid, fields)
		http.Redirect(w, r, "/access?done=declined", http.StatusSeeOther)
		return
	}
	next, err := policy.LoadAccess(b.rules().AccessFile)
	if err == nil {
		// The access list may have changed since it was filed.
		err = requests.Check(req, next)
	}
	if err != nil {
		_ = b.Requests.Put(req)
		b.render(w, http.StatusConflict, "error", sid, map[string]any{"Error": "Cannot approve: " + err.Error()})
		return
	}
	role, exists := next.Roles[req.Role]
	if !exists {
		role = policy.Role{TokenSHA256: req.Fingerprint, Access: map[string]policy.Access{}}
	}
	if role.Access == nil {
		role.Access = map[string]policy.Access{}
	}
	for _, svc := range req.Services {
		role.Access[svc] = fullAccess()
	}
	next.Roles[req.Role] = role
	if err := b.saveAndApply(next); err != nil {
		_ = b.Requests.Put(req)
		b.fail(w, sid, err)
		return
	}
	fields["new_agent"] = !exists
	b.Admin.Audit("request_approved", sid, fields)
	http.Redirect(w, r, "/access?done=approved", http.StatusSeeOther)
}
