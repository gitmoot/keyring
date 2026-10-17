package consent

import (
	"context"
	"net/http"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/workspace"
)

func (s *Server) SetWorkspace(boundary workspace.Boundary) { s.workspace = boundary }

// AccountLink is called behind the instance admin authentication boundary.
func (s *Server) AccountLink(w http.ResponseWriter, r *http.Request) {
	if s.workspace == nil || !workspace.ValidID(r.PathValue("account")) {
		workspace.WriteError(w, workspace.Failure(404, "account_not_found"))
		return
	}
	if s.config().Consent == nil {
		workspace.WriteError(w, workspace.Failure(409, "workspace_not_configured"))
		return
	}
	s.createLink(w, r)
}

// boundService revalidates the slot, generation and captured OAuth client at
// each browser transition. Neither a browser parameter nor a new default can
// retarget a link that was minted for a different connection.
func (s *Server) boundService(name, key string, binding *workspace.ConsentBinding) (policy.Service, bool) {
	if binding == nil {
		svc, ok := s.config().Services[name]
		return svc, ok && svc.Key == key
	}
	if s.workspace == nil {
		return policy.Service{}, false
	}
	current, err := s.workspace.PrepareConsent(binding.ID, binding.Generation, name)
	if err != nil || current == nil || !current.Service.OAuth2.Equal(binding.Service.OAuth2) {
		return policy.Service{}, false
	}
	return current.Service, true
}

func (s *Server) DisconnectAccount(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("account")
	if s.workspace == nil || !workspace.ValidID(id) {
		workspace.WriteError(w, workspace.Failure(404, "account_not_found"))
		return
	}
	s.disconnectWorkspace(w, r, id, r.Header.Get(workspace.GenerationHeader), false)
}

// A nil selection means that the legacy default has not been migrated yet.
func (s *Server) disconnectWorkspace(w http.ResponseWriter, r *http.Request, id, generation string, legacy bool) bool {
	s.mu.Lock()
	view, selected, err := s.workspace.Detach(r.Context(), id, generation)
	if err != nil {
		s.mu.Unlock()
		workspace.WriteError(w, err)
		return true
	}
	if selected == nil {
		s.mu.Unlock()
		return false
	}
	for hash, l := range s.links {
		if l.key == selected.Service.Key {
			delete(s.links, hash)
		}
	}
	for hash, f := range s.signIns {
		if f.key == selected.Service.Key {
			delete(s.signIns, hash)
		}
	}
	s.mu.Unlock()
	defer selected.Release()
	revoked := false
	var revokeErr error
	attempted := selected.Refresh != "" && selected.Service.OAuth2.RevokeURL != ""
	if attempted {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		revokeErr = s.revoke(ctx, *selected.Service.OAuth2, selected.Refresh, selected.Secret)
		revoked = revokeErr == nil
		cancel()
	}
	s.writeAudit("workspace_disconnected", map[string]any{"account_id": view.ID, "revoked": revoked})
	if legacy {
		result := map[string]any{"deleted": selected.Refresh != "", "key": selected.Service.Key}
		if attempted {
			result["revoked"] = revoked
			if revokeErr != nil {
				result["revoke_error"] = revokeErr.Error()
			}
		}
		writeJSON(w, 200, result)
		return true
	}
	writeJSON(w, 200, map[string]any{"account": view, "provider_revoked": revoked})
	return true
}
