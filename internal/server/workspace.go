package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/workspace"
)

// SetWorkspace installs the sealed account boundary before serving requests.
func (h *Handler) SetWorkspace(boundary workspace.Boundary) { h.workspace = boundary }

// workspaceRequest recognizes only the dedicated namespace. Account selection
// on an ordinary service path is never inferred from a header or account count.
func workspaceRequest(r *http.Request) (*http.Request, string, error) {
	tail, qualified := strings.CutPrefix(r.URL.Path, "/_accounts/")
	if !qualified {
		return r, "", nil
	}
	id, path, ok := strings.Cut(tail, "/")
	service, _, hasPath := strings.Cut(path, "/")
	if !ok || !hasPath || !workspace.ValidID(id) || !workspace.Service(service) {
		return nil, "", workspace.Failure(404, "account_not_found")
	}
	prefix := "/_accounts/" + id
	if !strings.HasPrefix(r.URL.EscapedPath(), prefix+"/") {
		return nil, "", workspace.Failure(400, "invalid_account_path")
	}
	request := *r
	url := *r.URL
	url.Path = "/" + path
	if url.RawPath != "" {
		url.RawPath = strings.TrimPrefix(url.RawPath, prefix)
	}
	request.URL = &url
	return &request, id, nil
}

// WorkspaceIdentity shares the production refresh cache. The caller owns the
// binding lease and must compare its generation again before publishing email.
func (h *Handler) WorkspaceIdentity(ctx context.Context, selected workspace.Selection) (string, error) {
	token, err := h.accessToken(ctx, selected.Service, selected.Refresh, selected.Secret)
	if err != nil {
		if errors.Is(err, errOAuthRejected) {
			return "", workspace.Failure(409, "account_reconnect_required")
		}
		return "", workspace.Failure(502, "account_identity_unavailable")
	}
	return workspace.VerifiedEmail(ctx, h.client, token)
}

// WorkspaceRejected reads cached status without refreshing a provider token.
func (h *Handler) WorkspaceRejected(svc policy.Service, refresh, secret string) bool {
	if svc.OAuth2 == nil {
		return false
	}
	key := oauthKey(*svc.OAuth2, refresh, secret)
	h.oauth.mu.Lock()
	defer h.oauth.mu.Unlock()
	entry := h.oauth.entries[key]
	return entry != nil && errors.Is(entry.err, errOAuthRejected)
}
