package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/gitmoot/keyring/internal/googlelogin"
	"github.com/gitmoot/keyring/internal/policy"
)

func (in *Instance) saveGoogle(ctx context.Context, expected string, next *googlelogin.Snapshot) error {
	version, err := in.change(func(s *State) error {
		// Cancellation is checked inside the transaction: an initial login
		// cannot publish after a concurrent disconnect committed nil.
		if err := ctx.Err(); err != nil {
			return err
		}
		current := ""
		if s.Google != nil {
			current = s.Google.Generation
		}
		if !(expected == "*" && next == nil) && expected != current {
			return &httpError{http.StatusConflict, "Google connection changed"}
		}
		if next != nil && (!in.opt.Container || s.Services["drive"].Auth != policy.AuthGcloudLogin) {
			return badRequest("Google consent service is not configured")
		}
		s.Google = next
		return nil
	})
	if err == nil {
		in.writeAudit("google_state_changed", map[string]any{"version": version, "connected": next != nil && next.Ready})
	}
	return err
}

func (in *Instance) disconnectGoogle(w http.ResponseWriter, r *http.Request) {
	if err := in.google.Disconnect(r.Context()); err != nil {
		writeError(w, &httpError{http.StatusBadGateway, err.Error()})
		return
	}
	in.mu.Lock()
	version := in.state.Version
	in.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"version": version})
}

// provisionGoogle is an atomic extension of an existing router role, never a
// replacement of its token or of unrelated grants. Reserved conflicts fail closed.
func (in *Instance) provisionGoogle(w http.ResponseWriter, r *http.Request) {
	if !in.opt.Container {
		writeError(w, &httpError{http.StatusNotFound, "container Google provisioning is unavailable"})
		return
	}
	var request *struct{}
	if err := decode(r, &request); err != nil || request == nil {
		writeError(w, badRequest("Google provisioning requires an empty JSON object"))
		return
	}
	services := map[string]policy.Service{
		"drive":            {Auth: policy.AuthGcloudLogin, GoogleAccount: "me"},
		"google-me-drive":  {Auth: policy.AuthGcloud, GoogleAccount: "me", Base: "https://www.googleapis.com/drive/v3"},
		"google-me-upload": {Auth: policy.AuthGcloud, GoogleAccount: "me", Base: "https://www.googleapis.com/upload/drive/v3"},
		"google-me-sheets": {Auth: policy.AuthGcloud, GoogleAccount: "me", Base: "https://sheets.googleapis.com/v4"},
	}
	access := map[string]policy.Access{
		"google-me-drive":  {Methods: []string{"GET", "POST"}, Paths: []string{"/about", "/files", "/changes", "/drives"}},
		"google-me-upload": {Methods: []string{"POST", "PATCH"}, Paths: []string{"/files"}},
		"google-me-sheets": {Methods: []string{"GET", "POST"}, Paths: []string{"/spreadsheets"}},
	}
	same := func(a, b any) bool {
		left, _ := json.Marshal(a)
		right, _ := json.Marshal(b)
		return bytes.Equal(left, right)
	}
	version, err := in.change(func(s *State) error {
		role, exists := s.Roles["router"]
		if !exists {
			return &httpError{http.StatusConflict, "router role must exist before Google provisioning"}
		}
		for name, desired := range services {
			if current, exists := s.Services[name]; exists && !same(current, desired) {
				return &httpError{http.StatusConflict, "reserved Google service conflicts with existing configuration"}
			}
		}
		for name, desired := range access {
			if current, exists := role.Access[name]; exists && !same(current, desired) {
				return &httpError{http.StatusConflict, "reserved Google access conflicts with existing configuration"}
			}
		}
		if _, exists := role.Access["drive"]; exists {
			return &httpError{http.StatusConflict, "Google consent service must not have proxy access"}
		}
		for name, desired := range services {
			s.Services[name] = desired
		}
		if role.Access == nil {
			role.Access = make(map[string]policy.Access, len(access))
		}
		for name, desired := range access {
			role.Access[name] = desired
		}
		s.Roles["router"] = role
		return nil
	})
	in.changed(w, "google_provisioned", nil, version, err, nil)
}
