package instance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"time"

	"github.com/gitmoot/keyring/internal/googlelogin"
	"github.com/gitmoot/keyring/internal/policy"
)

var renewalProcessStarted = time.Now().UTC()

// googleRenewal only observes memory. In particular it must not unlock an
// instance, inspect SDK files, mint a token, or persist a diagnostic read.
func (in *Instance) googleRenewal(w http.ResponseWriter, _ *http.Request) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if !in.opt.Container {
		writeError(w, &httpError{http.StatusNotFound, "container Google diagnostics are unavailable"})
		return
	}
	if in.state == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "reason": "locked"})
		return
	}
	record, ok := in.proxy.GoogleRenewal("me")
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false, "reason": "no_attempt", "process_started_at": renewalProcessStarted,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available": true, "process_started_at": renewalProcessStarted, "attempt": record,
	})
}

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

// provisionGoogle is an atomic extension of an existing router role, never a
// replacement of its token or of unrelated grants. Reserved conflicts fail closed.
// With a project (any value, even "" or null) it only chooses that project
// for the retained sign-in and provisions nothing, so a refused choice (400,
// 409) changes nothing. Only an omitted project provisions.
func (in *Instance) provisionGoogle(w http.ResponseWriter, r *http.Request) {
	if !in.opt.Container {
		writeError(w, &httpError{http.StatusNotFound, "container Google provisioning is unavailable"})
		return
	}
	var request *struct {
		// Project names an existing project of the signed-in account for
		// Drive setup instead of creating one (Google's project limit).
		// Raw, so that an explicit "" or null is told apart from omission.
		Project json.RawMessage `json:"project,omitempty"`
	}
	if err := decode(r, &request); err != nil || request == nil {
		writeError(w, badRequest(`Google provisioning requires a JSON object: {} or {"project": "<existing project ID>"}`))
		return
	}
	if request.Project != nil {
		var project string
		if err := json.Unmarshal(request.Project, &project); err != nil {
			writeError(w, badRequest("%v", googlelogin.ErrProjectID))
			return
		}
		version, err := in.chooseGoogleProject(r.Context(), project)
		in.changed(w, "google_project_chosen", nil, version, err, nil)
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
		} else {
			// The transaction clone shares immutable role grants. Copy only
			// the map this operation changes, before any fallible commit.
			role.Access = maps.Clone(role.Access)
		}
		for name, desired := range access {
			role.Access[name] = desired
		}
		s.Roles["router"] = role
		return nil
	})
	in.changed(w, "google_provisioned", nil, version, err, nil)
}

// chooseGoogleProject saves an existing project ID for the retained Google
// sign-in's setup; the owner then retries the Drive connection.
func (in *Instance) chooseGoogleProject(ctx context.Context, project string) (uint64, error) {
	if in.google == nil {
		return 0, &httpError{http.StatusNotFound, "container Google provisioning is unavailable"}
	}
	switch err := in.google.ChooseProject(ctx, project); {
	case errors.Is(err, googlelogin.ErrProjectID):
		return 0, badRequest("%v", err)
	case errors.Is(err, googlelogin.ErrProjectNotChoosable):
		return 0, &httpError{http.StatusConflict, err.Error()}
	case err != nil:
		return 0, err
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.state == nil {
		return 0, &httpError{http.StatusConflict, errLocked.Error()}
	}
	return in.state.Version, nil
}
