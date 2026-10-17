// Package workspace defines the container's account-bound Workspace contract.
// Provider credentials are never part of the public account view.
package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const GenerationHeader = "X-Keyring-Binding-Generation"

var idPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var aliasPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func ValidID(s string) bool    { return idPattern.MatchString(s) }
func ValidAlias(s string) bool { return aliasPattern.MatchString(s) }
func Service(name string) bool { return name == "gmail" || name == "calendar" }

// Record is sealed alongside the keys. Grants are a ceiling, not a replacement
// for the role's current policy. A disconnected slot retains its last identity.
type Record struct {
	ID         string                              `json:"account_id"`
	Alias      string                              `json:"alias"`
	Generation string                              `json:"binding_generation"`
	Key        string                              `json:"refresh_key"`
	Email      string                              `json:"email,omitempty"`
	VerifiedAt *time.Time                          `json:"email_verified_at,omitempty"`
	Grants     map[string]map[string]policy.Access `json:"grants"`
}

type ServiceStatus struct {
	Connected bool   `json:"connected"`
	Failing   string `json:"failing"`
}

type View struct {
	ID               string                   `json:"account_id"`
	Alias            string                   `json:"alias"`
	Default          bool                     `json:"default"`
	Provider         string                   `json:"provider"`
	Generation       string                   `json:"binding_generation"`
	Email            *string                  `json:"email"`
	VerifiedAt       *time.Time               `json:"email_verified_at"`
	IdentityState    string                   `json:"identity_state"`
	Connected        bool                     `json:"connected"`
	Status           string                   `json:"status"`
	AffectedServices []string                 `json:"affected_services"`
	Services         map[string]ServiceStatus `json:"services"`
}

type Error struct {
	Status int
	Code   string
}

func (e *Error) Error() string              { return e.Code }
func Failure(status int, code string) error { return &Error{status, code} }
func WriteError(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{http.StatusInternalServerError, "account_operation_failed"}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Code})
}

// Selection owns a read lease through upstream dispatch. Release must be called
// on every path, including failed refresh. No mutation may retarget this lease.
type Selection struct {
	ID            string
	Generation    string
	Service       policy.Service
	Refresh       string
	Secret        string
	DailyRequests int
	Release       func()
}

type ConsentBinding struct {
	ID          string
	Generation  string
	ServiceName string
	Service     policy.Service
	View        View
}

// Boundary is implemented by the sealed instance, never by model input.
type Boundary interface {
	Acquire(ctx context.Context, id, generation, role, token, service, method, path string) (*Selection, error)
	Revalidate(ctx context.Context, selected *Selection) error
	PrepareConsent(id, generation, service string) (*ConsentBinding, error)
	CommitConsent(ctx context.Context, binding ConsentBinding, refresh, email string) error
	Detach(ctx context.Context, id, generation string) (View, *Selection, error)
}

// VerifiedEmail uses the already-approved Gmail scope, not an added OIDC scope.
// Redirects are disabled by the caller's credential-safe HTTP client.
func VerifiedEmail(ctx context.Context, client *http.Client, token string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://gmail.googleapis.com/gmail/v1/users/me/profile", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return "", Failure(502, "account_identity_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", Failure(502, "account_identity_unavailable")
	}
	var profile struct {
		Email string `json:"emailAddress"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil || len(raw) > 64*1024 || json.Unmarshal(raw, &profile) != nil {
		return "", Failure(502, "account_identity_unavailable")
	}
	email := strings.ToLower(profile.Email)
	if len(email) > 254 || strings.Count(email, "@") != 1 || strings.ContainsAny(email, " \t\r\n<>") || strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") {
		return "", Failure(502, "account_identity_unavailable")
	}
	return email, nil
}
