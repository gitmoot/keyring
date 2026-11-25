package googlelogin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// projectCommand preserves any SDK refresh/reauth state before returning.
// The project ID was sealed before the first project creation attempt.
func (c *Controller) projectCommand(ctx context.Context, s *Snapshot, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	args = append(args, "--account="+s.Account, "--configuration=default", "--quiet")
	dir := filepath.Join(c.root, s.Generation)
	out, runErr := c.run(commandCtx, dir, nil, args...)
	current := c.snapshot()
	if current == nil || current.Generation != s.Generation {
		return nil, errors.New("Google connection was replaced")
	}
	next, err := capture(dir, current)
	if err != nil {
		return nil, err
	}
	if errors.Is(runErr, errLogin) {
		invalid := *next
		invalid.Ready, invalid.NeedsLogin, invalid.Refused = false, true, false
		next = &invalid
	}
	if next != current {
		if err := c.save(ctx, s.Generation, next); err != nil {
			return nil, err
		}
	}
	return out, runErr
}

func pause(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Controller) retryProjectCommand(ctx context.Context, s *Snapshot, args ...string) error {
	for attempt := 0; ; attempt++ {
		_, err := c.projectCommand(ctx, s, args...)
		if !errors.Is(err, errRate) || attempt == 5 {
			return err
		}
		if err := pause(ctx, min(10*time.Second<<attempt, time.Minute)); err != nil {
			return err
		}
	}
}

// stepError names the setup command that failed. The name is fixed text;
// the command's output never reaches it.
type stepError struct {
	step string
	err  error
}

func (e stepError) Error() string { return e.step + ": " + e.err.Error() }

func (e stepError) Unwrap() error { return e.err }

func atStep(step string, err error) error {
	if err == nil {
		return nil
	}
	return stepError{step, err}
}

func (c *Controller) setup(ctx context.Context, s *Snapshot) error {
	s, err := c.ensureProject(ctx, s)
	if err != nil {
		return err
	}
	if err := c.retryProjectCommand(ctx, s, "services", "enable", "drive.googleapis.com", "sheets.googleapis.com", "--project="+s.Project); err != nil {
		return atStep("services_enable", err)
	}
	for attempt := 0; attempt < 12; attempt++ {
		token, err := c.projectCommand(ctx, s, "auth", "print-access-token", s.Account)
		if err != nil {
			return atStep("access_token", err)
		}
		err = c.probe(ctx, s, strings.TrimSpace(string(token)))
		if err == nil {
			return nil
		}
		if err != commandError("api_disabled") || attempt == 11 {
			return err
		}
		if err := pause(ctx, 10*time.Second); err != nil {
			return err
		}
	}
	return commandError("api_disabled")
}

// ensureProject makes sure the retained project is ACTIVE, creating it on
// first use, and returns the snapshot setup continues with: s, or the one
// sealed with a fresh project ID. Google answers describe for a project
// deleted for good and for one this account cannot reach with the same "does
// not have permission to access projects instance [id] (or it may not
// exist)", and create with the same "already in use by another project" for
// both: the two cases cannot be told apart, so do not try. Either way the
// retained ID is unusable for this account, and Drive files live in the
// account, not the project, so a fresh project ID is created once. A fresh
// ID refused again is not retried.
func (c *Controller) ensureProject(ctx context.Context, s *Snapshot) (*Snapshot, error) {
	if s.ProjectChosen {
		// The owner's own project: check it, never create or replace it.
		err := c.describeProject(ctx, s)
		if errors.Is(err, errProjectHidden) {
			return nil, atStep("project_describe", errProjectNotFound)
		}
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	// A new ID answers describe as hidden too; any describe failure other
	// than login or terms may be a project not created yet.
	err := c.describeProject(ctx, s)
	if err == nil {
		return s, nil
	}
	if errors.Is(err, errProjectInactive) || errors.Is(err, errLogin) || errors.Is(err, errTerms) || ctx.Err() != nil {
		return nil, err
	}
	err = c.retryProjectCommand(ctx, s, "projects", "create", s.Project, "--name=drivekey")
	if err == nil {
		return s, nil
	}
	if !errors.Is(err, errProjectTaken) {
		return nil, atStep("project_create", err)
	}
	// The first describe may have failed for a passing reason while the
	// project is ours: ask once more before giving the ID up.
	err = c.describeProject(ctx, s)
	if err == nil {
		return s, nil
	}
	if !errors.Is(err, errProjectHidden) {
		return nil, err
	}
	fresh, err := c.freshProject(ctx, s)
	if err != nil {
		return nil, err
	}
	err = c.retryProjectCommand(ctx, fresh, "projects", "create", fresh.Project, "--name=drivekey")
	if errors.Is(err, errProjectTaken) {
		err = errProjectRefused
	}
	if err != nil {
		return nil, atStep("project_create", err)
	}
	return fresh, nil
}

func (c *Controller) describeProject(ctx context.Context, s *Snapshot) error {
	lifecycle, err := c.projectCommand(ctx, s, "projects", "describe", s.Project, "--format=value(lifecycleState)")
	if err != nil {
		return atStep("project_describe", err)
	}
	if strings.TrimSpace(string(lifecycle)) != "ACTIVE" {
		return atStep("project_describe", errProjectInactive)
	}
	return nil
}

// freshProject seals a new project ID before it is created, as the first
// connection does, so a retry after a crash reuses the same ID.
func (c *Controller) freshProject(ctx context.Context, s *Snapshot) (*Snapshot, error) {
	current := c.snapshot()
	if current == nil || current.Generation != s.Generation {
		return nil, errors.New("Google connection was replaced")
	}
	var random [10]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	next := *current
	next.Project = "drivekey-" + hex.EncodeToString(random[:])
	if err := c.save(ctx, s.Generation, &next); err != nil {
		return nil, err
	}
	return &next, nil
}

func (c *Controller) probe(ctx context.Context, s *Snapshot, token string) error {
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n \t") {
		return errLogin
	}
	for _, endpoint := range []string{
		"https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)",
		"https://sheets.googleapis.com/v4/spreadsheets/drivekey-setup-probe",
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return errCommand
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Goog-User-Project", s.Project)
		response, err := c.client.Do(req)
		if err != nil {
			return commandError("api_probe_failed")
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, commandOutputLimit+1))
		response.Body.Close()
		if readErr != nil || len(body) > commandOutputLimit {
			return commandError("api_probe_failed")
		}
		if req.URL.Host == "sheets.googleapis.com" && response.StatusCode == http.StatusNotFound {
			continue
		}
		if req.URL.Host == "www.googleapis.com" && response.StatusCode == http.StatusOK {
			var result struct {
				User struct {
					Email string `json:"emailAddress"`
				} `json:"user"`
			}
			if json.Unmarshal(body, &result) != nil || result.User.Email != s.Account {
				return commandError("wrong_google_account")
			}
			continue
		}
		if response.StatusCode == http.StatusForbidden {
			text := strings.ToLower(string(body))
			if strings.Contains(text, "accessnotconfigured") || strings.Contains(text, "service_disabled") || strings.Contains(text, "api has not been used") {
				return commandError("api_disabled")
			}
		}
		return commandError("api_probe_failed")
	}
	return nil
}
