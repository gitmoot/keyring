package googlelogin

import (
	"context"
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
	out, runErr := c.run(commandCtx, dir, args...)
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
		invalid.Ready, invalid.NeedsLogin = false, true
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

func (c *Controller) setup(ctx context.Context, s *Snapshot) error {
	lifecycle, err := c.projectCommand(ctx, s, "projects", "describe", s.Project, "--format=value(lifecycleState)")
	if err == nil {
		if strings.TrimSpace(string(lifecycle)) != "ACTIVE" {
			return commandError("project_not_active")
		}
	} else {
		if errors.Is(err, errLogin) || errors.Is(err, errTerms) || ctx.Err() != nil {
			return err
		}
		if err := c.retryProjectCommand(ctx, s, "projects", "create", s.Project, "--name=drivekey"); err != nil {
			return err
		}
	}
	if err := c.retryProjectCommand(ctx, s, "services", "enable", "drive.googleapis.com", "sheets.googleapis.com", "--project="+s.Project); err != nil {
		return err
	}
	for attempt := 0; attempt < 12; attempt++ {
		token, err := c.projectCommand(ctx, s, "auth", "print-access-token", s.Account)
		if err != nil {
			return err
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
