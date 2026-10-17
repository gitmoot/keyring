package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/gcloudexec"
	"github.com/gitmoot/keyring/internal/policy"
)

const googleTimeout = 30 * time.Second

// googleCache is separate from the OAuth refresh-token cache: gcloud owns
// its login and refresh logic. No gcloud credential database is read here.
type googleCache struct {
	mu      sync.Mutex
	entries map[policy.GoogleAccount]*googleEntry
}

type googleEntry struct {
	oauthEntry
	expires time.Time
}

// GoogleStatus is safe dashboard metadata, never command output or a token.
func (h *Handler) GoogleStatus(name string) (state string, expires time.Time) {
	a, ok := h.snap.Load().config.GoogleAccounts[name]
	if !ok {
		return "not configured", time.Time{}
	}
	h.google.mu.Lock()
	defer h.google.mu.Unlock()
	e := h.google.entries[a]
	if e == nil {
		return "not checked", time.Time{}
	}
	if e.refreshing != nil {
		return "renewing", time.Time{}
	}
	if e.err != nil {
		return e.err.Error(), time.Time{}
	}
	if e.token == "" || !h.now().Before(e.expires) {
		return "renewal required", time.Time{}
	}
	return "ready", e.expires
}

func (h *Handler) googleToken(ctx context.Context, name string, a policy.GoogleAccount) (string, error) {
	c := &h.google
	for {
		c.mu.Lock()
		if c.entries == nil {
			c.entries = map[policy.GoogleAccount]*googleEntry{}
		}
		e := c.entries[a]
		if e == nil {
			e = &googleEntry{}
			c.entries[a] = e
		}
		now := h.now()
		if e.token != "" && now.Before(e.refreshAt) {
			token := e.token
			c.mu.Unlock()
			return token, nil
		}
		if wait := e.refreshing; wait != nil {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return "", errors.New("gcloud request canceled")
			}
		}
		if e.err != nil && now.Before(e.retryAt) {
			err := e.err
			c.mu.Unlock()
			return "", err
		}
		done := make(chan struct{})
		e.refreshing = done
		c.mu.Unlock()

		// Other callers may still need this renewal if the first disconnects.
		timeout := googleTimeout
		if h.snap.Load().config.ContainerMode {
			// The lite container's 1/16 CPU can spend over 30s starting
			// the SDK. Leave 15s of the caller's 60s header budget for
			// forwarding; host renewal keeps its existing 30s bound.
			timeout = 45 * time.Second
		}
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		token, lifetime, err := h.fetchGoogleToken(fetchCtx, a)
		cancel()
		h.recordGoogleAttempt(name, a, h.now(), err)
		c.mu.Lock()
		now = h.now()
		if err != nil {
			e.token, e.err, e.retryAt = "", err, now.Add(oauthRetry)
			e.expires = time.Time{}
		} else {
			e.token, e.err = token, nil
			e.expires = now.Add(lifetime)
			e.refreshAt = now.Add(lifetime - min(oauthEarly, lifetime/2))
		}
		e.refreshing = nil
		close(done)
		c.mu.Unlock()
		return token, err
	}
}

func (h *Handler) dropGoogleToken(a policy.GoogleAccount, token string) {
	h.google.mu.Lock()
	defer h.google.mu.Unlock()
	if e := h.google.entries[a]; e != nil && e.token == token {
		e.token = ""
	}
}

func (h *Handler) retainGoogle(config *policy.Config) {
	keep := map[policy.GoogleAccount]bool{}
	for _, svc := range config.Services {
		if svc.Auth == policy.AuthGcloud {
			keep[config.GoogleAccounts[svc.GoogleAccount]] = true
		}
	}
	h.google.mu.Lock()
	defer h.google.mu.Unlock()
	for a, e := range h.google.entries {
		// As with OAuth refreshes, in-flight callers still own this entry.
		// Keep their single flight across a remove/re-add during renewal.
		if !keep[a] && e.refreshing == nil {
			delete(h.google.entries, a)
		}
	}
}

// limitedOutput retains at most 16 KiB transiently. Only fixed classifications
// may escape stderr; neither stream is retained in an incident.
type limitedOutput struct {
	buf      bytes.Buffer
	n        int
	exceeded bool
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > (16<<10)-w.n {
		w.exceeded = true
		return 0, errors.New("command output limit")
	}
	w.n += len(p)
	return w.buf.Write(p)
}

func (h *Handler) fetchGoogleToken(ctx context.Context, a policy.GoogleAccount) (string, time.Duration, error) {
	var token string
	if h.googleCommand != nil {
		var err error
		token, err = h.googleCommand(ctx, a)
		if err != nil {
			return "", 0, err
		}
	} else {
		info, err := os.Stat(a.ConfigDir)
		if err != nil || !info.IsDir() {
			if os.IsPermission(err) {
				return "", 0, googleFailure("permission_denied", "configuration", "permission_denied")
			}
			return "", 0, googleFailure("configuration_error", "configuration", "configuration_unavailable")
		}
		if info.Mode().Perm()&0077 != 0 {
			return "", 0, googleFailure("configuration_error", "configuration", "configuration_not_private")
		}
		cmd := exec.CommandContext(ctx, a.Executable, "auth", "print-access-token", a.Account, "--account="+a.Account, "--configuration=default", "--quiet")
		// Do not inherit proxy variables, CLOUDSDK_AUTH_ACCESS_TOKEN,
		// impersonation, credential overrides, Python hooks, or an agent's HOME.
		cmd.Env = []string{
			"PATH=" + filepath.Dir(a.Executable) + ":/usr/bin:/bin",
			"HOME=" + a.ConfigDir,
			"CLOUDSDK_CONFIG=" + a.ConfigDir,
			"CLOUDSDK_CORE_DISABLE_PROMPTS=1",
			"CLOUDSDK_CORE_DISABLE_FILE_LOGGING=true",
			"CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true",
			"CLOUDSDK_PYTHON_SITEPACKAGES=0",
			"LANG=C.UTF-8",
		}
		cmd.Dir = a.ConfigDir
		cmd.WaitDelay = time.Second
		cleanup, err := gcloudexec.Bound(cmd)
		if err != nil {
			return "", 0, googleFailure("runtime_unavailable", "command_start", "runtime_start_failed")
		}
		defer cleanup()
		stdout, stderr := &limitedOutput{}, &limitedOutput{}
		defer func() {
			clear(stdout.buf.Bytes())
			clear(stderr.buf.Bytes())
		}()
		cmd.Stdout, cmd.Stderr = stdout, stderr
		if err := cmd.Run(); err != nil {
			return "", 0, classifyGoogleCommand(ctx, err, stderr.buf.Bytes(), stdout.exceeded || stderr.exceeded)
		}
		token = strings.TrimSpace(stdout.buf.String())
	}
	if !usableAccessToken(token) {
		return "", 0, googleFailure("unknown", "command", "unusable_token_output")
	}
	// print-access-token may return a previously cached token. Never invent
	// a new one-hour expiry for it. Check remaining life AND account identity
	// at Google's fixed endpoint; a config's impersonation cannot cross accounts.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://oauth2.googleapis.com/tokeninfo?access_token="+url.QueryEscape(token), nil)
	if err != nil {
		return "", 0, googleFailure("unknown", "token_validation", "invalid_token_response")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return "", 0, classifyGoogleValidation(ctx, err)
	}
	defer resp.Body.Close()
	var result struct {
		Email     string          `json:"email"`
		ExpiresIn json.RawMessage `json:"expires_in"`
		Error     string          `json:"error"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result)
	if decodeErr == nil && result.Error == "invalid_token" {
		return "", 0, googleFailure("credentials_invalid", "token_validation", "invalid_token")
	}
	if resp.StatusCode != http.StatusOK || decodeErr != nil {
		return "", 0, googleFailure("provider_error", "token_validation", "invalid_token_response")
	}
	seconds, err := strconv.ParseInt(strings.Trim(string(result.ExpiresIn), `"`), 10, 64)
	if err != nil || seconds > 3600 {
		return "", 0, googleFailure("provider_error", "token_validation", "invalid_token_response")
	}
	if !strings.EqualFold(result.Email, a.Account) {
		return "", 0, googleFailure("credentials_invalid", "token_validation", "identity_mismatch")
	}
	if seconds <= 1 {
		return "", 0, googleFailure("credentials_invalid", "token_validation", "expired_access_token")
	}
	return token, time.Duration(seconds) * time.Second, nil
}
