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
	// seq numbers every use of a token, across accounts: answers are
	// ordered by it (see googleAnswered).
	seq uint64
}

type googleEntry struct {
	oauthEntry
	expires time.Time
	renewal gcloudexec.RenewalTrace
	// last is the latest token minted. A 401 drops token but not last, so
	// answers to calls still in flight with it are recorded in order.
	last string
	// answered is the sequence number of the call whose answer set refused;
	// answers to calls made before it change nothing.
	answered uint64
	// refused: Google answered 401 to the latest answered call made with
	// last. Only a later call it accepts clears it; a new token does not.
	refused bool
}

// Google answered 401 to a call with a token gcloud minted (#184). The
// messages are fixed text: never Google's body, the account or a token.
const (
	// GoogleRefusedContainer: the next Drive connection signs in again.
	GoogleRefusedContainer = "Google refused the sign-in (HTTP 401, session invalid); open a new Drive link to sign in again"
	googleRefusedHost      = "Google refused the gcloud token (HTTP 401); run gcloud auth login for this account"
)

// GoogleMint is the state of an account's token mint.
type GoogleMint string

const (
	GoogleNotConfigured   GoogleMint = "not configured"
	GoogleNotChecked      GoogleMint = "not checked"
	GoogleRenewing        GoogleMint = "renewing"
	GoogleMintFailed      GoogleMint = "failing"
	GoogleRenewalRequired GoogleMint = "renewal required"
	GoogleReady           GoogleMint = "ready"
)

// GoogleState is safe metadata about a Google account, never command
// output or a token.
type GoogleState struct {
	Mint GoogleMint
	// Failure is why the last mint failed (fixed text), for GoogleMintFailed.
	Failure string
	// Expires is the token's expiry, for GoogleReady.
	Expires time.Time
	// Refused: Google refuses the account's tokens (it answered 401 and has
	// accepted no call since). gcloud still mints them, but the sign-in
	// behind them must be made again. It is apart from the mint: a failed
	// or new mint does not clear it.
	Refused bool
}

// Failing is why the account cannot be used: its mint failing, else Google
// refusing its tokens, with how to sign in again in a container (the next
// Drive link) or on a host; "" for neither.
func (s GoogleState) Failing(container bool) string {
	switch {
	case s.Mint == GoogleMintFailed:
		return s.Failure
	case !s.Refused:
		return ""
	case container:
		return GoogleRefusedContainer
	}
	return googleRefusedHost
}

// Text is the dashboard's status line: Failing, else the mint state.
func (s GoogleState) Text(container bool) string {
	if why := s.Failing(container); why != "" {
		return why
	}
	return string(s.Mint)
}

// GoogleRenewal returns a fixed-size, credential-free snapshot of the latest
// actual attempt. It does not refresh, inspect SDK files, or change the cache.
func (h *Handler) GoogleRenewal(name string) (gcloudexec.RenewalRecord, bool) {
	a, ok := h.snap.Load().config.GoogleAccounts[name]
	if !ok {
		return gcloudexec.RenewalRecord{}, false
	}
	h.google.mu.Lock()
	e := h.google.entries[a]
	h.google.mu.Unlock()
	if e == nil {
		return gcloudexec.RenewalRecord{}, false
	}
	return e.renewal.Snapshot()
}

// GoogleStatus is safe dashboard metadata, never command output or a token.
func (h *Handler) GoogleStatus(name string) GoogleState {
	a, ok := h.snap.Load().config.GoogleAccounts[name]
	if !ok {
		return GoogleState{Mint: GoogleNotConfigured}
	}
	h.google.mu.Lock()
	defer h.google.mu.Unlock()
	e := h.google.entries[a]
	if e == nil {
		return GoogleState{Mint: GoogleNotChecked}
	}
	s := GoogleState{Refused: e.refused}
	switch {
	case e.refreshing != nil:
		s.Mint = GoogleRenewing
	case e.err != nil:
		s.Mint, s.Failure = GoogleMintFailed, e.err.Error()
	case e.token == "" || !h.now().Before(e.expires):
		s.Mint = GoogleRenewalRequired
	default:
		s.Mint, s.Expires = GoogleReady, e.expires
	}
	return s
}

// googleToken returns a token for a call and the call's sequence number,
// which orders Google's answer to it (googleAnswered).
func (h *Handler) googleToken(ctx context.Context, name string, a policy.GoogleAccount) (string, uint64, error) {
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
			c.seq++
			seq := c.seq
			c.mu.Unlock()
			return token, seq, nil
		}
		if wait := e.refreshing; wait != nil {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return "", 0, errors.New("gcloud request canceled")
			}
		}
		if e.err != nil && now.Before(e.retryAt) {
			err := e.err
			c.mu.Unlock()
			return "", 0, err
		}
		done := make(chan struct{})
		e.refreshing = done
		e.renewal.Begin()
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
		token, lifetime, err := h.fetchGoogleToken(fetchCtx, a, &e.renewal)
		e.renewal.Finish(err)
		cancel()
		h.recordGoogleAttempt(name, a, h.now(), err)
		c.mu.Lock()
		now = h.now()
		var seq uint64
		if err != nil {
			e.token, e.err, e.retryAt = "", err, now.Add(oauthRetry)
			e.expires = time.Time{}
		} else {
			e.token, e.last, e.err = token, token, nil
			e.expires = now.Add(lifetime)
			e.refreshAt = now.Add(lifetime - min(oauthEarly, lifetime/2))
			c.seq++
			seq = c.seq
		}
		e.refreshing = nil
		close(done)
		c.mu.Unlock()
		return token, seq, err
	}
}

// googleAnswerSave bounds how long a proxied answer waits for the container
// to seal Google's answer before it is returned.
const googleAnswerSave = 10 * time.Second

// googleAnswered records Google's answer to call seq, sent with token. A 401
// drops the token if the entry still holds it, so the next call mints a new
// one, and marks the account refused; a later accepted call clears it.
// Answers are ordered by the call's sequence number: one to a call made
// before the latest recorded answer's call, or with a token older than the
// latest minted, changes nothing. Credentials are never removed here. The
// container's controller also seals the answer (SetGoogleRefusal) before
// googleAnswered returns, within googleAnswerSave.
func (h *Handler) googleAnswered(ctx context.Context, a policy.GoogleAccount, token string, seq uint64, status int) {
	var refused bool
	switch {
	case status == http.StatusUnauthorized:
		refused = true
	case status < 400:
	default:
		return
	}
	h.google.mu.Lock()
	e := h.google.entries[a]
	if e == nil || e.last != token || seq < e.answered {
		h.google.mu.Unlock()
		return
	}
	e.answered, e.refused = seq, refused
	if refused && e.token == token {
		e.token = ""
	}
	h.google.mu.Unlock()
	if h.googleRefusal != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), googleAnswerSave)
		defer cancel()
		h.googleRefusal(ctx, a, refused, seq)
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

func (h *Handler) fetchGoogleToken(ctx context.Context, a policy.GoogleAccount, trace *gcloudexec.RenewalTrace) (string, time.Duration, error) {
	var token string
	if h.googleCommand != nil {
		var err error
		token, err = h.googleCommand(ctx, a, trace)
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
		trace.Enter(gcloudexec.RenewalSDK)
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
		err = cmd.Run()
		trace.Process(cmd.ProcessState)
		if err != nil {
			if ctx.Err() != nil {
				trace.End(ctx.Err())
			} else {
				trace.End(err)
			}
			return "", 0, classifyGoogleCommand(ctx, err, stderr.buf.Bytes(), stdout.exceeded || stderr.exceeded)
		}
		token = strings.TrimSpace(stdout.buf.String())
	}
	trace.Enter(gcloudexec.RenewalValidation)
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
		trace.End(err)
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
		if decodeErr != nil {
			trace.End(decodeErr)
		}
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
