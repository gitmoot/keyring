package server

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const (
	// oauthEarly is how long before its expiry an access token is replaced.
	oauthEarly = time.Minute
	// oauthRetry is how long a failed refresh is reported to callers before
	// the token endpoint is asked again.
	oauthRetry = 10 * time.Second
	// oauthNoExpiry is how long a token is used when the provider does not
	// say when it expires.
	oauthNoExpiry = 10 * time.Minute
	oauthTimeout  = 30 * time.Second
)

// errOAuthRejected: the provider refused the refresh token or the client, so
// the account must be connected again. Other refresh errors are transient.
var errOAuthRejected = errors.New("refresh token or client rejected")

// oauthError is a failed refresh. Its text is safe to show and log: it never
// holds a token, a secret or the provider's free-text description.
type oauthError struct {
	rejected bool
	msg      string
}

func (e *oauthError) Error() string { return e.msg }

func (e *oauthError) Is(target error) bool { return target == errOAuthRejected && e.rejected }

// oauthCache holds the access tokens minted from stored refresh tokens. An
// entry is keyed by a hash of everything the token was minted from, so a
// changed refresh token, client or endpoint never reuses an old token.
type oauthCache struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]*oauthEntry
}

type oauthEntry struct {
	token     string
	refreshAt time.Time // replace the token from this time on
	// refreshing is non-nil while one refresh runs; it is closed when the
	// refresh ends, and every caller that found it waits for that one.
	refreshing chan struct{}
	err        error // the last refresh failed; nil after a success
	retryAt    time.Time
}

// oauthKey identifies a refresh token and the client it belongs to.
func oauthKey(cfg policy.OAuth2, refresh, secret string) [sha256.Size]byte {
	h := sha256.New()
	for _, s := range []string{cfg.TokenURL, cfg.ClientID, refresh, secret} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	var k [sha256.Size]byte
	h.Sum(k[:0])
	return k
}

// oauthSecrets returns the refresh token and client secret of an oauth2
// service from keys.
func oauthSecrets(svc policy.Service, keys map[string]string) (refresh, secret string) {
	refresh = keys[svc.Key]
	if svc.OAuth2.ClientSecretKey != "" {
		secret = keys[svc.OAuth2.ClientSecretKey]
	}
	return refresh, secret
}

// accessToken returns a current access token for an oauth2 service, minting
// one from the refresh token if the cached one is missing or about to expire.
// Concurrent callers share one refresh. A failed refresh fails closed: callers
// get its error until oauthRetry has passed, and nothing else is tried.
func (h *Handler) accessToken(ctx context.Context, svc policy.Service, refresh, secret string) (string, error) {
	cfg := *svc.OAuth2
	k := oauthKey(cfg, refresh, secret)
	c := &h.oauth
	for {
		c.mu.Lock()
		if c.entries == nil {
			c.entries = map[[sha256.Size]byte]*oauthEntry{}
		}
		e := c.entries[k]
		if e == nil {
			e = &oauthEntry{}
			c.entries[k] = e
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
				return "", ctx.Err()
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

		// The refresh outlives a caller that gives up: others may be waiting.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), oauthTimeout)
		token, lifetime, err := h.fetchAccessToken(fetchCtx, cfg, refresh, secret)
		cancel()

		c.mu.Lock()
		now = h.now()
		if err != nil {
			e.token, e.err, e.retryAt = "", err, now.Add(oauthRetry)
		} else {
			e.token, e.err = token, nil
			e.refreshAt = now.Add(lifetime - min(oauthEarly, lifetime/2))
		}
		e.refreshing = nil
		close(done)
		c.mu.Unlock()
		if err != nil {
			return "", err
		}
		return token, nil
	}
}

// dropAccessToken forgets token if it is still the cached one for the
// service, so the next call mints a new one (the upstream refused it).
func (h *Handler) dropAccessToken(svc policy.Service, refresh, secret, token string) {
	k := oauthKey(*svc.OAuth2, refresh, secret)
	h.oauth.mu.Lock()
	defer h.oauth.mu.Unlock()
	if e := h.oauth.entries[k]; e != nil && e.token == token {
		e.token = ""
	}
}

// retainOAuth forgets the tokens of refresh tokens and clients no longer in
// use by any service.
func (h *Handler) retainOAuth(config *policy.Config, keys map[string]string) {
	keep := map[[sha256.Size]byte]bool{}
	for _, svc := range config.Services {
		if svc.Auth == policy.AuthOAuth2 {
			refresh, secret := oauthSecrets(svc, keys)
			keep[oauthKey(*svc.OAuth2, refresh, secret)] = true
		}
	}
	h.oauth.mu.Lock()
	defer h.oauth.mu.Unlock()
	for k, e := range h.oauth.entries {
		// A running refresh removes nothing; its waiters still hold e.
		if !keep[k] && e.refreshing == nil {
			delete(h.oauth.entries, k)
		}
	}
}

// OAuthFailure returns the last refresh failure and whether the provider
// rejected the credential or client. Values in use now are checked, so a
// replaced token starts clean. Neither result contains credential material.
func (h *Handler) OAuthFailure(keyName string) (message string, reconnect bool) {
	snap := h.snap.Load()
	for _, svc := range snap.config.Services {
		if svc.Auth != policy.AuthOAuth2 || svc.Key != keyName {
			continue
		}
		refresh, secret := oauthSecrets(svc, snap.keys)
		k := oauthKey(*svc.OAuth2, refresh, secret)
		h.oauth.mu.Lock()
		e := h.oauth.entries[k]
		var msg string
		var rejected bool
		if e != nil && e.err != nil {
			msg = e.err.Error()
			rejected = errors.Is(e.err, errOAuthRejected)
		}
		h.oauth.mu.Unlock()
		if msg != "" {
			return msg, rejected
		}
	}
	return "", false
}

var oauthErrorCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// usableAccessToken reports whether token may go into an Authorization
// header: 1 to 8192 printable ASCII characters, no spaces.
func usableAccessToken(token string) bool {
	if token == "" || len(token) > 8192 {
		return false
	}
	for i := range len(token) {
		if token[i] < 0x21 || token[i] > 0x7e {
			return false
		}
	}
	return true
}

// fetchAccessToken asks the token endpoint for a new access token
// (RFC 6749 section 6) and returns it with its lifetime.
func (h *Handler) fetchAccessToken(ctx context.Context, cfg policy.OAuth2, refresh, secret string) (string, time.Duration, error) {
	fail := func(rejected bool, format string, args ...any) (string, time.Duration, error) {
		return "", 0, &oauthError{rejected: rejected, msg: "oauth2 refresh failed: " + fmt.Sprintf(format, args...)}
	}
	if refresh == "" {
		return fail(true, "no refresh token stored")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {cfg.ClientID},
	}
	if cfg.ClientSecretKey != "" {
		if secret == "" {
			return fail(true, "no client secret stored")
		}
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fail(false, "bad token endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "keyring")
	resp, err := h.client.Do(req)
	if err != nil {
		return fail(false, "token endpoint unreachable")
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
		Error       string          `json:"error"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		code := "no error code"
		if decodeErr == nil && oauthErrorCode.MatchString(body.Error) {
			code = body.Error
		}
		switch body.Error {
		case "invalid_grant", "invalid_client", "unauthorized_client":
			return fail(true, "the provider rejected the refresh token or client (%s); connect the account again", code)
		}
		return fail(false, "token endpoint answered %d (%s)", resp.StatusCode, code)
	}
	if decodeErr != nil {
		return fail(false, "token endpoint sent invalid JSON")
	}
	if !strings.EqualFold(body.TokenType, "bearer") {
		return fail(false, "token endpoint sent a token that is not a bearer token")
	}
	if !usableAccessToken(body.AccessToken) {
		return fail(false, "token endpoint sent no usable access token")
	}
	lifetime := oauthNoExpiry
	if len(body.ExpiresIn) > 0 && string(body.ExpiresIn) != "null" {
		// Some providers send the number as a string.
		seconds, err := strconv.ParseInt(strings.Trim(string(body.ExpiresIn), `"`), 10, 64)
		if err != nil || seconds <= 0 || seconds > 366*24*3600 {
			return fail(false, "token endpoint sent an invalid expires_in")
		}
		lifetime = time.Duration(seconds) * time.Second
	}
	return body.AccessToken, lifetime, nil
}
