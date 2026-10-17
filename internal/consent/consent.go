// Package consent lets the owner of a key connect a service themselves,
// through a single-use, short-lived link: an OAuth sign-in (authorization
// code with PKCE) that stores the refresh token, or a one-time form for a
// fixed key. Links are created, and keys deleted, through an API that only
// the configured callers with the API token can use. The link pages and the
// API are two handlers for two listeners; neither serves the proxy or the
// dashboard.
package consent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gitmoot/keyring/internal/googlelogin"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const (
	// DefaultLinkTTL and MaxLinkTTL bound how long a link can be opened.
	DefaultLinkTTL = 15 * time.Minute
	MaxLinkTTL     = time.Hour
	// signInTTL is how long the person has to finish the provider sign-in
	// after pressing Connect.
	signInTTL = 10 * time.Minute
	// maxPending caps open links and sign-ins, so a caller with the API
	// token cannot fill memory.
	maxPending = 1000
	maxLabel   = 100
)

// Keys stores key values and applies them to the running proxy. The keyring
// serializes these with its other changes.
type Keys interface {
	Load() (map[string]string, error)
	Set(name, value string) error
	Delete(name string) error
}

// Server holds the open links and sign-ins. They live in memory only: a
// restart ends them all, which fails safe.
type Server struct {
	config func() *policy.Config
	keys   Keys
	audit  io.Writer
	client *http.Client
	now    func() time.Time
	google *googlelogin.Controller // container-only, set before serving

	auditMu sync.Mutex

	mu       sync.Mutex
	links    map[[sha256.Size]byte]*link
	signIns  map[[sha256.Size]byte]*signIn
	revoking map[string]bool // keys whose remote revocation is still pending
}

type link struct {
	service     string
	key         string
	label       string
	expires     time.Time
	google      bool
	googleEpoch uint64
}

type signIn struct {
	service  string
	oauth    policy.OAuth2 // the settings the sign-in started with
	key      string
	used     bool // retained during exchange so disconnect can invalidate it
	verifier string
	// browser is the hash of the cookie set on the browser that pressed
	// Connect; the callback must come from that browser.
	browser     [sha256.Size]byte
	expires     time.Time
	google      bool
	googleEpoch uint64
}

// New builds a consent server. config returns the settings in use (the
// proxy's); audit receives one JSON line per event, never a value.
func New(config func() *policy.Config, keys Keys, audit io.Writer) *Server {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Never send a code or token through an environment-configured proxy.
	transport.Proxy = nil
	return &Server{
		config: config,
		keys:   keys,
		audit:  audit,
		client: &http.Client{
			Transport:     transport,
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:     time.Now,
		links:   map[[sha256.Size]byte]*link{},
		signIns: map[[sha256.Size]byte]*signIn{},
	}
}

func hashOf(s string) [sha256.Size]byte { return sha256.Sum256([]byte(s)) }

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported systems
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ref is a short, non-secret name for a link or sign-in in the audit log.
func ref(h [sha256.Size]byte) string { return fmt.Sprintf("%x", h[:4]) }

func (s *Server) writeAudit(event string, fields map[string]any) {
	rec := map[string]any{"time": s.now().UTC().Format(time.RFC3339), "consent": event}
	for k, v := range fields {
		rec[k] = v
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	_, _ = s.audit.Write(append(line, '\n'))
}

// linkable reports whether a link can connect svc: an oauth2 service with a
// sign-in, or a service that sends a fixed key.
func linkable(svc policy.Service) bool {
	switch svc.Auth {
	case policy.AuthGcloudLogin:
		return true
	case policy.AuthOAuth2:
		return svc.OAuth2.CanSignIn()
	case policy.AuthBearer, policy.AuthHeader, policy.AuthQuery, policy.AuthEgressProxy:
		return true
	}
	return false
}

// proxyForm fills the page fields for an egress-proxy service.
func proxyForm(data *pageData, svc policy.Service) {
	e := svc.EgressProxy
	data.Proxy = true
	data.ProxyAsksAddress = e.Address == ""
	data.ProxyAsksType = e.Address == "" && e.Type == ""
}

// proxyValue builds the stored value from an egress-proxy form: the
// credential when the address is in config, otherwise one proxy URL holding
// type, address and credential together.
func proxyValue(r *http.Request, svc policy.Service) (string, error) {
	e := svc.EgressProxy
	user, pass := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("password")
	if e.Address != "" {
		if user == "" || strings.ContainsAny(user, ": \t\r\n") || strings.ContainsAny(pass, "\r\n") || len(user)+len(pass) > 511 {
			return "", errors.New("enter the proxy username (no : or spaces) and password")
		}
		return user + ":" + pass, nil
	}
	proxyType := e.Type
	if proxyType == "" {
		proxyType = r.PostFormValue("type")
	}
	value := strings.TrimSpace(r.PostFormValue("proxy"))
	tls := e.TLS
	// Credentials are literal, not URL-encoded. A password may contain both
	// @ and :, so split at the last @ and then the first credential colon.
	if scheme, rest, ok := strings.Cut(value, "://"); ok && !strings.ContainsAny(scheme, ":@") {
		switch strings.ToLower(scheme) {
		case "http":
			proxyType, tls = policy.ProxyHTTPConnect, false
		case "https":
			proxyType, tls = policy.ProxyHTTPConnect, true
		case "socks5":
			proxyType, tls = policy.ProxySOCKS5, false
		default:
			return "", errors.New("proxy scheme: use http://, https:// or socks5://")
		}
		value = rest
	}
	if proxyType == "" {
		proxyType = policy.ProxyHTTPConnect
	}
	if e.TLS && !tls {
		return "", errors.New("proxy scheme: this service requires HTTPS")
	}
	at := strings.LastIndexByte(value, '@')
	if at < 0 {
		return "", errors.New("proxy credentials missing: use username:password@host:port")
	}
	var hasPassword bool
	user, pass, hasPassword = strings.Cut(value[:at], ":")
	if !hasPassword {
		return "", errors.New("proxy credentials: separate username and password with a colon")
	}
	address := value[at+1:]
	v, err := policy.ProxyURL(proxyType, tls, address, user, pass)
	if err != nil {
		// Policy address errors include the input. Classify failures without
		// echoing it: a malformed paste can leave a password in the address.
		_, port, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			if !strings.Contains(address, ":") || strings.HasSuffix(address, "]") {
				return "", errors.New("proxy port missing: use host:port")
			}
			return "", errors.New("proxy address: use host:port and bracket IPv6 addresses")
		}
		if port == "" {
			return "", errors.New("proxy port missing: use host:port")
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return "", errors.New("proxy port: use a number from 1 to 65535")
		}
		if err := policy.CheckProxyAddress(address); err != nil {
			return "", errors.New("proxy address: use a public IP or valid DNS name")
		}
		// With a valid address, ProxyURL returns only static type/credential errors.
		return "", err
	}
	// The same checks the tunnel makes before every use.
	if _, _, err := e.Resolve(v); err != nil {
		return "", err
	}
	return v, nil
}

// prune drops expired links and sign-ins. Callers hold s.mu.
func (s *Server) prune(now time.Time) {
	for k, l := range s.links {
		if !now.Before(l.expires) {
			delete(s.links, k)
		}
	}
	for k, f := range s.signIns {
		if !now.Before(f.expires) {
			delete(s.signIns, k)
		}
	}
}

// ---- API ----

// APIHandler serves the consent API: POST /links and DELETE /keys/<service>.
func (s *Server) APIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /links", s.createLink)
	mux.HandleFunc("DELETE /keys/{service}", s.deleteKey)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := s.config().Consent
		addr, ok := remoteAddr(r.RemoteAddr)
		if k == nil || !ok || !k.APISourceAllowed(addr) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found || !k.APITokenMatches(token) {
			s.writeAudit("api_refused", map[string]any{"source": addr.String(), "path": r.URL.Path})
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func validLabel(s string) bool {
	if len(s) > maxLabel {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (s *Server) createLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Service    string `json:"service"`
		TTLSeconds int    `json:"ttl_seconds"`
		Label      string `json:"label"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apiError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	cfg := s.config()
	svc, ok := cfg.Services[req.Service]
	if !ok {
		apiError(w, http.StatusNotFound, "unknown service")
		return
	}
	if !linkable(svc) {
		apiError(w, http.StatusBadRequest, "this service cannot be connected by a link (an oauth2 service needs auth_url; signing keys are set by the owner)")
		return
	}
	if svc.Auth == policy.AuthGcloudLogin && s.google == nil {
		apiError(w, http.StatusServiceUnavailable, "Google connection is unavailable")
		return
	}
	ttl := DefaultLinkTTL
	if req.TTLSeconds != 0 {
		// Bounds first: a huge number would overflow the Duration.
		if req.TTLSeconds < 60 || req.TTLSeconds > int(MaxLinkTTL/time.Second) {
			apiError(w, http.StatusBadRequest, "ttl_seconds must be between 60 and 3600")
			return
		}
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if !validLabel(req.Label) {
		apiError(w, http.StatusBadRequest, "label must be at most 100 characters without control characters")
		return
	}
	id := randomToken()
	h := hashOf(id)
	now := s.now()
	expires := now.Add(ttl)
	s.mu.Lock()
	s.prune(now)
	if s.revoking[svc.Key] {
		s.mu.Unlock()
		apiError(w, http.StatusConflict, "disconnect is still in progress")
		return
	}
	if len(s.links) >= maxPending {
		s.mu.Unlock()
		apiError(w, http.StatusTooManyRequests, "too many open links")
		return
	}
	s.links[h] = &link{service: req.Service, key: svc.Key, label: req.Label, expires: expires}
	if svc.Auth == policy.AuthGcloudLogin {
		s.links[h].google = true
		s.links[h].googleEpoch = s.google.Epoch()
	}
	s.mu.Unlock()
	u := cfg.Consent.PublicBase()
	u.Path += "/c/" + id
	s.writeAudit("link_created", map[string]any{"service": req.Service, "link": ref(h), "expires": expires.UTC().Format(time.RFC3339)})
	writeJSON(w, http.StatusCreated, map[string]string{"url": u.String(), "expires_at": expires.UTC().Format(time.RFC3339)})
}

// deleteKey removes the service's stored key. OAuth removal also invalidates
// pending consent and attempts bounded remote revocation.
func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("service")
	svc, ok := s.config().Services[name]
	if !ok {
		apiError(w, http.StatusNotFound, "unknown service")
		return
	}
	if svc.Auth == policy.AuthGcloudLogin && s.google != nil {
		if err := s.google.Disconnect(r.Context()); err != nil {
			apiError(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
		return
	}
	if svc.SignOnly() {
		apiError(w, http.StatusBadRequest, "signing keys are deleted by the owner")
		return
	}
	if svc.Auth == policy.AuthOAuth2 {
		s.deleteOAuthKey(w, r, name, svc)
		return
	}
	keys, err := s.keys.Load()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "store unreadable")
		return
	}
	_, stored := keys[svc.Key]
	if !stored {
		writeJSON(w, http.StatusOK, map[string]any{"deleted": false, "key": svc.Key})
		return
	}
	result := map[string]any{"deleted": true, "key": svc.Key}
	if err := s.keys.Delete(svc.Key); err != nil {
		apiError(w, http.StatusInternalServerError, "could not delete the key")
		return
	}
	s.writeAudit("key_deleted", map[string]any{"service": name, "key": svc.Key, "revoked": result["revoked"]})
	writeJSON(w, http.StatusOK, result)
}

// deleteOAuthKey linearizes local removal against callback publication, without
// holding the consent lock across the provider request. New consent for this
// shared key stays blocked until the old grant's revocation attempt finishes.
func (s *Server) deleteOAuthKey(w http.ResponseWriter, r *http.Request, name string, svc policy.Service) {
	s.mu.Lock()
	if s.revoking[svc.Key] {
		s.mu.Unlock()
		apiError(w, http.StatusConflict, "disconnect is still in progress")
		return
	}
	if s.revoking == nil {
		s.revoking = make(map[string]bool)
	}
	s.revoking[svc.Key] = true
	for h, l := range s.links {
		if l.key == svc.Key {
			delete(s.links, h)
		}
	}
	for h, f := range s.signIns {
		if f.key == svc.Key {
			delete(s.signIns, h)
		}
	}
	keys, err := s.keys.Load()
	value, stored := keys[svc.Key]
	if err == nil && stored {
		err = s.keys.Delete(svc.Key)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.revoking, svc.Key)
		s.mu.Unlock()
	}()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "could not remove the connection")
		return
	}
	result := map[string]any{"deleted": stored, "key": svc.Key}
	if stored && svc.OAuth2.RevokeURL != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		revokeErr := s.revoke(ctx, *svc.OAuth2, value, keys[svc.OAuth2.ClientSecretKey])
		cancel()
		result["revoked"] = revokeErr == nil
		if revokeErr != nil {
			result["revoke_error"] = revokeErr.Error()
		}
	}
	s.writeAudit("key_deleted", map[string]any{"service": name, "key": svc.Key, "revoked": result["revoked"]})
	writeJSON(w, http.StatusOK, result)
}

// revoke tells the provider a refresh token is no longer used (RFC 7009).
func (s *Server) revoke(ctx context.Context, cfg policy.OAuth2, token, secret string) error {
	form := url.Values{"token": {token}, "token_type_hint": {"refresh_token"}, "client_id": {cfg.ClientID}}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("bad revoke_url")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.New("revoke endpoint unreachable")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke endpoint answered %d", resp.StatusCode)
	}
	return nil
}

// ---- Pages ----

// PagesHandler serves the link pages and the OAuth callback under the path
// of public_url, and nothing else.
func (s *Server) PagesHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := s.config().Consent
		if k == nil {
			http.NotFound(w, r)
			return
		}
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		// no-referrer makes browser form POSTs send Origin: null. Keep the
		// origin check usable without sending the capability path as Referer.
		h.Set("Referrer-Policy", "strict-origin")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		public := k.PublicBase()
		if public.Scheme == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		rest, ok := strings.CutPrefix(r.URL.Path, public.Path)
		googleID, googlePage := googlePagePath(rest)
		switch {
		case ok && googlePage:
			s.googlePage(w, r, googleID, public)
		case ok && rest == "/callback" && r.Method == http.MethodGet:
			s.callback(w, r, public)
		case ok && strings.HasPrefix(rest, "/c/") && !strings.Contains(rest[3:], "/") && rest != "/c/":
			id := rest[3:]
			switch r.Method {
			case http.MethodGet:
				s.linkPage(w, r, id)
			case http.MethodPost:
				s.linkSubmit(w, r, id, public)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

// openLink returns the link if it can still be used. Callers hold s.mu.
func (s *Server) openLink(id string, now time.Time) (*link, [sha256.Size]byte, bool) {
	h := hashOf(id)
	l, ok := s.links[h]
	if !ok || !now.Before(l.expires) {
		return nil, h, false
	}
	if l.google && (s.google == nil || l.googleEpoch != s.google.Epoch()) {
		return nil, h, false
	}
	return l, h, true
}

func (s *Server) linkPage(w http.ResponseWriter, r *http.Request, id string) {
	// Opening the page changes nothing: chat apps fetch links to show a
	// preview.
	s.mu.Lock()
	l, _, ok := s.openLink(id, s.now())
	var data pageData
	if ok {
		data = pageData{Service: l.service, Label: l.label}
	}
	s.mu.Unlock()
	if !ok {
		render(w, http.StatusGone, pageData{Message: "This link has expired or was already used. Ask for a new one."})
		return
	}
	svc, known := s.config().Services[data.Service]
	if !known || !linkable(svc) {
		render(w, http.StatusGone, pageData{Message: "This service can no longer be connected. Ask for a new link."})
		return
	}
	data.Form = true
	data.SignIn = svc.Auth == policy.AuthOAuth2 || svc.Auth == policy.AuthGcloudLogin
	data.Google = svc.Auth == policy.AuthGcloudLogin
	if svc.Auth == policy.AuthEgressProxy {
		proxyForm(&data, svc)
	}
	render(w, http.StatusOK, data)
}

// sameOrigin reports whether a form post came from the public page. Browsers
// send Origin on every POST.
func sameOrigin(r *http.Request, public *url.URL) bool {
	return r.Header.Get("Origin") == public.Scheme+"://"+public.Host
}

func cookieName(public *url.URL) string {
	if public.Scheme == "https" {
		return "__Host-keyring-consent"
	}
	return "keyring-consent" // loopback test server only
}

func (s *Server) linkSubmit(w http.ResponseWriter, r *http.Request, id string, public *url.URL) {
	if !sameOrigin(r, public) {
		render(w, http.StatusForbidden, pageData{Message: "Open the link again and use the button on its page."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		render(w, http.StatusBadRequest, pageData{Message: "The form could not be read."})
		return
	}
	cfg := s.config()
	now := s.now()
	s.mu.Lock()
	l, h, ok := s.openLink(id, now)
	if !ok {
		s.mu.Unlock()
		render(w, http.StatusGone, pageData{Message: "This link has expired or was already used. Ask for a new one."})
		return
	}
	svc, known := cfg.Services[l.service]
	if !known || !linkable(svc) || svc.Key != l.key {
		s.mu.Unlock()
		render(w, http.StatusGone, pageData{Message: "This service can no longer be connected. Ask for a new link."})
		return
	}
	if svc.Auth == policy.AuthGcloudLogin {
		s.startGoogle(w, r, l, h, public)
		return
	}
	service, label := l.service, l.label
	if svc.Auth != policy.AuthOAuth2 {
		var value string
		var err error
		retry := pageData{Service: service, Label: l.label, Form: true, Message: "Paste the value, on one line."}
		if svc.Auth == policy.AuthEgressProxy {
			value, err = proxyValue(r, svc)
			proxyForm(&retry, svc)
			if err != nil {
				retry.Message = "Not saved: " + err.Error() + "."
			}
		} else {
			value, err = readValue(r)
		}
		if err != nil {
			// The link stays usable: the person can correct the form.
			s.mu.Unlock()
			render(w, http.StatusBadRequest, retry)
			return
		}
		// Used up before the value is stored: a second post, even at the
		// same moment, finds no link.
		delete(s.links, h)
		s.mu.Unlock()
		if err := s.keys.Set(svc.Key, value); err != nil {
			s.writeAudit("connect_failed", map[string]any{"service": service, "link": ref(h), "reason": "store"})
			render(w, http.StatusInternalServerError, pageData{Message: "The value could not be saved. Ask for a new link."})
			return
		}
		s.writeAudit("connected", map[string]any{"service": service, "key": svc.Key, "link": ref(h), "kind": "value"})
		render(w, http.StatusOK, pageData{Service: service, Label: label, Message: "Saved. You can close this page."})
		return
	}
	if len(s.signIns) >= maxPending {
		s.prune(now)
	}
	if len(s.signIns) >= maxPending {
		s.mu.Unlock()
		render(w, http.StatusServiceUnavailable, pageData{Message: "Too many sign-ins are in progress. Try again in a few minutes."})
		return
	}
	delete(s.links, h)
	state, verifier, browser := randomToken(), randomToken(), randomToken()
	s.signIns[hashOf(state)] = &signIn{
		service:  service,
		key:      svc.Key,
		oauth:    *svc.OAuth2,
		verifier: verifier,
		browser:  hashOf(browser),
		expires:  now.Add(signInTTL),
	}
	s.mu.Unlock()

	challenge := sha256.Sum256([]byte(verifier))
	auth, _ := url.Parse(svc.OAuth2.AuthURL) // validated at load
	q := url.Values{}
	for k, v := range svc.OAuth2.AuthParams {
		q.Set(k, v)
	}
	q.Set("response_type", "code")
	q.Set("client_id", svc.OAuth2.ClientID)
	q.Set("redirect_uri", callbackURL(public))
	if len(svc.OAuth2.Scopes) > 0 {
		q.Set("scope", strings.Join(svc.OAuth2.Scopes, " "))
	}
	q.Set("state", state)
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	auth.RawQuery = q.Encode()
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName(public),
		Value:    browser,
		Path:     "/",
		MaxAge:   int(signInTTL / time.Second),
		HttpOnly: true,
		Secure:   public.Scheme == "https",
		// Lax: the provider sends the person back with a top-level GET.
		SameSite: http.SameSiteLaxMode,
	})
	s.writeAudit("sign_in_started", map[string]any{"service": service, "link": ref(h)})
	http.Redirect(w, r, auth.String(), http.StatusSeeOther)
}

func callbackURL(public *url.URL) string {
	u := *public
	u.Path += "/callback"
	return u.String()
}

var errorCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

func (s *Server) callback(w http.ResponseWriter, r *http.Request, public *url.URL) {
	q := r.URL.Query()
	state := q.Get("state")
	h := hashOf(state)
	now := s.now()
	s.mu.Lock()
	f, ok := s.signIns[h]
	// Mark used before releasing the lock, but keep the entry until publication.
	// Disconnect removes it even while the code exchange is in flight.
	if ok && !f.used {
		f.used = true
	} else {
		ok = false
	}
	s.mu.Unlock()
	if state == "" || !ok || !now.Before(f.expires) {
		render(w, http.StatusBadRequest, pageData{Message: "This sign-in has expired or was already used. Ask for a new link."})
		return
	}
	defer func() {
		s.mu.Lock()
		if s.signIns[h] == f {
			delete(s.signIns, h)
		}
		s.mu.Unlock()
	}()
	expire := &http.Cookie{Name: cookieName(public), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: public.Scheme == "https", SameSite: http.SameSiteLaxMode}
	http.SetCookie(w, expire)
	cookie, err := r.Cookie(cookieName(public))
	got := hashOf("")
	if err == nil {
		got = hashOf(cookie.Value)
	}
	if err != nil || subtle.ConstantTimeCompare(got[:], f.browser[:]) != 1 {
		s.writeAudit("connect_failed", map[string]any{"service": f.service, "reason": "browser"})
		render(w, http.StatusForbidden, pageData{Message: "Finish the sign-in in the browser where you opened the link. Ask for a new link."})
		return
	}
	if code := q.Get("error"); code != "" {
		if !errorCode.MatchString(code) {
			code = "error"
		}
		s.writeAudit("connect_failed", map[string]any{"service": f.service, "reason": "provider " + code})
		render(w, http.StatusOK, pageData{Service: f.service, Message: "Sign-in was not completed (" + code + "). Ask for a new link to try again.", Problem: true})
		return
	}
	svc, known := s.config().Services[f.service]
	if !known || svc.Key != f.key || svc.Auth != policy.AuthOAuth2 || !svc.OAuth2.Equal(&f.oauth) {
		s.writeAudit("connect_failed", map[string]any{"service": f.service, "reason": "service changed"})
		render(w, http.StatusConflict, pageData{Message: "This service's settings changed during the sign-in. Ask for a new link."})
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		render(w, http.StatusBadRequest, pageData{Message: "The provider sent no sign-in code. Ask for a new link."})
		return
	}
	keys, err := s.keys.Load()
	if err != nil {
		render(w, http.StatusInternalServerError, pageData{Message: "The keyring could not read its store. Ask for a new link."})
		return
	}
	var secret string
	if f.oauth.ClientSecretKey != "" {
		secret = keys[f.oauth.ClientSecretKey]
		if secret == "" {
			s.writeAudit("connect_failed", map[string]any{"service": f.service, "reason": "no client secret"})
			render(w, http.StatusServiceUnavailable, pageData{Message: "This service is not set up yet (no client secret). Tell the person who sent the link."})
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	refresh, err := s.exchange(ctx, f.oauth, code, f.verifier, callbackURL(public), secret)
	cancel()
	if err != nil {
		s.writeAudit("connect_failed", map[string]any{"service": f.service, "reason": err.Error()})
		render(w, http.StatusBadGateway, pageData{Service: f.service, Message: "Connecting failed: " + err.Error() + ". Ask for a new link."})
		return
	}
	s.mu.Lock()
	current, known := s.config().Services[f.service]
	if s.signIns[h] != f || !s.now().Before(f.expires) || !known ||
		current.Key != f.key || current.Auth != policy.AuthOAuth2 || !current.OAuth2.Equal(&f.oauth) {
		s.mu.Unlock()
		render(w, http.StatusConflict, pageData{Message: "This connection was removed or changed during sign-in. Ask for a new link."})
		return
	}
	err = s.keys.Set(f.key, refresh)
	s.mu.Unlock()
	if err != nil {
		s.writeAudit("connect_failed", map[string]any{"service": f.service, "reason": "store"})
		render(w, http.StatusInternalServerError, pageData{Message: "The sign-in worked but could not be saved. Ask for a new link."})
		return
	}
	s.writeAudit("connected", map[string]any{"service": f.service, "key": svc.Key, "kind": "oauth2"})
	render(w, http.StatusOK, pageData{Service: f.service, Message: "Connected. You can close this page."})
}

// exchange trades the authorization code for tokens (RFC 6749 4.1.3, RFC
// 7636) and returns the refresh token. Errors are safe to show: never a
// token, a secret or the provider's free text.
func (s *Server) exchange(ctx context.Context, cfg policy.OAuth2, code, verifier, redirectURI, secret string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {cfg.ClientID},
		"code_verifier": {verifier},
	}
	if secret != "" {
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("bad token endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", errors.New("the provider could not be reached")
	}
	defer resp.Body.Close()
	var body struct {
		RefreshToken string  `json:"refresh_token"`
		Error        string  `json:"error"`
		Scope        *string `json:"scope"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		code := "no error code"
		if decodeErr == nil && errorCode.MatchString(body.Error) {
			code = body.Error
		}
		return "", fmt.Errorf("the provider refused the sign-in code (%s)", code)
	}
	if decodeErr != nil {
		return "", errors.New("the provider sent invalid JSON")
	}
	// RFC 6749 section 5.1 permits omission only when the granted scopes
	// equal those requested. An explicit partial grant must not activate
	// services that share this credential.
	if body.Scope != nil {
		granted := strings.Fields(*body.Scope)
		for _, required := range cfg.Scopes {
			if !slices.Contains(granted, required) {
				return "", errors.New("the provider did not grant all required permissions")
			}
		}
	}
	if !usableToken(body.RefreshToken) {
		return "", errors.New("the provider sent no refresh token (check the service's auth_params, e.g. access_type=offline and prompt=consent for Google)")
	}
	return body.RefreshToken, nil
}

func usableToken(t string) bool {
	if t == "" || len(t) > 8192 {
		return false
	}
	for i := range len(t) {
		if t[i] < 0x21 || t[i] > 0x7e {
			return false
		}
	}
	return true
}

func readValue(r *http.Request) (string, error) {
	v := strings.TrimRight(r.PostFormValue("value"), "\r\n")
	if v == "" || strings.ContainsAny(v, "\r\n") {
		return "", errors.New("paste the value on one line")
	}
	return v, nil
}

func remoteAddr(hostport string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

type pageData struct {
	Service, Label, Message string
	Form, SignIn            bool
	// Proxy: an egress-proxy form; it asks for the address (and the type)
	// when the service's config leaves them to the person.
	Proxy, ProxyAsksAddress, ProxyAsksType bool
	// Status is the HTTP status, set by render: it picks how a message
	// looks (done, or a problem). Problem marks a failure shown with 200
	// (the provider refused the sign-in) so it does not look like success.
	Status                                                int
	Problem                                               bool
	Google, GoogleCode, GoogleRetry, GoogleTerms, Refresh bool
	GoogleURL, GoogleAccount, GoogleProject               string
}

// page is plain HTML and inline CSS: the pages' CSP allows inline styles
// only, no scripts, images or fonts. The look follows the site that sends
// people here (system font, light grey, thin lines, rounded buttons); it
// names no product, since one keyring host can serve several.
var page = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
{{if .Refresh}}<meta http-equiv="refresh" content="2">{{end}}
<title>{{if .Label}}Connect {{.Label}}{{else if .Service}}Connect {{.Service}}{{else}}Private connection page{{end}}</title>
<style>
:root{--bg:#f7f8fa;--card:#fff;--ink:#16181d;--mut:#5f6670;--line:#e6e9ee;--blue:#2466e0;--green:#1f7d5a;--red:#b42318;--font:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,"Helvetica Neue",Arial,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font:400 17px/1.5 var(--font);-webkit-font-smoothing:antialiased;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:28px 18px 40px}
.top{width:100%;max-width:480px;display:flex;align-items:center;gap:10px;font:500 11px/1 var(--font);letter-spacing:.22em;text-transform:uppercase;color:var(--mut)}
.top svg{flex:none}
.card{width:100%;max-width:480px;margin-top:22px;background:var(--card);border:1px solid var(--line);border-radius:22px;padding:32px 28px 30px;box-shadow:0 1px 2px rgba(22,24,29,.04),0 20px 40px -24px rgba(22,24,29,.18)}
h1{font:500 32px/1.12 var(--font);letter-spacing:-.03em}
.for{margin-top:10px;color:var(--mut)}
.for b{color:var(--ink);font-weight:600}
p{margin-top:16px}
.msg{display:flex;gap:12px;align-items:flex-start;margin-top:20px;padding:16px 18px;border-radius:14px;background:var(--bg);border:1px solid var(--line)}
.msg svg{flex:none;margin-top:2px}
.msg.ok{background:#eefaf4;border-color:#c9ebd9;color:#14513b}
.msg.err{background:#fef3f2;border-color:#f8d4d0;color:#7a271a}
.msg.only{margin-top:0}
form{margin-top:22px}
label{display:block;font:500 15px/1.3 var(--font);margin:18px 0 8px}
input,select{width:100%;font:400 17px/1.3 var(--font);color:var(--ink);background:var(--card);border:1px solid #d6dae1;border-radius:14px;padding:15px 16px;outline:none;-webkit-appearance:none;appearance:none}
select{background-image:linear-gradient(45deg,transparent 50%,var(--mut) 50%),linear-gradient(135deg,var(--mut) 50%,transparent 50%);background-position:calc(100% - 22px) 50%,calc(100% - 16px) 50%;background-size:6px 6px;background-repeat:no-repeat;padding-right:42px}
input:focus,select:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(36,102,224,.18)}
.btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;margin-top:22px;font:500 17px/1 var(--font);color:#fff;background:var(--ink);border:0;border-radius:999px;padding:18px 24px;cursor:pointer;box-shadow:0 8px 20px -8px rgba(22,24,29,.45)}
.btn:hover{background:#000}
.btn:focus-visible{outline:3px solid var(--blue);outline-offset:3px}
.hint{margin-top:10px;font-size:14px;color:var(--mut)}
.note{display:flex;gap:10px;align-items:flex-start;margin-top:24px;padding-top:20px;border-top:1px solid var(--line);font-size:14px;color:var(--mut)}
.note svg{flex:none;margin-top:1px}
.foot{max-width:480px;margin-top:22px;text-align:center;font-size:13px;color:var(--mut)}
@media (max-width:480px){body{padding:20px 14px 32px}.card{padding:26px 20px 24px;border-radius:20px}h1{font-size:27px}}
</style>
</head><body>
<div class="top"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2.5"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>Private connection page</div>
<main class="card">
{{if .Label}}<h1>Connect {{.Label}}</h1>{{else if .Service}}<h1>Connect {{.Service}}</h1>{{end}}
{{if .Message}}<div class="msg{{if or .Problem (ge .Status 400)}} err{{else if not (or .Form .Refresh)}} ok{{end}}{{if not (or .Label .Service)}} only{{end}}" role="{{if or .Problem (ge .Status 400)}}alert{{else}}status{{end}}">
{{if or .Problem (ge .Status 400)}}<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9.5"/><path d="M12 7.5v5.5M12 16.5v.01"/></svg>{{else if not (or .Form .Refresh)}}<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9.5"/><path d="m7.5 12.5 3 3 6-6.5"/></svg>{{end}}<span>{{.Message}}</span></div>{{end}}
{{if .Google}}
{{if .SignIn}}<p class="hint">Connect your own Google Drive and Sheets. After sign-in, this creates a Google Cloud project in your account and enables their APIs. No billing account is attached. Your Google credentials stay in your private keyring, not with the assistant.</p>{{end}}
{{with .GoogleAccount}}<p class="hint">Google account: {{.}}</p>{{end}}
{{with .GoogleProject}}<p class="hint">Your Google Cloud project: {{.}}</p>{{end}}
{{if .GoogleURL}}<a class="btn" href="{{.GoogleURL}}" target="_blank" rel="noopener noreferrer">Open Google sign-in</a>{{end}}
{{if .GoogleTerms}}<p class="hint">Open <a href="https://console.cloud.google.com/" target="_blank" rel="noopener noreferrer">Google Cloud Console</a> with the same Google account and accept its terms. Then return here and retry.</p>{{end}}
{{end}}
{{if .Form}}<form method="post" autocomplete="off">
{{if .GoogleCode}}<label for="code">Google verification code</label>
<input id="code" type="password" name="code" required maxlength="4096" autocomplete="off" spellcheck="false">
<button class="btn" type="submit">Finish Google sign-in</button>
{{else if .GoogleRetry}}<input type="hidden" name="action" value="retry">
<button class="btn" type="submit">Retry connection</button>
{{else if .SignIn}}<p>You will sign in on the provider's own page. Your password is never seen here.</p>
<button class="btn" type="submit">Sign in and connect</button>
{{else if .Proxy}}<p>Your proxy's details are stored only in your own keyring and never shown again. The password is only ever sent to the proxy address saved with it.</p>
{{if .ProxyAsksType}}<label for="type">Type</label><select id="type" name="type"><option value="http-connect">HTTP</option><option value="socks5">SOCKS5</option></select>{{end}}
{{if .ProxyAsksAddress}}<label for="proxy">Your proxy</label><input id="proxy" type="password" name="proxy" required autocomplete="off" spellcheck="false" placeholder="username:password@host:port">
<p class="hint">Paste the whole proxy, as your provider gave it. An optional http://, https:// or socks5:// at the start sets its type. Username and password are needed. Passwords may contain @ and :, paste them as they are.</p>
{{else}}<label for="username">Username</label><input id="username" name="username" required autocomplete="off" spellcheck="false">
<label for="password">Password</label><input id="password" type="password" name="password" autocomplete="off" spellcheck="false">{{end}}
<button class="btn" type="submit">Save</button>
{{else}}<p>Paste the key. It is stored only in your own keyring and never shown again.</p>
<label for="value">Key</label><input id="value" type="password" name="value" required autocomplete="off" spellcheck="false">
<button class="btn" type="submit">Save</button>
{{end}}</form>
<div class="note"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg><span>This link works once and expires soon. Don't forward it to anyone.</span></div>{{end}}
</main>
<p class="foot">Never type a password into the chat. Only on a page like this one.</p>
</body></html>
`))

func render(w http.ResponseWriter, status int, data pageData) {
	data.Status = status
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = page.Execute(w, data)
}
