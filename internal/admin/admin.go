// Package admin serves the keyring dashboard on a loopback listener. Every
// request is checked before routing: the Host must name the listener (DNS
// rebinding), a change must come from the same origin with the session's CSRF
// token, and the session must be current. The proxy never serves this.
package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cookieName  = "keyring_session"
	csrfField   = "csrf"
	csrfHeader  = "X-CSRF-Token"
	IdleTimeout = 30 * time.Minute
	MaxLifetime = 8 * time.Hour
	// ReauthWindow: sensitive changes need the password again after this.
	ReauthWindow = 5 * time.Minute
	// Login limits: after freeFailures failed logins in an hour, each further
	// attempt waits longer; after lockFailures the login is closed for an hour.
	freeFailures = 5
	lockFailures = 20
	maxBodyBytes = 64 << 10
)

type session struct {
	csrf                        string
	created, lastSeen, lastAuth time.Time
}

// Server is the dashboard handler.
type Server struct {
	hosts map[string]bool // accepted Host values, e.g. 127.0.0.1:7702, localhost:7702
	audit io.Writer
	now   func() time.Time
	mux   *http.ServeMux

	mu       sync.Mutex
	password PasswordHash
	sessions map[string]*session
	failures []time.Time
	blocked  time.Time

	auditMu sync.Mutex
}

// New builds the dashboard for the loopback address listen ("127.0.0.1:7702").
func New(listen string, password PasswordHash, audit io.Writer) *Server {
	_, port, _ := net.SplitHostPort(listen)
	s := &Server{
		hosts:    map[string]bool{listen: true, "localhost:" + port: true},
		audit:    audit,
		now:      time.Now,
		password: password,
		sessions: map[string]*session{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.withSession(s.logout))
	mux.HandleFunc("POST /reauth", s.withSession(s.reauth))
	mux.HandleFunc("GET /api/session", s.withSession(s.sessionInfo))
	mux.HandleFunc("GET /static/app.css", serveCSS)
	mux.HandleFunc("GET /{$}", s.withSession(s.home))
	s.mux = mux
	return s
}

// SetPassword replaces the password hash. If it changed, every session ends.
func (s *Server) SetPassword(p PasswordHash) (changed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.password.Equal(p) {
		return false
	}
	s.password = p
	s.sessions = map[string]*session{}
	return true
}

// Handle adds a route that needs a current session. Later steps register
// the keys and access pages through it.
func (s *Server) Handle(pattern string, h func(w http.ResponseWriter, r *http.Request, sid string)) {
	s.mux.HandleFunc(pattern, s.withSession(h))
}

// RecentlyAuthenticated reports whether the session entered the password
// within ReauthWindow. Sensitive handlers must check it.
func (s *Server) RecentlyAuthenticated(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	return ok && s.now().Sub(sess.lastAuth) < ReauthWindow
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	// same-origin, not no-referrer: with no-referrer Chrome sends
	// "Origin: null" on the dashboard's own form posts, which the Origin check
	// below must refuse, so nobody could log in.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	if !s.hosts[r.Host] {
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.Header.Get("Origin") != "http://"+r.Host {
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	}
	s.mux.ServeHTTP(w, r)
}

// withSession requires a current session and, for changes, its CSRF token.
func (s *Server) withSession(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sid, ok := s.current(r)
		if !ok {
			if r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "not logged in", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			token := r.Header.Get(csrfHeader)
			if token == "" {
				token = r.PostFormValue(csrfField)
			}
			if !s.csrfMatches(sid, token) {
				http.Error(w, "missing or wrong CSRF token", http.StatusForbidden)
				return
			}
		}
		next(w, r, sid)
	}
}

func (s *Server) current(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	if !ok {
		return "", false
	}
	now := s.now()
	if now.Sub(sess.lastSeen) >= IdleTimeout || now.Sub(sess.created) >= MaxLifetime {
		delete(s.sessions, c.Value)
		return "", false
	}
	sess.lastSeen = now
	return c.Value, true
}

func (s *Server) csrfMatches(sid, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	return ok && token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(sess.csrf)) == 1
}

// allowAttempt applies the login limits. It returns how long to wait when
// refused.
func (s *Server) allowAttempt() (time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	cut := now.Add(-time.Hour)
	kept := s.failures[:0]
	for _, t := range s.failures {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	s.failures = kept
	if now.Before(s.blocked) {
		return s.blocked.Sub(now), false
	}
	return 0, true
}

func (s *Server) recordFailure() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.failures = append(s.failures, now)
	switch n := len(s.failures); {
	case n >= lockFailures:
		s.blocked = now.Add(time.Hour)
	case n > freeFailures:
		wait := time.Second << min(n-freeFailures, 6) // 2s, 4s, ... 64s
		s.blocked = now.Add(wait)
	}
}

func (s *Server) passwordMatches(password string) bool {
	s.mu.Lock()
	p := s.password
	s.mu.Unlock()
	return p.Matches(password)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if wait, ok := s.allowAttempt(); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		s.writeAudit("login_refused_rate_limit", "")
		http.Error(w, "too many failed logins; try again later", http.StatusTooManyRequests)
		return
	}
	if !s.passwordMatches(r.PostFormValue("password")) {
		s.recordFailure()
		s.writeAudit("login_failed", "")
		s.renderLogin(w, http.StatusUnauthorized, "Wrong password.")
		return
	}
	sid, csrf := randomToken(), randomToken()
	now := s.now()
	s.mu.Lock()
	s.sessions[sid] = &session{csrf: csrf, created: now, lastSeen: now, lastAuth: now}
	s.failures = nil
	s.blocked = time.Time{}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.writeAudit("login", sid)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sid string) {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.writeAudit("logout", sid)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) reauth(w http.ResponseWriter, r *http.Request, sid string) {
	if wait, ok := s.allowAttempt(); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		http.Error(w, "too many failed attempts; try again later", http.StatusTooManyRequests)
		return
	}
	if !s.passwordMatches(r.PostFormValue("password")) {
		s.recordFailure()
		s.writeAudit("reauth_failed", sid)
		http.Error(w, "wrong password", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	if sess, ok := s.sessions[sid]; ok {
		sess.lastAuth = s.now()
	}
	s.mu.Unlock()
	s.writeAudit("reauth", sid)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sessionInfo(w http.ResponseWriter, r *http.Request, sid string) {
	s.mu.Lock()
	csrf := s.sessions[sid].csrf
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"csrf": csrf, "recently_authenticated": s.RecentlyAuthenticated(sid)})
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, sid string) {
	s.mu.Lock()
	csrf := s.sessions[sid].csrf
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.ExecuteTemplate(w, "home", map[string]string{"CSRF": csrf})
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.renderLogin(w, http.StatusOK, "")
}

func (s *Server) renderLogin(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pages.ExecuteTemplate(w, "login", map[string]string{"Message": message})
}

// audit lines use the same JSON-lines log as the proxy. A session is named
// by a short fingerprint, never by its cookie value.
func (s *Server) writeAudit(event, sid string) {
	rec := map[string]any{"time": s.now().UTC().Format(time.RFC3339), "admin": event}
	if sid != "" {
		rec["session"] = SessionRef(sid)
	}
	s.WriteAudit(rec)
}

// WriteAudit appends one JSON line to the audit log.
func (s *Server) WriteAudit(rec map[string]any) {
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	_, _ = s.audit.Write(append(line, '\n'))
}

// SessionRef is a short, non-secret name for a session in logs.
func SessionRef(sid string) string {
	if len(sid) < 8 {
		return "?"
	}
	return sid[:8]
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("keyring admin: no randomness: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func serveCSS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = io.WriteString(w, css)
}

var pages = template.Must(template.New("pages").Parse(`
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Keyring</title><link rel="stylesheet" href="/static/app.css"></head><body>{{end}}
{{define "login"}}{{template "head"}}
<main class="narrow"><h1>Keyring</h1>
{{with .Message}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/login"><label>Password<input type="password" name="password" autocomplete="current-password" autofocus required></label><button>Log in</button></form>
</main></body></html>{{end}}
{{define "home"}}{{template "head"}}
<header class="top"><h1>Keyring</h1><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="ghost">Log out</button></form></header>
<main><p>Logged in. The keys and access pages come next.</p></main></body></html>{{end}}
`))

const css = `*{box-sizing:border-box}body{margin:0;font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f6f7f9;color:#15181d}
main{padding:24px;max-width:1180px}main.narrow{max-width:360px;margin:12vh auto}
h1{font-size:22px;margin:0 0 16px}header.top{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid #e5e7eb;background:#fff}header.top h1{margin:0}
label{display:block;font-size:13px;color:#6b7280}input{display:block;width:100%;margin:6px 0 14px;padding:9px 10px;border:1px solid #e5e7eb;border-radius:8px;font:inherit;color:#15181d}
button{background:#4f46e5;color:#fff;border:0;border-radius:8px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer}button.ghost{background:#fff;color:#15181d;border:1px solid #e5e7eb}
.error{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:8px 10px}`
