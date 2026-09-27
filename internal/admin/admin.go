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
	"net/netip"
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
	// Login limits: after freeFailures failed logins in an hour, each further
	// attempt waits longer; after lockFailures the login is closed for an hour.
	freeFailures = 5
	lockFailures = 20
	maxBodyBytes = 64 << 10
)

type session struct {
	csrf              string
	created, lastSeen time.Time
}

// Server is the dashboard handler.
type Server struct {
	hosts map[string]bool // accepted Host values, e.g. 127.0.0.1:7702, localhost:7702
	// httpsHost is served through a local HTTPS proxy, to devices only.
	httpsHost string
	devices   map[netip.Addr]bool
	audit     io.Writer
	now       func() time.Time
	mux       *http.ServeMux
	homePath  string // where "/" sends a logged-in user; "" shows the plain home page

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
	mux.HandleFunc("GET /api/session", s.withSession(s.sessionInfo))
	mux.HandleFunc("GET /static/app.css", serveCSS)
	mux.HandleFunc("GET /static/app.js", serveJS)
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

// Confirm checks the password for a sensitive change. Every change asks for
// it: browsers send the session cookie to every port of the host, so a local
// web server the owner visits could replay a stolen session, and no time
// window may make that enough. Attempts count toward the login limits.
func (s *Server) Confirm(sid, password string) bool {
	if password == "" { // forgot to type it: not a guess
		return false
	}
	if _, ok := s.beginAttempt(); !ok {
		s.writeAudit("confirm_refused_rate_limit", sid)
		return false
	}
	if !s.passwordMatches(password) {
		s.writeAudit("confirm_failed", sid)
		return false
	}
	s.attemptSucceeded()
	return true
}

// SetClock replaces the clock (tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// SetHome makes "/" redirect logged-in users to path.
func (s *Server) SetHome(path string) { s.homePath = path }

// Audit writes one admin event with the session reference and extra fields.
func (s *Server) Audit(event, sid string, fields map[string]any) {
	rec := map[string]any{"time": s.now().UTC().Format(time.RFC3339), "admin": event}
	if sid != "" {
		rec["session"] = SessionRef(sid)
	}
	for k, v := range fields {
		rec[k] = v
	}
	s.WriteAudit(rec)
}

// ClientHeader carries the client's IP from the local HTTPS proxy.
const ClientHeader = "X-Keyring-Client"

// AllowHTTPS also serves the dashboard as https://host through a proxy on
// this machine, to the given device IPs only. Call it before serving.
func (s *Server) AllowHTTPS(host string, devices []netip.Addr) {
	s.httpsHost = host
	s.devices = map[netip.Addr]bool{}
	for _, d := range devices {
		s.devices[d.Unmap()] = true
	}
}

// viaHTTPS reports whether r came through the HTTPS proxy's name.
func (s *Server) viaHTTPS(r *http.Request) bool {
	return s.httpsHost != "" && r.Host == s.httpsHost
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
	scheme := "http://"
	switch {
	case s.viaHTTPS(r):
		// Only the proxy reaches this name from outside the machine, and it
		// sets the header; a local process could forge it, but could as well
		// use the loopback address directly.
		ip, err := netip.ParseAddr(r.Header.Get(ClientHeader))
		if err != nil || !s.devices[ip.Unmap()] {
			s.Audit("device_refused", "", map[string]any{"client": r.Header.Get(ClientHeader)})
			http.Error(w, "this device may not use the dashboard", http.StatusForbidden)
			return
		}
		scheme = "https://"
		h.Set("Strict-Transport-Security", "max-age=31536000")
	case !s.hosts[r.Host]:
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if r.Header.Get("Origin") != scheme+r.Host {
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

// beginAttempt applies the login limits and, in the same step, counts the
// attempt as a failure until attemptSucceeded clears it, so requests sent at
// once cannot all pass the check before any failure is recorded. It returns
// how long to wait when refused.
func (s *Server) beginAttempt() (time.Duration, bool) {
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
	s.failures = append(s.failures, now)
	switch n := len(s.failures); {
	case n >= lockFailures:
		s.blocked = now.Add(time.Hour)
	case n > freeFailures:
		wait := time.Second << min(n-freeFailures, 6) // 2s, 4s, ... 64s
		s.blocked = now.Add(wait)
	}
	return 0, true
}

// attemptSucceeded forgets the failures: the password was right.
func (s *Server) attemptSucceeded() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = nil
	s.blocked = time.Time{}
}

func (s *Server) passwordMatches(password string) bool {
	s.mu.Lock()
	p := s.password
	s.mu.Unlock()
	return p.Matches(password)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if wait, ok := s.beginAttempt(); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		s.writeAudit("login_refused_rate_limit", "")
		http.Error(w, "too many failed logins; try again later", http.StatusTooManyRequests)
		return
	}
	if !s.passwordMatches(r.PostFormValue("password")) {
		s.writeAudit("login_failed", "")
		s.renderLogin(w, http.StatusUnauthorized, "Wrong password.")
		return
	}
	s.attemptSucceeded()
	sid, csrf := randomToken(), randomToken()
	now := s.now()
	s.mu.Lock()
	s.sessions[sid] = &session{csrf: csrf, created: now, lastSeen: now}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: sid, Path: "/", HttpOnly: true, Secure: s.viaHTTPS(r), SameSite: http.SameSiteStrictMode})
	s.writeAudit("login", sid)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sid string) {
	s.mu.Lock()
	delete(s.sessions, sid)
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.viaHTTPS(r), SameSite: http.SameSiteStrictMode})
	s.writeAudit("logout", sid)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) sessionInfo(w http.ResponseWriter, r *http.Request, sid string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"csrf": s.CSRF(sid)})
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, sid string) {
	if s.homePath != "" {
		http.Redirect(w, r, s.homePath, http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pages.ExecuteTemplate(w, "home", map[string]string{"CSRF": s.CSRF(sid)})
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

// js is the dashboard's only script: a copy button for a token shown once.
// A button with data-copy="ID" copies the value of the element with that ID.
const js = `document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-copy]");
  if (!b) return;
  var el = document.getElementById(b.dataset.copy);
  el.select();
  navigator.clipboard.writeText(el.value).then(function () { b.textContent = "Copied"; });
});
`

func serveJS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	_, _ = io.WriteString(w, js)
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
.error{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:8px 10px}
.notice{background:#ecfdf5;border:1px solid #a7f3d0;border-radius:8px;padding:8px 10px}
nav.tabs{display:flex;gap:6px}nav.tabs a{padding:6px 12px;border-radius:999px;color:#15181d;text-decoration:none;border:1px solid #e5e7eb;background:#fff}nav.tabs a.on{background:#15181d;color:#fff;border-color:#15181d}
.bar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}.bar form{display:flex;gap:8px}.bar input{margin:0;width:240px}
a.btn{display:inline-block;background:#4f46e5;color:#fff;border-radius:8px;padding:9px 16px;font-weight:600;text-decoration:none}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;font-size:14px}
th,td{text-align:left;padding:10px 14px;border-bottom:1px solid #e5e7eb;vertical-align:middle}th{color:#6b7280;font-size:12px;text-transform:uppercase;letter-spacing:.03em;background:#fafafa}
td a{color:#15181d;font-weight:600}code{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}.masked{letter-spacing:2px;color:#9ca3af}.mute{color:#6b7280}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;background:#cbd5e1}.dot.ok{background:#16a34a}.dot.bad{background:#dc2626}.dot.warn{background:#d97706}
.chip{display:inline-block;font-size:12px;padding:2px 8px;border-radius:999px;background:#f1f5f9;margin:1px 2px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px 18px;margin-bottom:14px;max-width:720px}.card h2{font-size:16px;margin:0 0 10px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}.row label{flex:1;min-width:160px}
select{display:block;width:100%;margin:6px 0 14px;padding:9px 10px;border:1px solid #e5e7eb;border-radius:8px;font:inherit;background:#fff}
button.danger{background:#dc2626}.check{display:flex;gap:8px;align-items:center;color:#15181d;font-size:14px;margin-bottom:12px}.check input{width:auto;margin:0}
dl{display:grid;grid-template-columns:140px 1fr;gap:6px 12px;margin:0}dt{color:#6b7280}dd{margin:0}
.grid{overflow-x:auto}.grid td,.grid th{text-align:center;white-space:nowrap}.grid td:first-child,.grid th:first-child{text-align:left}
.cell{display:inline-block;min-width:92px;padding:6px 8px;border-radius:8px;text-decoration:none;font-weight:500;font-size:13px}
.cell.on{background:#ecfdf5;color:#065f46;border:1px solid #a7f3d0}.cell.off{background:#f8fafc;color:#94a3b8;border:1px dashed #e2e8f0}.cell.ended{background:#fff7ed;color:#9a3412;border:1px solid #fed7aa}
.cell small{display:block;font-weight:400;color:#6b7280}textarea{display:block;width:100%;min-height:80px;margin:6px 0 14px;padding:9px 10px;border:1px solid #e5e7eb;border-radius:8px;font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
.token{display:flex;gap:8px}.token input{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;margin:0}.warnbox{background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:8px 10px}`

// CSRF returns the session's CSRF token, for forms ("" once the session has
// ended, for instance by a logout in another tab).
func (s *Server) CSRF(sid string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[sid]; ok {
		return sess.csrf
	}
	return ""
}
