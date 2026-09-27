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

// js is the dashboard's only script, and the pages work without it: a copy
// button for a token shown once (data-copy="ID"), and selects that act when
// changed (data-autosubmit submits the form; a form with data-pathpick opens
// its action with the chosen value in place of the final "-").
const js = `document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-copy]");
  if (!b) return;
  var el = document.getElementById(b.dataset.copy);
  el.select();
  navigator.clipboard.writeText(el.value).then(function () { b.textContent = "Copied"; });
});
document.addEventListener("change", function (e) {
  var t = e.target;
  if (t.matches("select[data-autosubmit]")) t.form.submit();
  var f = t.closest("form[data-pathpick]");
  if (f && t.value) location.href = f.getAttribute("action").replace(/\/-$/, "/" + encodeURIComponent(t.value));
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
{{define "head"}}<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><meta name="color-scheme" content="light dark"><title>Keyring</title><link rel="stylesheet" href="/static/app.css"></head><body>{{end}}
{{define "login"}}{{template "head"}}
<main class="narrow"><h1>Keyring</h1>
{{with .Message}}<p class="error">{{.}}</p>{{end}}
<form method="post" action="/login" class="card"><label>Password<input type="password" name="password" autocomplete="current-password" autofocus required></label><button>Log in</button></form>
</main></body></html>{{end}}
{{define "home"}}{{template "head"}}
<header class="top"><h1>Keyring</h1><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="ghost">Log out</button></form></header>
<main><p>Logged in. The keys and access pages come next.</p></main></body></html>{{end}}
`))

const css = `:root{--bg:#f5f6f8;--card:#fff;--text:#111418;--mute:#667085;--line:#e4e7ec;--brand:#4f46e5;--brand-text:#fff;--ok:#067647;--ok-bg:#ecfdf3;--bad:#b42318;--bad-bg:#fef3f2;--warn:#b54708;--warn-bg:#fffaeb;--chip:#f2f4f7;--radius:14px;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0c0e12;--card:#161a21;--text:#eceef2;--mute:#98a2b3;--line:#262b35;--brand:#7c74ff;--chip:#222833;--ok:#47cd89;--ok-bg:#0e2a1d;--bad:#f97066;--bad-bg:#2d1411;--warn:#fdb022;--warn-bg:#2b200a}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
a{color:inherit}.wrap{max-width:760px;margin:0 auto;padding:0 16px}
main.wrap{padding-top:18px;padding-bottom:calc(40px + env(safe-area-inset-bottom))}
header.top{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line);padding-top:env(safe-area-inset-top)}
header.top .wrap{display:flex;align-items:center;gap:12px;height:56px}
.brand{font-weight:700;font-size:18px;text-decoration:none;margin-right:auto}
.tabs{display:flex;gap:4px;background:var(--chip);padding:3px;border-radius:10px}
.tabs a{padding:6px 14px;border-radius:8px;text-decoration:none;font-size:15px;color:var(--mute)}.tabs a.on{background:var(--card);color:var(--text);font-weight:600;box-shadow:0 1px 2px rgba(0,0,0,.08)}
.logout{margin:0}button.link{background:none;border:0;color:var(--mute);padding:8px 4px;font:inherit;font-size:14px;min-height:0}
h1{font-size:24px;line-height:1.25;margin:0}h2{font-size:17px;margin:0 0 12px}
.head{display:flex;align-items:center;flex-wrap:wrap;gap:8px 12px;margin:4px 0 16px}.head h1{margin-right:auto;word-break:break-all}
.back{flex-basis:100%;font-size:14px;color:var(--mute);text-decoration:none}.back::before{content:"‹ "}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:16px;margin-bottom:14px}
label{display:block;font-size:14px;color:var(--mute);margin-bottom:14px}
input::placeholder,textarea::placeholder{color:var(--mute);opacity:.6}
input,select,textarea{display:block;width:100%;margin-top:6px;padding:11px 12px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--text);font:inherit;font-size:16px;min-height:46px}
textarea{min-height:96px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:14px}
input:focus,select:focus,textarea:focus{outline:2px solid var(--brand);outline-offset:-1px;border-color:transparent}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:44px;padding:0 18px;border:0;border-radius:10px;background:var(--brand);color:var(--brand-text);font:inherit;font-weight:600;text-decoration:none;cursor:pointer}
button.ghost,.btn.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}button.danger{background:var(--bad);color:#fff}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:4px}.inline{margin-top:14px}
.notice,.error,.warnbox{border-radius:10px;padding:10px 12px;margin:0 0 14px}.notice{background:var(--ok-bg);color:var(--ok)}.error{background:var(--bad-bg);color:var(--bad)}.warnbox{background:var(--warn-bg);color:var(--warn)}
.mute,.hint{color:var(--mute)}.hint{font-size:14px;margin:-6px 0 14px}
.pill{display:inline-block;font-size:13px;font-weight:600;padding:2px 10px;border-radius:999px;background:var(--chip);color:var(--mute);white-space:nowrap}
.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.bad{background:var(--bad-bg);color:var(--bad)}.pill.warn{background:var(--warn-bg);color:var(--warn)}
.chip{display:inline-block;font-size:14px;padding:3px 10px;border-radius:999px;background:var(--chip);margin:2px 4px 2px 0;text-decoration:none}
.search{margin:0 0 12px}.search input{margin:0}
.list{list-style:none;margin:0;padding:0;background:var(--card);border:1px solid var(--line);border-radius:var(--radius);overflow:hidden}
.list li+li{border-top:1px solid var(--line)}.list .empty{padding:18px;color:var(--mute)}
.item{display:grid;grid-template-columns:1fr auto;gap:2px 10px;padding:12px 16px;text-decoration:none;align-items:center}.item:active{background:var(--chip)}
.item .name{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:15px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.item .meta{grid-column:1/-1;font-size:14px;color:var(--mute)}
dl{display:grid;grid-template-columns:96px 1fr;gap:8px 12px;margin:0}dt{color:var(--mute);font-size:14px;padding-top:2px}dd{margin:0;min-width:0;overflow-wrap:anywhere}
.masked{letter-spacing:2px;color:var(--mute)}code{font:14px ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
details>summary{cursor:pointer;font-weight:600;list-style:none;padding:4px 0;margin-bottom:10px}details>summary::-webkit-details-marker{display:none}details>summary::before{content:"▸ ";color:var(--mute)}details[open]>summary::before{content:"▾ "}
.card details{border-top:1px solid var(--line);padding-top:10px;margin-bottom:10px}details.card>summary{margin-bottom:0}details.card[open]>summary{margin-bottom:12px}
.danger>summary{color:var(--bad)}hr{border:0;border-top:1px solid var(--line);margin:16px 0}
.two{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}@media (max-width:420px){.two{grid-template-columns:1fr}}
.check{display:flex;align-items:center;gap:10px;color:var(--text);font-size:15px;margin-bottom:12px}.check input{width:22px;height:22px;min-height:0;margin:0;flex:none;accent-color:var(--brand)}
.switch{display:flex;align-items:center;gap:12px;color:var(--text);font-size:16px;font-weight:600;margin-bottom:16px}.switch input{width:24px;height:24px;min-height:0;margin:0;accent-color:var(--brand)}
.lbl{font-size:14px;color:var(--mute);margin:0 0 6px}
.seg{display:flex;background:var(--chip);border-radius:10px;padding:3px;margin-bottom:12px}
.seg label{flex:1;margin:0;text-align:center;min-width:0;position:relative}.seg input{position:absolute;inset:0;width:100%;height:100%;min-height:0;margin:0;opacity:0;pointer-events:none}.seg span{display:block;padding:9px 4px;border-radius:8px;color:var(--mute);font-size:15px;white-space:nowrap}.seg input:checked+span{background:var(--card);color:var(--text);font-weight:600;box-shadow:0 1px 2px rgba(0,0,0,.08)}.seg input:focus-visible+span{outline:2px solid var(--brand)}
.methods{display:none;flex-wrap:wrap;gap:4px 16px}form:has(input[value=custom]:checked) .methods{display:flex}.methods .check{margin-bottom:8px;font-size:14px}
.agenthead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}.agenthead .name{font-weight:700;font-size:17px;text-decoration:none;margin-right:auto}
.grants{list-style:none;margin:0 0 4px;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px}
.grant{display:flex;flex-direction:column;gap:1px;padding:10px 12px;border:1px solid var(--line);border-radius:10px;text-decoration:none}
.grant .svc{font-weight:600}.grant .what{font-size:13px;color:var(--ok);font-weight:600}.grant .mute{font-size:13px}.grant.ended .what{color:var(--warn)}
.add{margin-top:10px}.add select{margin:0}
.token{display:flex;gap:8px}.token input{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:14px}
.empty{color:var(--mute)}
main.narrow{max-width:400px;margin:0 auto;padding:18vh 16px 40px}main.narrow h1{margin-bottom:20px}main.narrow button{width:100%}`

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
