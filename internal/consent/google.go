package consent

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/googlelogin"
	"github.com/gitmoot/keyring/internal/policy"
)

// SetGoogle attaches the fixed container runtime before any listener starts.
func (s *Server) SetGoogle(controller *googlelogin.Controller) { s.google = controller }

// startGoogle consumes an initial link only after reserving a bounded login.
// It is called with s.mu held and always releases it.
func (s *Server) startGoogle(w http.ResponseWriter, r *http.Request, l *link, h [sha256.Size]byte, public *url.URL) {
	if s.google == nil {
		s.mu.Unlock()
		render(w, http.StatusServiceUnavailable, pageData{Message: "Google connection is unavailable on this keyring."})
		return
	}
	s.prune(s.now())
	if len(s.signIns) >= maxPending {
		s.mu.Unlock()
		render(w, http.StatusServiceUnavailable, pageData{Message: "Too many sign-ins are in progress. Try again shortly."})
		return
	}
	state, browser := randomToken(), randomToken()
	if err := s.google.Start(state, l.googleEpoch); err != nil {
		s.mu.Unlock()
		render(w, http.StatusConflict, pageData{Message: err.Error()})
		return
	}
	delete(s.links, h)
	s.signIns[hashOf(state)] = &signIn{
		service: l.service, browser: hashOf(browser), expires: s.now().Add(signInTTL),
		google: true, googleEpoch: l.googleEpoch,
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(public), Value: browser, Path: "/",
		MaxAge: int(signInTTL / time.Second), HttpOnly: true,
		Secure: public.Scheme == "https", SameSite: http.SameSiteLaxMode,
	})
	s.writeAudit("sign_in_started", map[string]any{"service": l.service, "link": ref(h), "kind": "gcloud"})
	location := *public
	location.Path += "/g/" + state
	http.Redirect(w, r, location.String(), http.StatusSeeOther)
}

func (s *Server) googlePage(w http.ResponseWriter, r *http.Request, id string, public *url.URL) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost && !sameOrigin(r, public) {
		render(w, http.StatusForbidden, pageData{Message: "Use the form in the browser that started this sign-in."})
		return
	}
	s.mu.Lock()
	f := s.signIns[hashOf(id)]
	valid := f != nil && f.google && s.now().Before(f.expires)
	s.mu.Unlock()
	if !valid || s.google == nil || f.googleEpoch != s.google.Epoch() {
		render(w, http.StatusGone, pageData{Message: "This Google sign-in expired or was revoked. Ask for a new connection link."})
		return
	}
	cookie, err := r.Cookie(cookieName(public))
	got := hashOf("")
	if err == nil {
		got = hashOf(cookie.Value)
	}
	if err != nil || subtle.ConstantTimeCompare(got[:], f.browser[:]) != 1 {
		render(w, http.StatusForbidden, pageData{Message: "Use the browser that started this Google sign-in."})
		return
	}
	if service, ok := s.config().Services[f.service]; !ok || service.Auth != policy.AuthGcloudLogin {
		render(w, http.StatusGone, pageData{Message: "This service can no longer be connected."})
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if r.ParseForm() != nil {
			render(w, http.StatusBadRequest, pageData{Message: "The form could not be read."})
			return
		}
		if r.PostForm.Get("action") == "retry" {
			err = s.google.Start(id, f.googleEpoch)
		} else {
			err = s.google.Submit(id, r.PostForm.Get("code"))
		}
		if err != nil {
			render(w, http.StatusBadRequest, pageData{Message: err.Error()})
			return
		}
		location := *public
		location.Path += "/g/" + id
		http.Redirect(w, r, location.String(), http.StatusSeeOther)
		return
	}
	view, ok := s.google.View(id)
	if !ok {
		render(w, http.StatusGone, pageData{Message: "This Google sign-in is no longer active. Ask for a new link."})
		return
	}
	data := pageData{Service: "drive", Google: true, GoogleURL: view.URL,
		GoogleAccount: view.Account, GoogleProject: view.Project,
		Refresh: view.Busy && view.Phase != "awaiting_code"}
	switch view.Phase {
	case "awaiting_code":
		data.Form, data.GoogleCode = true, true
		data.Message = "Open Google sign-in, then paste its verification code here. Never send the code in chat."
	case "connected":
		data.Message = "Drive and Sheets are connected. You can close this page."
	case "failed":
		data.Problem = true
		data.Form, data.GoogleRetry = true, true
		switch view.Error {
		case "cloud_terms_not_accepted":
			data.GoogleTerms = true
			data.Message = "Google requires you to accept its Cloud terms before creating your project."
		case "login_required", "wrong_google_account":
			data.Message = "Google sign-in must be completed with the intended account. Retry, or disconnect first to change accounts."
		case "rate_limited":
			data.Message = "Google limited project setup requests. Wait a few minutes, then retry; the same project ID is retained."
		case "connection_timed_out":
			data.Message = "Connection timed out. Retry or ask for a new link; completed login and project progress are retained."
		default:
			data.Message = "Google connection could not finish. Retry or ask for a new link; completed progress is retained."
		}
	case "setting_up_project":
		data.GoogleStep = 2
		data.Message = "Setting up Drive and Sheets in your Google account. This can take a few minutes; keep this page open."
	case "signing_in":
		data.GoogleStep = 1
		data.Message = "Signing in to Google…"
	default:
		data.GoogleStep = 1
		data.Message = "Preparing Google sign-in…"
	}
	render(w, http.StatusOK, data)
}

func googlePagePath(rest string) (string, bool) {
	id, ok := strings.CutPrefix(rest, "/g/")
	return id, ok && id != "" && !strings.Contains(id, "/")
}
