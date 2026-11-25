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
	if err := s.google.Start(state, l.googleEpoch, ""); err != nil {
		s.mu.Unlock()
		render(w, http.StatusConflict, pageData{Message: err.Error()})
		return
	}
	delete(s.links, h)
	s.signIns[hashOf(state)] = &signIn{
		service: l.service, browser: hashOf(browser), expires: s.now().Add(signInTTL),
		google: true, googleEpoch: l.googleEpoch, returnURL: l.returnURL,
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
			// An existing project the account owns, when Google will not
			// create another one. Optional; not a secret. Choosing it and
			// retrying are one operation: a refused retry chooses nothing.
			err = s.google.Start(id, f.googleEpoch, strings.TrimSpace(r.PostForm.Get("project")))
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
		data = done(data, "Drive and Sheets are connected.", f.returnURL)
	case "failed":
		data.Problem = true
		data.Form, data.GoogleRetry = true, true
		data.GoogleTerms = view.Error == "cloud_terms_not_accepted"
		// Whatever failed, a retained sign-in may still take another project.
		data.GoogleChooseProject = view.ProjectChoosable
		data.Message = googleFailureMessage(view)
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

// googleFailureMessage tells the owner what each failed connection code
// means and what to do. The step is a fixed name, never command output.
func googleFailureMessage(view googlelogin.View) string {
	var message string
	switch view.Error {
	case "cloud_terms_not_accepted":
		message = "Google requires you to accept its Cloud terms before creating your project."
	case "login_required", "wrong_google_account":
		message = "Google sign-in must be completed with the intended account. Retry, or disconnect first to change accounts."
	case "rate_limited":
		message = "Google limited project setup requests. Wait a few minutes, then retry; the same project ID is retained."
	case "connection_timed_out":
		message = "Connection timed out. Retry or ask for a new link; completed login and project progress are retained."
	case "google_command_failed":
		message = "A Google Cloud command failed while setting up Drive. Retry; if it fails again, check the project in Google Cloud Console."
	case "project_not_active":
		message = "The Drive project in your Google account is deleted or pending deletion. Restore it in Google Cloud Console (Manage resources), enter the ID of another project you own, or disconnect Drive to start with a new project."
	case "project_not_accessible":
		message = "Google would not create a new Drive project for this account. Retry later, enter the ID of a project you already own, or disconnect Drive and connect again."
	case "project_limit_reached":
		message = "Your Google account has reached its Google Cloud project limit, so a new Drive project could not be created. Enter the ID of a project you already own (for example an older drivekey-… project) and retry. Deleting projects frees the limit only after 30 days."
	case "project_not_found":
		message = "Google did not find that project for this account. Check the ID in Google Cloud Console (Manage resources) and that this Google account owns it, then enter it again."
	case "api_disabled":
		message = "The Drive and Sheets APIs are not enabled yet. Google can take a few minutes; wait, then retry."
	case "api_probe_failed":
		message = "Google refused the test call. If this account recently signed out everywhere or changed its password, disconnect Drive and connect again to sign in afresh; otherwise retry."
	default:
		message = "Google connection could not finish. Retry or ask for a new link; completed progress is retained."
	}
	if view.Step != "" {
		message += " (Failed step: " + view.Step + ".)"
	}
	return message
}
