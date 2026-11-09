package dashboard

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The owner shows a key's value with the password and can copy it; the audit
// says the key was shown, never the value.
func TestShowKeyValue(t *testing.T) {
	e := newEnv(t)
	if page := e.request("GET", "/keys/API_KEY", nil).Body.String(); !strings.Contains(page, `action="/keys/API_KEY/reveal"`) || strings.Contains(page, oldValue) {
		t.Fatal("the key page should offer Show and not contain the value")
	}
	w := e.request("POST", "/keys/API_KEY/reveal", url.Values{"password": {password}})
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `value="`+oldValue+`"`) || !strings.Contains(body, `data-copy="value-a"`) {
		t.Fatalf("reveal: %d", w.Code)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the reveal page may be cached")
	}
	if a := e.audit.String(); !strings.Contains(a, `"admin":"key_revealed"`) || strings.Contains(a, oldValue) {
		t.Fatalf("audit: %s", a)
	}
}

// Without the password, or without the session's CSRF token, nothing is
// shown; a GET does not show it either.
func TestShowKeyValueNeedsPassword(t *testing.T) {
	e := newEnv(t)
	if w := e.request("POST", "/keys/API_KEY/reveal", url.Values{"password": {"wrong"}}); strings.Contains(w.Body.String(), oldValue) || !strings.Contains(w.Header().Get("Location"), "error=password") {
		t.Fatalf("wrong password: %d", w.Code)
	}
	if w := e.request("GET", "/keys/API_KEY/reveal", nil); strings.Contains(w.Body.String(), oldValue) || w.Code == http.StatusOK {
		t.Fatalf("GET: %d", w.Code)
	}
	csrf := e.csrf
	e.csrf = "not-the-token"
	if w := e.request("POST", "/keys/API_KEY/reveal", url.Values{"password": {password}}); strings.Contains(w.Body.String(), oldValue) {
		t.Fatal("shown without the CSRF token")
	}
	e.csrf = csrf
	if strings.Contains(e.audit.String(), "key_revealed") {
		t.Fatal("a refused request was audited as shown")
	}
}

// A key with several values shows each, and a multi-line file key (an Apple
// .p8) is shown whole.
func TestShowNamedValuesAndFileKeys(t *testing.T) {
	e := newEnv(t)
	addModal(e)
	body := e.request("POST", "/keys/MODAL/reveal", url.Values{"password": {password}}).Body.String()
	if !strings.Contains(body, modalID) || !strings.Contains(body, modalSecret) || !strings.Contains(body, "Copy secret") {
		t.Fatal("named values not shown")
	}
	file, _ := p8(t)
	e.upload(map[string]string{"name": "APNS_KEY", "password": password}, "k.p8", file, e.csrf)
	body = e.request("POST", "/keys/APNS_KEY/reveal", url.Values{"password": {password}}).Body.String()
	if !strings.Contains(body, "<textarea") || !strings.Contains(html.UnescapeString(body), string(file)) {
		t.Fatal("the .p8 is not shown whole")
	}
}
