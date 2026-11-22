package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestConnectAndEditBearerScheme(t *testing.T) {
	e := newEnv(t)
	const value = "key-id-0123:key-secret-4567"
	var got string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer up.Close()
	_, w := e.addAndConnect("HIGGSFIELD_KEY", value, url.Values{
		"pasted": {`{"service":"higgsfield","base":"` + up.URL + `","auth":"bearer","scheme":"Key","test_path":"/v1/ping"}`}})
	if w.Header().Get("Location") != "/keys/HIGGSFIELD_KEY?done=connected" {
		t.Fatalf("connect with pasted scheme: %d %s", w.Code, w.Body.String())
	}
	svc := e.proxy.Config().Services["higgsfield"]
	if svc.Scheme != "Key" {
		t.Fatalf("pasted scheme not saved: %+v", svc)
	}
	if status, err := e.proxy.TestKey(context.Background(), svc, value); err != nil || status != http.StatusNoContent || got != "Key "+value {
		scheme, _, _ := strings.Cut(got, " ")
		t.Fatalf("test request: %d %v, Authorization scheme %q", status, err, scheme)
	}
	if page := e.request("GET", "/services/higgsfield", nil).Body.String(); !strings.Contains(page, "Authorization: Key …") {
		t.Error("service page does not show the scheme")
	}

	// Typed: the scheme box goes with the bearer choice, and is dropped for another.
	w = e.request("POST", "/keys/HIGGSFIELD_KEY/connect", url.Values{"password": {password}, "service": {"typed"},
		"base": {up.URL}, "auth": {"bearer"}, "scheme": {"Token"}})
	if w.Code != http.StatusSeeOther || e.proxy.Config().Services["typed"].Scheme != "Token" {
		t.Fatalf("typed scheme: %d %+v", w.Code, e.proxy.Config().Services["typed"])
	}
	w = e.request("POST", "/keys/HIGGSFIELD_KEY/connect", url.Values{"password": {password}, "service": {"typedh"},
		"base": {up.URL}, "auth": {"header"}, "header": {"X-Api-Key"}, "scheme": {"Token"}})
	if w.Code != http.StatusSeeOther || e.proxy.Config().Services["typedh"].Scheme != "" {
		t.Fatalf("scheme kept on a header service: %d %+v", w.Code, e.proxy.Config().Services["typedh"])
	}

	for name, pasted := range map[string]string{
		"two words":   `{"service":"bad1","base":"` + up.URL + `","auth":"bearer","scheme":"Key x"}`,
		"header auth": `{"service":"bad2","base":"` + up.URL + `","auth":"header","header":"X-Api-Key","scheme":"Key"}`,
	} {
		w := e.request("POST", "/keys/HIGGSFIELD_KEY/connect", url.Values{"pasted": {pasted}, "password": {password}})
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, w.Code)
		}
	}

	// Edit by paste: scheme left out goes back to Bearer and is listed as changed.
	w = e.request("POST", "/services/higgsfield", url.Values{"password": {password},
		"pasted": {`{"base":"` + up.URL + `","auth":"bearer","test_path":"/v1/ping"}`}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	if s := e.proxy.Config().Services["higgsfield"].Scheme; s != "" {
		t.Fatalf("scheme after edit: %q", s)
	}
	if !strings.Contains(e.audit.String(), `"changed":["scheme"]`) {
		t.Error("edit audit does not list scheme as changed")
	}
	// A refused edit shows the stored scheme in the summary, not the refused one.
	w = e.request("POST", "/services/higgsfield", url.Values{"password": {password}, "key": {"HIGGSFIELD_KEY"},
		"base": {up.URL}, "auth": {"bearer"}, "scheme": {"Bad Scheme"}, "test_path": {"/v1/ping"}})
	if body := w.Body.String(); w.Code != http.StatusBadRequest || !strings.Contains(body, "Authorization: Bearer …") || strings.Contains(body, "Authorization: Bad Scheme") {
		t.Fatalf("refused edit: %d, summary does not show the stored scheme", w.Code)
	}
}
