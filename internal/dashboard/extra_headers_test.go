package dashboard

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const (
	modalID     = "wk-fixture-proxy-id-0123456789"
	modalSecret = "ws-fixture-proxy-secret-9876543210"
)

// twoSecretAPI answers 200 only when both secret headers carry the right
// values, like Modal's proxy-token auth, and remembers what it was sent.
func twoSecretAPI(t *testing.T) (*httptest.Server, func() []http.Header) {
	t.Helper()
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		if r.Header.Get("Modal-Key") != modalID || r.Header.Get("Modal-Secret") != modalSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []http.Header {
		mu.Lock()
		defer mu.Unlock()
		return append([]http.Header(nil), seen...)
	}
}

// The owner sets up a service that needs two secret values from the
// dashboard alone: two keys, then one pasted line naming the second key as an
// extra secret header. Test passes against an API that needs both, and no
// value appears on any page or in the audit log.
func TestConnectServiceWithTwoSecretValues(t *testing.T) {
	e := newEnv(t)
	api, seen := twoSecretAPI(t)
	e.request("POST", "/keys", url.Values{"name": {"MODAL_PROXY_SECRET"}, "value": {modalSecret}, "password": {password}})
	pasted := `{"service":"modal-ocr","base":"` + api.URL + `","auth":"header","header":"Modal-Key","test_path":"/health","extra_headers":{"Modal-Secret":"MODAL_PROXY_SECRET"}}`
	add, conn := e.addAndConnect("MODAL_PROXY_ID", modalID, url.Values{"pasted": {pasted}})
	if add.Code != http.StatusSeeOther || conn.Header().Get("Location") != "/keys/MODAL_PROXY_ID?done=connected" {
		t.Fatalf("connect: %d %s", conn.Code, conn.Body.String())
	}
	svc := e.proxy.Config().Services["modal-ocr"]
	if !maps.Equal(svc.ExtraHeaders, map[string]string{"Modal-Secret": "MODAL_PROXY_SECRET"}) || svc.Key != "MODAL_PROXY_ID" {
		t.Fatalf("stored service = %+v", svc)
	}
	w := e.request("POST", "/keys/MODAL_PROXY_ID/test", url.Values{})
	if !strings.Contains(w.Header().Get("Location"), "done=tested") {
		t.Fatalf("test: %d %s", w.Code, w.Header().Get("Location"))
	}
	got := seen()
	if len(got) != 1 || got[0].Get("Modal-Key") != modalID || got[0].Get("Modal-Secret") != modalSecret {
		t.Fatalf("the API did not receive both secrets: %v", got)
	}
	if !strings.Contains(e.request("GET", "/keys/MODAL_PROXY_ID", nil).Body.String(), "Working") {
		t.Fatal("the key is not shown as working after a passing test")
	}
	page := e.request("GET", "/services/modal-ocr", nil).Body.String()
	if !strings.Contains(page, "Modal-Secret ← MODAL_PROXY_SECRET") {
		t.Fatalf("service page does not name the extra secret header:\n%s", page)
	}
	// The second key is shown as used by the service, so it is not deleted by
	// mistake.
	if !strings.Contains(e.request("GET", "/keys/MODAL_PROXY_SECRET", nil).Body.String(), `href="/services/modal-ocr"`) {
		t.Fatal("the second key's page does not show the service that uses it")
	}
	all := e.everyPage("/keys", "/keys/MODAL_PROXY_ID", "/keys/MODAL_PROXY_SECRET", "/services/modal-ocr") + e.audit.String()
	if strings.Contains(all, modalSecret) || strings.Contains(all, modalID) {
		t.Fatal("a secret value appears on a page or in the audit log")
	}
	if !strings.Contains(e.audit.String(), `"extra_headers":{"Modal-Secret":"MODAL_PROXY_SECRET"}`) {
		t.Fatalf("connect audit does not name the extra header: %s", e.audit.String())
	}
}

// Pasted extra_headers must name stored keys, and only safe header names;
// a refused paste changes nothing.
func TestExtraHeaderRefusals(t *testing.T) {
	e := newEnv(t)
	e.request("POST", "/keys", url.Values{"name": {"MODAL_PROXY_ID"}, "value": {modalID}, "password": {password}})
	e.request("POST", "/keys", url.Values{"name": {"MODAL_PROXY_SECRET"}, "value": {modalSecret}, "password": {password}})
	before := e.accessBytes()
	for name, extra := range map[string]string{
		"key without a value":      `{"Modal-Secret":"NO_SUCH_KEY"}`,
		"a value instead of a key": `{"Modal-Secret":"` + modalSecret + `"}`,
		"Authorization header":     `{"Authorization":"MODAL_PROXY_SECRET"}`,
		"the main key again":       `{"Modal-Secret":"MODAL_PROXY_ID"}`,
		"the main header again":    `{"modal-key":"MODAL_PROXY_SECRET"}`,
	} {
		pasted := `{"service":"modal-ocr","base":"https://example.modal.run","auth":"header","header":"Modal-Key","extra_headers":` + extra + `}`
		w := e.request("POST", "/keys/MODAL_PROXY_ID/connect", url.Values{"pasted": {pasted}, "password": {password}})
		if w.Code != http.StatusBadRequest || !bytesEqual(e.accessBytes(), before) {
			t.Errorf("%s: status %d, want 400 and no change", name, w.Code)
		}
		if strings.Contains(w.Body.String(), modalSecret) {
			t.Errorf("%s: the refusal echoes a secret value", name)
		}
		// The setting is understood and refused for its reason, not as an
		// unknown field.
		if body := w.Body.String(); strings.Contains(body, "unknown field") || !strings.Contains(body, "extra_headers") {
			t.Errorf("%s: refusal does not explain the extra header problem", name)
		}
	}
}

// Editing a service: extra_headers left out keeps them, a new map replaces
// them, {} removes them; each change is audit-logged by name.
func TestEditExtraHeaders(t *testing.T) {
	e := newEnv(t)
	api, _ := twoSecretAPI(t)
	e.request("POST", "/keys", url.Values{"name": {"MODAL_PROXY_SECRET"}, "value": {modalSecret}, "password": {password}})
	e.request("POST", "/keys", url.Values{"name": {"MODAL_OTHER_SECRET"}, "value": {"ws-other-0123456789"}, "password": {password}})
	base := `"base":"` + api.URL + `","auth":"header","header":"Modal-Key","test_path":"/health"`
	e.addAndConnect("MODAL_PROXY_ID", modalID, url.Values{"pasted": {`{"service":"modal-ocr",` + base + `,"extra_headers":{"Modal-Secret":"MODAL_PROXY_SECRET"}}`}})
	extra := func() map[string]string { return e.proxy.Config().Services["modal-ocr"].ExtraHeaders }

	if w := e.edit("modal-ocr", url.Values{"pasted": {`{` + base + `}`}}); w.Header().Get("Location") != "/services/modal-ocr?done=saved" || extra()["Modal-Secret"] != "MODAL_PROXY_SECRET" {
		t.Fatalf("paste without extra_headers lost them: %d %v", w.Code, extra())
	}
	// The form fields (no paste) keep them too.
	if w := e.edit("modal-ocr", url.Values{"base": {api.URL}, "auth": {"header"}, "header": {"Modal-Key"}, "test_path": {"/health"}}); w.Header().Get("Location") != "/services/modal-ocr?done=saved" || len(extra()) != 1 {
		t.Fatalf("form save lost them: %d %v", w.Code, extra())
	}
	if w := e.edit("modal-ocr", url.Values{"pasted": {`{` + base + `,"extra_headers":{"Modal-Secret":"MODAL_OTHER_SECRET"}}`}}); w.Header().Get("Location") != "/services/modal-ocr?done=saved" || extra()["Modal-Secret"] != "MODAL_OTHER_SECRET" {
		t.Fatalf("replace: %d %v", w.Code, extra())
	}
	if !strings.Contains(e.audit.String(), `"changed":["extra_headers"]`) {
		t.Fatalf("edit audit does not name the change: %s", e.audit.String())
	}
	before := e.accessBytes()
	if w := e.edit("modal-ocr", url.Values{"pasted": {`{` + base + `,"extra_headers":{"Modal-Secret":"NO_SUCH_KEY"}}`}}); w.Code != http.StatusBadRequest || !bytesEqual(e.accessBytes(), before) {
		t.Fatalf("unknown key on edit: %d", w.Code)
	}
	if w := e.edit("modal-ocr", url.Values{"pasted": {`{` + base + `,"extra_headers":{}}`}}); w.Header().Get("Location") != "/services/modal-ocr?done=saved" || len(extra()) != 0 {
		t.Fatalf("remove: %d %v", w.Code, extra())
	}
}

func bytesEqual(a, b []byte) bool { return string(a) == string(b) }
