package dashboard

import (
	"html"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Jarvis 488255: the owner finds which agent cancelled a macserve job at a
// given minute, from the dashboard, without sudo.
func TestActivityFindsTheCallerByMinuteAndPath(t *testing.T) {
	e := newEnv(t)
	log := strings.Join([]string{
		`{"time":"2026-11-15T16:39:53Z","source":"100.64.0.9","role":"tandem","service":"macserve-builds","method":"POST","path":"/v1/jobs/j_ce4ce15b617d/cancel","status":200,"bytes":2,"ms":40}`,
		`{"time":"2026-11-15T16:39:50Z","source":"100.64.0.9","role":"herdrup-duo","service":"macserve-builds","method":"GET","path":"/v1/jobs/j_other","status":200,"bytes":2,"ms":40}`,
		`{"time":"2026-11-15T16:41:00Z","source":"100.64.0.9","role":"usmle-app","service":"macserve-builds","method":"POST","path":"/v1/jobs/j_ce4ce15b617d/cancel","status":200,"bytes":2,"ms":40}`,
		`{"admin":"key added","key":"X","session":"s1","time":"2026-11-15T16:39:10Z"}`,
		`{"time":"2026-11-15T16:39:30Z","role":"<script>","service":"macserve-builds","method":"GET","path":"/v1/j_ce4ce15b<b>","status":404}`,
		`{"time":"2026-11-15T16:39:31Z","note":"` + strings.Repeat("x", 70<<10) + `"}`,
		`not json "time":"2026-11-15T16:39:40Z"`,
		`{"time":"2026-11-15T15:00:00Z","role":"tandem","service":"macserve-builds","method":"POST","path":"/v1/jobs/j_ce4ce15b617d/cancel","status":200}`,
	}, "\n") + "\n"
	if err := os.WriteFile(e.proxy.Config().AuditLog, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"from": {"2026-11-15T16:39"}, "to": {"2026-11-15T16:39"}, "service": {"macserve-builds"}, "path": {"j_ce4ce15b"}}
	w := e.request("GET", "/activity?"+q.Encode(), nil)
	body := html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || !strings.Contains(body, "<td>tandem</td>") || !strings.Contains(body, "POST /v1/jobs/j_ce4ce15b617d/cancel") {
		t.Fatalf("the 16:39:53 cancel by tandem is not listed (%d):\n%s", w.Code, body)
	}
	for _, not := range []string{"herdrup-duo", "usmle-app", "15:00:00", "key added", "xxxxxxxx"} {
		if strings.Contains(body, not) {
			t.Errorf("listed %q, outside the minute, service or path", not)
		}
	}
	if strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), "<b>") {
		t.Error("audit text reached the page unescaped")
	}
	// Newest first, and the end minute is included.
	if i, j := strings.Index(body, "16:39:53"), strings.Index(body, "16:39:30"); i < 0 || j < 0 || i > j {
		t.Errorf("rows not newest first")
	}
	// Dashboard events show with no filter; a bad time is a 400 with a hint.
	if body := e.request("GET", "/activity?from=2026-11-15T16:39&to=2026-11-15T16:39", nil).Body.String(); !strings.Contains(body, "key added") {
		t.Error("dashboard event missing without filters")
	}
	if w := e.request("GET", "/activity?to=yesterday", nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "2026-11-15T16:39") {
		t.Errorf("bad time: %d", w.Code)
	}
}
