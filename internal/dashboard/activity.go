package dashboard

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/server"
)

// Activity (Jarvis 488255): the owner looks up who called what, and when,
// from the audit log, without a terminal or sudo. Read-only. The search is
// server.SearchAudit, which agents allowed to read the log also use.

func registerActivity(b *Backend) {
	b.Admin.Handle("GET /activity", b.activityPage)
}

type activityQuery struct {
	From, To, Service, Role, Path string
}

func (b *Backend) activityPage(w http.ResponseWriter, r *http.Request, sid string) {
	q := activityQuery{From: r.FormValue("from"), To: r.FormValue("to"),
		Service: strings.TrimSpace(r.FormValue("service")), Role: strings.TrimSpace(r.FormValue("role")), Path: strings.TrimSpace(r.FormValue("path"))}
	data := map[string]any{"Q": &q}
	from, to, err := server.AuditWindow(q.From, q.To, b.Now())
	if err != nil {
		data["ActivityError"] = strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + "."
		b.render(w, http.StatusBadRequest, "activity", sid, data)
		return
	}
	q.From, q.To = from.Format(server.AuditMinute), to.Add(-time.Minute).Format(server.AuditMinute)
	rows, more, err := server.SearchAudit(b.rules().AuditLog, from, to, server.AuditFilter{Service: q.Service, Role: q.Role, Path: q.Path})
	switch {
	case errors.Is(err, os.ErrNotExist) || b.rules().AuditLog == "":
		data["ActivityError"] = "There is no audit log yet."
	case err != nil:
		data["ActivityError"] = "The audit log could not be read."
	}
	data["Rows"], data["More"], data["Limit"] = rows, more, server.AuditLimit
	b.render(w, http.StatusOK, "activity", sid, data)
}
