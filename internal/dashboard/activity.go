package dashboard

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// Activity (Jarvis 488255): the owner looks up who called what, and when,
// from the audit log, without a terminal or sudo. Read-only.

func registerActivity(b *Backend) {
	b.Admin.Handle("GET /activity", b.activityPage)
}

// activityLimit caps the rows shown; the newest matches are kept.
const activityLimit = 500

// activityFormat is the form's time format, as a datetime-local input sends it.
const activityFormat = "2006-01-02T15:04"

type activityRow struct {
	Time    string `json:"time"`
	Source  string `json:"source"`
	Role    string `json:"role"`
	Service string `json:"service"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Note    string `json:"note"`
	// Admin is a dashboard event (login, key added, ...).
	Admin string `json:"admin"`
}

type activityQuery struct {
	From, To, Service, Role, Path string
}

func (b *Backend) activityPage(w http.ResponseWriter, r *http.Request, sid string) {
	now := b.Now().UTC()
	q := activityQuery{From: r.FormValue("from"), To: r.FormValue("to"),
		Service: strings.TrimSpace(r.FormValue("service")), Role: strings.TrimSpace(r.FormValue("role")), Path: strings.TrimSpace(r.FormValue("path"))}
	data := map[string]any{"Q": &q}
	from, to, err := activityWindow(q.From, q.To, now)
	if err != nil {
		data["ActivityError"] = err.Error()
		b.render(w, http.StatusBadRequest, "activity", sid, data)
		return
	}
	q.From, q.To = from.Format(activityFormat), to.Add(-time.Minute).Format(activityFormat)
	rows, more, err := readActivity(b.rules().AuditLog, from, to, q)
	switch {
	case errors.Is(err, os.ErrNotExist) || b.rules().AuditLog == "":
		data["ActivityError"] = "There is no audit log yet."
	case err != nil:
		data["ActivityError"] = "The audit log could not be read."
	}
	data["Rows"], data["More"], data["Limit"] = rows, more, activityLimit
	b.render(w, http.StatusOK, "activity", sid, data)
}

// activityWindow reads the form's UTC minutes; the end minute is included.
// The default is the last hour.
func activityWindow(fromText, toText string, now time.Time) (time.Time, time.Time, error) {
	to := now.Truncate(time.Minute).Add(time.Minute)
	from := to.Add(-time.Hour)
	if toText != "" {
		t, err := time.Parse(activityFormat, toText)
		if err != nil {
			return from, to, errors.New("Write the times as 2026-11-15T16:39 (UTC).")
		}
		to = t.Add(time.Minute)
		if fromText == "" {
			from = to.Add(-time.Hour)
		}
	}
	if fromText != "" {
		t, err := time.Parse(activityFormat, fromText)
		if err != nil {
			return from, to, errors.New("Write the times as 2026-11-15T16:39 (UTC).")
		}
		from = t
	}
	if !from.Before(to) {
		return from, to, errors.New("The start must be before the end.")
	}
	return from, to, nil
}

// readActivity scans the audit log for lines in [from, to) matching q,
// newest first; past activityLimit it keeps the last ones written. The log is append-only and never rotated, so it is streamed:
// a line's time is compared as text before it is decoded.
func readActivity(path string, from, to time.Time, q activityQuery) ([]activityRow, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	lo, hi := from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339)
	var kept []activityRow
	more := false
	rd := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := rd.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			// A line this long is not an audit record worth showing; skip it.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = rd.ReadSlice('\n')
			}
			continue
		}
		if len(line) > 0 {
			if row, ok := activityMatch(line, lo, hi, q); ok {
				if len(kept) == activityLimit {
					kept, more = kept[1:], true
				}
				kept = append(kept, row)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, err
		}
	}
	// A line is written when the call ends but stamped with its start, so
	// file order is not time order.
	slices.SortStableFunc(kept, func(a, b activityRow) int { return strings.Compare(b.Time, a.Time) })
	return kept, more, nil
}

func activityMatch(line []byte, lo, hi string, q activityQuery) (activityRow, bool) {
	var row activityRow
	s := string(line)
	i := strings.Index(s, `"time":"`)
	if i < 0 || len(s) < i+8+len(lo) {
		return row, false
	}
	if t := s[i+8 : i+8+len(lo)]; t < lo || t >= hi {
		return row, false
	}
	if json.Unmarshal(line, &row) != nil {
		return row, false
	}
	if q.Service != "" && row.Service != q.Service || q.Role != "" && row.Role != q.Role ||
		q.Path != "" && !strings.Contains(row.Path, q.Path) {
		return row, false
	}
	return row, true
}
