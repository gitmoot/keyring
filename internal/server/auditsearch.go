package server

import (
	"bufio"
	"container/heap"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// AuditPath answers an agent the owner allowed to read the audit log
// (policy.Role.AuditRead; Jarvis 488255): GET with from, to, service, role
// and path, the same search as the dashboard's Activity page, as JSON.
const AuditPath = "/_keyring/audit"

// AuditLimit caps the rows a search returns; the newest written are kept.
const AuditLimit = 500

// AuditMinute is the minute format a search takes (a datetime-local input);
// RFC 3339 times are accepted too.
const AuditMinute = "2006-01-02T15:04"

// AuditRow is one audit record as a search shows it.
type AuditRow struct {
	Time    string `json:"time"`
	Source  string `json:"source,omitempty"`
	Role    string `json:"role,omitempty"`
	Service string `json:"service,omitempty"`
	Method  string `json:"method,omitempty"`
	Path    string `json:"path,omitempty"`
	Status  int    `json:"status,omitempty"`
	Note    string `json:"note,omitempty"`
	// Admin is a dashboard event (login, key added, ...).
	Admin string `json:"admin,omitempty"`
	// Bitcoin is a PSBT signature (#187).
	Bitcoin *BitcoinAudit `json:"bitcoin,omitempty"`
}

// AuditFilter narrows a search: exact service and role, path substring, and
// with Bitcoin only PSBT signatures (so other calls cannot push them out of
// the AuditLimit newest).
type AuditFilter struct {
	Service, Role, Path string
	Bitcoin             bool
}

var errAuditTime = errors.New("write the times as 2026-11-15T16:39 (UTC) or RFC 3339")

func parseAuditTime(s string) (time.Time, bool, error) {
	if t, err := time.Parse(AuditMinute, s); err == nil {
		return t, true, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return t, false, errAuditTime
	}
	return t.UTC(), false, nil
}

// AuditWindow reads a search window: from and to in UTC; a to given as a
// minute includes that minute. Either may be empty: the default is the hour
// up to now, or the hour before to.
func AuditWindow(fromText, toText string, now time.Time) (time.Time, time.Time, error) {
	to := now.UTC().Truncate(time.Minute).Add(time.Minute)
	from := to.Add(-time.Hour)
	if toText != "" {
		t, minute, err := parseAuditTime(toText)
		if err != nil {
			return from, to, err
		}
		if to = t; minute {
			to = t.Add(time.Minute)
		}
		from = to.Add(-time.Hour)
	}
	if fromText != "" {
		t, _, err := parseAuditTime(fromText)
		if err != nil {
			return from, to, err
		}
		from = t
	}
	if !from.Before(to) {
		return from, to, errors.New("the start must be before the end")
	}
	return from, to, nil
}

func ceilSecond(t time.Time) time.Time {
	if s := t.Truncate(time.Second); !s.Equal(t) {
		return s.Add(time.Second)
	}
	return t
}

// SearchAudit scans the audit log at path for records in [from, to)
// matching f, newest first; past AuditLimit it keeps the newest by time and
// reports more. A record is written when its call ends but stamped with its
// start, so the last written are not the newest (#153 review). The log is append-only and never rotated, so it is streamed:
// a line's time is compared as text before it is decoded.
func SearchAudit(path string, from, to time.Time, f AuditFilter) ([]AuditRow, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	// Records are stamped to the second and compared as text, so compare
	// against whole seconds: for a whole-second t, t >= x and t < y exactly
	// when t >= ceil(x) and t < ceil(y) (#155 review). The caller's window
	// itself is not changed.
	lo, hi := ceilSecond(from).UTC().Format(time.RFC3339), ceilSecond(to).UTC().Format(time.RFC3339)
	kept := &newestRows{}
	more := false
	rd := bufio.NewReaderSize(file, 64<<10)
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
			if row, ok := auditMatch(line, lo, hi, f); ok {
				if kept.Len() < AuditLimit {
					heap.Push(kept, row)
				} else {
					more = true
					if row.Time > (*kept)[0].Time {
						(*kept)[0] = row
						heap.Fix(kept, 0)
					}
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, err
		}
	}
	rows := []AuditRow(*kept)
	slices.SortStableFunc(rows, func(a, b AuditRow) int { return strings.Compare(b.Time, a.Time) })
	return rows, more, nil
}

// newestRows is a min-heap by time: its root is the oldest row kept.
type newestRows []AuditRow

func (h newestRows) Len() int           { return len(h) }
func (h newestRows) Less(i, j int) bool { return h[i].Time < h[j].Time }
func (h newestRows) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *newestRows) Push(x any)        { *h = append(*h, x.(AuditRow)) }
func (h *newestRows) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

func auditMatch(line []byte, lo, hi string, f AuditFilter) (AuditRow, bool) {
	var row AuditRow
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
	if f.Service != "" && row.Service != f.Service || f.Role != "" && row.Role != f.Role ||
		f.Path != "" && !strings.Contains(row.Path, f.Path) || f.Bitcoin && row.Bitcoin == nil {
		return row, false
	}
	return row, true
}

// serveAuditSearch answers AuditPath for a role with AuditRead. One search
// runs at a time: each one reads the whole log.
func (h *Handler) serveAuditSearch(w http.ResponseWriter, r *http.Request, snap *snapshot, allowed bool, rec *auditRecord, fail func(int, string)) {
	rec.Path = AuditPath
	switch {
	case r.Method != http.MethodGet:
		fail(http.StatusMethodNotAllowed, "the audit search is GET only")
		return
	case !allowed:
		fail(http.StatusForbidden, "this agent may not read the audit log; the owner allows it on the agent's page in the dashboard")
		return
	}
	q := r.URL.Query()
	from, to, err := AuditWindow(q.Get("from"), q.Get("to"), h.now())
	if err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	if !h.auditSearch.TryLock() {
		fail(http.StatusTooManyRequests, "another audit search is running; try again shortly")
		return
	}
	defer h.auditSearch.Unlock()
	rows, more, err := SearchAudit(snap.config.AuditLog, from, to,
		AuditFilter{Service: q.Get("service"), Role: q.Get("role"), Path: q.Get("path")})
	if errors.Is(err, os.ErrNotExist) {
		rows, err = nil, nil
	}
	if err != nil {
		fail(http.StatusInternalServerError, "the audit log could not be read")
		return
	}
	if rows == nil {
		rows = []AuditRow{}
	}
	rec.Status = http.StatusOK
	rec.Note = "audit search"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"from": from.Format(time.RFC3339Nano), "to": to.Format(time.RFC3339Nano), "rows": rows, "more": more, "limit": AuditLimit,
	})
}
