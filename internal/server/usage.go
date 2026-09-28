package server

import (
	"maps"
	"sort"
	"sync"
	"time"
)

// Usage is what the dashboard shows per role and service. It holds counts,
// times and status codes only: no paths, queries or values.
type Usage struct {
	Role       string    `json:"role"`
	Service    string    `json:"service"`
	Day        string    `json:"day"` // UTC date that Calls counts
	Calls      int       `json:"calls"`
	LastUsed   time.Time `json:"last_used"`
	LastStatus int       `json:"last_status"`
	// Past holds the calls of the previous days (UTC date → calls), at most
	// historyDays-1 of them, for the dashboard's 7-day chart.
	Past map[string]int `json:"past,omitempty"`
}

const historyDays = 7

// rollTo moves the counts of an earlier day into Past and keeps only the
// days that still fit in the history window ending on day.
func (u *Usage) rollTo(day string) {
	if u.Day == day {
		return
	}
	if u.Day != "" && u.Calls > 0 {
		if u.Past == nil {
			u.Past = map[string]int{}
		}
		u.Past[u.Day] += u.Calls
	}
	u.Day, u.Calls = day, 0
	end, err := time.Parse("2006-01-02", day)
	if err != nil {
		return
	}
	oldest := end.AddDate(0, 0, -(historyDays - 1)).Format("2006-01-02")
	for d := range u.Past {
		if d < oldest || d >= day {
			delete(u.Past, d)
		}
	}
	if len(u.Past) == 0 {
		u.Past = nil
	}
}

// Week returns the calls of the historyDays days ending today, oldest
// first. It reads a copy made by Handler.Usage, whose Day is today.
func (u Usage) Week() [historyDays]int {
	var out [historyDays]int
	end, err := time.Parse("2006-01-02", u.Day)
	if err != nil {
		return out
	}
	for i := 0; i < historyDays; i++ {
		d := end.AddDate(0, 0, i-(historyDays-1)).Format("2006-01-02")
		if d == u.Day {
			out[i] = u.Calls
		} else {
			out[i] = u.Past[d]
		}
	}
	return out
}

type usageBook struct {
	mu   sync.Mutex
	rows map[[2]string]*Usage
}

// record counts one call. Only a known role and a configured service are
// recorded, so arbitrary requests cannot grow the table.
func (b *usageBook) record(role, service string, status int, at time.Time) {
	day := at.UTC().Format("2006-01-02")
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rows == nil {
		b.rows = map[[2]string]*Usage{}
	}
	k := [2]string{role, service}
	u, ok := b.rows[k]
	if !ok {
		u = &Usage{Role: role, Service: service}
		b.rows[k] = u
	}
	u.rollTo(day)
	u.Calls++
	if at.After(u.LastUsed) {
		u.LastUsed, u.LastStatus = at.UTC(), status
	}
}

// Usage returns a copy of the table, sorted by role then service. Calls from
// an earlier day read as zero today.
func (h *Handler) Usage() []Usage {
	today := h.now().UTC().Format("2006-01-02")
	h.usage.mu.Lock()
	out := make([]Usage, 0, len(h.usage.rows))
	for _, u := range h.usage.rows {
		c := *u
		c.Past = maps.Clone(u.Past)
		c.rollTo(today)
		out = append(out, c)
	}
	h.usage.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Service < out[j].Service
	})
	return out
}

// RestoreUsage loads a saved table, for example after a restart.
func (h *Handler) RestoreUsage(rows []Usage) {
	h.usage.mu.Lock()
	defer h.usage.mu.Unlock()
	h.usage.rows = make(map[[2]string]*Usage, len(rows))
	for _, u := range rows {
		c := u
		c.Past = maps.Clone(u.Past)
		h.usage.rows[[2]string{u.Role, u.Service}] = &c
	}
}
