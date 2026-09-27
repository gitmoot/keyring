package server

import (
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
	if u.Day != day {
		u.Day, u.Calls = day, 0
	}
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
		if c.Day != today {
			c.Day, c.Calls = today, 0
		}
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
		h.usage.rows[[2]string{u.Role, u.Service}] = &c
	}
}
