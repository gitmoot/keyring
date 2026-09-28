package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

func TestUsageCountsCallsAndRefusals(t *testing.T) {
	up, _ := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, policy.Access{Paths: []string{"/v1/a"}, Methods: []string{"GET"}})
	now := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if w := call(h, "GET", "/api/v1/a", testToken, nil); w.Code != 200 {
			t.Fatalf("call %d: %d", i, w.Code)
		}
		now = now.Add(time.Minute)
	}
	if w := call(h, "GET", "/api/v1/other", testToken, nil); w.Code != http.StatusForbidden {
		t.Fatalf("refused call: %d", w.Code)
	}
	call(h, "GET", "/nosuchservice/x", testToken, nil)
	call(h, "GET", "/api/v1/a", "wrong-token", nil)
	rows := h.Usage()
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want only phobos/api", rows)
	}
	u := rows[0]
	if u.Role != "phobos" || u.Service != "api" || u.Calls != 4 || u.LastStatus != http.StatusForbidden || !u.LastUsed.Equal(now) {
		t.Fatalf("usage = %+v", u)
	}
}

func TestUsageResetsDailyAndRestores(t *testing.T) {
	up, _ := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	now := time.Date(2026, 9, 27, 23, 59, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	call(h, "GET", "/api/v1/a", testToken, nil)
	saved := h.Usage()
	now = now.Add(2 * time.Minute) // next UTC day
	if got := h.Usage(); got[0].Calls != 0 || !got[0].LastUsed.Equal(saved[0].LastUsed) {
		t.Fatalf("next day: %+v, want 0 calls and the old last-used time", got[0])
	}
	call(h, "GET", "/api/v1/a", testToken, nil)
	if got := h.Usage(); got[0].Calls != 1 {
		t.Fatalf("first call of the new day: %+v", got[0])
	}
	fresh, _ := newHandler(t, up.URL, bearer, allowAll)
	fresh.now = func() time.Time { return now }
	fresh.RestoreUsage(saved)
	if got := fresh.Usage(); len(got) != 1 || !got[0].LastUsed.Equal(saved[0].LastUsed) || got[0].LastStatus != 200 {
		t.Fatalf("restored: %+v", got)
	}
}

func TestUsageKeepsSevenDaysAcrossRestarts(t *testing.T) {
	up, _ := upstream(t)
	h, _ := newHandler(t, up.URL, bearer, allowAll)
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	// Day 20: 1 call, day 21: 2 calls, ... day 28: 9 calls.
	for d := 0; d < 9; d++ {
		for i := 0; i <= d; i++ {
			call(h, "GET", "/api/v1/a", testToken, nil)
		}
		if d == 4 { // a restart mid-way keeps the history
			saved := h.Usage()
			h, _ = newHandler(t, up.URL, bearer, allowAll)
			h.now = func() time.Time { return now }
			h.RestoreUsage(saved)
		}
		now = now.AddDate(0, 0, 1)
	}
	now = now.AddDate(0, 0, -1) // back to day 28, the last day called
	if got := h.Usage()[0].Week(); got != [7]int{3, 4, 5, 6, 7, 8, 9} {
		t.Fatalf("week on day 28 = %v, want 3..9", got)
	}
	now = now.AddDate(0, 0, 2) // two quiet days later
	got := h.Usage()[0]
	if got.Week() != [7]int{5, 6, 7, 8, 9, 0, 0} || len(got.Past) != 5 {
		t.Fatalf("week two days later = %v (past %v)", got.Week(), got.Past)
	}
}
