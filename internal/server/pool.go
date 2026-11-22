package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

// Key pools (owner, 2026-11-22): a service with key_pool sends each call with
// one of its key's values and, when the provider says that value is the
// problem, sends it again with the next. P0 is staying up when a key dies or
// runs out; the dashboard shows each value's state and use.

// poolBodyLimit is the largest request body kept to send again. A larger
// body goes out once, with the first value in line.
const poolBodyLimit = 32 << 20

// poolPeek is how much of a 400 answer is read to tell a spend limit from a
// bad request. Error answers are small JSON; the bytes are passed on.
const poolPeek = 16 << 10

// verdict is what an answer says about the value that was sent.
type verdict struct {
	keyProblem bool
	// hard: the value itself is bad (rejected, no credit, spend limit), not
	// just busy; the dashboard shows it as failing.
	hard   bool
	cool   time.Duration
	reason string
}

// judge reads an answer, received at now, for a key problem. Only answers
// that mean the request was refused because of the key count: a malformed
// request (other 400s) or the provider being down (5xx) would fail with
// every key.
func judge(svc policy.Service, resp *http.Response, now time.Time) verdict {
	anthropic := isAnthropic(svc)
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return verdict{true, true, time.Hour, "401 key rejected"}
	case http.StatusForbidden:
		return verdict{true, true, time.Hour, "403 key not allowed"}
	case http.StatusPaymentRequired:
		return verdict{true, true, time.Hour, "402 billing problem"}
	case http.StatusTooManyRequests:
		if wait, ok := retryAfter(resp.Header.Get("Retry-After"), now); ok {
			return verdict{true, false, wait, "429 rate limit"}
		}
		if anthropic {
			// Anthropic: a 429 without retry-after is the monthly spend
			// cap, which keeps failing until access resumes.
			return verdict{true, true, time.Hour, "429 spend cap reached"}
		}
		return verdict{true, false, time.Minute, "429 rate limit"}
	case http.StatusBadRequest:
		// Only Anthropic says a spend limit with a 400; any other 400 is
		// passed on untouched.
		if anthropic && spendLimitMessage(peekBody(resp)) {
			return verdict{true, true, time.Hour, "400 spend limit or credit exhausted"}
		}
	}
	return verdict{}
}

// isAnthropic reports whether svc calls the Anthropic API, whose answers
// have their own meanings.
func isAnthropic(svc policy.Service) bool { return svc.Provider() == "api.anthropic.com" }

// retryAfter reads Retry-After, delay-seconds or an HTTP-date (RFC 9110
// 10.2.3), as a wait from now bounded to [1 s, 1 h].
func retryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	var wait time.Duration
	if v != "" && strings.Trim(v, "0123456789") == "" {
		// Too many digits for a uint64 is still a long wait.
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n > 3600 {
			n = 3600
		}
		wait = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		wait = t.Sub(now)
	} else {
		return 0, false
	}
	return min(max(wait, time.Second), time.Hour), true
}

// spendLimitMessage reports whether an Anthropic error body says a spend
// limit or the credit balance stopped the request.
func spendLimitMessage(body []byte) bool {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return false
	}
	m := strings.ToLower(e.Error.Message)
	return strings.Contains(m, "spend limit") || strings.Contains(m, "usage limit") || strings.Contains(m, "credit balance")
}

// poolKey is what the keyring knows about one value of a pooled key. It is
// tied to the value: replacing the value starts over.
type poolKey struct {
	value       [sha256.Size]byte
	coolUntil   time.Time
	hard        bool
	lastStatus  int
	reason      string
	lastFailure time.Time
	lastOK      time.Time
	failDay     string
	failures    int
}

type poolBook struct {
	mu   sync.Mutex
	keys map[string]*poolKey
}

func (b *poolBook) entry(name, value string) *poolKey {
	sum := sha256.Sum256([]byte(value))
	if b.keys == nil {
		b.keys = map[string]*poolKey{}
	}
	k := b.keys[name]
	if k == nil || k.value != sum {
		k = &poolKey{value: sum}
		b.keys[name] = k
	}
	return k
}

// order lists the members to try: those not set aside in pool order, then
// those set aside, soonest back first. A call never fails locally because
// every value is set aside: they are still tried.
func (b *poolBook) order(members []string, keys map[string]string, now time.Time) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var ready, waiting []string
	until := map[string]time.Time{}
	for _, name := range members {
		k := b.entry(name, keys[name])
		if now.Before(k.coolUntil) {
			waiting = append(waiting, name)
			until[name] = k.coolUntil
		} else {
			ready = append(ready, name)
		}
	}
	slices.SortStableFunc(waiting, func(x, y string) int { return until[x].Compare(until[y]) })
	return append(ready, waiting...)
}

// sendable keeps the members whose value can go out the way svc sends it
// (a header value may not hold a line break or control character).
func sendable(svc policy.Service, members []string, keys map[string]string) []string {
	var out []string
	for _, name := range members {
		if unsendableKey(svc, keys[name], keys) == "" {
			out = append(out, name)
		}
	}
	return out
}

// current is the entry for name if it is still about value: an answer to a
// value that has since been replaced says nothing about the new one.
func (b *poolBook) current(name, value string) *poolKey {
	if k := b.keys[name]; k != nil && k.value == sha256.Sum256([]byte(value)) {
		return k
	}
	return nil
}

// failed sets value aside after a refusal received at now.
func (b *poolBook) failed(name, value string, status int, v verdict, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := b.current(name, value)
	if k == nil {
		return
	}
	k.coolUntil, k.hard, k.lastStatus, k.reason, k.lastFailure = now.Add(v.cool), v.hard, status, v.reason, now
	day := now.UTC().Format("2006-01-02")
	if k.failDay != day {
		k.failDay, k.failures = day, 0
	}
	k.failures++
}

func (b *poolBook) worked(name, value string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if k := b.current(name, value); k != nil {
		k.coolUntil, k.hard, k.lastOK = time.Time{}, false, now
	}
}

// PoolKeyStatus is one pooled value as the dashboard shows it. No value, no
// part of one.
type PoolKeyStatus struct {
	// State: "failing" (set aside, the value itself is the problem),
	// "cooling" (set aside, busy), "working" (worked last), or "" (nothing
	// known since the value was stored or the keyring started).
	State         string
	Until         time.Time
	Status        int
	Reason        string
	LastFailure   time.Time
	FailuresToday int
}

// PoolKeyStatus reports what the keyring knows about the pooled store key
// name, for its current value.
func (h *Handler) PoolKeyStatus(name string) PoolKeyStatus {
	snap := h.snap.Load()
	value := snap.keys[name]
	for _, svc := range snap.config.Services {
		if slices.Contains(policy.PoolMembers(svc, snap.keys), name) && unsendableKey(svc, value, snap.keys) != "" {
			return PoolKeyStatus{State: "failing", Reason: "the value has a line break or control character and cannot be sent; replace it"}
		}
	}
	now := h.now()
	h.pool.mu.Lock()
	defer h.pool.mu.Unlock()
	k := h.pool.current(name, value)
	if k == nil {
		return PoolKeyStatus{}
	}
	st := PoolKeyStatus{Until: k.coolUntil, Status: k.lastStatus, Reason: k.reason, LastFailure: k.lastFailure}
	if k.failDay == now.UTC().Format("2006-01-02") {
		st.FailuresToday = k.failures
	}
	switch {
	case now.Before(k.coolUntil) && k.hard:
		st.State = "failing"
	case now.Before(k.coolUntil):
		st.State = "cooling"
	case !k.lastOK.IsZero() && k.lastOK.After(k.lastFailure):
		st.State = "working"
	}
	return st
}

// replayable holds a request body so it can be sent more than once.
type replayable struct {
	buf  []byte
	rest io.Reader // non-nil: the body was larger than poolBodyLimit
}

func readReplayable(r *http.Request) (*replayable, error) {
	if r.ContentLength > poolBodyLimit {
		return &replayable{rest: r.Body}, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, poolBodyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > poolBodyLimit {
		return &replayable{buf: buf, rest: r.Body}, nil
	}
	return &replayable{buf: buf}, nil
}

// once reports whether the body can be sent only one time.
func (p *replayable) once() bool { return p.rest != nil }

func (p *replayable) body(length int64) (io.Reader, int64) {
	if p.rest != nil {
		return io.MultiReader(bytes.NewReader(p.buf), p.rest), length
	}
	return bytes.NewReader(p.buf), int64(len(p.buf))
}

// peekBody reads up to poolPeek bytes of the answer and puts them back in
// front of the rest, so the caller still gets the whole answer.
func peekBody(resp *http.Response) []byte {
	peek, _ := io.ReadAll(io.LimitReader(resp.Body, poolPeek))
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(peek), resp.Body), resp.Body}
	return peek
}
