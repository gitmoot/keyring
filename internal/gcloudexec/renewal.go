package gcloudexec

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"
)

// RenewalPhase is fixed metadata, never derived from command or provider output.
type RenewalPhase uint8

const (
	RenewalConfiguration RenewalPhase = iota
	RenewalControllerWait
	RenewalSDK
	RenewalPersistence
	RenewalValidation
	renewalPhaseCount
)

var renewalPhaseNames = [renewalPhaseCount]string{"configuration", "controller_wait", "sdk_execution", "persistence", "token_validation"}

type RenewalStep struct {
	Phase      string `json:"phase"`
	DurationMS int64  `json:"duration_ms"`
	Outcome    string `json:"outcome"`
}

type RenewalProcess struct {
	Available bool  `json:"available"`
	CPUTimeMS int64 `json:"cpu_time_ms"`
	ExitCode  int   `json:"exit_code"`
	Signal    int   `json:"signal"`
}

// RenewalRecord describes only the latest attempt, including an in-flight one.
// There are no error strings, arguments, identities, URLs or credential bytes.
type RenewalRecord struct {
	StartedAt   time.Time                      `json:"started_at"`
	CompletedAt time.Time                      `json:"completed_at,omitzero"`
	Phase       string                         `json:"phase"`
	Outcome     string                         `json:"outcome"`
	DurationMS  int64                          `json:"duration_ms"`
	Process     RenewalProcess                 `json:"process"`
	Steps       [renewalPhaseCount]RenewalStep `json:"steps"`
}

// RenewalTrace is embedded in the existing account cache entry. Its fixed-size
// record is replaced on the next actual renewal; cache hits do not reset it.
// A nil trace permits credential operations without a diagnostic observer.
type RenewalTrace struct {
	mu      sync.Mutex
	record  RenewalRecord
	started time.Time
	entered time.Time
	phase   RenewalPhase
	active  bool
	failed  bool
	failure RenewalPhase
}

func (t *RenewalTrace) Begin() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.record = RenewalRecord{StartedAt: now.UTC(), Outcome: "running"}
	for i, name := range renewalPhaseNames {
		t.record.Steps[i] = RenewalStep{Phase: name, Outcome: "not_run"}
	}
	t.started, t.entered = now, now
	t.phase, t.active, t.failed = RenewalConfiguration, true, false
	t.record.Steps[t.phase].Outcome = "running"
}

func (t *RenewalTrace) Enter(phase RenewalPhase) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.end(nil, now)
	t.phase, t.entered, t.active = phase, now, true
	t.record.Steps[phase].Outcome = "running"
}

func (t *RenewalTrace) End(err error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.end(err, time.Now())
}

func renewalOutcome(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "error"
	}
}

func (t *RenewalTrace) end(err error, now time.Time) {
	if !t.active {
		return
	}
	s := &t.record.Steps[t.phase]
	s.DurationMS += now.Sub(t.entered).Milliseconds()
	s.Outcome = renewalOutcome(err)
	if err != nil && !t.failed {
		t.failure, t.failed = t.phase, true
	}
	t.active = false
}

func (t *RenewalTrace) Finish(err error) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.end(err, now)
	t.record.CompletedAt = now.UTC()
	t.record.DurationMS = now.Sub(t.started).Milliseconds()
	t.record.Outcome = renewalOutcome(err)
	t.record.Phase = "complete"
	if err != nil {
		phase := t.phase
		if t.failed {
			phase = t.failure
			t.record.Outcome = t.record.Steps[phase].Outcome
		}
		t.record.Phase = renewalPhaseNames[phase]
	}
}

// Process records only numeric terminal process metadata, never output.
func (t *RenewalTrace) Process(state *os.ProcessState) {
	if t == nil || state == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record.Process = RenewalProcess{Available: true,
		CPUTimeMS: (state.UserTime() + state.SystemTime()).Milliseconds(),
		ExitCode:  state.ExitCode()}
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		t.record.Process.Signal = int(status.Signal())
	}
}

func (t *RenewalTrace) Snapshot() (RenewalRecord, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started.IsZero() {
		return RenewalRecord{}, false
	}
	r := t.record
	if r.CompletedAt.IsZero() {
		now := time.Now()
		r.DurationMS = now.Sub(t.started).Milliseconds()
		r.Phase = renewalPhaseNames[t.phase]
		if t.active {
			r.Steps[t.phase].DurationMS += now.Sub(t.entered).Milliseconds()
		}
	}
	return r, true
}
