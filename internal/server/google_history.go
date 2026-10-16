package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/policy"
)

const (
	googleHistoryAccounts  = 64
	googleHistoryIncidents = 8
	googleHistoryBytes     = 1 << 20
)

// GoogleIncident keeps only fixed diagnoses and timestamps, never SDK output.
// A cause change is not recovery; only a validated successful renewal is.
type GoogleIncident struct {
	FirstFailure time.Time     `json:"first_failure"`
	LastFailure  time.Time     `json:"last_failure"`
	LastSuccess  time.Time     `json:"last_success,omitempty"`
	RecoveredAt  time.Time     `json:"recovered_at,omitempty"`
	Outcome      string        `json:"outcome"`
	Attempts     uint64        `json:"attempts"`
	Failure      GoogleFailure `json:"failure"`
}

type googleAccountHistory struct {
	Label       string           `json:"account"`
	Binding     string           `json:"binding"`
	LastSuccess time.Time        `json:"last_success,omitempty"`
	Updated     time.Time        `json:"updated"`
	Incidents   []GoogleIncident `json:"incidents,omitempty"`
}

type googleHistoryFile struct {
	Version  int                              `json:"version"`
	Accounts map[string]*googleAccountHistory `json:"accounts"`
}

type googleHistory struct {
	mu          sync.Mutex
	file        googleHistoryFile
	path        string
	unavailable bool
}

// GoogleHistoryStatus is owner-only metadata. Looking it up requires both the
// current label and full binding: reusing a label never exposes the old account.
type GoogleHistoryStatus struct {
	LastSuccess time.Time
	Incidents   []GoogleIncident
	Unavailable bool
}

func googleBindingID(a policy.GoogleAccount) string {
	data, _ := json.Marshal(a)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func historyLabel(label string) bool {
	if len(label) == 0 || len(label) > 128 {
		return false
	}
	for _, c := range label {
		if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func (f *googleHistoryFile) valid() bool {
	if f.Version != 1 || len(f.Accounts) > googleHistoryAccounts {
		return false
	}
	for key, account := range f.Accounts {
		if account == nil || !historyLabel(account.Label) || len(account.Binding) != 64 || key != account.Label+":"+account.Binding || len(account.Incidents) > googleHistoryIncidents || account.Updated.IsZero() {
			return false
		}
		if _, err := hex.DecodeString(account.Binding); err != nil {
			return false
		}
		for i, incident := range account.Incidents {
			if !incident.Failure.valid() || incident.Attempts == 0 || incident.FirstFailure.IsZero() || incident.LastFailure.Before(incident.FirstFailure) || incident.LastSuccess.After(incident.FirstFailure) {
				return false
			}
			switch incident.Outcome {
			case "active":
				if i != len(account.Incidents)-1 || !incident.RecoveredAt.IsZero() {
					return false
				}
			case "renewed":
				if incident.RecoveredAt.IsZero() || incident.RecoveredAt.Before(incident.LastFailure) {
					return false
				}
			case "diagnosis_changed":
				if !incident.RecoveredAt.IsZero() {
					return false
				}
			default:
				return false
			}
		}
	}
	return true
}

// OpenGoogleHistory is called once before serving. A corrupt/insecure history
// is left untouched; callers must surface the error instead of overwriting it.
func (h *Handler) OpenGoogleHistory(path string) error {
	book := &h.googleHistory
	book.mu.Lock()
	defer book.mu.Unlock()
	book.file = googleHistoryFile{Version: 1, Accounts: map[string]*googleAccountHistory{}}
	book.path = ""
	book.unavailable = true
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return errors.New("Google incident directory is unavailable or writable by other users")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		book.path, book.unavailable = path, false
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > googleHistoryBytes {
		return errors.New("Google incident file is unavailable, unsafe or oversized")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("Google incident file cannot be opened")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return errors.New("Google incident file changed while opening")
	}
	var restored googleHistoryFile
	decoder := json.NewDecoder(io.LimitReader(file, googleHistoryBytes+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&restored) != nil || !restored.valid() {
		return errors.New("Google incident file contains invalid metadata")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("Google incident file contains trailing data")
	}
	book.file, book.path, book.unavailable = restored, path, false
	if book.file.Accounts == nil {
		book.file.Accounts = map[string]*googleAccountHistory{}
	}
	return nil
}

func (h *Handler) GoogleHistory(name string) GoogleHistoryStatus {
	a, ok := h.snap.Load().config.GoogleAccounts[name]
	if !ok {
		return GoogleHistoryStatus{}
	}
	key := name + ":" + googleBindingID(a)
	book := &h.googleHistory
	book.mu.Lock()
	defer book.mu.Unlock()
	result := GoogleHistoryStatus{Unavailable: book.unavailable}
	if entry := book.file.Accounts[key]; entry != nil {
		result.LastSuccess = entry.LastSuccess
		result.Incidents = append([]GoogleIncident(nil), entry.Incidents...)
		for i := range result.Incidents {
			failure := &result.Incidents[i].Failure
			failure.Evidence = append([]string(nil), failure.Evidence...)
			if failure.ExitCode != nil {
				value := *failure.ExitCode
				failure.ExitCode = &value
			}
		}
	}
	return result
}

// Called once per actual attempt, before its single-flight waiters are released.
// Cached errors and ordinary proxy requests do not create incident writes.
func (h *Handler) recordGoogleAttempt(label string, a policy.GoogleAccount, at time.Time, attemptErr error) {
	if label == "" {
		return
	}
	book := &h.googleHistory
	book.mu.Lock()
	defer book.mu.Unlock()
	if !historyLabel(label) {
		book.unavailable = true
		return
	}
	if book.file.Accounts == nil {
		book.file = googleHistoryFile{Version: 1, Accounts: map[string]*googleAccountHistory{}}
	}
	binding := googleBindingID(a)
	key := label + ":" + binding
	entry := book.file.Accounts[key]
	if entry == nil {
		entry = &googleAccountHistory{Label: label, Binding: binding}
		book.file.Accounts[key] = entry
	}
	at = at.UTC()
	// Wall-clock adjustments must not create backwards incident transitions.
	if at.Before(entry.Updated) {
		at = entry.Updated
	}
	entry.Updated = at
	var active *GoogleIncident
	if n := len(entry.Incidents); n != 0 && entry.Incidents[n-1].Outcome == "active" {
		active = &entry.Incidents[n-1]
	}
	if attemptErr == nil {
		entry.LastSuccess = at
		if active != nil {
			active.Outcome, active.RecoveredAt = "renewed", at
		}
	} else {
		var failure *GoogleFailure
		if !errors.As(attemptErr, &failure) || !failure.valid() {
			failure = googleFailure("unknown", "command")
		}
		if active != nil && !sameGoogleFailure(&active.Failure, failure) {
			active.Outcome = "diagnosis_changed"
			active = nil
		}
		if active == nil {
			if len(entry.Incidents) == googleHistoryIncidents {
				entry.Incidents = entry.Incidents[1:]
			}
			entry.Incidents = append(entry.Incidents, GoogleIncident{FirstFailure: at, LastSuccess: entry.LastSuccess, Outcome: "active"})
			active = &entry.Incidents[len(entry.Incidents)-1]
		}
		active.LastFailure, active.Failure = at, *failure
		if active.Attempts != ^uint64(0) {
			active.Attempts++
		}
	}
	if len(book.file.Accounts) > googleHistoryAccounts {
		keys := make([]string, 0, len(book.file.Accounts))
		for candidate := range book.file.Accounts {
			keys = append(keys, candidate)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := book.file.Accounts[keys[i]], book.file.Accounts[keys[j]]
			if a.Updated.Equal(b.Updated) {
				return strings.Compare(keys[i], keys[j]) < 0
			}
			return a.Updated.Before(b.Updated)
		})
		for _, candidate := range keys[:len(keys)-googleHistoryAccounts] {
			delete(book.file.Accounts, candidate)
		}
	}
	if book.path == "" {
		return
	}
	data, err := json.Marshal(book.file)
	if err != nil || len(data) > googleHistoryBytes {
		book.unavailable = true
		return
	}
	book.unavailable = fileutil.WriteAtomic(book.path, data, 0o600) != nil
}
