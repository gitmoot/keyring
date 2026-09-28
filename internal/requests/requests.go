// Package requests keeps access requests that agents file with the keyring
// and the owner approves or declines in the dashboard. A request changes
// nothing by itself: it is a proposal, kept in a file next to the store.
package requests

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/policy"
)

const (
	// MaxPending bounds the file: an agent filing requests in a loop cannot
	// fill the disk or bury real requests.
	MaxPending  = 20
	maxServices = 30
	maxNote     = 300
)

var fingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Request asks for an agent (a role) to use some services with full access.
// Fingerprint is set only for a new agent: the SHA-256 of the token the
// agent made on its own machine. A request never changes an existing
// agent's token.
type Request struct {
	ID          string    `json:"id"`
	Role        string    `json:"role"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Services    []string  `json:"services"`
	Note        string    `json:"note,omitempty"`
	From        string    `json:"from"` // the address that filed it
	Filed       time.Time `json:"filed"`
}

// Store is the requests file. Its methods are safe for concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
}

func Open(path string) *Store { return &Store{path: path} }

func (s *Store) load() ([]Request, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Request
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", s.path, err)
	}
	return out, nil
}

func (s *Store) save(list []Request) error {
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(s.path, append(raw, '\n'), 0o600)
}

// Pending lists open requests, oldest first.
func (s *Store) Pending() ([]Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// Check validates a request against the running access list: known
// services, a fingerprint exactly when the agent is new, no token already in
// use. It is run when filing and again when approving.
func Check(r Request, access policy.AccessList) error {
	if !policy.ValidRoleName(r.Role) {
		return fmt.Errorf("role %q: letters, digits, dot, dash or underscore, starting with a letter or digit", r.Role)
	}
	if len(r.Services) == 0 || len(r.Services) > maxServices {
		return fmt.Errorf("ask for 1 to %d services", maxServices)
	}
	seen := map[string]bool{}
	for _, svc := range r.Services {
		if _, ok := access.Services[svc]; !ok {
			return fmt.Errorf("unknown service %q", svc)
		}
		if seen[svc] {
			return fmt.Errorf("service %q listed twice", svc)
		}
		seen[svc] = true
	}
	if len(r.Note) > maxNote {
		return fmt.Errorf("note longer than %d characters", maxNote)
	}
	_, exists := access.Roles[r.Role]
	switch {
	case exists && r.Fingerprint != "":
		return fmt.Errorf("agent %s exists: a request cannot change its token", r.Role)
	case !exists && !fingerprint.MatchString(r.Fingerprint):
		return fmt.Errorf("new agent %s needs its token's sha256 (64 lowercase hex characters, from keyring new-token)", r.Role)
	}
	for name, role := range access.Roles {
		if r.Fingerprint != "" && role.TokenSHA256 == r.Fingerprint {
			return fmt.Errorf("agent %s already uses this token", name)
		}
	}
	return nil
}

// File adds a checked request and returns it with its ID. A request equal
// to a pending one (same role, fingerprint and services) is not filed twice.
func (s *Store) File(r Request, access policy.AccessList, from string, now time.Time) (Request, error) {
	r.Services = append([]string(nil), r.Services...)
	sort.Strings(r.Services)
	if err := Check(r, access); err != nil {
		return Request{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return Request{}, err
	}
	for _, p := range list {
		if p.Role == r.Role && p.Fingerprint == r.Fingerprint && fmt.Sprint(p.Services) == fmt.Sprint(r.Services) {
			return p, nil
		}
		if r.Fingerprint != "" && p.Role == r.Role && p.Fingerprint != r.Fingerprint {
			return Request{}, fmt.Errorf("a request for new agent %s with another token is already waiting; the owner answers it first", r.Role)
		}
	}
	if len(list) >= MaxPending {
		return Request{}, fmt.Errorf("%d requests are already waiting for the owner", MaxPending)
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return Request{}, err
	}
	r.ID, r.From, r.Filed = hex.EncodeToString(id), from, now.UTC()
	if err := s.save(append(list, r)); err != nil {
		return Request{}, err
	}
	return r, nil
}

// Take removes and returns the request with id, if it is pending.
func (s *Store) Take(id string) (Request, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return Request{}, false, err
	}
	for i, r := range list {
		if r.ID == id {
			return r, true, s.save(append(list[:i], list[i+1:]...))
		}
	}
	return Request{}, false, nil
}

// Put puts a taken request back (its approval failed).
func (s *Store) Put(r Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list, err := s.load()
	if err != nil {
		return err
	}
	return s.save(append([]Request{r}, list...))
}
