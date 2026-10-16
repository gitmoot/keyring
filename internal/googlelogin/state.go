// Package googlelogin owns the fixed, per-container Google CLI login.
// Its opaque database files are encrypted with the instance, never stored as
// proxy keys or returned by a metadata endpoint.
package googlelogin

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"github.com/gitmoot/keyring/internal/policy"
)

const maxFilesBytes = 256 << 10

var databaseNames = [...]string{"credentials.db", "access_tokens.db", "default_configs.db"}

// Snapshot is immutable after publication to the instance state.
// Configuration text is regenerated, not imported from an arbitrary gcloud
// configuration that could select another credential source or executable.
type Snapshot struct {
	Generation string            `json:"generation"`
	Account    string            `json:"account,omitempty"`
	Project    string            `json:"project,omitempty"`
	Ready      bool              `json:"ready,omitempty"`
	NeedsLogin bool              `json:"needs_login,omitempty"`
	Files      map[string][]byte `json:"files,omitempty"`
}

func validGeneration(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validProject(value string) bool {
	if len(value) < 6 || len(value) > 30 || value[0] < 'a' || value[0] > 'z' || value[len(value)-1] == '-' {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func databaseName(name string) bool {
	for _, allowed := range databaseNames {
		if name == allowed {
			return true
		}
	}
	return false
}

func (s *Snapshot) Validate() error {
	if s == nil {
		return nil
	}
	if !validGeneration(s.Generation) {
		return errors.New("invalid Google login generation")
	}
	if s.Account != "" {
		address, err := mail.ParseAddress(s.Account)
		if err != nil || address.Address != s.Account || len(s.Account) > 254 || strings.HasPrefix(s.Account, "-") || strings.ContainsAny(s.Account, " \t\r\n\x00") {
			return errors.New("invalid Google login account")
		}
	}
	if s.Project != "" && !validProject(s.Project) {
		return errors.New("invalid Google project")
	}
	total := 0
	for name, data := range s.Files {
		if !databaseName(name) || len(data) == 0 || len(data) > maxFilesBytes-total {
			return errors.New("invalid Google login storage")
		}
		total += len(data)
	}
	if s.Ready && (s.NeedsLogin || s.Account == "" || s.Project == "" || len(s.Files["credentials.db"]) == 0) {
		return errors.New("incomplete Google login")
	}
	return nil
}

func (s *Snapshot) Binding() policy.GoogleAccount {
	return policy.GoogleAccount{
		Executable:   policy.ContainerGoogleExecutable,
		ConfigDir:    filepath.Join(policy.ContainerGoogleRoot, s.Generation),
		Account:      s.Account,
		QuotaProject: s.Project,
	}
}

func privateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("Google login directory is not private")
	}
	return nil
}

func replacePrivate(path string, data []byte) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("unsafe Google login file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".google-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

// restore is called only before this generation admits any SDK command.
func restore(root string, s *Snapshot) (string, error) {
	if err := s.Validate(); err != nil || s == nil {
		return "", errors.New("invalid Google login snapshot")
	}
	if err := privateDirectory(root); err != nil {
		return "", err
	}
	dir := filepath.Join(root, s.Generation)
	if err := privateDirectory(dir); err != nil {
		return "", err
	}
	// Never let an old SQLite journal undo the authoritative sealed snapshot
	// after a crash. This generation has no running SDK writer during restore.
	if err := os.RemoveAll(dir); err != nil {
		return "", err
	}
	if err := privateDirectory(dir); err != nil {
		return "", err
	}
	if err := privateDirectory(filepath.Join(dir, "configurations")); err != nil {
		return "", err
	}
	config := "[core]\ndisable_usage_reporting = true\n"
	if s.Account != "" {
		config += "account = " + s.Account + "\n"
	}
	if s.Project != "" {
		config += "project = " + s.Project + "\n"
	}
	if err := replacePrivate(filepath.Join(dir, "configurations", "config_default"), []byte(config)); err != nil {
		return "", err
	}
	for _, name := range databaseNames {
		// Pre-create even new databases privately: SQLite otherwise inherits
		// the process umask. SQLite initializes an empty file on first open.
		if err := replacePrivate(filepath.Join(dir, name), s.Files[name]); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// capture runs after the SDK process has exited, with all SDK operations for
// this generation serialized. Never snapshot an open SQLite transaction.
func capture(dir string, previous *Snapshot) (*Snapshot, error) {
	next := *previous
	next.Files = make(map[string][]byte, len(databaseNames))
	total := 0
	changed := false
	for _, name := range databaseNames {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			changed = changed || previous.Files[name] != nil
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > int64(maxFilesBytes-total) {
			return nil, errors.New("unsafe or oversized Google login storage")
		}
		if info.Size() == 0 {
			changed = changed || previous.Files[name] != nil
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("cannot preserve Google login storage")
		}
		if len(data) > maxFilesBytes-total {
			return nil, errors.New("Google login storage exceeds its bound")
		}
		total += len(data)
		if bytes.Equal(data, previous.Files[name]) {
			next.Files[name] = previous.Files[name]
		} else {
			next.Files[name] = data
			changed = true
		}
	}
	if !changed {
		return previous, nil
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	return &next, nil
}
