package policy

import (
	"errors"
	"fmt"
	"net/mail"
	"path/filepath"
	"strings"
)

// GoogleAccountNameLimit bounds labels stored in protected renewal history.
const GoogleAccountNameLimit = 128

// Container Google paths are image-owned, never chosen by the admin API.
const (
	ContainerGoogleExecutable = "/opt/google-cloud-sdk/bin/gcloud"
	ContainerGoogleRoot       = "/run/keyring/google"
)

func containerGoogleDir(dir string) bool {
	generation, ok := strings.CutPrefix(dir, ContainerGoogleRoot+"/")
	if !ok || len(generation) != 32 {
		return false
	}
	for _, c := range generation {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func containerGoogleService(name string, svc Service) bool {
	if svc.GoogleAccount != "me" {
		return false
	}
	switch name {
	case "google-me-drive":
		return svc.Base == "https://www.googleapis.com/drive/v3"
	case "google-me-upload":
		return svc.Base == "https://www.googleapis.com/upload/drive/v3"
	case "google-me-sheets":
		return svc.Base == "https://sheets.googleapis.com/v4"
	default:
		return false
	}
}

// GoogleAccount binds one gcloud login. All fields participate in the cache
// identity. Hosts use root-owned rules; containers derive only fixed bindings.
type GoogleAccount struct {
	Executable   string `json:"executable"`
	ConfigDir    string `json:"config_dir"`
	Account      string `json:"account"`
	QuotaProject string `json:"quota_project,omitempty"`
}

func (c *Config) validateGoogleAccounts() error {
	dirs := map[string]bool{}
	for name, a := range c.GoogleAccounts {
		if c.ContainerMode && (name != "me" || a.Executable != ContainerGoogleExecutable || !containerGoogleDir(a.ConfigDir)) {
			return errors.New("container Google accounts require the fixed me runtime")
		}
		if len(name) > GoogleAccountNameLimit || !serviceName.MatchString(name) {
			return fmt.Errorf("google_accounts names must use lowercase letters, digits and - and be at most %d characters", GoogleAccountNameLimit)
		}
		for _, p := range []string{a.Executable, a.ConfigDir} {
			if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\x00\r\n") {
				return fmt.Errorf("google_account %s: executable and config_dir must be clean absolute paths", name)
			}
		}
		if a.ConfigDir == "/" || dirs[a.ConfigDir] {
			return errors.New("each google_account requires its own private config_dir")
		}
		dirs[a.ConfigDir] = true
		addr, err := mail.ParseAddress(a.Account)
		if err != nil || addr.Address != a.Account || len(a.Account) > 254 || strings.HasPrefix(a.Account, "-") || strings.ContainsAny(a.Account, " \t\r\n\x00") {
			return fmt.Errorf("google_account %s: account must be an explicit email address", name)
		}
		if a.QuotaProject != "" && (!serviceName.MatchString(a.QuotaProject) || len(a.QuotaProject) > 63) {
			return fmt.Errorf("google_account %s: invalid quota_project", name)
		}
	}
	return nil
}
