package policy

import (
	"errors"
	"fmt"
	"net/mail"
	"path/filepath"
	"strings"
)

// GoogleAccount binds one host-side gcloud login. All fields participate in
// the credential cache identity. It is configured only in root-owned rules.
type GoogleAccount struct {
	Executable   string `json:"executable"`
	ConfigDir    string `json:"config_dir"`
	Account      string `json:"account"`
	QuotaProject string `json:"quota_project,omitempty"`
}

func (c *Config) validateGoogleAccounts() error {
	if c.ContainerMode && len(c.GoogleAccounts) != 0 {
		return errors.New("google_accounts requires host file mode")
	}
	dirs := map[string]bool{}
	for name, a := range c.GoogleAccounts {
		if !serviceName.MatchString(name) {
			return errors.New("google_accounts names must use lowercase letters, digits and -")
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
