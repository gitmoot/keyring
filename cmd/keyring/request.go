package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/relay"
	"github.com/gitmoot/keyring/internal/server"
)

// fileRequest asks the keyring for full access to services for role. With
// tokensDir (a new agent), the role's token is made there if it is missing,
// and only its SHA-256 is sent: the token never leaves this machine. The
// owner approves the request in the dashboard.
func fileRequest(upstream, role string, services []string, note, tokensDir string, stdout io.Writer) error {
	u, err := relay.CheckUpstream(upstream)
	if err != nil {
		return err
	}
	if !policy.ValidRoleName(role) || len(services) == 0 {
		return errors.New("give --role NAME and at least one --service")
	}
	body := map[string]any{"role": role, "services": services}
	if note != "" {
		body["note"] = note
	}
	if tokensDir != "" {
		sha, created, err := roleToken(tokensDir, role)
		if err != nil {
			return err
		}
		body["fingerprint"] = sha
		if created {
			fmt.Fprintf(stdout, "made %s; restart the relay so it uses it\n", filepath.Join(tokensDir, role+".token"))
		}
	}
	raw, _ := json.Marshal(body)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Post(strings.TrimSuffix(u.String(), "/")+server.RequestsPath, "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("keyring answered %d: %s", resp.StatusCode, strings.TrimSpace(string(answer)))
	}
	var out struct{ ID string }
	_ = json.Unmarshal(answer, &out)
	fmt.Fprintf(stdout, "request %s filed: %s for %s; the owner approves it under Agents in the dashboard\n", out.ID, strings.Join(services, ", "), role)
	return nil
}

// roleToken returns the SHA-256 of dir/<role>.token, making the token
// (mode 600) when the file does not exist.
func roleToken(dir, role string) (sha string, created bool, err error) {
	path := filepath.Join(dir, role+".token")
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		token, sha, err := policy.NewToken()
		if err != nil {
			return "", false, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", false, err
		}
		if _, err := fmt.Fprintln(f, token); err != nil {
			f.Close()
			return "", false, err
		}
		return sha, true, f.Close()
	}
	if err != nil {
		return "", false, err
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(string(raw))))
	return hex.EncodeToString(sum[:]), false, nil
}
