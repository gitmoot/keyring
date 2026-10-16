package googlelogin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/gcloudexec"
)

const commandOutputLimit = 16 << 10

type commandError string

func (e commandError) Error() string { return string(e) }

const (
	errLogin   commandError = "login_required"
	errTerms   commandError = "cloud_terms_not_accepted"
	errRate    commandError = "rate_limited"
	errCommand commandError = "google_command_failed"
)

// Raw SDK output never becomes an error, log entry or HTTP response.
func classifyCommand(data []byte) error {
	text := bytes.ToLower(data)
	defer clear(text)
	has := func(s string) bool { return bytes.Contains(text, []byte(s)) }
	switch {
	case has("callers must accept terms of service"):
		return errTerms
	case has("invalid_grant: token has been expired or revoked"),
		has("'error': 'invalid_grant'"), has(`"error":"invalid_grant"`), has(`"error": "invalid_grant"`),
		gcloudexec.ClassifyReauth(text).Required,
		has("you do not currently have an active account selected"):
		return errLogin
	case has("resource_exhausted"), has("quota exceeded"), has("'status': 429"):
		return errRate
	default:
		return errCommand
	}
}

type commandOutput struct {
	mu    sync.Mutex
	data  bytes.Buffer
	onURL func(string)
}

func (out *commandOutput) Write(data []byte) (int, error) {
	out.mu.Lock()
	defer out.mu.Unlock()
	if len(data) > commandOutputLimit-out.data.Len() {
		return 0, errors.New("Google command output limit")
	}
	out.data.Write(data)
	if out.onURL != nil {
		text := out.data.String()
		if start := strings.Index(text, "https://accounts.google.com/"); start >= 0 {
			text = text[start:]
			// Wait for a complete printed URL, not a partial pipe read.
			if end := strings.IndexAny(text, " \t\r\n"); end >= 0 {
				candidate := text[:end]
				u, err := url.Parse(candidate)
				if err == nil && u.Scheme == "https" && u.Host == "accounts.google.com" && u.User == nil && strings.HasPrefix(u.Path, "/o/oauth2/") {
					out.onURL(candidate)
					out.onURL = nil
				}
			}
		}
	}
	return len(data), nil
}

func (c *Controller) command(ctx context.Context, dir string, args ...string) (*exec.Cmd, func(), error) {
	cmd := exec.CommandContext(ctx, c.executable, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + filepath.Dir(c.executable) + ":/usr/bin:/bin",
		"HOME=" + dir, "CLOUDSDK_CONFIG=" + dir,
		"CLOUDSDK_CORE_DISABLE_PROMPTS=1",
		"CLOUDSDK_CORE_DISABLE_FILE_LOGGING=true",
		"CLOUDSDK_CORE_DISABLE_USAGE_REPORTING=true",
		"CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=true",
		"CLOUDSDK_PYTHON_SITEPACKAGES=0",
		"CLOUDSDK_CORE_CHECK_GCE_METADATA=false",
		"LANG=C.UTF-8",
	}
	cmd.WaitDelay = time.Second
	cleanup, err := gcloudexec.Bound(cmd)
	return cmd, cleanup, err
}

func (c *Controller) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd, cleanup, err := c.command(ctx, dir, args...)
	if err != nil {
		return nil, errCommand
	}
	defer cleanup()
	stdout, stderr := &commandOutput{}, &commandOutput{}
	defer func() { clear(stderr.data.Bytes()) }()
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		clear(stdout.data.Bytes())
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, classifyCommand(stderr.data.Bytes())
	}
	return stdout.data.Bytes(), nil
}

func (c *Controller) login(ctx context.Context, j *job, dir string, account string) error {
	args := []string{"auth", "login", "--enable-gdrive-access", "--no-launch-browser", "--configuration=default"}
	if account != "" {
		args = append(args, account)
	}
	cmd, cleanup, err := c.command(ctx, dir, args...)
	if err != nil {
		return errCommand
	}
	defer cleanup()
	input, err := cmd.StdinPipe()
	if err != nil {
		return errCommand
	}
	defer input.Close()
	out := &commandOutput{onURL: func(address string) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.job == j && !j.done {
			j.view.URL, j.view.Phase = address, "awaiting_code"
		}
	}}
	defer func() { clear(out.data.Bytes()) }()
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		return errCommand
	}
	inputCtx, cancelInput := context.WithCancel(ctx)
	defer cancelInput()
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		select {
		case code := <-j.code:
			_, _ = io.WriteString(input, code+"\n")
			_ = input.Close()
		case <-inputCtx.Done():
		}
	}()
	err = cmd.Wait()
	cancelInput()
	<-inputDone
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return classifyCommand(out.data.Bytes())
	}
	return nil
}
