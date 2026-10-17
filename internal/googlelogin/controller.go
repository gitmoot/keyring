package googlelogin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/gcloudexec"
	"github.com/gitmoot/keyring/internal/policy"
)

// View contains no credentials. URL is returned only to the consent session
// that started the login, never through Status or the instance admin metadata.
type View struct {
	Phase   string `json:"phase"`
	Account string `json:"account,omitempty"`
	Project string `json:"quota_project,omitempty"`
	Busy    bool   `json:"busy"`
	URL     string `json:"-"`
	Error   string `json:"error,omitempty"`
}

type job struct {
	id         string
	generation string
	view       View
	code       chan string
	cancel     context.CancelFunc
	done       bool
}

// Controller serializes every SDK writer, including refresh and revocation.
// save checks ctx and the expected generation inside the instance transaction,
// durably commits, then calls SetState. "*" is accepted only for disconnect's
// nil snapshot. No controller mutex is held while save runs.
type Controller struct {
	mu           sync.Mutex
	ops          chan struct{}
	state        *Snapshot
	job          *job
	closing      bool
	activeCancel context.CancelFunc
	epoch        uint64 // invalidates all pre-disconnect consent capabilities
	save         func(ctx context.Context, expected string, next *Snapshot) error
	executable   string
	root         string
	client       *http.Client
}

func New(save func(context.Context, string, *Snapshot) error) *Controller {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Controller{
		ops: make(chan struct{}, 1), save: save,
		executable: policy.ContainerGoogleExecutable, root: policy.ContainerGoogleRoot,
		client: &http.Client{Transport: transport, Timeout: 15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

// Close cancels SDK writers without revoking a login or changing its sealed
// snapshot. It never waits while the instance transaction mutex may be held.
func (c *Controller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closing = true
	if c.activeCancel != nil {
		c.activeCancel()
	}
	if c.job != nil && !c.job.done {
		c.job.cancel()
	}
}

// SetState is non-blocking with respect to SDK commands and filesystem I/O.
// It is safe to call while holding the instance transaction mutex.
func (c *Controller) SetState(next *Snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = next
	if j := c.job; j != nil && !j.done && j.generation != "" && (next == nil || next.Generation != j.generation) {
		j.cancel()
	}
}

// Restore is used only on initial unlock, before proxy listeners are opened.
func (c *Controller) Restore(next *Snapshot) error {
	if next == nil {
		return nil
	}
	_, err := restore(c.root, next)
	return err
}

func stateView(s *Snapshot) View {
	v := View{Phase: "disconnected"}
	if s == nil {
		return v
	}
	v.Account, v.Project = s.Account, s.Project
	switch {
	case s.Ready:
		v.Phase = "connected"
	case s.NeedsLogin || s.Account == "":
		v.Phase = "login_required"
	default:
		v.Phase = "setup_required"
	}
	return v
}

func (c *Controller) Status() View {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := stateView(c.state)
	if c.closing {
		v.Phase, v.Busy = "disconnecting", true
	} else if c.job != nil && !c.job.done {
		v.Phase, v.Busy = c.job.view.Phase, true
	} else if c.job != nil && c.job.done && (c.state == nil || !c.state.Ready) {
		v.Error = c.job.view.Error
	}
	return v
}

func (c *Controller) View(id string) (View, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.job == nil || c.job.id != id {
		return View{}, false
	}
	v := c.job.view
	v.Busy = !c.job.done
	if c.state != nil && c.state.Generation == c.job.generation {
		v.Account, v.Project = c.state.Account, c.state.Project
	}
	return v, true
}

func (c *Controller) Epoch() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch
}

func (c *Controller) Start(id string, epoch uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if epoch != c.epoch {
		return errors.New("this Google connection link was revoked")
	}
	if c.closing || c.job != nil && !c.job.done {
		return errors.New("a Google connection is already in progress")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	j := &job{id: id, view: View{Phase: "starting"}, code: make(chan string, 1), cancel: cancel}
	c.job = j
	go c.connect(ctx, j)
	return nil
}

func (c *Controller) Submit(id, code string) error {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 4096 || strings.ContainsAny(code, "\r\n\t\x00") {
		return errors.New("enter the code from Google")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	j := c.job
	if c.closing || j == nil || j.id != id || j.done || j.view.Phase != "awaiting_code" {
		return errors.New("this Google sign-in is not waiting for a code")
	}
	j.view.Phase, j.view.URL = "signing_in", ""
	j.code <- code
	return nil
}

func (c *Controller) acquire(ctx context.Context) error {
	select {
	case c.ops <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Controller) snapshot() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func generation(s *Snapshot) string {
	if s == nil {
		return ""
	}
	return s.Generation
}

func (c *Controller) finish(j *job, err error) {
	j.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	j.done, j.view.URL = true, ""
	j.view.Phase = "connected"
	if err != nil {
		j.view.Phase = "failed"
		var classified commandError
		if errors.As(err, &classified) {
			j.view.Error = string(classified)
		} else if errors.Is(err, context.DeadlineExceeded) {
			j.view.Error = "connection_timed_out"
		} else {
			j.view.Error = "connection_failed"
		}
	}
}

func (c *Controller) connect(ctx context.Context, j *job) {
	err := c.acquire(ctx)
	if err != nil {
		c.finish(j, err)
		return
	}
	defer func() { <-c.ops }()
	err = c.connectLocked(ctx, j)
	c.finish(j, err)
}

func (c *Controller) connectLocked(ctx context.Context, j *job) error {
	current := c.snapshot()
	if current != nil && current.Ready {
		return nil
	}
	next := current
	if current == nil || current.NeedsLogin || current.Account == "" || len(current.Files["credentials.db"]) == 0 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return err
		}
		id := hex.EncodeToString(random[:])
		next = &Snapshot{Generation: id, Project: "drivekey-" + id[:20], NeedsLogin: true}
		if current != nil {
			next.Account = current.Account
			if current.Project != "" {
				next.Project = current.Project
			}
		}
		c.mu.Lock()
		j.generation = next.Generation
		c.mu.Unlock()
		dir, err := restore(c.root, next)
		if err != nil {
			return err
		}
		if err := c.save(ctx, generation(current), next); err != nil {
			_ = os.RemoveAll(dir)
			return err
		}
		if current != nil && current.Generation != next.Generation {
			_ = os.RemoveAll(filepath.Join(c.root, current.Generation))
		}
		if err := c.login(ctx, j, dir, next.Account); err != nil {
			return err
		}
		account, err := c.run(ctx, dir, nil, "auth", "list", "--filter=status:ACTIVE", "--format=value(account)", "--configuration=default", "--quiet")
		if err != nil {
			return err
		}
		email := strings.TrimSpace(string(account))
		if next.Account != "" && next.Account != email {
			return commandError("wrong_google_account")
		}
		loggedIn := *next
		loggedIn.Account, loggedIn.NeedsLogin = email, false
		if email == "" || loggedIn.Validate() != nil {
			return errLogin
		}
		next, err = capture(dir, &loggedIn)
		if err != nil {
			return err
		}
		if err := c.save(ctx, next.Generation, next); err != nil {
			return err
		}
	} else {
		c.mu.Lock()
		j.generation = next.Generation
		c.mu.Unlock()
	}
	c.mu.Lock()
	j.view.Phase = "setting_up_project"
	c.mu.Unlock()
	if err := c.setup(ctx, next); err != nil {
		return err
	}
	current = c.snapshot()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if current == nil || current.Generation != next.Generation {
		return errors.New("Google connection was replaced")
	}
	done := *current
	done.Ready = true
	return c.save(ctx, next.Generation, &done)
}

// Token is the container provider's command boundary. A refreshed credential
// is sealed before its access token can escape to an upstream request.
func (c *Controller) Token(ctx context.Context, binding policy.GoogleAccount, trace *gcloudexec.RenewalTrace) (string, error) {
	trace.Enter(gcloudexec.RenewalControllerWait)
	if err := c.acquire(ctx); err != nil {
		return "", err
	}
	ctx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		cancel()
		<-c.ops
		return "", errLogin
	}
	c.activeCancel = cancel
	s := c.state
	c.mu.Unlock()
	defer func() {
		cancel()
		c.mu.Lock()
		c.activeCancel = nil
		c.mu.Unlock()
		<-c.ops
	}()
	if s == nil || !s.Ready || s.Binding() != binding {
		return "", errLogin
	}
	dir := filepath.Join(c.root, s.Generation)
	trace.Enter(gcloudexec.RenewalSDK)
	out, runErr := c.run(ctx, dir, trace, "auth", "print-access-token", s.Account, "--account="+s.Account, "--configuration=default", "--quiet")
	trace.End(runErr)
	trace.Enter(gcloudexec.RenewalPersistence)
	defer clear(out)
	next, err := capture(dir, s)
	if err != nil {
		trace.End(err)
		return "", errCommand
	}
	if errors.Is(runErr, errLogin) {
		invalid := *next
		invalid.Ready, invalid.NeedsLogin = false, true
		next = &invalid
	}
	if next != s {
		if err := c.save(ctx, s.Generation, next); err != nil {
			trace.End(err)
			return "", errCommand
		}
	}
	if current := c.snapshot(); current == nil || current.Generation != s.Generation {
		trace.End(errLogin)
		return "", errLogin
	}
	trace.End(nil)
	if runErr != nil {
		return "", runErr
	}
	return strings.TrimSpace(string(out)), nil
}

// Disconnect persists denial first. It then cancels and joins the old SDK
// writer, attempts remote revocation and removes the private configuration.
// New logins stay blocked until revocation ends, preventing an old revoke from
// invalidating a newly connected token for the same Google account.
func (c *Controller) Disconnect(ctx context.Context) error {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return errors.New("Google disconnect is already in progress")
	}
	c.closing = true
	c.epoch++
	if c.activeCancel != nil {
		c.activeCancel()
	}
	if c.job != nil && !c.job.done {
		c.job.cancel()
	}
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.closing = false; c.mu.Unlock() }()
	if err := c.save(context.WithoutCancel(ctx), "*", nil); err != nil {
		return errors.New("Google disconnect could not be saved")
	}
	// Finish local removal even if the caller goes away after the durable
	// denial. The bounded cleanup is independent of the HTTP connection.
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 25*time.Second)
	defer cancel()
	if err := c.acquire(cleanupCtx); err != nil {
		return errors.New("Google access disabled; local credential cleanup timed out")
	}
	defer func() { <-c.ops }()
	entries, err := os.ReadDir(c.root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("Google access disabled; local credential cleanup failed")
	}
	var revokeErr error
	for _, entry := range entries {
		if !validGeneration(entry.Name()) {
			continue
		}
		dir := filepath.Join(c.root, entry.Name())
		if entry.IsDir() {
			_, err := c.run(cleanupCtx, dir, nil, "auth", "revoke", "--all", "--configuration=default", "--quiet")
			revokeErr = errors.Join(revokeErr, err)
		}
		if err := os.RemoveAll(dir); err != nil {
			return errors.New("Google access disabled; local credential cleanup failed")
		}
	}
	if revokeErr != nil {
		return errors.New("Google access disabled and local credentials removed; remote revocation could not be confirmed")
	}
	return nil
}
