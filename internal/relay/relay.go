// Package relay runs on the agent machine. It takes "/<role>/<service>/<path>"
// on a loopback port, adds that role's token, and forwards the call to the
// keyring on another machine. It never holds an API key, and it never falls
// back to local keys when the keyring cannot be reached.
package relay

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// TokenHeader must match the keyring's server.TokenHeader.
	TokenHeader = "X-Keyring-Token"
	HealthPath  = "/_relay/health"
	// keyringHealth is the keyring's own health path.
	keyringHealth = "/_keyring/health"
)

var (
	roleName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	tokenText = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{16,512}$`)
	tailnet   = netip.MustParsePrefix("100.64.0.0/10")
)

// Relay forwards calls to one keyring.
type Relay struct {
	upstream *url.URL
	tokens   map[string]string
	client   *http.Client
}

// CheckUpstream accepts https, or plain http only to a tailnet or loopback
// address: the tailnet already encrypts, and the role token must not cross
// any other network in clear.
func CheckUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("upstream %q is not a URL", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("upstream %q: want scheme://host:port only", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		addr, err := netip.ParseAddr(u.Hostname())
		if err != nil || !(addr.IsLoopback() || tailnet.Contains(addr.Unmap())) {
			return nil, fmt.Errorf("upstream %q: plain http only to a tailnet (100.64.0.0/10) or loopback IP; otherwise use https", raw)
		}
	default:
		return nil, fmt.Errorf("upstream %q: want http or https", raw)
	}
	u.Path = ""
	return u, nil
}

// LoadTokens reads "<role>.token" files from dir. The directory must be a real
// directory (not a symlink), owned by the user running the relay, and closed
// to other users; each token file likewise. Files are checked after they are
// opened, with symlinks refused, so a file swapped between check and read is
// never trusted.
func LoadTokens(dir string) (map[string]string, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s must be a directory, not a symlink or file", dir)
	}
	if err := private(dir, info, 0o077, "chmod 700"); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	tokens := map[string]string{}
	for _, e := range entries {
		role, ok := strings.CutSuffix(e.Name(), ".token")
		if !ok || e.IsDir() {
			continue
		}
		if !roleName.MatchString(role) {
			return nil, fmt.Errorf("token file %s: invalid role name", e.Name())
		}
		token, err := readToken(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		tokens[role] = token
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no <role>.token files in %s", dir)
	}
	return tokens, nil
}

func readToken(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("%s: open without following symlinks: %w", path, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular file", path)
	}
	if err := private(path, fi, 0o077, "chmod 600"); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if !tokenText.MatchString(token) {
		// Never print the file's content.
		return "", fmt.Errorf("%s does not hold a valid token", path)
	}
	return token, nil
}

// private checks that info is owned by the current user and has none of the
// bits in open set.
func private(path string, info os.FileInfo, open os.FileMode, fix string) error {
	if perm := info.Mode().Perm(); perm&open != 0 {
		return fmt.Errorf("%s is open to other users (mode %04o); run %s %s", path, perm, fix, path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read owner", path)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is owned by uid %d, not the relay's user (uid %d)", path, st.Uid, os.Geteuid())
	}
	return nil
}

// New builds a relay. upstream must have passed CheckUpstream.
func New(upstream *url.URL, tokens map[string]string) *Relay {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 5 * time.Minute
	transport.DisableCompression = true // pass bodies through untouched
	return &Relay{
		upstream: upstream,
		tokens:   tokens,
		client: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

var hopByHop = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (rl *Relay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == HealthPath {
		rl.health(w, r)
		return
	}
	escaped := r.URL.EscapedPath()
	role, rest, ok := strings.Cut(strings.TrimPrefix(escaped, "/"), "/")
	if !ok || !roleName.MatchString(role) || rest == "" {
		http.Error(w, "relay: path must be /<role>/<service>/<path>", http.StatusBadRequest)
		return
	}
	token, ok := rl.tokens[role]
	if !ok {
		http.Error(w, "relay: no token for role "+role, http.StatusForbidden)
		return
	}
	// Forward the rest as the caller wrote it; the keyring applies the rules.
	target, err := url.Parse(rl.upstream.String() + "/" + rest)
	if err != nil {
		http.Error(w, "relay: bad path", http.StatusBadRequest)
		return
	}
	target.RawQuery = r.URL.RawQuery
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), r.Body)
	if err != nil {
		http.Error(w, "relay: bad request", http.StatusBadRequest)
		return
	}
	out.Header = r.Header.Clone()
	for _, field := range r.Header.Values("Connection") {
		for _, name := range strings.Split(field, ",") {
			out.Header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopByHop {
		out.Header.Del(name)
	}
	out.Header.Set(TokenHeader, token)
	out.ContentLength = r.ContentLength
	resp, err := rl.client.Do(out)
	if err != nil {
		if r.Context().Err() != nil {
			return // the caller went away
		}
		http.Error(w, "relay: keyring unreachable at "+rl.upstream.Host+"; calls never fall back to local keys", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for name, values := range resp.Header {
		skip := false
		for _, h := range hopByHop {
			if strings.EqualFold(name, h) {
				skip = true
			}
		}
		if skip {
			continue
		}
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			return
		}
	}
}

func (rl *Relay) health(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, rl.upstream.String()+keyringHealth, nil)
	if err == nil {
		if resp, err := rl.client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				_, _ = io.WriteString(w, "ok: keyring reachable at "+rl.upstream.Host+"\n")
				return
			}
		}
	}
	http.Error(w, "relay: keyring unreachable at "+rl.upstream.Host, http.StatusBadGateway)
}
