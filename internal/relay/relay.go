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

// LoadTokens reads "<role>.token" files from dir. The directory and every
// token file must be private to their owner.
func LoadTokens(dir string) (map[string]string, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("%s is open to other users (mode %04o); run chmod 700 %s", dir, perm, dir)
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
		path := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s must be a regular file with mode 600", path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		token := strings.TrimSpace(string(raw))
		if !tokenText.MatchString(token) {
			// Never print the file's content.
			return nil, fmt.Errorf("%s does not hold a valid token", path)
		}
		tokens[role] = token
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("no <role>.token files in %s", dir)
	}
	return tokens, nil
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
