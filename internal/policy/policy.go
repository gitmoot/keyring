// Package policy reads and checks the keyring's rules: where it listens, who
// may connect, which services exist, and what each role may do with them.
package policy

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/store"
)

// Auth kinds: how a service expects its key.
const (
	AuthBearer = "bearer" // Authorization: Bearer <key>
	AuthHeader = "header" // <Header>: <key>
	AuthQuery  = "query"  // ?<Param>=<key>
)

type Config struct {
	// Listen is one specific IP and port, for example the Mac's tailnet
	// address. Wildcard addresses are refused.
	Listen string `json:"listen"`
	// AllowSources lists the addresses or CIDR ranges allowed to connect.
	AllowSources []string           `json:"allow_sources"`
	AuditLog     string             `json:"audit_log"`
	Services     map[string]Service `json:"services"`
	Roles        map[string]Role    `json:"roles"`

	sources []netip.Prefix
}

type Service struct {
	// Base is the API origin (and optional base path) requests are sent to.
	Base   string `json:"base"`
	Key    string `json:"key"`
	Auth   string `json:"auth"`
	Header string `json:"header,omitempty"`
	Param  string `json:"param,omitempty"`

	base *url.URL
}

type Role struct {
	// TokenSHA256 is the hex SHA-256 of the role's token (keyring new-token).
	TokenSHA256 string            `json:"token_sha256"`
	Expires     *time.Time        `json:"expires,omitempty"`
	Access      map[string]Access `json:"access"`
}

type Access struct {
	// Methods allowed; empty means GET, HEAD and POST.
	Methods []string `json:"methods,omitempty"`
	// Paths are allowed path prefixes below the service base; "/" allows all.
	Paths []string `json:"paths"`
	// DailyRequests caps calls per UTC day; 0 means no cap.
	DailyRequests int `json:"daily_requests,omitempty"`
}

var (
	serviceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	roleName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	headerName  = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
	tokenHash   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	methods     = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
)

// Load reads and validates a rules file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &cfg, nil
}

// Validate checks every field and prepares the parsed forms.
func (c *Config) Validate() error {
	listen, err := netip.ParseAddrPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen %q: want IP:port", c.Listen)
	}
	if listen.Addr().IsUnspecified() {
		return fmt.Errorf("listen %q: use one specific address, not a wildcard", c.Listen)
	}
	if len(c.AllowSources) == 0 {
		return errors.New("allow_sources is empty")
	}
	c.sources = nil
	for _, s := range c.AllowSources {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			addr, addrErr := netip.ParseAddr(s)
			if addrErr != nil {
				return fmt.Errorf("allow_sources %q: want an address or CIDR", s)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Bits() == 0 {
			return fmt.Errorf("allow_sources %q allows every address", s)
		}
		c.sources = append(c.sources, prefix.Masked())
	}
	if strings.TrimSpace(c.AuditLog) == "" {
		return errors.New("audit_log is empty")
	}
	for name, svc := range c.Services {
		if !serviceName.MatchString(name) {
			return fmt.Errorf("service %q: use lowercase letters, digits and -", name)
		}
		if err := svc.validate(); err != nil {
			return fmt.Errorf("service %s: %w", name, err)
		}
		c.Services[name] = svc
	}
	seen := map[string]string{}
	for name, role := range c.Roles {
		if !roleName.MatchString(name) {
			return fmt.Errorf("role %q: invalid name", name)
		}
		if !tokenHash.MatchString(role.TokenSHA256) {
			return fmt.Errorf("role %s: token_sha256 must be 64 lowercase hex characters", name)
		}
		if other, dup := seen[role.TokenSHA256]; dup {
			return fmt.Errorf("roles %s and %s share a token", other, name)
		}
		seen[role.TokenSHA256] = name
		for svcName, access := range role.Access {
			if _, ok := c.Services[svcName]; !ok {
				return fmt.Errorf("role %s: unknown service %q", name, svcName)
			}
			if err := access.validate(); err != nil {
				return fmt.Errorf("role %s, service %s: %w", name, svcName, err)
			}
		}
	}
	return nil
}

func (s *Service) validate() error {
	u, err := url.Parse(s.Base)
	if err != nil || u.Host == "" {
		return fmt.Errorf("base %q is not a URL", s.Base)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("base %q must not carry credentials, a query or a fragment", s.Base)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// Plain HTTP would send the key in clear; only a loopback test
		// server may use it.
		if addr, err := netip.ParseAddr(u.Hostname()); err != nil || !addr.IsLoopback() {
			return fmt.Errorf("base %q: use https", s.Base)
		}
	default:
		return fmt.Errorf("base %q: use https", s.Base)
	}
	if !store.ValidName(s.Key) {
		return fmt.Errorf("key %q is not a valid key name", s.Key)
	}
	switch s.Auth {
	case AuthBearer:
	case AuthHeader:
		if !headerName.MatchString(s.Header) {
			return fmt.Errorf("auth header needs a valid header name, got %q", s.Header)
		}
	case AuthQuery:
		if strings.TrimSpace(s.Param) == "" {
			return errors.New("auth query needs a param name")
		}
	default:
		return fmt.Errorf("auth %q: want bearer, header or query", s.Auth)
	}
	s.base = u
	return nil
}

func (a Access) validate() error {
	for _, m := range a.Methods {
		if !methods[m] {
			return fmt.Errorf("method %q not supported", m)
		}
	}
	if len(a.Paths) == 0 {
		return errors.New("paths is empty; use [\"/\"] to allow all")
	}
	for _, p := range a.Paths {
		if !strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.Contains(p, "%") {
			return fmt.Errorf("path %q must start with / and contain no .. or %%", p)
		}
	}
	if a.DailyRequests < 0 {
		return errors.New("daily_requests is negative")
	}
	return nil
}

// BaseURL returns the parsed base of a validated service.
func (s Service) BaseURL() *url.URL {
	u := *s.base
	return &u
}

// SourceAllowed reports whether a connection from addr is accepted.
func (c *Config) SourceAllowed(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range c.sources {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RoleForToken finds the role whose token hash matches token. Every role is
// compared in constant time, so timing does not reveal a partial match.
func (c *Config) RoleForToken(token string) (string, Role, bool) {
	if token == "" {
		return "", Role{}, false
	}
	sum := sha256.Sum256([]byte(token))
	got := []byte(hex.EncodeToString(sum[:]))
	var (
		found string
		role  Role
		ok    bool
	)
	for name, r := range c.Roles {
		if subtle.ConstantTimeCompare(got, []byte(r.TokenSHA256)) == 1 {
			found, role, ok = name, r, true
		}
	}
	return found, role, ok
}

// Expired reports whether the role's expiry has passed.
func (r Role) Expired(now time.Time) bool {
	return r.Expires != nil && !now.Before(*r.Expires)
}

// AllowsMethod reports whether method is allowed.
func (a Access) AllowsMethod(method string) bool {
	if len(a.Methods) == 0 {
		return method == "GET" || method == "HEAD" || method == "POST"
	}
	for _, m := range a.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// AllowsPath reports whether p (a decoded path below the service base) falls
// under an allowed prefix. A prefix matches whole path segments only, so
// "/v1" allows "/v1" and "/v1/x" but not "/v10".
func (a Access) AllowsPath(p string) bool {
	for _, prefix := range a.Paths {
		trimmed := strings.TrimSuffix(prefix, "/")
		if trimmed == "" || p == trimmed || strings.HasPrefix(p, trimmed+"/") {
			return true
		}
	}
	return false
}
