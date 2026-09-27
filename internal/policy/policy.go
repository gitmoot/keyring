// Package policy reads and checks the keyring's rules: where it listens, who
// may connect, which services exist, and what each role may do with them.
package policy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/store"
)

// Auth kinds: how a service expects its key.
const (
	AuthBearer = "bearer" // Authorization: Bearer <key>
	AuthHeader = "header" // <Header>: <key>
	AuthQuery  = "query"  // ?<Param>=<key>
)

// Rules is the root-owned rules file: the network boundary. The service can
// read it but not change it.
type Rules struct {
	// Listen is one specific IP and port. Wildcard addresses are refused.
	Listen string `json:"listen"`
	// AllowSources lists the addresses or CIDR ranges allowed to connect.
	AllowSources []string `json:"allow_sources"`
	AuditLog     string   `json:"audit_log"`
	// AccessFile is the absolute path of the access file.
	AccessFile string `json:"access_file"`
	// AdminListen, when set, serves the dashboard on this loopback address
	// only. The proxy never serves the dashboard, and this listener never
	// serves the proxy.
	AdminListen string `json:"admin_listen,omitempty"`
	// AdminPasswordFile is the absolute path of the dashboard password hash,
	// written by root with "keyring admin-password".
	AdminPasswordFile string `json:"admin_password_file,omitempty"`
	// AdminHTTPS, when set, also serves the dashboard under a DNS name through
	// an HTTPS proxy on this machine, to the listed devices only.
	AdminHTTPS *AdminHTTPS `json:"admin_https,omitempty"`
}

// AdminHTTPS is the dashboard's name behind a local HTTPS proxy. The proxy
// connects to admin_listen and puts the client's IP in the X-Keyring-Client
// header (replacing any the client sent); requests for Host are refused unless
// that IP is one of Devices.
type AdminHTTPS struct {
	Host    string   `json:"host"`
	Devices []string `json:"devices"`
}

// Equal reports whether a and b are the same settings (nil is off).
func (a *AdminHTTPS) Equal(b *AdminHTTPS) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Host == b.Host && slices.Equal(a.Devices, b.Devices)
}

// AccessList is the access file: which services exist and what each role may
// do. The service owns it, so access can change without touching the rules.
type AccessList struct {
	Services map[string]Service `json:"services"`
	Roles    map[string]Role    `json:"roles"`
}

// Config is the rules and the access list together, validated.
type Config struct {
	Rules
	AccessList

	sources []netip.Prefix
}

type Service struct {
	// Base is the API origin (and optional base path) requests are sent to.
	Base   string `json:"base"`
	Key    string `json:"key"`
	Auth   string `json:"auth"`
	Header string `json:"header,omitempty"`
	Param  string `json:"param,omitempty"`
	// TestMethod and TestPath make a harmless request that shows whether the
	// key works (the dashboard's Test button). TestPath may carry a query.
	TestMethod string `json:"test_method,omitempty"`
	TestPath   string `json:"test_path,omitempty"`

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
	// Expires ends this access (the role keeps its others); nil means never.
	Expires *time.Time `json:"expires,omitempty"`
}

var (
	dnsName     = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	serviceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	roleName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	headerName  = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
	tokenHash   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	methods     = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
)

// ErrNeedsMigration: the rules file still holds services or roles.
var ErrNeedsMigration = errors.New("rules file still holds services and roles; move them to the access file with: keyring migrate")

// Load reads the rules file and the access file it names, and validates both.
func Load(rulesPath string) (*Config, error) {
	rules, err := LoadRules(rulesPath)
	if err != nil {
		return nil, err
	}
	access, err := LoadAccess(rules.AccessFile)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Rules: rules, AccessList: access}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadRules reads the rules file without validating its values.
func LoadRules(path string) (Rules, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Rules{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Rules{}, fmt.Errorf("%s: %w", path, err)
	}
	if _, ok := fields["services"]; ok {
		return Rules{}, fmt.Errorf("%s: %w", path, ErrNeedsMigration)
	}
	if _, ok := fields["roles"]; ok {
		return Rules{}, fmt.Errorf("%s: %w", path, ErrNeedsMigration)
	}
	var rules Rules
	if err := decodeStrict(raw, &rules); err != nil {
		return Rules{}, fmt.Errorf("%s: %w", path, err)
	}
	if !filepath.IsAbs(rules.AccessFile) {
		return Rules{}, fmt.Errorf("%s: access_file must be an absolute path", path)
	}
	return rules, nil
}

// LoadAccess reads an access file. Like the key store, it must not be open to
// other users.
func LoadAccess(path string) (AccessList, error) {
	info, err := os.Stat(path)
	if err != nil {
		return AccessList{}, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return AccessList{}, fmt.Errorf("%s is open to other users (mode %04o); run chmod 600 %s", path, perm, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return AccessList{}, err
	}
	var access AccessList
	if err := decodeStrict(raw, &access); err != nil {
		return AccessList{}, fmt.Errorf("%s: %w", path, err)
	}
	// Both lists may be left out of the file; callers add to them.
	if access.Services == nil {
		access.Services = map[string]Service{}
	}
	if access.Roles == nil {
		access.Roles = map[string]Role{}
	}
	return access, nil
}

// SaveAccess validates access against rules, then replaces the access file
// atomically. An invalid access list is never written.
func SaveAccess(rules Rules, access AccessList) (*Config, error) {
	cfg := &Config{Rules: rules, AccessList: access}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.MarshalIndent(access, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := fileutil.WriteAtomic(rules.AccessFile, append(raw, '\n'), 0o600); err != nil {
		return nil, err
	}
	return cfg, nil
}

func decodeStrict(raw []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data after the JSON object")
	}
	return nil
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
	if c.AdminListen != "" {
		admin, err := netip.ParseAddrPort(c.AdminListen)
		if err != nil || !admin.Addr().IsLoopback() || admin.Port() == 0 {
			return fmt.Errorf("admin_listen %q: must be a loopback IP:port", c.AdminListen)
		}
		if admin == listen {
			return errors.New("admin_listen must differ from listen")
		}
		if !filepath.IsAbs(c.AdminPasswordFile) {
			return errors.New("admin_listen needs an absolute admin_password_file")
		}
	}
	if h := c.AdminHTTPS; h != nil {
		if c.AdminListen == "" {
			return errors.New("admin_https needs admin_listen")
		}
		if !dnsName.MatchString(h.Host) {
			return fmt.Errorf("admin_https host %q: want a lowercase DNS name like keyring.example.com", h.Host)
		}
		if len(h.Devices) == 0 {
			return errors.New("admin_https needs at least one device IP")
		}
		for _, d := range h.Devices {
			if _, err := netip.ParseAddr(d); err != nil {
				return fmt.Errorf("admin_https device %q: want an IP address", d)
			}
		}
	}
	if c.Services == nil {
		c.Services = map[string]Service{}
	}
	if c.Roles == nil {
		c.Roles = map[string]Role{}
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
	switch s.TestMethod {
	case "", "GET", "HEAD", "POST":
	default:
		return fmt.Errorf("test_method %q: want GET, HEAD or POST", s.TestMethod)
	}
	if s.TestPath != "" {
		path, _, _ := strings.Cut(s.TestPath, "?")
		if !strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "%\\;") {
			return fmt.Errorf("test_path %q must start with / and contain no .., %%, ; or \\", s.TestPath)
		}
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

// Expired reports whether this access has ended.
func (a Access) Expired(now time.Time) bool {
	return a.Expires != nil && !now.Before(*a.Expires)
}

// NewToken makes a role token and the hex SHA-256 that goes in the access
// file. Only the caller's machine keeps the token.
func NewToken() (token, sha string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// ValidRoleName reports whether name may name a role (an agent).
func ValidRoleName(name string) bool { return roleName.MatchString(name) }

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
