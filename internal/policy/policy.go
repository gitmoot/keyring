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
	"maps"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/store"
)

// Auth kinds: how a service expects its key.
const (
	AuthBearer              = "bearer"         // Authorization: Bearer <key>
	AuthHeader              = "header"         // <Header>: <key>
	AuthQuery               = "query"          // ?<Param>=<key>
	AuthAppleAdsSign        = "apple-ads-sign" // Local ES256 signing only; never proxy the key.
	AuthAppStoreConnectSign = "app-store-connect-sign"
	AuthEd25519Sign         = "ed25519-sign" // Local Ed25519 signing only; never proxy the key.
	// AuthOAuth2 sends Authorization: Bearer <access token>, minted from the
	// refresh token stored under Key; the refresh token never goes upstream.
	AuthOAuth2 = "oauth2"
	// AuthGcloud mints a Google token using a root-configured account.
	AuthGcloud = "gcloud"
	// AuthGcloudLogin is the container's consent-only Drive connection.
	AuthGcloudLogin = "gcloud-login"
	// AuthEgressProxy opens TCP tunnels through a person's own proxy; the
	// proxy credential stored under Key goes only to that proxy.
	AuthEgressProxy = "egress-proxy"
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
	// Consent, when set, lets the owners of keys connect services
	// themselves through single-use links (see Consent). Off by default.
	Consent *Consent `json:"consent,omitempty"`
	// GoogleAccounts is privileged host configuration, never dashboard input.
	GoogleAccounts map[string]GoogleAccount `json:"google_accounts,omitempty"`
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

// Consent turns on consent links. The pages are served on Listen, normally
// behind an HTTPS reverse proxy at PublicURL: the link pages and the OAuth
// callback only. The API that creates links and deletes keys is served on
// APIListen, to APIAllowSources only, for callers holding the API token.
// Neither listener serves the proxy or the dashboard.
type Consent struct {
	Listen          string   `json:"listen"`
	PublicURL       string   `json:"public_url"`
	APIListen       string   `json:"api_listen"`
	APIAllowSources []string `json:"api_allow_sources"`
	// APITokenSHA256 is the hex SHA-256 of the API token (keyring new-token).
	APITokenSHA256 string `json:"api_token_sha256"`

	public     *url.URL
	apiSources []netip.Prefix
	anySource  bool // container mode: no source check (see Config.ContainerMode)
}

// Equal reports whether a and b are the same settings (nil is off).
func (a *Consent) Equal(b *Consent) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Listen == b.Listen && a.PublicURL == b.PublicURL && a.APIListen == b.APIListen &&
		slices.Equal(a.APIAllowSources, b.APIAllowSources) && a.APITokenSHA256 == b.APITokenSHA256
}

// PublicBase returns the parsed public_url of validated settings.
func (a *Consent) PublicBase() *url.URL {
	u := *a.public
	return &u
}

// APISourceAllowed reports whether addr may call the consent API.
func (a *Consent) APISourceAllowed(addr netip.Addr) bool {
	if a.anySource {
		return true
	}
	addr = addr.Unmap()
	for _, p := range a.apiSources {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// APITokenMatches reports whether token is the consent API token.
func (a *Consent) APITokenMatches(token string) bool {
	sum := sha256.Sum256([]byte(token))
	return token != "" && subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(a.APITokenSHA256)) == 1
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

	// ContainerMode is set only by "keyring instance --container", never by
	// a file: the instance runs in a container reached only through its
	// supervisor (at Cloudflare, the person's Durable Object), so it may
	// listen on a wildcard address and checks no source address. See
	// CallerHeader.
	ContainerMode bool `json:"-"`

	sources []netip.Prefix
}

// CallerHeader carries the router's proof of identity to the supervisor in
// container mode. The supervisor checks and removes it; the keyring never
// forwards it upstream either.
const CallerHeader = "X-Keyring-Caller"

// listenAddr parses an IP:port a listener uses. A wildcard address is only
// allowed in container mode.
func (c *Config) listenAddr(field, value string) (netip.AddrPort, error) {
	addr, err := netip.ParseAddrPort(value)
	if err != nil || addr.Port() == 0 {
		return addr, fmt.Errorf("%s %q: want IP:port", field, value)
	}
	if addr.Addr().IsUnspecified() && !c.ContainerMode {
		return addr, fmt.Errorf("%s %q: use one specific address, not a wildcard", field, value)
	}
	return addr, nil
}

// sameSocket reports whether two listeners would need the same port on the
// same address; a wildcard address holds the port on every address.
func sameSocket(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && (a.Addr() == b.Addr() || a.Addr().IsUnspecified() || b.Addr().IsUnspecified())
}

// sourcesFor parses an allow list. In container mode the list must be empty:
// every request arrives through the supervisor, so a source address proves
// nothing.
func (c *Config) sourcesFor(field string, list []string) ([]netip.Prefix, error) {
	if c.ContainerMode {
		if len(list) > 0 {
			return nil, fmt.Errorf("%s must be empty in container mode: requests arrive only through the supervisor", field)
		}
		return nil, nil
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%s is empty", field)
	}
	return parseSources(field, list)
}

type Service struct {
	// Base is the API origin (and optional base path) requests are sent to.
	Base          string `json:"base,omitempty"`
	Key           string `json:"key"`
	Auth          string `json:"auth"`
	Header        string `json:"header,omitempty"`
	Param         string `json:"param,omitempty"`
	GoogleAccount string `json:"google_account,omitempty"`
	// TestMethod and TestPath make a harmless request that shows whether the
	// key works (the dashboard's Test button). TestPath may carry a query.
	TestMethod      string           `json:"test_method,omitempty"`
	TestPath        string           `json:"test_path,omitempty"`
	AppleAds        *AppleAds        `json:"apple_ads,omitempty"`
	AppStoreConnect *AppStoreConnect `json:"app_store_connect,omitempty"`
	// TLSPinSHA256, when set, is the lowercase hex SHA-256 of the upstream's
	// leaf certificate (DER). The keyring then trusts exactly that
	// certificate for this service instead of the system CA roots, so a
	// self-signed upstream can be used. https only.
	TLSPinSHA256 string `json:"tls_pin_sha256,omitempty"`
	// OAuth2 tells an oauth2 service how to turn its stored refresh token
	// into access tokens.
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// EgressProxy configures an egress-proxy service.
	EgressProxy *EgressProxy `json:"egress_proxy,omitempty"`

	base *url.URL
}

// AppleAds fixes the public identity of the Apple Ads client secret.
type AppleAds struct {
	ClientID string `json:"client_id"`
	TeamID   string `json:"team_id"`
	KeyID    string `json:"key_id"`
}

// AppStoreConnect fixes the public identity of an App Store Connect API key.
type AppStoreConnect struct {
	IssuerID string `json:"issuer_id"`
	KeyID    string `json:"key_id"`
}

// OAuth2 is the public half of an OAuth client: the refresh token and client
// secret stay in the store.
type OAuth2 struct {
	// TokenURL is the provider's token endpoint, e.g.
	// https://oauth2.googleapis.com/token.
	TokenURL string `json:"token_url"`
	ClientID string `json:"client_id"`
	// ClientSecretKey names the store key holding the client secret; empty
	// for a public client.
	ClientSecretKey string `json:"client_secret_key,omitempty"`

	// Sign-in through a consent link (optional). AuthURL is the provider's
	// authorization endpoint; Scopes and AuthParams are added to it (for
	// Google, auth_params {"access_type": "offline", "prompt": "consent"}
	// so that a refresh token is returned). The link never chooses them.
	AuthURL    string            `json:"auth_url,omitempty"`
	Scopes     []string          `json:"scopes,omitempty"`
	AuthParams map[string]string `json:"auth_params,omitempty"`
	// RevokeURL, when set, is told about a refresh token being deleted
	// through the consent API (RFC 7009).
	RevokeURL string `json:"revoke_url,omitempty"`
}

// Equal reports whether o and p are the same settings.
func (o *OAuth2) Equal(p *OAuth2) bool {
	if o == nil || p == nil {
		return o == p
	}
	return o.TokenURL == p.TokenURL && o.ClientID == p.ClientID && o.ClientSecretKey == p.ClientSecretKey &&
		o.AuthURL == p.AuthURL && slices.Equal(o.Scopes, p.Scopes) && maps.Equal(o.AuthParams, p.AuthParams) && o.RevokeURL == p.RevokeURL
}

// reservedAuthParams are set by the keyring on every sign-in.
var reservedAuthParams = map[string]bool{
	"response_type": true, "client_id": true, "redirect_uri": true, "scope": true,
	"state": true, "code_challenge": true, "code_challenge_method": true,
}

// CanSignIn reports whether a consent link can run the provider sign-in.
func (o *OAuth2) CanSignIn() bool { return o != nil && o.AuthURL != "" }

func (o *OAuth2) validateSignIn() error {
	if o.AuthURL == "" {
		if len(o.Scopes) > 0 || len(o.AuthParams) > 0 {
			return errors.New("oauth2 scopes and auth_params need auth_url")
		}
	} else if _, err := upstreamURL("oauth2 auth_url", o.AuthURL); err != nil {
		return err
	}
	for _, s := range o.Scopes {
		if !printableToken(s, 512) {
			return fmt.Errorf("oauth2 scope %q: want printable ASCII without spaces", s)
		}
	}
	for k, v := range o.AuthParams {
		if !printableToken(k, 64) || reservedAuthParams[k] || len(v) > 512 {
			return fmt.Errorf("oauth2 auth_params %q: not allowed (the keyring sets response_type, client_id, redirect_uri, scope, state and PKCE)", k)
		}
	}
	if o.RevokeURL != "" {
		if _, err := upstreamURL("oauth2 revoke_url", o.RevokeURL); err != nil {
			return err
		}
	}
	return nil
}

// printableToken: 1 to max printable ASCII characters, no spaces.
func printableToken(s string, max int) bool {
	return s != "" && len(s) <= max && strings.IndexFunc(s, func(r rune) bool { return r < 33 || r > 126 }) < 0
}

// KeyNames are the store keys the service needs: its key and, for oauth2, the
// client secret.
func (s Service) KeyNames() []string {
	if s.Auth == AuthGcloud {
		return nil // credentials live in the host's private gcloud directory
	}
	if s.OAuth2 != nil && s.OAuth2.ClientSecretKey != "" {
		return []string{s.Key, s.OAuth2.ClientSecretKey}
	}
	return []string{s.Key}
}

// Proxy kinds for egress-proxy services.
const (
	ProxyHTTPConnect = "http-connect"
	ProxySOCKS5      = "socks5"
)

// EgressProxy is the person's own proxy. The credential ("user:password")
// is the service's key.
type EgressProxy struct {
	Type string `json:"type"`
	// Address is host:port of the proxy. An IP address must be public; a
	// name is checked again when it resolves. Empty: the person gives the
	// address together with the credential (a consent link), and the key
	// holds both as a proxy URL (see Resolve).
	Address string `json:"address,omitempty"`
	// TLS wraps the connection to the proxy in TLS (for http-connect).
	TLS bool `json:"tls,omitempty"`
	// Ports are the destination ports allowed; default [443].
	Ports []int `json:"ports,omitempty"`
	// IdleSeconds closes a tunnel with no bytes either way (default 300);
	// MaxSeconds ends any tunnel (default 3600).
	IdleSeconds int `json:"idle_seconds,omitempty"`
	MaxSeconds  int `json:"max_seconds,omitempty"`
}

// CheckProxyAddress checks a proxy's host:port: a DNS name or a public IP,
// and a port.
func CheckProxyAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("address %q: want host:port", address)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if !PublicAddr(a) {
			return fmt.Errorf("address %q: a private, loopback or reserved address is not allowed", address)
		}
	} else if !tunnelName.MatchString(host) {
		return fmt.Errorf("address %q: want a DNS name or public IP", address)
	}
	return nil
}

// ProxyURL is what a person-provided proxy is stored as: one value holding
// the type, address and credential, so they are set and deleted together and
// a credential is only ever sent to the address given with it.
// Schemes: http (http-connect), https (http-connect over TLS), socks5.
func ProxyURL(proxyType string, tls bool, address, user, password string) (string, error) {
	scheme := map[string]string{ProxyHTTPConnect: "http", ProxySOCKS5: "socks5"}[proxyType]
	if scheme == "" || (tls && proxyType != ProxyHTTPConnect) {
		return "", errors.New("proxy type: want http-connect or socks5")
	}
	if tls {
		scheme = "https"
	}
	if err := CheckProxyAddress(address); err != nil {
		return "", err
	}
	if !proxyUser(user) || len(password) > 255 || strings.ContainsAny(password, "\r\n") {
		return "", errors.New("proxy username: 1-255 characters without : or spaces; password at most 255 characters")
	}
	u := url.URL{Scheme: scheme, User: url.UserPassword(user, password), Host: address}
	return u.String(), nil
}

func proxyUser(user string) bool {
	return user != "" && len(user) <= 255 && !strings.ContainsAny(user, ": \t\r\n")
}

// Resolve returns the proxy to use and its credential ("user:password"),
// given the service's stored key. With an address in config the key is the
// credential; without one the key is a ProxyURL the person gave, checked
// again here.
func (e *EgressProxy) Resolve(key string) (EgressProxy, string, error) {
	if e.Address != "" {
		return *e, key, nil
	}
	u, err := url.Parse(key)
	if err != nil || u.User == nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return EgressProxy{}, "", errors.New("the stored proxy settings are not valid")
	}
	out := *e
	switch u.Scheme {
	case "http":
		out.Type, out.TLS = ProxyHTTPConnect, false
	case "https":
		out.Type, out.TLS = ProxyHTTPConnect, true
	case "socks5":
		out.Type, out.TLS = ProxySOCKS5, false
	default:
		return EgressProxy{}, "", errors.New("the stored proxy settings are not valid")
	}
	if e.Type != "" && out.Type != e.Type {
		return EgressProxy{}, "", errors.New("the stored proxy type does not match the service")
	}
	if err := CheckProxyAddress(u.Host); err != nil {
		return EgressProxy{}, "", err
	}
	pass, _ := u.User.Password()
	if !proxyUser(u.User.Username()) {
		return EgressProxy{}, "", errors.New("the stored proxy settings are not valid")
	}
	out.Address = u.Host
	return out, u.User.Username() + ":" + pass, nil
}

// AllowedPorts returns the destination ports allowed.
func (e *EgressProxy) AllowedPorts() []int {
	if len(e.Ports) == 0 {
		return []int{443}
	}
	return e.Ports
}

// Idle and Max return the tunnel time limits.
func (e *EgressProxy) Idle() time.Duration { return seconds(e.IdleSeconds, 300) }
func (e *EgressProxy) Max() time.Duration  { return seconds(e.MaxSeconds, 3600) }

func seconds(n, def int) time.Duration {
	if n == 0 {
		n = def
	}
	return time.Duration(n) * time.Second
}

// PublicAddr reports whether a is an address a tunnel or proxy may reach:
// not private, loopback, link-local, multicast, unspecified, CGNAT (which
// holds Tailscale's range), benchmarking or reserved.
func PublicAddr(a netip.Addr) bool {
	// A zone names a local interface and is ignored by every check below
	// (and dropped on the wire), so an address with one is never public.
	if a.Zone() != "" {
		return false
	}
	a = a.Unmap()
	if !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	// IPv6: only global unicast, so deprecated and translation forms that
	// carry an IPv4 address (::/96, ::ffff:0:0:0/96, ...) are out by default.
	if a.Is6() && !globalUnicast6.Contains(a) {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var globalUnicast6 = netip.MustParsePrefix("2000::/3")

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// IPv6 forms that carry or reach an IPv4 address: NAT64, 6to4, Teredo.
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// TunnelHost checks a tunnel destination name or address.
func TunnelHost(host string) bool {
	if a, err := netip.ParseAddr(host); err == nil {
		return PublicAddr(a)
	}
	return len(host) <= 253 && tunnelName.MatchString(host)
}

var tunnelName = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$`)

// SignOnly services never send their private key to an upstream.
func (s Service) SignOnly() bool {
	return s.Auth == AuthAppleAdsSign || s.Auth == AuthAppStoreConnectSign || s.Auth == AuthEd25519Sign
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
	// DailyBytes caps tunnel bytes (both ways) per UTC day for an
	// egress-proxy service; 0 means no cap.
	DailyBytes int64 `json:"daily_bytes,omitempty"`
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
	listen, err := c.listenAddr("listen", c.Listen)
	if err != nil {
		return err
	}
	if c.sources, err = c.sourcesFor("allow_sources", c.AllowSources); err != nil {
		return err
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
	if k := c.Consent; k != nil {
		if err := k.validate(c, listen); err != nil {
			return err
		}
	}
	if c.Services == nil {
		c.Services = map[string]Service{}
	}
	if c.Roles == nil {
		c.Roles = map[string]Role{}
	}
	if err := c.validateGoogleAccounts(); err != nil {
		return err
	}
	for name, svc := range c.Services {
		if !serviceName.MatchString(name) {
			return fmt.Errorf("service %q: use lowercase letters, digits and -", name)
		}
		if svc.Auth == AuthAppleAdsSign && name != "apple-ads" {
			return errors.New("apple-ads-sign requires service name apple-ads")
		}
		if svc.Auth == AuthAppStoreConnectSign && name != "appstoreconnect" {
			return errors.New("app-store-connect-sign requires service name appstoreconnect")
		}
		if svc.Auth == AuthGcloudLogin && (!c.ContainerMode || name != "drive") {
			return errors.New("Google login is only the container drive consent service")
		}
		if err := svc.validate(); err != nil {
			return fmt.Errorf("service %s: %w", name, err)
		}
		if svc.Auth == AuthGcloud {
			if c.ContainerMode {
				if !containerGoogleService(name, svc) {
					return fmt.Errorf("service %s: container Google services require the fixed me API routes", name)
				}
				// A disconnected container keeps its routes, but has no credential
				// binding. Requests fail closed until consent finishes.
			} else if _, ok := c.GoogleAccounts[svc.GoogleAccount]; !ok {
				return fmt.Errorf("service %s: unknown google_account", name)
			}
		}
		c.Services[name] = svc
	}
	for signerName, signer := range c.Services {
		if !signer.SignOnly() {
			continue
		}
		for name, svc := range c.Services {
			if name != signerName && svc.Key == signer.Key {
				return errors.New("a signing key cannot be shared with another service")
			}
		}
	}
	for oauthName, oauth := range c.Services {
		if oauth.Auth != AuthOAuth2 {
			continue
		}
		for name, svc := range c.Services {
			// A refresh token goes only to the token endpoint: a service
			// that sends its key upstream must not hold it, and services
			// sharing it share one access token, so one OAuth client.
			if name != oauthName && svc.Key == oauth.Key && (svc.Auth != AuthOAuth2 || !svc.OAuth2.Equal(oauth.OAuth2)) {
				return errors.New("an oauth2 refresh token can be shared only by oauth2 services with the same oauth2 settings")
			}
			// A client secret is the key of no service (so no refresh
			// token either, as svc ranges over every oauth2 service) and
			// goes to one token endpoint only.
			secret := oauth.OAuth2.ClientSecretKey
			if secret != "" && svc.Key == secret {
				return errors.New("an oauth2 client secret cannot be a service's key")
			}
			if secret != "" && svc.OAuth2 != nil && svc.OAuth2.ClientSecretKey == secret && svc.OAuth2.TokenURL != oauth.OAuth2.TokenURL {
				return errors.New("an oauth2 client secret can be shared only by services with the same token_url")
			}
		}
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
		if c.Consent != nil && role.TokenSHA256 == c.Consent.APITokenSHA256 {
			return fmt.Errorf("role %s shares its token with the consent API", name)
		}
		seen[role.TokenSHA256] = name
		for svcName, access := range role.Access {
			if _, ok := c.Services[svcName]; !ok {
				return fmt.Errorf("role %s: unknown service %q", name, svcName)
			}
			if err := access.validate(); err != nil {
				return fmt.Errorf("role %s, service %s: %w", name, svcName, err)
			}
			if access.DailyBytes != 0 && c.Services[svcName].Auth != AuthEgressProxy {
				return fmt.Errorf("role %s, service %s: daily_bytes applies only to egress-proxy services", name, svcName)
			}
		}
	}
	return nil
}

// parseSources reads addresses and CIDR ranges, refusing one that allows
// every address.
func parseSources(field string, list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			addr, addrErr := netip.ParseAddr(s)
			if addrErr != nil {
				return nil, fmt.Errorf("%s %q: want an address or CIDR", field, s)
			}
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("%s %q allows every address", field, s)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

func (k *Consent) validate(c *Config, proxy netip.AddrPort) error {
	pages, err := c.listenAddr("consent listen", k.Listen)
	if err != nil {
		return err
	}
	api, err := c.listenAddr("consent api_listen", k.APIListen)
	if err != nil {
		return err
	}
	admin, _ := netip.ParseAddrPort(c.AdminListen)
	for _, other := range []netip.AddrPort{proxy, admin} {
		if other.IsValid() && (sameSocket(pages, other) || sameSocket(api, other)) {
			return errors.New("consent listen and api_listen must differ from listen and admin_listen")
		}
	}
	if sameSocket(pages, api) {
		return errors.New("consent listen and api_listen must differ")
	}
	if k.public, err = upstreamURL("consent public_url", k.PublicURL); err != nil {
		return err
	}
	k.public.Path = strings.TrimSuffix(k.public.Path, "/")
	// Browsers leave a default port out of Origin; so does the public base.
	if p := k.public.Port(); (k.public.Scheme == "https" && p == "443") || (k.public.Scheme == "http" && p == "80") {
		k.public.Host = k.public.Hostname()
		if strings.Contains(k.public.Host, ":") {
			k.public.Host = "[" + k.public.Host + "]"
		}
	}
	if k.apiSources, err = c.sourcesFor("consent api_allow_sources", k.APIAllowSources); err != nil {
		return err
	}
	k.anySource = c.ContainerMode
	if !tokenHash.MatchString(k.APITokenSHA256) {
		return errors.New("consent api_token_sha256 must be 64 lowercase hex characters")
	}
	return nil
}

var tlsPin = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (s *Service) validate() error {
	if s.Auth == AuthGcloudLogin {
		if s.GoogleAccount != "me" || s.Base != "" || s.Key != "" || s.Header != "" || s.Param != "" ||
			s.TestMethod != "" || s.TestPath != "" || s.TLSPinSHA256 != "" || s.OAuth2 != nil ||
			s.AppleAds != nil || s.AppStoreConnect != nil || s.EgressProxy != nil {
			return errors.New("Google login requires only the fixed me account and no proxy settings")
		}
		s.base = nil
		return nil
	}
	if s.GoogleAccount != "" && s.Auth != AuthGcloud {
		return errors.New("google_account requires auth gcloud")
	}
	if s.SignOnly() {
		if !store.ValidName(s.Key) {
			return errors.New("sign-only service needs a valid key name")
		}
		if s.Base != "" || s.Header != "" || s.Param != "" || s.TestMethod != "" || s.TestPath != "" || s.TLSPinSHA256 != "" || s.OAuth2 != nil {
			return errors.New("sign-only service cannot have proxy or test settings")
		}
		var identity []string
		switch s.Auth {
		case AuthAppleAdsSign:
			if s.AppleAds == nil || s.AppStoreConnect != nil {
				return errors.New("apple-ads-sign requires only apple_ads identity")
			}
			identity = []string{s.AppleAds.ClientID, s.AppleAds.TeamID, s.AppleAds.KeyID}
		case AuthAppStoreConnectSign:
			if s.AppStoreConnect == nil || s.AppleAds != nil {
				return errors.New("app-store-connect-sign requires only app_store_connect identity")
			}
			identity = []string{s.AppStoreConnect.IssuerID, s.AppStoreConnect.KeyID}
		case AuthEd25519Sign:
			if s.AppleAds != nil || s.AppStoreConnect != nil {
				return errors.New("ed25519-sign takes no signing identity fields")
			}
		}
		for _, value := range identity {
			if value == "" || len(value) > 256 || strings.IndexFunc(value, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
				return errors.New("signing identity fields must be nonempty printable ASCII without spaces, at most 256 bytes")
			}
		}
		s.base = nil
		return nil
	}
	if s.AppleAds != nil || s.AppStoreConnect != nil {
		return errors.New("signing identity requires the corresponding sign-only auth")
	}
	if s.Auth == AuthEgressProxy {
		return s.validateEgress()
	}
	if s.EgressProxy != nil {
		return errors.New("egress_proxy settings require auth egress-proxy")
	}
	u, err := upstreamURL("base", s.Base)
	if err != nil {
		return err
	}
	if s.TLSPinSHA256 != "" {
		if u.Scheme != "https" {
			return fmt.Errorf("tls_pin_sha256 needs an https base, got %q", s.Base)
		}
		if !tlsPin.MatchString(s.TLSPinSHA256) {
			return errors.New("tls_pin_sha256: want 64 lowercase hex characters (SHA-256 of the certificate DER)")
		}
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
	if s.Auth != AuthGcloud && !store.ValidName(s.Key) {
		return fmt.Errorf("key %q is not a valid key name", s.Key)
	}
	switch s.Auth {
	case AuthBearer:
	case AuthGcloud:
		if !serviceName.MatchString(s.GoogleAccount) || s.Key != "" || s.Header != "" || s.Param != "" || s.TLSPinSHA256 != "" {
			return errors.New("auth gcloud needs google_account and no key, header, param or TLS pin")
		}
		if u.Scheme != "https" || u.Port() != "" || (u.Host != "www.googleapis.com" && u.Host != "sheets.googleapis.com" && u.Host != "drive.googleapis.com") {
			return errors.New("auth gcloud requires a supported Google API HTTPS origin")
		}
	case AuthHeader:
		if !headerName.MatchString(s.Header) {
			return fmt.Errorf("auth header needs a valid header name, got %q", s.Header)
		}
	case AuthQuery:
		if strings.TrimSpace(s.Param) == "" {
			return errors.New("auth query needs a param name")
		}
	case AuthOAuth2:
		if s.OAuth2 == nil {
			return errors.New("auth oauth2 needs oauth2 settings (token_url, client_id)")
		}
		if _, err := upstreamURL("oauth2 token_url", s.OAuth2.TokenURL); err != nil {
			return err
		}
		if !printableToken(s.OAuth2.ClientID, 512) {
			return errors.New("oauth2 client_id must be nonempty printable ASCII without spaces, at most 512 bytes")
		}
		if secret := s.OAuth2.ClientSecretKey; secret != "" && (!store.ValidName(secret) || secret == s.Key) {
			return fmt.Errorf("oauth2 client_secret_key %q must be a valid key name other than key", secret)
		}
		if err := s.OAuth2.validateSignIn(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("auth %q: want bearer, header, query, oauth2 or gcloud", s.Auth)
	}
	if s.OAuth2 != nil && s.Auth != AuthOAuth2 {
		return errors.New("oauth2 settings require auth oauth2")
	}
	s.base = u
	return nil
}

// upstreamURL parses a URL the keyring sends a secret to: https, or plain
// http to a loopback test server only. field names it in errors.
func upstreamURL(field, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%s %q is not a URL", field, raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s %q must not carry credentials, a query or a fragment", field, raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// Plain HTTP would send the secret in clear; only a loopback test
		// server may use it.
		if addr, err := netip.ParseAddr(u.Hostname()); err != nil || !addr.IsLoopback() {
			return nil, fmt.Errorf("%s %q: use https", field, raw)
		}
	default:
		return nil, fmt.Errorf("%s %q: use https", field, raw)
	}
	return u, nil
}

func (s *Service) validateEgress() error {
	e := s.EgressProxy
	if e == nil {
		return errors.New("auth egress-proxy needs egress_proxy settings (type, address)")
	}
	if s.Base != "" || s.Header != "" || s.Param != "" || s.TestMethod != "" || s.TestPath != "" || s.TLSPinSHA256 != "" || s.OAuth2 != nil {
		return errors.New("an egress-proxy service takes only key and egress_proxy")
	}
	if !store.ValidName(s.Key) {
		return fmt.Errorf("key %q is not a valid key name", s.Key)
	}
	// With no address the person chooses it, and may choose the type too.
	if e.Type != ProxyHTTPConnect && e.Type != ProxySOCKS5 && (e.Type != "" || e.Address != "") {
		return fmt.Errorf("egress_proxy type %q: want http-connect or socks5", e.Type)
	}
	if e.TLS && e.Type != ProxyHTTPConnect {
		return errors.New("egress_proxy tls is only for http-connect")
	}
	if e.Address != "" {
		if err := CheckProxyAddress(e.Address); err != nil {
			return fmt.Errorf("egress_proxy %w", err)
		}
	}
	for _, p := range e.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("egress_proxy port %d out of range", p)
		}
	}
	if e.IdleSeconds < 0 || e.IdleSeconds > 3600 || e.MaxSeconds < 0 || e.MaxSeconds > 24*3600 {
		return errors.New("egress_proxy idle_seconds must be 0-3600 and max_seconds 0-86400")
	}
	s.base = nil
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
	if a.DailyRequests < 0 || a.DailyBytes < 0 {
		return errors.New("daily_requests or daily_bytes is negative")
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
	if c.ContainerMode {
		return true
	}
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
