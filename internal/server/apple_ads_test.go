package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/relay"
)

const signPath = "/_keyring/sign/apple-ads"

func appleConfig(t *testing.T) *policy.Config {
	t.Helper()
	var access policy.AccessList
	if err := json.Unmarshal([]byte(`{"services":{"apple-ads":{"key":"APPLE_ADS_KEY","auth":"apple-ads-sign","apple_ads":{"client_id":"SEARCHADS.test-client","team_id":"TEAM123","key_id":"KEY123"}}},"roles":{}}`), &access); err != nil {
		t.Fatal(err)
	}
	access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"apple-ads": {Methods: []string{"POST"}, Paths: []string{"/"}}}}
	cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller, "127.0.0.1"}, AuditLog: "audit.log"}, AccessList: access}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func generatedAppleKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func signCall(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = caller + ":51000"
	r.Header.Set(TokenHeader, token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func verifiedAppleExpiry(t *testing.T, w *httptest.ResponseRecorder, pub *ecdsa.PublicKey, now time.Time) time.Time {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("sign status = %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("signing response can be cached")
	}
	var response struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(response.Token, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var header map[string]string
	if err := json.Unmarshal(decode(parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "ES256" || header["kid"] != "KEY123" {
		t.Fatal("wrong fixed signing header")
	}
	var claims struct {
		Iss string
		Sub string
		Aud string
		Iat int64
		Exp int64
	}
	if err := json.Unmarshal(decode(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Iss != "TEAM123" || claims.Sub != "SEARCHADS.test-client" || claims.Aud != "https://appleid.apple.com" || claims.Iat != now.Unix() {
		t.Fatal("wrong fixed claims or issue time")
	}
	if claims.Exp <= claims.Iat || claims.Exp > claims.Iat+1200 || claims.Exp != response.ExpiresAt.Unix() {
		t.Fatal("invalid or inconsistent expiry")
	}
	sig := decode(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("JWT ES256 signature does not verify")
	}
	return response.ExpiresAt
}

func TestAppleAdsSigningThroughRelayAndExpiryBounds(t *testing.T) {
	key, material := generatedAppleKey(t, elliptic.P256())
	now := time.Date(2026, 10, 2, 12, 0, 0, 123000000, time.UTC)
	for _, tc := range []struct {
		name         string
		role, access time.Duration
		want         time.Duration
	}{
		{"maximum", 0, 0, 20 * time.Minute}, {"role", 5 * time.Minute, 10 * time.Minute, 5 * time.Minute}, {"access", 10 * time.Minute, 3 * time.Minute, 3 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := appleConfig(t)
			role := cfg.Roles["phobos"]
			acc := role.Access["apple-ads"]
			if tc.role != 0 {
				end := now.Add(tc.role)
				role.Expires = &end
			}
			if tc.access != 0 {
				end := now.Add(tc.access)
				acc.Expires = &end
			}
			role.Access["apple-ads"] = acc
			cfg.Roles["phobos"] = role
			audit := &bytes.Buffer{}
			h := New(cfg, map[string]string{"APPLE_ADS_KEY": material}, audit)
			h.now = func() time.Time { return now }
			up := httptest.NewServer(h)
			defer up.Close()
			u, _ := url.Parse(up.URL)
			rl := relay.New(u, map[string]string{"phobos": testToken})
			w := signCall(rl, "POST", "/phobos"+signPath, "", "attacker-token")
			exp := verifiedAppleExpiry(t, w, &key.PublicKey, now)
			if !exp.Equal(time.Unix(now.Add(tc.want).Unix(), 0)) {
				t.Fatal("expiry did not honor earliest bound")
			}
			if strings.Contains(audit.String(), "PRIVATE KEY") || strings.Contains(audit.String(), material) || strings.Contains(audit.String(), `"token"`) {
				t.Fatal("secret in audit")
			}
			var rec auditRecord
			if err := json.Unmarshal(bytes.TrimSpace(audit.Bytes()), &rec); err != nil {
				t.Fatal(err)
			}
			if rec.Role != "phobos" || rec.Service != "apple-ads" || rec.Status != 200 || rec.Bytes != int64(w.Body.Len()) {
				t.Fatal("signing bypassed audit")
			}
			if w := signCall(rl, "POST", "/phobos"+signPath+"?", "", ""); w.Code != 400 {
				t.Fatalf("relay dropped forbidden empty query: %d", w.Code)
			}
		})
	}
}

func TestAppleAdsSigningRejectsUnauthorizedAndMalformedRequests(t *testing.T) {
	_, material := generatedAppleKey(t, elliptic.P256())
	now := time.Date(2026, 10, 2, 12, 0, 0, 500000000, time.UTC)
	for _, tc := range []struct {
		name, method, path, body, token string
		status                          int
		change                          func(*policy.Config)
	}{
		{name: "unauthorized", token: "wrong", status: 401},
		{name: "role expired", status: 401, change: func(c *policy.Config) { r := c.Roles["phobos"]; r.Expires = &now; c.Roles["phobos"] = r }},
		{name: "access expired", status: 403, change: func(c *policy.Config) {
			a := c.Roles["phobos"].Access["apple-ads"]
			a.Expires = &now
			c.Roles["phobos"].Access["apple-ads"] = a
		}},
		{name: "subsecond boundary", status: 503, change: func(c *policy.Config) {
			end := now.Add(time.Millisecond)
			a := c.Roles["phobos"].Access["apple-ads"]
			a.Expires = &end
			c.Roles["phobos"].Access["apple-ads"] = a
		}},
		{name: "no grant", status: 403, change: func(c *policy.Config) { delete(c.Roles["phobos"].Access, "apple-ads") }},
		{name: "missing service", status: 403, change: func(c *policy.Config) { delete(c.Services, "apple-ads"); delete(c.Roles["phobos"].Access, "apple-ads") }},
		{name: "method grant", status: 403, change: func(c *policy.Config) {
			a := c.Roles["phobos"].Access["apple-ads"]
			a.Methods = []string{"GET"}
			c.Roles["phobos"].Access["apple-ads"] = a
		}},
		{name: "path grant", status: 403, change: func(c *policy.Config) {
			a := c.Roles["phobos"].Access["apple-ads"]
			a.Paths = []string{"/other"}
			c.Roles["phobos"].Access["apple-ads"] = a
		}},
		{name: "GET", method: "GET", status: 405}, {name: "PUT", method: "PUT", status: 405},
		{name: "claims", body: `{"sub":"attacker"}`, status: 400}, {name: "empty JSON", body: `{}`, status: 400}, {name: "whitespace", body: " ", status: 400},
		{name: "query", path: signPath + "?exp=999", status: 400}, {name: "empty query", path: signPath + "?", status: 400},
		{name: "encoded path", path: "/_keyring/sign/%61pple-ads", status: 400},
		{name: "trailing slash", path: signPath + "/", status: 403},
		{name: "proxy", path: "/apple-ads/", status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := appleConfig(t)
			if tc.change != nil {
				tc.change(cfg)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			audit := &bytes.Buffer{}
			h := New(cfg, map[string]string{"APPLE_ADS_KEY": material}, audit)
			h.now = func() time.Time { return now }
			method, path, token := tc.method, tc.path, tc.token
			if method == "" {
				method = "POST"
			}
			if path == "" {
				path = signPath
			}
			if token == "" {
				token = testToken
			}
			w := signCall(h, method, path, tc.body, token)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if strings.Contains(w.Body.String()+audit.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), `"token"`) {
				t.Fatal("denied response leaked signing material")
			}
		})
	}
	cfg := appleConfig(t)
	a := cfg.Roles["phobos"].Access["apple-ads"]
	a.DailyRequests = 1
	cfg.Roles["phobos"].Access["apple-ads"] = a
	h := New(cfg, map[string]string{"APPLE_ADS_KEY": material}, &bytes.Buffer{})
	if w := signCall(h, "POST", signPath, "", testToken); w.Code != 200 {
		t.Fatal("first signing failed")
	}
	if w := signCall(h, "POST", signPath, "", testToken); w.Code != 429 {
		t.Fatal("signing bypassed daily limit")
	}
	r := httptest.NewRequest("POST", signPath, nil)
	r.RemoteAddr = "203.0.113.1:1234"
	r.Header.Set(TokenHeader, testToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("signing bypassed source restriction")
	}
}

func TestAppleAdsSigningBadKeysAndNoProxyEscape(t *testing.T) {
	_, p384 := generatedAppleKey(t, elliptic.P384())
	_, good := generatedAppleKey(t, elliptic.P256())
	for _, material := range []string{"", "secret-bad-key", p384, good + good} {
		h := New(appleConfig(t), map[string]string{"APPLE_ADS_KEY": material}, &bytes.Buffer{})
		w := signCall(h, "POST", signPath, "", testToken)
		if w.Code != 503 || strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), "secret-bad-key") {
			t.Fatal("invalid signing key did not fail closed")
		}
	}
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer up.Close()
	cfg := appleConfig(t)
	svc := cfg.Services["apple-ads"]
	svc.Base = up.URL
	svc.TestPath = "/"
	cfg.Services["apple-ads"] = svc
	// Defense in depth: even an unvalidated snapshot must not reach upstream.
	h := New(cfg, map[string]string{"APPLE_ADS_KEY": good}, &bytes.Buffer{})
	if w := signCall(h, "POST", "/apple-ads/", "", testToken); w.Code != 403 {
		t.Fatal("sign-only proxy accepted")
	}
	if _, err := h.TestKey(context.Background(), svc, good); err == nil {
		t.Fatal("dashboard Test accepted signing key")
	}
	if _, err := buildOutbound(context.Background(), svc, good, "POST", "/", "", http.Header{}, http.NoBody, 0); err == nil {
		t.Fatal("outbound builder accepted signing key")
	}
	if calls.Load() != 0 {
		t.Fatal("signing key was sent upstream")
	}
}
