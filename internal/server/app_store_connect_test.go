package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

const ascSignPath = "/_keyring/sign/appstoreconnect"

func ascConfig(t *testing.T) *policy.Config {
	t.Helper()
	cfg := appleConfig(t)
	var svc policy.Service
	if err := json.Unmarshal([]byte(`{"key":"ASC_KEY","auth":"app-store-connect-sign","app_store_connect":{"issuer_id":"00000000-1111-2222-3333-444444444444","key_id":"ASC123"}}`), &svc); err != nil {
		t.Fatal(err)
	}
	cfg.Services["appstoreconnect"] = svc
	cfg.Roles["phobos"].Access["appstoreconnect"] = policy.Access{Methods: []string{"POST"}, Paths: []string{"/"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func verifyASCToken(t *testing.T, w *httptest.ResponseRecorder, pub *ecdsa.PublicKey, now, expires time.Time) {
	t.Helper()
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("uncacheable signing response: status=%d", w.Code)
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
	if header["alg"] != "ES256" || header["kid"] != "ASC123" || header["typ"] != "JWT" {
		t.Fatal("wrong App Store signing header")
	}
	var claims map[string]any
	if err := json.Unmarshal(decode(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != "00000000-1111-2222-3333-444444444444" || claims["aud"] != "appstoreconnect-v1" || claims["iat"] != float64(now.Unix()) {
		t.Fatal("wrong fixed App Store claims")
	}
	if _, ok := claims["sub"]; ok {
		t.Fatal("App Store JWT contains Apple Ads subject")
	}
	if _, ok := claims["scope"]; ok {
		t.Fatal("unexpected caller-controlled scope")
	}
	if claims["exp"] != float64(expires.Unix()) || !response.ExpiresAt.Equal(expires) {
		t.Fatal("expiry did not honor the earliest bound")
	}
	sig := decode(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("App Store ES256 signature does not verify with its own key")
	}
}

func TestAppStoreConnectSigningThroughRelay(t *testing.T) {
	key, material := generatedAppleKey(t, elliptic.P256())
	adsKey, adsMaterial := generatedAppleKey(t, elliptic.P256())
	now := time.Date(2026, 10, 6, 12, 0, 0, 123000000, time.UTC)
	for _, tc := range []struct {
		name               string
		role, access, want time.Duration
	}{
		{"maximum", 0, 0, 20 * time.Minute},
		{"role", 5 * time.Minute, 10 * time.Minute, 5 * time.Minute},
		{"access", 10 * time.Minute, 3 * time.Minute, 3 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ascConfig(t)
			r := cfg.Roles["phobos"]
			a := r.Access["appstoreconnect"]
			if tc.role != 0 {
				end := now.Add(tc.role)
				r.Expires = &end
			}
			if tc.access != 0 {
				end := now.Add(tc.access)
				a.Expires = &end
			}
			r.Access["appstoreconnect"] = a
			cfg.Roles["phobos"] = r
			audit := &bytes.Buffer{}
			h := New(cfg, map[string]string{"ASC_KEY": material, "APPLE_ADS_KEY": adsMaterial}, audit)
			h.now = func() time.Time { return now }
			up := httptest.NewServer(h)
			defer up.Close()
			u, _ := url.Parse(up.URL)
			rl := relay.New(u, map[string]string{"phobos": testToken})
			w := signCall(rl, "POST", "/phobos"+ascSignPath, "", "untrusted-caller-token")
			verifyASCToken(t, w, &key.PublicKey, now, time.Unix(now.Add(tc.want).Unix(), 0))
			var response struct{ Token string }
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(audit.String(), material) || strings.Contains(audit.String(), response.Token) || strings.Contains(audit.String(), "PRIVATE KEY") {
				t.Fatal("secret in audit")
			}
			var rec auditRecord
			if err := json.Unmarshal(bytes.TrimSpace(audit.Bytes()), &rec); err != nil {
				t.Fatal(err)
			}
			if rec.Role != "phobos" || rec.Service != "appstoreconnect" || rec.Status != 200 {
				t.Fatal("signing not attributed to the App Store grant")
			}
			// Both services coexist without mixing keys, issuer, audience or subject.
			verifiedAppleExpiry(t, signCall(rl, "POST", "/phobos"+signPath, "", ""), &adsKey.PublicKey, now)
			if got := signCall(rl, "POST", "/phobos"+ascSignPath+"?", "", "").Code; got != 400 {
				t.Fatalf("empty query through relay: %d", got)
			}
		})
	}
}

func TestAppStoreConnectSigningRejectsUnauthorizedAndMalformedRequests(t *testing.T) {
	_, material := generatedAppleKey(t, elliptic.P256())
	now := time.Date(2026, 10, 6, 12, 0, 0, 500000000, time.UTC)
	for _, tc := range []struct {
		name, method, path, body, token string
		status                          int
		change                          func(*policy.Config)
	}{
		{name: "wrong token", token: "wrong", status: 401},
		{name: "Ads grant only", status: 403, change: func(c *policy.Config) { delete(c.Roles["phobos"].Access, "appstoreconnect") }},
		{name: "expired role", status: 401, change: func(c *policy.Config) { r := c.Roles["phobos"]; r.Expires = &now; c.Roles["phobos"] = r }},
		{name: "expired access", status: 403, change: func(c *policy.Config) {
			a := c.Roles["phobos"].Access["appstoreconnect"]
			a.Expires = &now
			c.Roles["phobos"].Access["appstoreconnect"] = a
		}},
		{name: "subsecond expiry", status: 503, change: func(c *policy.Config) {
			end := now.Add(time.Millisecond)
			a := c.Roles["phobos"].Access["appstoreconnect"]
			a.Expires = &end
			c.Roles["phobos"].Access["appstoreconnect"] = a
		}},
		{name: "read-only", status: 403, change: func(c *policy.Config) {
			a := c.Roles["phobos"].Access["appstoreconnect"]
			a.Methods = []string{"GET"}
			c.Roles["phobos"].Access["appstoreconnect"] = a
		}},
		{name: "path grant", status: 403, change: func(c *policy.Config) {
			a := c.Roles["phobos"].Access["appstoreconnect"]
			a.Paths = []string{"/other"}
			c.Roles["phobos"].Access["appstoreconnect"] = a
		}},
		{name: "GET", method: "GET", status: 405},
		{name: "claims", body: `{"iss":"attacker","aud":"other","exp":9999999999}`, status: 400},
		{name: "whitespace", body: " ", status: 400},
		{name: "query", path: ascSignPath + "?scope=admin", status: 400},
		{name: "encoded path", path: "/_keyring/sign/%61ppstoreconnect", status: 400},
		{name: "trailing slash", path: ascSignPath + "/", status: 403},
		{name: "proxy escape", path: "/appstoreconnect/v1/apps", status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ascConfig(t)
			if tc.change != nil {
				tc.change(cfg)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			audit := &bytes.Buffer{}
			h := New(cfg, map[string]string{"ASC_KEY": material}, audit)
			h.now = func() time.Time { return now }
			method, path, token := tc.method, tc.path, tc.token
			if method == "" {
				method = "POST"
			}
			if path == "" {
				path = ascSignPath
			}
			if token == "" {
				token = testToken
			}
			w := signCall(h, method, path, tc.body, token)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if strings.Contains(w.Body.String()+audit.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), `"token"`) {
				t.Fatal("denied request leaked signing material")
			}
		})
	}
	cfg := ascConfig(t)
	a := cfg.Roles["phobos"].Access["appstoreconnect"]
	a.DailyRequests = 1
	cfg.Roles["phobos"].Access["appstoreconnect"] = a
	h := New(cfg, map[string]string{"ASC_KEY": material}, &bytes.Buffer{})
	if got := signCall(h, "POST", ascSignPath, "", testToken).Code; got != 200 {
		t.Fatalf("first request: %d", got)
	}
	if got := signCall(h, "POST", ascSignPath, "", testToken).Code; got != 429 {
		t.Fatalf("quota bypass: %d", got)
	}
}

func TestAppStoreConnectKeyIsolationAndReload(t *testing.T) {
	key, good := generatedAppleKey(t, elliptic.P256())
	_, p384 := generatedAppleKey(t, elliptic.P384())
	cfg := ascConfig(t)
	for _, material := range []string{"", "not-a-private-key", p384, good + good} {
		h := New(cfg, map[string]string{"ASC_KEY": material}, &bytes.Buffer{})
		if got := signCall(h, "POST", ascSignPath, "", testToken).Code; got != 503 {
			t.Fatalf("bad key status=%d", got)
		}
	}
	var calls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer up.Close()
	svc := cfg.Services["appstoreconnect"]
	svc.Base = up.URL
	svc.TestPath = "/"
	cfg.Services["appstoreconnect"] = svc
	h := New(cfg, map[string]string{"ASC_KEY": good}, &bytes.Buffer{})
	if got := signCall(h, "POST", "/appstoreconnect/", "", testToken).Code; got != 403 {
		t.Fatalf("proxy escape status=%d", got)
	}
	if _, err := h.TestKey(context.Background(), svc, good); err == nil {
		t.Fatal("dashboard Test can expose ASC key")
	}
	if _, err := buildOutbound(context.Background(), svc, good, "POST", "/", "", http.Header{}, http.NoBody, 0); err == nil {
		t.Fatal("outbound builder can expose ASC key")
	}
	if calls.Load() != 0 {
		t.Fatal("private key sent upstream")
	}
	cfg = ascConfig(t)
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	h.Swap(cfg, map[string]string{"ASC_KEY": good})
	h.now = func() time.Time { return now }
	verifyASCToken(t, signCall(h, "POST", ascSignPath, "", testToken), &key.PublicKey, now, now.Add(20*time.Minute))
	h.Swap(cfg, map[string]string{})
	if got := signCall(h, "POST", ascSignPath, "", testToken).Code; got != 503 {
		t.Fatalf("removed key remains usable: %d", got)
	}
}
