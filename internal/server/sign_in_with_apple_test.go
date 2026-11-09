package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

func siwaHandler(t *testing.T, material string) *Handler {
	t.Helper()
	var access policy.AccessList
	if err := json.Unmarshal([]byte(`{"services":{"tandem-siwa":{"key":"TANDEM_SIWA_KEY","auth":"sign-in-with-apple-sign","sign_in_with_apple":{"client_id":"com.jerryfane.tandem","team_id":"FXQ5Z9HHY6","key_id":"SIWAKEY123"}}},"roles":{}}`), &access); err != nil {
		t.Fatal(err)
	}
	access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"tandem-siwa": {Methods: []string{"POST"}, Paths: []string{"/"}}}}
	access.Roles["other"] = policy.Role{TokenSHA256: tokenHash("other-role-token-0123456789"), Access: map[string]policy.Access{}}
	cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: "audit.log"}, AccessList: access}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return New(cfg, map[string]string{"TANDEM_SIWA_KEY": material}, &strings.Builder{})
}

// A Sign in with Apple client secret for revoking a user's sign-in: ES256,
// kid = key ID, iss = team ID, sub = the app's client ID, aud Apple's ID
// server, short expiry, signed by the stored key, on any service name.
func TestSignInWithAppleClientSecret(t *testing.T) {
	key, material := generatedAppleKey(t, elliptic.P256())
	h := siwaHandler(t, material)
	now := time.Now()
	w := signCall(h, "POST", "/_keyring/sign/tandem-siwa", "", testToken)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	var reply struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(reply.Token, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWT")
	}
	var header map[string]string
	var claims struct {
		Iss, Sub, Aud string
		Iat, Exp      int64
	}
	for i, v := range []any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, v) != nil {
			t.Fatalf("part %d does not decode", i)
		}
	}
	if header["alg"] != "ES256" || header["kid"] != "SIWAKEY123" {
		t.Fatalf("header = %v", header)
	}
	if claims.Iss != "FXQ5Z9HHY6" || claims.Sub != "com.jerryfane.tandem" || claims.Aud != "https://appleid.apple.com" {
		t.Fatalf("claims = %+v", claims)
	}
	if d := claims.Iat - now.Unix(); d < -5 || d > 5 || claims.Exp <= claims.Iat || claims.Exp > claims.Iat+1200 || claims.Exp != reply.ExpiresAt.Unix() {
		t.Fatalf("times: iat %d exp %d", claims.Iat, claims.Exp)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("not signed by the stored key")
	}
	if strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal("key material in the reply")
	}
}

// Only a role granted the service may sign, only with an empty POST, and a
// sign-only service never proxies; an unusable key is reported, not used.
func TestSignInWithAppleRefusals(t *testing.T) {
	_, material := generatedAppleKey(t, elliptic.P256())
	h := siwaHandler(t, material)
	for name, c := range map[string]struct {
		method, path, body, token string
		want                      int
	}{
		"no grant":        {"POST", "/_keyring/sign/tandem-siwa", "", "other-role-token-0123456789", http.StatusForbidden},
		"GET":             {"GET", "/_keyring/sign/tandem-siwa", "", testToken, http.StatusMethodNotAllowed},
		"a body":          {"POST", "/_keyring/sign/tandem-siwa", "x", testToken, http.StatusBadRequest},
		"a query":         {"POST", "/_keyring/sign/tandem-siwa?x=1", "", testToken, http.StatusBadRequest},
		"proxy attempt":   {"POST", "/tandem-siwa/auth/revoke", "", testToken, http.StatusForbidden},
		"unknown service": {"POST", "/_keyring/sign/nope", "", testToken, http.StatusForbidden},
	} {
		if w := signCall(h, c.method, c.path, c.body, c.token); w.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", name, w.Code, c.want, w.Body.String())
		}
	}
	_, p384 := generatedAppleKey(t, elliptic.P384())
	for name, bad := range map[string]string{"not a key": "not-a-key", "P-384 key": p384} {
		if w := signCall(siwaHandler(t, bad), "POST", "/_keyring/sign/tandem-siwa", "", testToken); w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d, want 503", name, w.Code)
		}
	}
}
