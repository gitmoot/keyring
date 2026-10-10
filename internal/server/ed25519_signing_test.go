package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const ed25519SignTestPath = "/_keyring/sign/release"

func ed25519Config(t *testing.T) *policy.Config {
	t.Helper()
	var access policy.AccessList
	if err := json.Unmarshal([]byte(`{"services":{"release":{"key":"RELEASE_KEY","auth":"ed25519-sign"}},"roles":{}}`), &access); err != nil {
		t.Fatal(err)
	}
	access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"release": {Methods: []string{"POST"}, Paths: []string{"/"}}}}
	access.Roles["outsider"] = policy.Role{TokenSHA256: tokenHash("role-token-outsider"), Access: map[string]policy.Access{"release": {Methods: []string{"POST"}, Paths: []string{"/"}}}}
	cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller, "127.0.0.1"}, AuditLog: "audit.log"}, AccessList: access}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func generatedEd25519Key(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(key)
}

func ed25519Handler(t *testing.T, cfg *policy.Config, key string) *Handler {
	t.Helper()
	return New(cfg, map[string]string{"RELEASE_KEY": key}, io.Discard)
}

func TestEd25519SigningVerifies(t *testing.T) {
	priv, stored := generatedEd25519Key(t)
	h := ed25519Handler(t, ed25519Config(t), stored)
	message := []byte("0123456789abcdef0123456789abcdef") // a 32-byte digest, as the update feed signs
	body := `{"message_base64":"` + base64.StdEncoding.EncodeToString(message) + `"}`
	w := signCall(h, "POST", ed25519SignTestPath, body, testToken)
	if w.Code != 200 {
		t.Fatalf("sign status = %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("signing response can be cached")
	}
	var response struct {
		SignatureBase64 string `json:"signature_base64"`
		PublicKeyBase64 string `json:"public_key_base64"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(response.SignatureBase64)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(priv.Public().(ed25519.PublicKey), message, signature) {
		t.Fatal("signature does not verify against the private key's public half")
	}
	// The published public key is the same half, so a caller can pin it in the app.
	published, err := base64.StdEncoding.DecodeString(response.PublicKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(published), message, signature) {
		t.Fatal("signature does not verify against the returned public key")
	}
	// The private key never appears: the response carries nothing that decodes to it.
	if strings.Contains(w.Body.String(), stored) {
		t.Fatal("private key material leaked into the response")
	}
}

func TestEd25519SigningRejectsMalformedAndUnauthorized(t *testing.T) {
	_, stored := generatedEd25519Key(t)
	h := ed25519Handler(t, ed25519Config(t), stored)
	message := base64.StdEncoding.EncodeToString([]byte("digest"))
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		token  string
		want   int
	}{
		{"get is not signing", "GET", ed25519SignTestPath, `{"message_base64":"` + message + `"}`, testToken, 405},
		{"empty body", "POST", ed25519SignTestPath, "", testToken, 400},
		{"not json", "POST", ed25519SignTestPath, "hello", testToken, 400},
		{"bad base64", "POST", ed25519SignTestPath, `{"message_base64":"!!!"}`, testToken, 400},
		{"empty message", "POST", ed25519SignTestPath, `{"message_base64":""}`, testToken, 400},
		{"trailing garbage", "POST", ed25519SignTestPath, `{"message_base64":"` + message + `"} GARBAGE`, testToken, 400},
		{"trailing object", "POST", ed25519SignTestPath, `{"message_base64":"` + message + `"}{"message_base64":"` + message + `"}`, testToken, 400},
		{"query is refused", "POST", ed25519SignTestPath + "?x=1", `{"message_base64":"` + message + `"}`, testToken, 400},
		{"extra segment", "POST", ed25519SignTestPath + "/extra", `{"message_base64":"` + message + `"}`, testToken, 403},
		{"unconfigured service", "POST", "/_keyring/sign/nope", `{"message_base64":"` + message + `"}`, testToken, 403},
		{"unknown token", "POST", ed25519SignTestPath, `{"message_base64":"` + message + `"}`, "wrong-token", 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := signCall(h, tc.method, tc.path, tc.body, tc.token)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
	// A role whose access list does not name the service gets 403.
	w := signCall(h, "POST", "/_keyring/sign/other-svc", `{"message_base64":"`+message+`"}`, testToken)
	if w.Code != 403 {
		t.Fatalf("service outside config: status = %d, want 403", w.Code)
	}
}

func TestEd25519MalformedBodyDoesNotBurnQuota(t *testing.T) {
	// DailyRequests=1: a 400 body must not charge the daily allowance, so the
	// first valid request still signs.
	_, stored := generatedEd25519Key(t)
	var access policy.AccessList
	if err := json.Unmarshal([]byte(`{"services":{"release":{"key":"RELEASE_KEY","auth":"ed25519-sign"}},"roles":{}}`), &access); err != nil {
		t.Fatal(err)
	}
	access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"release": {Methods: []string{"POST"}, Paths: []string{"/"}, DailyRequests: 1}}}
	cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: "audit.log"}, AccessList: access}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h := ed25519Handler(t, cfg, stored)
	w := signCall(h, "POST", ed25519SignTestPath, "not json", testToken)
	if w.Code != 400 {
		t.Fatalf("malformed body: status = %d, want 400", w.Code)
	}
	message := base64.StdEncoding.EncodeToString([]byte("digest"))
	w = signCall(h, "POST", ed25519SignTestPath, `{"message_base64":"`+message+`"}`, testToken)
	if w.Code != 200 {
		t.Fatalf("first valid request after a 400: status = %d, want 200: %s", w.Code, w.Body.String())
	}
	w = signCall(h, "POST", ed25519SignTestPath, `{"message_base64":"`+message+`"}`, testToken)
	if w.Code != 429 {
		t.Fatalf("second valid request: status = %d, want 429", w.Code)
	}
}

func TestEd25519SignPathIsNotAProxy(t *testing.T) {
	// An ed25519-sign service must never proxy: its own name on a normal path
	// is refused, and a bearer service on the sign path is refused.
	_, stored := generatedEd25519Key(t)
	var access policy.AccessList
	if err := json.Unmarshal([]byte(`{"services":{"release":{"key":"RELEASE_KEY","auth":"ed25519-sign"},"api":{"base":"https://example.com","key":"RELEASE_KEY","auth":"bearer"}},"roles":{}}`), &access); err == nil {
		access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"release": {Methods: []string{"POST"}, Paths: []string{"/"}}, "api": {Methods: []string{"GET"}, Paths: []string{"/"}}}}
		cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: "audit.log"}, AccessList: access}
		if err := cfg.Validate(); err == nil {
			t.Fatal("a signing key shared with a proxy service must not validate")
		}
	}
	h := ed25519Handler(t, ed25519Config(t), stored)
	message := base64.StdEncoding.EncodeToString([]byte("x"))
	w := signCall(h, "POST", "/release/anything", `{"message_base64":"`+message+`"}`, testToken)
	if w.Code != 403 {
		t.Fatalf("sign-only service proxying: status = %d, want 403", w.Code)
	}
}

func TestEd25519SigningBadKey(t *testing.T) {
	h := ed25519Handler(t, ed25519Config(t), "not-valid-base64-key")
	message := base64.StdEncoding.EncodeToString([]byte("x"))
	w := signCall(h, "POST", ed25519SignTestPath, `{"message_base64":"`+message+`"}`, testToken)
	if w.Code != 503 {
		t.Fatalf("bad key: status = %d, want 503", w.Code)
	}
	short := base64.StdEncoding.EncodeToString([]byte("32-byte seed only................."))
	h = ed25519Handler(t, ed25519Config(t), short)
	w = signCall(h, "POST", ed25519SignTestPath, `{"message_base64":"`+message+`"}`, testToken)
	if w.Code != 503 {
		t.Fatalf("short key: status = %d, want 503", w.Code)
	}
}

func TestEd25519SignPolicyValidation(t *testing.T) {
	for name, service := range map[string]string{
		"with base":        `{"key":"K","auth":"ed25519-sign","base":"https://example.com"}`,
		"with test path":   `{"key":"K","auth":"ed25519-sign","test_path":"/x"}`,
		"with identity":    `{"key":"K","auth":"ed25519-sign","apple_ads":{"client_id":"c","team_id":"t","key_id":"k"}}`,
		"not a store name": `{"key":"","auth":"ed25519-sign"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var access policy.AccessList
			raw := `{"services":{"release":` + service + `},"roles":{}}`
			if err := json.Unmarshal([]byte(raw), &access); err != nil {
				t.Fatal(err)
			}
			access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"release": {}}}
			cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}}, AccessList: access}
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid ed25519-sign service must not validate")
			}
		})
	}
}

// Guard against the original confusion: a sign path must not answer for a
// proxy service that merely shares a name with the path tail.
func TestEd25519SignPathServiceMustBeSignOnly(t *testing.T) {
	var access policy.AccessList
	if err := json.Unmarshal([]byte(`{"services":{"release":{"base":"https://example.com","key":"RELEASE_KEY","auth":"bearer"}},"roles":{}}`), &access); err != nil {
		t.Fatal(err)
	}
	access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"release": {Methods: []string{"POST"}, Paths: []string{"/"}}}}
	cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller}, AuditLog: "audit.log"}, AccessList: access}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h := New(cfg, map[string]string{"RELEASE_KEY": "sk-test"}, io.Discard)
	message := base64.StdEncoding.EncodeToString([]byte("x"))
	w := signCall(h, "POST", ed25519SignTestPath, `{"message_base64":"`+message+`"}`, testToken)
	if w.Code != 403 {
		t.Fatalf("bearer service on sign path: status = %d, want 403", w.Code)
	}
}

func TestEd25519AuditDoesNotCarryKey(t *testing.T) {
	priv, stored := generatedEd25519Key(t)
	var audit strings.Builder
	cfg := ed25519Config(t)
	h := New(cfg, map[string]string{"RELEASE_KEY": stored}, &audit)
	message := base64.StdEncoding.EncodeToString([]byte("digest"))
	w := signCall(h, "POST", ed25519SignTestPath, `{"message_base64":"`+message+`"}`, testToken)
	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(audit.String(), base64.StdEncoding.EncodeToString(priv)) || strings.Contains(audit.String(), stored) {
		t.Fatal("private key material in audit log")
	}
}

var _ = time.Now // keep time imported if later tests need it
