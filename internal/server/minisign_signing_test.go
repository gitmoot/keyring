package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/minisign"
	"github.com/gitmoot/keyring/internal/policy"
)

const minisignTestPath = "/_keyring/minisign/herdr-release"

func minisignConfig(t *testing.T) *policy.Config {
	t.Helper()
	var access policy.AccessList
	if err := json.Unmarshal([]byte(`{"services":{"herdr-release":{"key":"HERDR_KEY","auth":"minisign-sign","minisign":{"trusted_comment_prefix":"herdr-preview "}}},"roles":{}}`), &access); err != nil {
		t.Fatal(err)
	}
	access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"herdr-release": {Methods: []string{"GET", "POST"}, Paths: []string{"/"}}}}
	cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller, "127.0.0.1"}, AuditLog: "audit.log"}, AccessList: access}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

const testDigestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func minisignBody(digest, comment string) string {
	body, _ := json.Marshal(map[string]string{"blake2b512_hex": digest, "trusted_comment": comment})
	return string(body)
}

// verifyMinisig checks a .minisig file the way minisign does: prehashed
// algorithm, matching key ID, signature over the digest and global signature
// over signature || trusted comment.
func verifyMinisig(t *testing.T, minisig string, pub ed25519.PublicKey, digest []byte, wantComment string) {
	t.Helper()
	lines := strings.Split(minisig, "\n")
	if len(lines) != 5 || lines[4] != "" || !strings.HasPrefix(lines[0], "untrusted comment: ") {
		t.Fatalf("minisig layout: %q", minisig)
	}
	sigLine, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(sigLine) != 74 || string(sigLine[:2]) != "ED" {
		t.Fatalf("signature line is not a prehashed minisign signature: %q", lines[1])
	}
	id := minisign.KeyID(pub)
	if !bytes.Equal(sigLine[2:10], id[:]) {
		t.Fatal("signature key ID does not match the public key")
	}
	if !ed25519.Verify(pub, digest, sigLine[10:]) {
		t.Fatal("signature does not verify over the digest")
	}
	comment, ok := strings.CutPrefix(lines[2], "trusted comment: ")
	if !ok || comment != wantComment {
		t.Fatalf("trusted comment = %q", lines[2])
	}
	global, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil || !ed25519.Verify(pub, append(append([]byte{}, sigLine[10:]...), comment...), global) {
		t.Fatal("global signature does not cover the trusted comment")
	}
}

func TestMinisignSigningVerifiesAndIsAudited(t *testing.T) {
	priv, stored := generatedEd25519Key(t)
	pub := priv.Public().(ed25519.PublicKey)
	var audit bytes.Buffer
	h := New(minisignConfig(t), map[string]string{"HERDR_KEY": stored}, &audit)
	comment := "herdr-preview 20261028.1 8a02b834"
	w := signCall(h, "POST", minisignTestPath, minisignBody(strings.ToUpper(testDigestHex), comment), testToken)
	if w.Code != 200 {
		t.Fatalf("sign status = %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("signing response can be cached")
	}
	var signed struct {
		Minisig   string `json:"minisig"`
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(testDigestHex)
	if err != nil {
		t.Fatal(err)
	}
	verifyMinisig(t, signed.Minisig, pub, digest, comment)
	if signed.PublicKey != minisign.PublicKey(pub) || signed.KeyID != minisign.KeyIDHex(pub) {
		t.Fatal("sign reply names a different public key")
	}
	if strings.Contains(w.Body.String(), stored) || strings.Contains(audit.String(), stored) {
		t.Fatal("private key material leaked")
	}
	var rec auditRecord
	if err := json.Unmarshal(bytes.TrimSpace(audit.Bytes()), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Role != "phobos" || rec.Service != "herdr-release" || rec.Status != 200 || rec.Digest != testDigestHex || rec.TrustedComment != comment || rec.Time == "" {
		t.Fatalf("audit record = %+v", rec)
	}
}

func TestMinisignPublicKeyExport(t *testing.T) {
	priv, stored := generatedEd25519Key(t)
	pub := priv.Public().(ed25519.PublicKey)
	h := New(minisignConfig(t), map[string]string{"HERDR_KEY": stored}, &bytes.Buffer{})
	w := signCall(h, "GET", minisignTestPath, "", testToken)
	if w.Code != 200 {
		t.Fatalf("export status = %d: %s", w.Code, w.Body.String())
	}
	var exported struct {
		KeyID         string `json:"key_id"`
		PublicKey     string `json:"public_key"`
		PublicKeyFile string `json:"public_key_file"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(exported.PublicKey)
	id := minisign.KeyID(pub)
	if err != nil || len(raw) != 42 || string(raw[:2]) != "Ed" || !bytes.Equal(raw[2:10], id[:]) || !bytes.Equal(raw[10:], pub) {
		t.Fatalf("public key is not the minisign form of the key: %q", exported.PublicKey)
	}
	if exported.PublicKeyFile != "untrusted comment: minisign public key "+exported.KeyID+"\n"+exported.PublicKey+"\n" {
		t.Fatalf("public key file = %q", exported.PublicKeyFile)
	}
	if strings.Contains(w.Body.String(), stored) {
		t.Fatal("private key material leaked")
	}
}

func TestMinisignRefusesOtherUses(t *testing.T) {
	_, stored := generatedEd25519Key(t)
	h := New(minisignConfig(t), map[string]string{"HERDR_KEY": stored}, &bytes.Buffer{})
	good := "herdr-preview 1 abc"
	raw := `{"message_base64":"` + base64.StdEncoding.EncodeToString([]byte("anything")) + `"}`
	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"raw ed25519 route cannot use the key", "POST", "/_keyring/sign/herdr-release", raw, 403},
		{"proxy path is refused", "POST", "/herdr-release/anything", raw, 403},
		{"other method", "PUT", minisignTestPath, minisignBody(testDigestHex, good), 405},
		{"query", "POST", minisignTestPath + "?x=1", minisignBody(testDigestHex, good), 400},
		{"another product's comment", "POST", minisignTestPath, minisignBody(testDigestHex, "adspower-desk 1 abc"), 400},
		{"prefix alone", "POST", minisignTestPath, minisignBody(testDigestHex, "herdr-preview "), 400},
		{"comment with a newline", "POST", minisignTestPath, minisignBody(testDigestHex, "herdr-preview 1\ntrusted comment: x"), 400},
		{"comment too long", "POST", minisignTestPath, minisignBody(testDigestHex, "herdr-preview "+strings.Repeat("x", 243)), 400},
		{"short digest", "POST", minisignTestPath, minisignBody(testDigestHex[:64], good), 400},
		{"digest not hex", "POST", minisignTestPath, minisignBody(strings.Repeat("zz", 64), good), 400},
		{"unknown field", "POST", minisignTestPath, `{"blake2b512_hex":"` + testDigestHex + `","trusted_comment":"` + good + `","message_base64":"eA=="}`, 400},
		{"trailing object", "POST", minisignTestPath, minisignBody(testDigestHex, good) + "{}", 400},
		{"unconfigured service", "POST", "/_keyring/minisign/nope", minisignBody(testDigestHex, good), 403},
		{"export with a body", "GET", minisignTestPath, "x", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := signCall(h, tc.method, tc.path, tc.body, testToken)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
	// The longest accepted comment is 256 bytes.
	w := signCall(h, "POST", minisignTestPath, minisignBody(testDigestHex, "herdr-preview "+strings.Repeat("x", 242)), testToken)
	if w.Code != 200 {
		t.Fatalf("256-byte comment status = %d: %s", w.Code, w.Body.String())
	}
}

func TestMinisignBadStoredKeyIsUnavailable(t *testing.T) {
	h := New(minisignConfig(t), map[string]string{"HERDR_KEY": base64.StdEncoding.EncodeToString([]byte("short"))}, &bytes.Buffer{})
	w := signCall(h, "POST", minisignTestPath, minisignBody(testDigestHex, "herdr-preview 1 abc"), testToken)
	if w.Code != 503 {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}
