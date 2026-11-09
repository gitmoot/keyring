package dashboard

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/store"
)

// upload posts the upload form as a browser does: multipart, with the
// session cookie, Origin and CSRF field. Empty csrf sends none.
func (e *env) upload(fields map[string]string, filename string, content []byte, csrf string) *httptest.ResponseRecorder {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if csrf != "" {
		_ = mw.WriteField("csrf", csrf)
	}
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	if filename != "" {
		fw, _ := mw.CreateFormFile("file", filename)
		_, _ = fw.Write(content)
	}
	_ = mw.Close()
	r := httptest.NewRequest("POST", "/new/key/upload", &body)
	r.Host = listen
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.AddCookie(&http.Cookie{Name: "keyring_session", Value: e.cookie})
	w := httptest.NewRecorder()
	e.admin.ServeHTTP(w, r)
	return w
}

func p8(t *testing.T) ([]byte, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	sum := sha256.Sum256(spki)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), hex.EncodeToString(sum[:8])
}

// The owner uploads an Apple .p8 from the browser: it is stored exactly as the
// file, the page shows its kind and public-key fingerprint and offers the
// Apple connect lines, the audit names it, and the key text is shown nowhere.
func TestUploadAppleKeyFile(t *testing.T) {
	e := newEnv(t)
	file, fp := p8(t)
	w := e.upload(map[string]string{"name": "TANDEM_APNS_KEY", "password": password}, "AuthKey_X2RWDT68P4.p8", file, e.csrf)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/keys/TANDEM_APNS_KEY?done=uploaded" {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	keys, _ := store.Load(e.backend.StorePath)
	if keys["TANDEM_APNS_KEY"] != string(file) {
		t.Fatal("stored value differs from the file")
	}
	if info, _ := os.Stat(e.backend.StorePath); info.Mode().Perm() != 0o600 {
		t.Fatalf("store mode %v", info.Mode().Perm())
	}
	page := e.request("GET", "/keys/TANDEM_APNS_KEY?done=uploaded", nil).Body.String()
	for _, want := range []string{"Key file stored: EC P-256 private key, fingerprint " + fp, "<code>" + fp + "</code>", `"auth":"apns"`, `"auth":"sign-in-with-apple-sign"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("key page lacks %q", want)
		}
	}
	if !strings.Contains(e.audit.String(), `"admin":"key_uploaded"`) || !strings.Contains(e.audit.String(), `"fingerprint":"`+fp+`"`) {
		t.Fatalf("audit: %s", e.audit.String())
	}
	body := strings.TrimSpace(strings.Split(string(file), "\n")[1])
	if all := page + e.everyPage("/keys", "/new/key") + e.audit.String(); strings.Contains(all, body) || strings.Contains(all, "PRIVATE KEY-----") {
		t.Fatal("key text is shown or logged")
	}
}

// A wrong file is caught at upload, nothing is stored, and the message says
// what is wrong without repeating the file.
func TestUploadRefusesUnusableFiles(t *testing.T) {
	e := newEnv(t)
	_, rsaKey := func() ([]byte, []byte) {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.MarshalPKCS8PrivateKey(k)
		return nil, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}()
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKCS8PrivateKey(ec384)
	pub, _ := x509.MarshalPKIXPublicKey(&ec384.PublicKey)
	good, _ := p8(t)
	cases := []struct {
		name, file string
		content    []byte
		want       string
	}{
		{"public key", "k.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), "public key or certificate"},
		{"broken PEM", "k.p8", []byte("-----BEGIN PRIVATE KEY-----\nnot base64 at all\n-----END PRIVATE KEY-----\n"), "cannot be read"},
		{"garbage key", "k.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk-junk-junk")}), "usable private key"},
		{"RSA as .p8", "AuthKey_X.p8", rsaKey, "EC P-256"},
		{"P-384 as .p8", "AuthKey_X.p8", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der384}), "EC P-256"},
		{"no key in .p8", "AuthKey_X.p8", []byte("hello"), "no key in it"},
		{"encrypted", "k.pem", pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}), "password-protected"},
		{"two blocks", "k.pem", append(append([]byte{}, good...), good...), "more than one"},
		{"binary", "k.p8", []byte{0x30, 0x82, 0x00, 0xff, 0x00}, "not a text key file"},
		{"empty", "k.p8", []byte("  \n"), "empty"},
		{"no key in .pem", "private.pem", []byte("just some text\n"), "no PEM private key"},
		{"no key in .key", "server.key", []byte("just some text\n"), "no PEM private key"},
	}
	for _, c := range cases {
		w := e.upload(map[string]string{"name": "WRONG_FILE", "password": password}, c.file, c.content, e.csrf)
		if w.Code == http.StatusSeeOther || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d, want refusal saying %q", c.name, w.Code, c.want)
		}
		if len(c.content) > 20 && strings.Contains(w.Body.String(), string(c.content[11:20])) {
			t.Errorf("%s: refusal repeats the file", c.name)
		}
	}
	if keys, _ := store.Load(e.backend.StorePath); keys["WRONG_FILE"] != "" {
		t.Fatal("a refused file was stored")
	}
}

// The same protections as every other change: no session, no CSRF token,
// wrong password, or an existing name without Replace store nothing; Replace
// overwrites. A file over 60 KiB is refused.
func TestUploadNeedsSessionPasswordAndReplace(t *testing.T) {
	e := newEnv(t)
	file, _ := p8(t)
	if w := e.upload(map[string]string{"name": "K", "password": password}, "k.p8", file, ""); w.Code != http.StatusForbidden {
		t.Errorf("no CSRF token: %d", w.Code)
	}
	if w := e.upload(map[string]string{"name": "K", "password": "wrong"}, "k.p8", file, e.csrf); w.Code != http.StatusForbidden {
		t.Errorf("wrong password: %d", w.Code)
	}
	cookie := e.cookie
	e.cookie = "not-a-session"
	if w := e.upload(map[string]string{"name": "K", "password": password}, "k.p8", file, e.csrf); w.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", w.Code)
	}
	e.cookie = cookie
	if keys, _ := store.Load(e.backend.StorePath); keys["K"] != "" {
		t.Fatal("refused upload stored a value")
	}
	// API_KEY exists: refused without Replace, replaced with it.
	if w := e.upload(map[string]string{"name": "API_KEY", "password": password}, "k.p8", file, e.csrf); w.Code != http.StatusConflict {
		t.Errorf("existing name without Replace: %d", w.Code)
	}
	if keys, _ := store.Load(e.backend.StorePath); keys["API_KEY"] != oldValue {
		t.Fatal("the existing key changed without Replace")
	}
	if w := e.upload(map[string]string{"name": "API_KEY", "password": password, "replace": "yes"}, "k.p8", file, e.csrf); w.Code != http.StatusSeeOther {
		t.Errorf("Replace: %d", w.Code)
	}
	if keys, _ := store.Load(e.backend.StorePath); keys["API_KEY"] != string(file) {
		t.Fatal("Replace did not store the file")
	}
	big := append([]byte("-----BEGIN PRIVATE KEY-----\n"), bytes.Repeat([]byte("A"), 61<<10)...)
	if w := e.upload(map[string]string{"name": "BIG", "password": password}, "k.pem", big, e.csrf); w.Code == http.StatusSeeOther {
		t.Errorf("oversized file accepted: %d", w.Code)
	}
}

// Other private keys and plain text files work too, as with keyring set --file.
func TestUploadOtherKeyKinds(t *testing.T) {
	e := newEnv(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	for name, c := range map[string]struct {
		file    string
		content []byte
		kind    string
	}{
		"ED_KEY":   {"signing.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "Ed25519 private key"},
		"TEXT_KEY": {"token.txt", []byte("line one\nline two\n"), "text value"},
	} {
		if w := e.upload(map[string]string{"name": name, "password": password}, c.file, c.content, e.csrf); w.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
		if page := e.request("GET", "/keys/"+name, nil).Body.String(); !strings.Contains(page, "<dt>File</dt><dd>"+c.kind) {
			t.Errorf("%s: kind not shown", name)
		}
		if keys, _ := store.Load(e.backend.StorePath); keys[name] != string(c.content) {
			t.Errorf("%s: stored value differs from the file", name)
		}
	}
}

// Review of #127, F1: a replacement is live at once, even when the access file
// cannot be read at that moment: a signer using the key signs with the new
// one. The store and the running keyring agree.
func TestUploadReplacementIsLiveWithoutReadingTheAccessFile(t *testing.T) {
	e := newEnv(t)
	first, _ := p8(t)
	e.upload(map[string]string{"name": "SIGNER", "password": password}, "a.p8", first, e.csrf)
	cfg := e.proxy.Config()
	access := cfg.AccessList
	access.Services["siwa"] = policy.Service{Key: "SIGNER", Auth: policy.AuthSignInWithAppleSign,
		SignInWithApple: &policy.SignInWithApple{ClientID: "com.example.app", TeamID: "TEAM123456", KeyID: "KEY1234567"}}
	role := access.Roles["phobos"]
	role.Access = map[string]policy.Access{"siwa": {Methods: []string{"POST"}, Paths: []string{"/"}}}
	access.Roles["phobos"] = role
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(next, keys)
	// Readable by others: the keyring refuses to load it (root ignores 0000).
	if err := os.Chmod(next.AccessFile, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(next.AccessFile, 0o600)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	second := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if w := e.upload(map[string]string{"name": "SIGNER", "password": password, "replace": "yes"}, "b.p8", second, e.csrf); w.Code != http.StatusSeeOther {
		t.Fatalf("replace: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("POST", "/_keyring/sign/siwa", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set(server.TokenHeader, token)
	w := httptest.NewRecorder()
	e.proxy.ServeHTTP(w, r)
	var reply struct{ Token string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	parts := strings.Split(reply.Token, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the running keyring still signs with the old key")
	}
	if !strings.Contains(e.audit.String(), `"replaced":true`) {
		t.Fatal("the replacement was not audited")
	}
}

// A file goes into a key with one value; a key with several named values, or
// a dotted name, is refused (they are managed on the key's page).
func TestUploadRefusesMultiValueKeys(t *testing.T) {
	e := newEnv(t)
	file, _ := p8(t)
	if err := store.Set(e.backend.StorePath, "MODAL.id", "wk-0123456789"); err != nil {
		t.Fatal(err)
	}
	for name, fields := range map[string]map[string]string{
		"dotted name":     {"name": "MODAL.secret", "password": password},
		"multi-value key": {"name": "MODAL", "password": password, "replace": "yes"},
	} {
		if w := e.upload(fields, "k.p8", file, e.csrf); w.Code == http.StatusSeeOther {
			t.Errorf("%s: accepted", name)
		}
	}
	keys, _ := store.Load(e.backend.StorePath)
	if keys["MODAL"] != "" || keys["MODAL.secret"] != "" {
		t.Fatal("a refused upload was stored")
	}
}
