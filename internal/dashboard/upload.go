package dashboard

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/gitmoot/keyring/internal/store"
)

// Uploading a key file from the dashboard (gitmoot/keyring#126): the same
// result as `keyring set --file NAME`, from the owner's browser. The request is
// a normal dashboard form post (session, CSRF, Origin, password) and the admin
// server caps every request body at 64 KiB, so the file is parsed in memory and
// never written to a temporary file. The value is never shown or logged; the
// page shows its kind and a short fingerprint of the public key.

// maxUploadBytes bounds the file itself (the request cap is 64 KiB in all).
const maxUploadBytes = 60 << 10

// keyFile is what the page may say about an uploaded value.
type keyFile struct {
	Kind        string // e.g. "EC P-256 private key"
	Fingerprint string // first 16 hex of SHA-256 of the public key (or of the file)
	AppleP8     bool   // an EC P-256 PKCS#8 key, the kind Apple issues
}

var errNotAKey = errors.New("not a key file")

// inspectKeyFile checks a file before it is stored. A PEM file must hold one
// usable private key; a .p8 must be an EC P-256 key. Other text files are
// stored as they are, like `keyring set --file`. Errors name the problem,
// never the content.
func inspectKeyFile(filename string, raw []byte) (keyFile, string) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return keyFile{}, "The file is empty."
	}
	if !utf8.Valid(raw) || strings.ContainsRune(string(raw), 0) {
		return keyFile{}, "The file is not a text key file. Upload the .p8 or .pem file itself."
	}
	lower := strings.ToLower(filename)
	p8 := strings.HasSuffix(lower, ".p8")
	if !strings.Contains(string(raw), "-----BEGIN") {
		if p8 {
			return keyFile{}, "This .p8 file has no key in it. Download the key again from Apple Developer > Keys."
		}
		if strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".key") {
			return keyFile{}, "This file has no PEM private key in it. Check you picked the right file."
		}
		// No fingerprint: a hash of a secret confirms a guess at it (#128).
		return keyFile{Kind: "text value"}, ""
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		return keyFile{}, "The file looks like a PEM key but cannot be read. Upload the file as downloaded, unchanged."
	}
	if extra, _ := pem.Decode(rest); extra != nil {
		return keyFile{}, "The file holds more than one PEM block. Upload a file with just the private key."
	}
	if strings.Contains(block.Type, "PUBLIC KEY") || block.Type == "CERTIFICATE" {
		return keyFile{}, "This is a public key or certificate, not a private key. Upload the private key file."
	}
	if strings.Contains(block.Type, "ENCRYPTED") || block.Headers["Proc-Type"] != "" {
		return keyFile{}, "The key is password-protected. Upload an unencrypted key."
	}
	key, err := parsePrivateKey(block)
	if err != nil {
		return keyFile{}, "The file does not hold a usable private key."
	}
	var f keyFile
	var public any
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		f.Kind, public = "EC "+k.Curve.Params().Name+" private key", &k.PublicKey
		f.AppleP8 = k.Curve == elliptic.P256() && block.Type == "PRIVATE KEY"
	case ed25519.PrivateKey:
		f.Kind, public = "Ed25519 private key", k.Public()
	case *rsa.PrivateKey:
		f.Kind, public = "RSA private key", &k.PublicKey
	default:
		return keyFile{}, "The file does not hold a usable private key."
	}
	if p8 && !f.AppleP8 {
		return keyFile{}, "A .p8 from Apple is an EC P-256 key; this one is a " + f.Kind + ". Check you picked the right file."
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return keyFile{}, "The file does not hold a usable private key."
	}
	sum := sha256.Sum256(spki)
	f.Fingerprint = hex.EncodeToString(sum[:8])
	return f, ""
}

func parsePrivateKey(block *pem.Block) (any, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	return nil, errNotAKey
}

// uploadKey stores a key from an uploaded file.
func (b *Backend) uploadKey(w http.ResponseWriter, r *http.Request, sid string) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	again := func(status int, msg string) { b.renderNewKeyUpload(w, sid, status, name, msg) }
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if !b.Admin.Confirm(sid, r.PostFormValue("password")) {
		again(http.StatusForbidden, "Enter your dashboard password to upload a key.")
		return
	}
	if base, part := store.SplitPart(name); part != "" || !store.ValidName(base) {
		again(http.StatusBadRequest, "The name must be letters, digits and _, not starting with a digit.")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		again(http.StatusBadRequest, "Choose the key file to upload.")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxUploadBytes+1))
	if err != nil {
		again(http.StatusBadRequest, "The file could not be read.")
		return
	}
	if len(raw) > maxUploadBytes {
		again(http.StatusRequestEntityTooLarge, "The file is larger than 60 KiB; a key file is much smaller.")
		return
	}
	info, msg := inspectKeyFile(header.Filename, raw)
	if msg != "" {
		again(http.StatusBadRequest, msg)
		return
	}
	value := string(raw)
	b.Mu.Lock()
	defer b.Mu.Unlock()
	keys, err := store.Load(b.StorePath)
	if err != nil {
		b.fail(w, sid, err)
		return
	}
	_, exists := keys[name]
	for stored := range keys {
		if base, part := store.SplitPart(stored); base == name && part != "" {
			again(http.StatusConflict, name+" has several values; replace them one by one on its page.")
			return
		}
	}
	if exists && r.PostFormValue("replace") != "yes" {
		again(http.StatusConflict, "A key named "+name+" exists. Tick Replace to overwrite it, or pick another name.")
		return
	}
	if err := store.Set(b.StorePath, name, value); err != nil {
		b.fail(w, sid, err)
		return
	}
	keys[name] = value
	// The running config with the new value: keys parsed at load (APNs,
	// signers) pick it up. Nothing here can fail after the value is stored,
	// so the store and the running keyring never disagree.
	b.Proxy.Swap(b.Proxy.Config(), keys)
	if meta, err := b.loadMeta(); err == nil {
		now := b.Now().UTC()
		created := meta[name].CreatedAt
		if created == nil || !exists {
			created = &now
		}
		meta[name] = KeyMeta{UpdatedAt: &now, CreatedAt: created, Kind: info.Kind, Fingerprint: info.Fingerprint}
		_ = b.saveMeta(meta)
	}
	fields := map[string]any{"key": name, "kind": info.Kind, "replaced": exists}
	if info.Fingerprint != "" {
		fields["fingerprint"] = info.Fingerprint
	}
	b.Admin.Audit("key_uploaded", sid, fields)
	http.Redirect(w, r, "/keys/"+name+"?done=uploaded", http.StatusSeeOther)
}
