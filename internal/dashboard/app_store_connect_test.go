package dashboard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/url"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

func TestDashboardAccessEditsPreserveAppStoreConnectSigning(t *testing.T) {
	e := newEnv(t)
	var svc policy.Service
	if err := json.Unmarshal([]byte(`{"auth":"app-store-connect-sign","key":"ASC_KEY","app_store_connect":{"issuer_id":"issuer-id","key_id":"key-id"}}`), &svc); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(e.backend.StorePath, "ASC_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))); err != nil {
		t.Fatal(err)
	}
	cfg := e.proxy.Config()
	next, err := policy.LoadAccess(cfg.AccessFile)
	if err != nil {
		t.Fatal(err)
	}
	next.Services["appstoreconnect"] = svc
	if err := e.backend.saveAndApply(next); err != nil {
		t.Fatal(err)
	}
	if w := e.saveCell("phobos", "appstoreconnect", url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}}); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatal("could not grant App Store signing")
	}
	if code := e.call("POST", "/_keyring/sign/appstoreconnect", token); code != 200 {
		t.Fatalf("signing after grant: %d", code)
	}
	if w := e.request("POST", "/keys/ASC_KEY/test", url.Values{}); w.Header().Get("Location") != "/keys/ASC_KEY?error=no-test" {
		t.Fatal("dashboard offered an upstream private-key test")
	}
	if w := e.saveCell("phobos", "appstoreconnect", url.Values{"on": {"yes"}, "mode": {"read"}, "paths": {"/"}}); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatal("could not restrict App Store signing")
	}
	if code := e.call("POST", "/_keyring/sign/appstoreconnect", token); code != 403 {
		t.Fatal("read-only grant still signs")
	}
	if code := e.call("GET", "/api/v1/x", token); code != 200 {
		t.Fatal("App Store grant edit broke unrelated access")
	}
}
