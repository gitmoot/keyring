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

func TestDashboardAccessEditsPreserveAppleAdsSigning(t *testing.T) {
	e := newEnv(t)
	var svc policy.Service
	if err := json.Unmarshal([]byte(`{"auth":"apple-ads-sign","key":"APPLE_ADS_KEY","apple_ads":{"client_id":"SEARCHADS.client","team_id":"TEAM","key_id":"KEY"}}`), &svc); err != nil {
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
	if err := store.Set(e.backend.StorePath, "APPLE_ADS_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))); err != nil {
		t.Fatal(err)
	}
	cfg := e.proxy.Config()
	next, err := policy.LoadAccess(cfg.AccessFile)
	if err != nil {
		t.Fatal(err)
	}
	next.Services["apple-ads"] = svc
	if err := e.backend.saveAndApply(next); err != nil {
		t.Fatal(err)
	}
	if w := e.saveCell("phobos", "apple-ads", url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}}); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatal("could not grant signing access")
	}
	if code := e.call("POST", "/_keyring/sign/apple-ads", token); code != 200 {
		t.Fatalf("signing after access edit: %d", code)
	}
	if w := e.request("POST", "/keys/APPLE_ADS_KEY/test", url.Values{}); w.Header().Get("Location") != "/keys/APPLE_ADS_KEY?error=no-test" {
		t.Fatal("dashboard offered an upstream signing-key test")
	}
	if w := e.saveCell("phobos", "apple-ads", url.Values{"on": {"yes"}, "mode": {"read"}, "paths": {"/"}}); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatal("could not restrict signing access")
	}
	if code := e.call("POST", "/_keyring/sign/apple-ads", token); code != 403 {
		t.Fatal("dashboard read-only grant still signs")
	}
	if code := e.call("GET", "/api/v1/x", token); code != 200 {
		t.Fatal("signing service broke ordinary proxy access")
	}
}
