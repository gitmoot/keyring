package policy

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestAppStoreConnectConfigurationAndPersistence(t *testing.T) {
	const valid = `{"services":{"appstoreconnect":{"auth":"app-store-connect-sign","key":"ASC_KEY","app_store_connect":{"issuer_id":"issuer-id","key_id":"key-id"}}},"roles":{}}`
	load := func() *Config {
		var access AccessList
		if err := json.Unmarshal([]byte(valid), &access); err != nil {
			t.Fatal(err)
		}
		return &Config{Rules: Rules{Listen: "127.0.0.1:7701", AllowSources: []string{"127.0.0.1"}, AuditLog: "audit.log", AccessFile: filepath.Join(t.TempDir(), "access.json")}, AccessList: access}
	}
	cfg := load()
	if _, err := SaveAccess(cfg.Rules, cfg.AccessList); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAccess(cfg.AccessFile)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(loaded.Services["appstoreconnect"])
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	identity, ok := fields["app_store_connect"].(map[string]any)
	if !ok || identity["issuer_id"] != "issuer-id" || identity["key_id"] != "key-id" {
		t.Fatal("stored App Store identity changed")
	}
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"base", "base", "https://example.com"},
		{"header", "header", "Authorization"},
		{"query param", "param", "key"},
		{"test path", "test_path", "/"},
		{"test method", "test_method", "POST"},
		{"missing identity", "app_store_connect", nil},
		{"missing issuer", "app_store_connect", map[string]string{"key_id": "key-id"}},
		{"missing key id", "app_store_connect", map[string]string{"issuer_id": "issuer-id"}},
		{"identity whitespace", "app_store_connect", map[string]string{"issuer_id": " issuer", "key_id": "key"}},
		{"mixed identities", "apple_ads", map[string]string{"client_id": "client", "team_id": "team", "key_id": "key"}},
		{"proxy identity", "auth", "bearer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := load()
			raw, _ := json.Marshal(c.Services["appstoreconnect"])
			var edited map[string]any
			if err := json.Unmarshal(raw, &edited); err != nil {
				t.Fatal(err)
			}
			edited[tc.field] = tc.value
			raw, _ = json.Marshal(edited)
			var svc Service
			if err := json.Unmarshal(raw, &svc); err != nil {
				t.Fatal(err)
			}
			c.Services["appstoreconnect"] = svc
			if err := c.Validate(); err == nil {
				t.Fatal("unsafe App Store service accepted")
			}
		})
	}
	cfg = load()
	cfg.Services["other"] = cfg.Services["appstoreconnect"]
	delete(cfg.Services, "appstoreconnect")
	if err := cfg.Validate(); err == nil {
		t.Fatal("arbitrary signing service name accepted")
	}
	cfg = load()
	cfg.Services["proxy"] = Service{Base: "https://example.com", Key: "ASC_KEY", Auth: AuthBearer}
	if err := cfg.Validate(); err == nil {
		t.Fatal("App Store key may be forwarded by a proxy")
	}
	cfg = load()
	var ads Service
	if err := json.Unmarshal([]byte(`{"auth":"apple-ads-sign","key":"ASC_KEY","apple_ads":{"client_id":"client","team_id":"team","key_id":"key"}}`), &ads); err != nil {
		t.Fatal(err)
	}
	cfg.Services["apple-ads"] = ads
	if err := cfg.Validate(); err == nil {
		t.Fatal("App Store key may be used through an Apple Ads grant")
	}
}
