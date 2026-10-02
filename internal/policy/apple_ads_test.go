package policy

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestAppleAdsSignOnlyConfigurationAndPersistence(t *testing.T) {
	const valid = `{"services":{"apple-ads":{"auth":"apple-ads-sign","key":"APPLE_ADS_KEY","apple_ads":{"client_id":"SEARCHADS.client","team_id":"TEAM","key_id":"KEY"}}},"roles":{}}`
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
	encoded, err := json.Marshal(loaded)
	if err != nil {
		t.Fatal(err)
	}
	// Check persistence through the existing access editor's save/load boundary
	// using JSON so this test also compiles against pre-signing policy types.
	var got, want any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(valid), &want); err != nil {
		t.Fatal(err)
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatal("access save corrupted signing identity")
	}
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"base", "base", "https://example.com"}, {"header", "header", "Authorization"}, {"param", "param", "key"}, {"test path", "test_path", "/"}, {"test method", "test_method", "POST"},
		{"missing identity", "apple_ads", nil}, {"missing field", "apple_ads", map[string]string{"client_id": "client", "team_id": "team"}},
		{"identity whitespace", "apple_ads", map[string]string{"client_id": " client", "team_id": "team", "key_id": "kid"}},
		{"proxy identity", "auth", "bearer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := load()
			raw, _ := json.Marshal(c.Services["apple-ads"])
			var fields map[string]any
			json.Unmarshal(raw, &fields)
			fields[tc.field] = tc.value
			raw, _ = json.Marshal(fields)
			var svc Service
			if err := json.Unmarshal(raw, &svc); err != nil {
				t.Fatal(err)
			}
			c.Services["apple-ads"] = svc
			if err := c.Validate(); err == nil {
				t.Fatal("unsafe signing service accepted")
			}
		})
	}
	cfg = load()
	cfg.Services["other"] = cfg.Services["apple-ads"]
	delete(cfg.Services, "apple-ads")
	if err := cfg.Validate(); err == nil {
		t.Fatal("arbitrary signing service accepted")
	}
	cfg = load()
	cfg.Services["proxy"] = Service{Base: "https://example.com", Key: "APPLE_ADS_KEY", Auth: AuthBearer}
	if err := cfg.Validate(); err == nil {
		t.Fatal("signing key can be exposed through another proxy service")
	}
}
