package policy

import (
	"strings"
	"testing"
)

func TestValidateAuthScheme(t *testing.T) {
	ok := validConfig()
	svc := ok.Services["openrouter"]
	svc.Auth, svc.Scheme = AuthBearer, "Key"
	ok.Services["openrouter"] = svc
	if err := ok.Validate(); err != nil {
		t.Fatalf("scheme Key refused: %v", err)
	}
	for name, set := range map[string]func(*Service){
		"two words":    func(s *Service) { s.Scheme = "Key x" },
		"control char": func(s *Service) { s.Scheme = "Key\x01" },
		"line break":   func(s *Service) { s.Scheme = "Key\r\nX-Evil: 1" },
		"non-token":    func(s *Service) { s.Scheme = "Key:" },
		"too long":     func(s *Service) { s.Scheme = strings.Repeat("k", 33) },
		"header auth":  func(s *Service) { s.Auth, s.Header, s.Scheme = AuthHeader, "X-Api-Key", "Key" },
		"query auth":   func(s *Service) { s.Auth, s.Param, s.Scheme = AuthQuery, "key", "Key" },
		"non-ascii":    func(s *Service) { s.Scheme = "Kéy" },
		"trailing tab": func(s *Service) { s.Scheme = "Key\t" },
		"sign-only":    func(s *Service) { s.Auth, s.Scheme = AuthEd25519Sign, "Key" },
		"egress-proxy": func(s *Service) { s.Auth, s.Scheme = AuthEgressProxy, "Key" },
	} {
		c := validConfig()
		s := c.Services["openrouter"]
		s.Auth = AuthBearer
		set(&s)
		c.Services["openrouter"] = s
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "scheme") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
