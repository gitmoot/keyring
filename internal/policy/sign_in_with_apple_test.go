package policy

import "testing"

func TestValidateSignInWithApple(t *testing.T) {
	good := func() Service {
		return Service{Key: "TANDEM_SIWA_KEY", Auth: AuthSignInWithAppleSign, SignInWithApple: &SignInWithApple{ClientID: "com.jerryfane.tandem", TeamID: "FXQ5Z9HHY6", KeyID: "SIWAKEY123"}}
	}
	c := validConfig()
	c.Services["tandem-siwa"] = good()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid service refused: %v", err)
	}
	for name, mutate := range map[string]func(*Service){
		"no settings":         func(s *Service) { s.SignInWithApple = nil },
		"lower-case team":     func(s *Service) { s.SignInWithApple.TeamID = "fxq5z9hhy6" },
		"short key id":        func(s *Service) { s.SignInWithApple.KeyID = "KEY" },
		"client id spaces":    func(s *Service) { s.SignInWithApple.ClientID = "com.x tandem" },
		"empty client id":     func(s *Service) { s.SignInWithApple.ClientID = "" },
		"a base":              func(s *Service) { s.Base = "https://appleid.apple.com" },
		"apple ads too":       func(s *Service) { s.AppleAds = &AppleAds{ClientID: "c", TeamID: "t", KeyID: "k"} },
		"settings on bearer":  func(s *Service) { s.Auth = AuthBearer; s.Base = "https://api.example.com" },
		"settings on ed25519": func(s *Service) { s.Auth = AuthEd25519Sign },
	} {
		s := good()
		mutate(&s)
		c := validConfig()
		c.Services["tandem-siwa"] = s
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
