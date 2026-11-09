package dashboard

import (
	"net/url"
	"testing"

	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/store"
)

// The owner creates the Sign in with Apple signer from the key's page with one
// pasted line; connecting gives no agent access.
func TestConnectSignInWithAppleKey(t *testing.T) {
	e := newEnv(t)
	if err := store.Set(e.backend.StorePath, "TANDEM_SIWA_KEY", "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----"); err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(e.proxy.Config(), keys)
	pasted := `{"service":"tandem-siwa","auth":"sign-in-with-apple-sign","sign_in_with_apple":{"client_id":"com.jerryfane.tandem","team_id":"FXQ5Z9HHY6","key_id":"SIWAKEY123"}}`
	w := e.request("POST", "/keys/TANDEM_SIWA_KEY/connect", url.Values{"pasted": {pasted}, "password": {password}})
	if w.Header().Get("Location") != "/keys/TANDEM_SIWA_KEY?done=connected" {
		t.Fatalf("connect: %d %s", w.Code, w.Body.String())
	}
	svc := e.proxy.Config().Services["tandem-siwa"]
	if svc.Auth != policy.AuthSignInWithAppleSign || svc.SignInWithApple == nil || svc.SignInWithApple.ClientID != "com.jerryfane.tandem" {
		t.Fatalf("service = %+v", svc)
	}
	for role, rl := range e.proxy.Config().Roles {
		if _, ok := rl.Access["tandem-siwa"]; ok {
			t.Fatalf("connecting gave %s access", role)
		}
	}
}
