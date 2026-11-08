package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/policy"
)

const (
	apnsKeyID  = "ABC123DEFG"
	apnsTeamID = "TEAM456789"
)

func apnsKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// apnsRecorder stands in for api.push.apple.com: it remembers each request
// and echoes the Authorization it got, as a careless API might.
type apnsRecorder struct {
	mu    sync.Mutex
	calls []*http.Request
	body  []string
}

func (a *apnsRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(r.Body)
	a.mu.Lock()
	a.calls = append(a.calls, r.Clone(r.Context()))
	a.body = append(a.body, string(b))
	a.mu.Unlock()
	return &http.Response{StatusCode: 200, Header: http.Header{"Apns-Id": {"0D3F-1"}}, Request: r,
		Body: io.NopCloser(strings.NewReader("echo " + r.Header.Get("Authorization")))}, nil
}

func (a *apnsRecorder) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.calls)
}

func (a *apnsRecorder) auth(i int) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls[i].Header.Get("Authorization")
}

func apnsHandler(t *testing.T, value string, daily int) (*Handler, *apnsRecorder, *bytes.Buffer) {
	t.Helper()
	svc := policy.Service{Auth: policy.AuthAPNs, APNs: &policy.APNs{KeyID: apnsKeyID, TeamID: apnsTeamID}}
	h, audit := newHandlerKey(t, "https://api.push.apple.com", svc, policy.Access{Paths: []string{"/3/device"}, Methods: []string{"POST"}, DailyRequests: daily}, value)
	rec := &apnsRecorder{}
	h.client = &http.Client{Transport: rec}
	return h, rec, audit
}

func push(h *Handler) (int, string) {
	w := call(h, "POST", "/api/3/device/a1b2c3", testToken, map[string]string{
		"apns-topic": "app.tandem.ios", "apns-push-type": "alert", "apns-priority": "10", "Authorization": "bearer caller-supplied",
	})
	return w.Code, w.Body.String()
}

// The call carries "authorization: bearer <provider token>" minted from the
// .p8: ES256 with kid = key ID, claims iss = team ID and iat only. The .p8
// never goes upstream, apns-* headers pass through, the caller cannot supply
// its own Authorization, and the token is masked in the reply.
func TestAPNsSendsAProviderTokenNotTheKey(t *testing.T) {
	key, value := apnsKey(t)
	h, rec, _ := apnsHandler(t, value, 0)
	code, body := push(h)
	if code != 200 {
		t.Fatalf("push: %d %s", code, body)
	}
	out := rec.calls[0]
	if out.URL.String() != "https://api.push.apple.com/3/device/a1b2c3" || out.Method != "POST" || rec.body[0] != "payload" {
		t.Fatalf("request = %s %s body %q", out.Method, out.URL, rec.body[0])
	}
	for name, want := range map[string]string{"Apns-Topic": "app.tandem.ios", "Apns-Push-Type": "alert", "Apns-Priority": "10"} {
		if got := out.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	auth := out.Header.Get("Authorization")
	token, ok := strings.CutPrefix(auth, "bearer ")
	if !ok || strings.Contains(auth, "caller-supplied") || strings.Contains(auth, "PRIVATE KEY") {
		t.Fatalf("Authorization = %q", auth)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	var header map[string]any
	var claims map[string]any
	for i, v := range []any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, v) != nil {
			t.Fatalf("part %d does not decode", i)
		}
	}
	if len(header) != 2 || header["alg"] != "ES256" || header["kid"] != apnsKeyID {
		t.Fatalf("header = %v", header)
	}
	if iat, _ := claims["iat"].(float64); len(claims) != 2 || claims["iss"] != apnsTeamID || time.Since(time.Unix(int64(iat), 0)) > time.Minute {
		t.Fatalf("claims = %v", claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("the token is not signed by the .p8 key")
	}
	if strings.Contains(body, token) || !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("reply leaks the token: %q", body)
	}
}

// One token serves calls for 40 minutes and survives a reload with the same
// key (Apple refuses refreshes more often than every 20 minutes); after that,
// or with a new key, a fresh one is minted.
func TestAPNsTokenIsReusedThenRefreshed(t *testing.T) {
	_, value := apnsKey(t)
	h, rec, _ := apnsHandler(t, value, 0)
	now := time.Now()
	h.now = func() time.Time { return now }
	push(h)
	now = now.Add(39 * time.Minute)
	push(h)
	h.Swap(h.Config(), map[string]string{"API_KEY": value})
	push(h)
	if rec.auth(0) != rec.auth(1) || rec.auth(1) != rec.auth(2) {
		t.Fatal("the token was not reused within 40 minutes or across a reload with the same key")
	}
	now = now.Add(2 * time.Minute)
	push(h)
	if rec.auth(3) == rec.auth(2) {
		t.Fatal("the token was not refreshed after 40 minutes")
	}
	_, other := apnsKey(t)
	h.Swap(h.Config(), map[string]string{"API_KEY": other})
	push(h)
	if rec.auth(4) == rec.auth(3) {
		t.Fatal("a replaced key kept the old token")
	}
}

// A stored value that is not an ES256 .p8 key is reported as such, nothing is
// sent and the call is not charged; nothing about the value is written.
func TestAPNsUnusableKey(t *testing.T) {
	h, rec, audit := apnsHandler(t, "not-a-p8-key-0123456789", 1)
	for range 2 {
		code, body := push(h)
		if code != http.StatusServiceUnavailable || !strings.Contains(body, "stored key API_KEY is not a usable APNs .p8 key") {
			t.Fatalf("unusable key: %d %q", code, body)
		}
	}
	if rec.count() != 0 {
		t.Fatal("a call with an unusable key reached Apple")
	}
	_, value := apnsKey(t)
	h.Swap(h.Config(), map[string]string{"API_KEY": value})
	if code, _ := push(h); code != 200 {
		t.Fatalf("after a good key: %d (the refusals spent the daily limit?)", code)
	}
	if strings.Contains(audit.String(), "not-a-p8") {
		t.Fatal("key text in the audit log")
	}
}

// Review of #117: requests that started earlier but reach the signer later
// share the newest token instead of replacing it; many concurrent pushes mint
// one token. Freshness is judged by the clock at minting, not request start.
func TestAPNsConcurrentPushesShareOneToken(t *testing.T) {
	_, value := apnsKey(t)
	h, rec, _ := apnsHandler(t, value, 0)
	var mu sync.Mutex
	clock := time.Now()
	h.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(time.Second) // every reading is later than the last
		return clock
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); push(h) }()
	}
	wg.Wait()
	first := rec.auth(0)
	for i := 1; i < rec.count(); i++ {
		if rec.auth(i) != first {
			t.Fatalf("push %d used a different token: concurrent pushes replaced the cached one", i)
		}
	}
	// A signer asked with an earlier time than its token's keeps the token.
	signer := h.snap.Load().apns["api"]
	before := clock.Add(-30 * time.Second)
	if tok, err := signer.token(func() time.Time { return before }); err != nil || "bearer "+tok != first {
		t.Fatal("an earlier-started request replaced the newer token")
	}
}
