package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// addBitcoin stores the test master key as BTC_ORD, adds the regtest
// service btc-ord and grants it to phobos with a per-PSBT limit.
func addBitcoin(e *env) {
	e.t.Helper()
	if err := store.Set(e.backend.StorePath, "BTC_ORD", bitcointest.Master); err != nil {
		e.t.Fatal(err)
	}
	cfg := e.proxy.Config()
	access := cfg.AccessList
	access.Services["btc-ord"] = policy.Service{Key: "BTC_ORD", Auth: policy.AuthBitcoinPSBTSign,
		Bitcoin: &policy.Bitcoin{Network: "regtest", Paths: []string{"m/86'/1'/0'/0/*", "m/86'/1'/0'/1/*", "m/84'/1'/0'/0/*"}}}
	access.Roles["phobos"].Access["btc-ord"] = policy.Access{Paths: []string{"/"}, BitcoinMaxSatsPerTx: 70_000}
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		e.t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(next, keys)
}

func assertNoBitcoinKey(t *testing.T, outputs ...string) {
	t.Helper()
	for _, out := range outputs {
		for _, secret := range []string{bitcointest.Master[:20], bitcointest.Master[len(bitcointest.Master)-20:], bitcointest.WIF[:20]} {
			if strings.Contains(out, secret) {
				t.Fatal("bitcoin key material in output")
			}
		}
	}
}

// A bitcoin key is never shown: not when a service uses it, and not when it
// was only pasted with Add key; its page shows the fingerprint instead.
func TestBitcoinKeyIsNeverShown(t *testing.T) {
	e := newEnv(t)
	addBitcoin(e)
	if w := e.request("POST", "/keys", url.Values{"name": {"LOOSE_WIF"}, "value": {bitcointest.WIF}, "password": {password}}); w.Code != http.StatusSeeOther {
		t.Fatalf("paste a WIF key with Add key: %d", w.Code)
	}
	var outputs []string
	for _, name := range []string{"BTC_ORD", "LOOSE_WIF"} {
		page := e.request("GET", "/keys/"+name, nil).Body.String()
		if strings.Contains(page, `action="/keys/`+name+`/reveal"`) || !strings.Contains(page, "Bitcoin key") || !strings.Contains(page, "fingerprint <code>") {
			t.Fatalf("%s: the key page offers Show or lacks the fingerprint", name)
		}
		w := e.request("POST", "/keys/"+name+"/reveal", url.Values{"password": {password}})
		if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "error=never-shown") {
			t.Fatalf("%s: reveal answered %d", name, w.Code)
		}
		outputs = append(outputs, page, w.Body.String())
	}
	if strings.Contains(e.audit.String(), "key_revealed") {
		t.Fatal("a bitcoin key was audited as shown")
	}
	if page := e.request("GET", "/keys/BTC_ORD", nil).Body.String(); !strings.Contains(page, "73c5da0a") {
		t.Fatal("the master fingerprint is not on the key page")
	}
	assertNoBitcoinKey(t, append(outputs, e.audit.String())...)
}

// The service page shows the watch-only side of the key and the signatures
// from the audit log, never the key or a PSBT.
func TestBitcoinServicePageListsSignatures(t *testing.T) {
	e := newEnv(t)
	addBitcoin(e)
	change := bitcointest.Coin{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/1/0"}
	unsigned := bitcointest.Encode(t, bitcointest.Build(t,
		[]bitcointest.Coin{{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/0/0", Value: 50_000}, {Key: bitcointest.Master, Kind: "p2wpkh", Path: "m/84'/1'/0'/0/1", Value: 30_000}},
		[]bitcointest.Out{{Value: 60_000, Script: bitcointest.External}, {Value: 15_000, Coin: &change}}))
	body, _ := json.Marshal(map[string]any{"psbt": unsigned, "inputs": []int{0, 1}})
	r := httptest.NewRequest("POST", "/_keyring/bitcoin/btc-ord/sign-psbt", strings.NewReader(string(body)))
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set(server.TokenHeader, token)
	w := httptest.NewRecorder()
	e.proxy.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	var reply struct {
		PSBT string `json:"psbt"`
		Txid string `json:"txid"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	// The proxy's audit goes to a buffer here; the page reads the log file.
	if err := os.WriteFile(e.proxy.Config().AuditLog, e.audit.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	page := e.request("GET", "/services/btc-ord", nil).Body.String()
	for _, want := range []string{reply.Txid, "<td class=\"num\">65000</td>", "<td class=\"num\">5000</td>", "phobos", "regtest", "0, 1", "tr([73c5da0a/86h/1h/0h/0]tpub", "wpkh([73c5da0a/84h/1h/0h/0]tpub", "bcrt1p", "Signatures"} {
		if !strings.Contains(page, want) {
			t.Fatalf("service page lacks %q", want)
		}
	}
	if strings.Contains(page, unsigned) || strings.Contains(page, reply.PSBT) || strings.Contains(page, "tprv") {
		t.Fatal("the service page carries a PSBT or a private key")
	}
	assertNoBitcoinKey(t, page, e.audit.String())
}

// Saving a bitcoin grant on the dashboard keeps and edits its sats limits.
func TestBitcoinGrantFormKeepsSatsLimits(t *testing.T) {
	e := newEnv(t)
	addBitcoin(e)
	page := e.request("GET", "/access/phobos/btc-ord", nil).Body.String()
	if !strings.Contains(page, `name="max_sats_tx" inputmode="numeric" value="70000"`) {
		t.Fatal("the grant form does not show the per-PSBT limit")
	}
	w := e.request("POST", "/access/phobos/btc-ord", url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}, "max_sats_tx": {"70000"}, "max_sats_day": {"200000"}, "password": {password}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	got := e.proxy.Config().Roles["phobos"].Access["btc-ord"]
	if got.BitcoinMaxSatsPerTx != 70_000 || got.BitcoinMaxSatsPerDay != 200_000 {
		t.Fatalf("grant = %+v", got)
	}
	if page := e.request("GET", "/access/phobos/api", nil).Body.String(); strings.Contains(page, "max_sats_tx") {
		t.Fatal("sats limits offered for a service that is not bitcoin")
	}
}
