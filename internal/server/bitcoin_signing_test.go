package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"

	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
	"github.com/gitmoot/keyring/internal/policy"
)

const (
	bitcoinSignPath      = "/_keyring/bitcoin/btc-ord/sign-psbt"
	bitcoinAddressesPath = "/_keyring/bitcoin/btc-ord/addresses"
)

var bitcoinTestPaths = `["m/86'/1'/0'/0/*","m/86'/1'/0'/1/*","m/84'/1'/0'/0/*","m/84'/1'/0'/1/*"]`

// bitcoinConfig is a regtest bitcoin-psbt-sign service btc-ord with paths
// (a JSON list) and phobos's grant to it.
func bitcoinConfig(t *testing.T, paths string, grant policy.Access) *policy.Config {
	t.Helper()
	var access policy.AccessList
	if err := json.Unmarshal([]byte(`{"services":{"btc-ord":{"key":"BTC_ORD","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","paths":`+paths+`}}},"roles":{}}`), &access); err != nil {
		t.Fatal(err)
	}
	if grant.Paths == nil {
		grant.Methods, grant.Paths = []string{"GET", "POST"}, []string{"/"}
	}
	access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{"btc-ord": grant}}
	cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller, "127.0.0.1"}, AuditLog: "audit.log"}, AccessList: access}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

var (
	btcTap    = bitcointest.Coin{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/0/0", Value: 50_000}
	btcWpkh   = bitcointest.Coin{Key: bitcointest.Master, Kind: "p2wpkh", Path: "m/84'/1'/0'/0/1", Value: 30_000}
	btcChange = bitcointest.Coin{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/1/0"}
)

// psbt65k spends both coins: 60000 out, 15000 proven change, fee 5000, so
// 65000 external sats.
func psbt65k(t *testing.T) string {
	return bitcointest.Encode(t, bitcointest.Build(t, []bitcointest.Coin{btcTap, btcWpkh}, []bitcointest.Out{{Value: 60_000, Script: bitcointest.External}, {Value: 15_000, Coin: &btcChange}}))
}

// psbt30k spends the P2WPKH coin: 25000 out, fee 5000: 30000 external sats.
func psbt30k(t *testing.T) string {
	return bitcointest.Encode(t, bitcointest.Build(t, []bitcointest.Coin{btcWpkh}, []bitcointest.Out{{Value: 25_000, Script: bitcointest.External}}))
}

func signBody(psbtBase64 string, inputs ...int) string {
	body, _ := json.Marshal(map[string]any{"psbt": psbtBase64, "inputs": inputs})
	return string(body)
}

type bitcoinReply struct {
	PSBT         string `json:"psbt"`
	Txid         string `json:"txid"`
	Signed       []int  `json:"signed"`
	ExternalSats int64  `json:"external_sats"`
	FeeSats      int64  `json:"fee_sats"`
}

func TestBitcoinSignPSBTVerifiesAndIsAudited(t *testing.T) {
	var audit bytes.Buffer
	h := New(bitcoinConfig(t, bitcoinTestPaths, policy.Access{}), map[string]string{"BTC_ORD": bitcointest.Master}, &audit)
	unsigned := psbt65k(t)
	w := signCall(h, "POST", bitcoinSignPath, signBody(unsigned, 0, 1), testToken)
	if w.Code != 200 {
		t.Fatalf("sign status = %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("signing response can be cached")
	}
	var reply bitcoinReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	tx := bitcointest.Verify(t, reply.PSBT)
	if reply.Txid != tx.TxHash().String() || reply.ExternalSats != 65_000 || reply.FeeSats != 5_000 || len(reply.Signed) != 2 {
		t.Fatalf("reply = %+v", reply)
	}
	rec := lastAudit(t, &audit)
	if rec.Role != "phobos" || rec.Service != "btc-ord" || rec.Path != "/sign-psbt" || rec.Status != 200 || rec.Bitcoin == nil ||
		rec.Bitcoin.Network != "regtest" || rec.Bitcoin.Txid != reply.Txid || len(rec.Bitcoin.Inputs) != 2 ||
		rec.Bitcoin.ExternalSats != 65_000 || rec.Bitcoin.FeeSats != 5_000 {
		t.Fatalf("audit = %+v", rec)
	}
	if strings.Contains(audit.String(), unsigned) || strings.Contains(audit.String(), reply.PSBT) {
		t.Fatal("PSBT in the audit")
	}
	assertNoBitcoinKey(t, w.Body.String(), audit.String())
}

// assertNoBitcoinKey fails when the stored key, or its first or last
// characters, show up in any recorded output.
func assertNoBitcoinKey(t *testing.T, outputs ...string) {
	t.Helper()
	for _, out := range outputs {
		for _, secret := range []string{bitcointest.Master, bitcointest.Master[:20], bitcointest.Master[len(bitcointest.Master)-20:], bitcointest.WIF, bitcointest.WIF[:20], bitcointest.MasterMainnet[:20]} {
			if strings.Contains(out, secret) {
				t.Fatalf("key material in output: %q", out)
			}
		}
	}
}

func TestBitcoinRefusalsSignNothing(t *testing.T) {
	foreign := bitcointest.Coin{Key: bitcointest.Foreign, Kind: "p2tr", Path: "m/86'/1'/0'/0/0", Value: 50_000}
	opReturn := bitcointest.Build(t, []bitcointest.Coin{btcTap}, []bitcointest.Out{{Value: 0, Script: []byte{0x6a, 0x01, 0x00}}})
	cases := []struct{ name, body, want string }{
		{"foreign fingerprint", signBody(bitcointest.Encode(t, bitcointest.Build(t, []bitcointest.Coin{foreign}, []bitcointest.Out{{Value: 40_000, Script: bitcointest.External}})), 0), "input 0 has no derivation with this key's fingerprint 73c5da0a"},
		{"output that is no address", signBody(bitcointest.Encode(t, opReturn), 0), "output 0 is not an address on regtest"},
		{"input that does not exist", signBody(psbt65k(t), 5), "input 5 does not exist"},
		{"not JSON", `{"psbt":`, "body must be one JSON object"},
		{"unknown field", `{"psbt":"x","inputs":[0],"sighash":"all"}`, "body must be one JSON object"},
		{"no inputs", signBody(psbt65k(t)), "psbt and inputs are required"},
		{"null input index", `{"psbt":"` + psbt65k(t) + `","inputs":[null]}`, "inputs must be input indices, not null"},
	}
	var audit bytes.Buffer
	h := New(bitcoinConfig(t, bitcoinTestPaths, policy.Access{}), map[string]string{"BTC_ORD": bitcointest.Master}, &audit)
	for _, c := range cases {
		w := signCall(h, "POST", bitcoinSignPath, c.body, testToken)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), c.want) || strings.Contains(w.Header().Get("Content-Type"), "json") {
			t.Fatalf("%s: %d %s", c.name, w.Code, w.Body.String())
		}
		if rec := lastAudit(t, &audit); rec.Bitcoin != nil || rec.Status != http.StatusBadRequest || !strings.Contains(rec.Note, c.want) {
			t.Fatalf("%s: audit %+v", c.name, rec)
		}
		assertNoBitcoinKey(t, w.Body.String())
	}
	assertNoBitcoinKey(t, audit.String())
}

func TestBitcoinMaxSatsPerTx(t *testing.T) {
	h := New(bitcoinConfig(t, bitcoinTestPaths, policy.Access{BitcoinMaxSatsPerTx: 64_999}), map[string]string{"BTC_ORD": bitcointest.Master}, &bytes.Buffer{})
	w := signCall(h, "POST", bitcoinSignPath, signBody(psbt65k(t), 0, 1), testToken)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "bitcoin_max_sats_per_tx: 65000 external sats is over the limit of 64999") {
		t.Fatalf("over the per-PSBT limit: %d %s", w.Code, w.Body.String())
	}
	h = New(bitcoinConfig(t, bitcoinTestPaths, policy.Access{BitcoinMaxSatsPerTx: 65_000}), map[string]string{"BTC_ORD": bitcointest.Master}, &bytes.Buffer{})
	if w := signCall(h, "POST", bitcoinSignPath, signBody(psbt65k(t), 0, 1), testToken); w.Code != 200 {
		t.Fatalf("at the per-PSBT limit: %d %s", w.Code, w.Body.String())
	}
}

func TestBitcoinMaxSatsPerDaySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	spendFile := BitcoinSpendPath(filepath.Join(dir, "keys.json"))
	cfg := bitcoinConfig(t, bitcoinTestPaths, policy.Access{BitcoinMaxSatsPerDay: 100_000})
	day := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	start := func() *Handler {
		h := New(cfg, map[string]string{"BTC_ORD": bitcointest.Master}, &bytes.Buffer{})
		h.now = func() time.Time { return day }
		if err := h.OpenBitcoinSpend(spendFile); err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := start()
	if w := signCall(h, "POST", bitcoinSignPath, signBody(psbt65k(t), 0, 1), testToken); w.Code != 200 {
		t.Fatalf("first: %d %s", w.Code, w.Body.String())
	}
	if info, err := os.Stat(spendFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("spend file: %v", err)
	}
	over := signCall(h, "POST", bitcoinSignPath, signBody(psbt65k(t), 0, 1), testToken)
	if over.Code != http.StatusBadRequest || !strings.Contains(over.Body.String(), "bitcoin_max_sats_per_day: 65000 sats signed today plus 65000 external sats is over the limit of 100000") {
		t.Fatalf("second: %d %s", over.Code, over.Body.String())
	}
	// A restart keeps the day's total: the same PSBT is still refused, and
	// the refusal above did not count.
	h = start()
	if w := signCall(h, "POST", bitcoinSignPath, signBody(psbt65k(t), 0, 1), testToken); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "65000 sats signed today") {
		t.Fatalf("after restart: %d %s", w.Code, w.Body.String())
	}
	if w := signCall(h, "POST", bitcoinSignPath, signBody(psbt30k(t), 0), testToken); w.Code != 200 {
		t.Fatalf("within the rest of the day: %d %s", w.Code, w.Body.String())
	}
	// The next UTC day starts from zero.
	day = time.Date(2026, 11, 26, 0, 0, 30, 0, time.UTC)
	if w := signCall(h, "POST", bitcoinSignPath, signBody(psbt65k(t), 0, 1), testToken); w.Code != 200 {
		t.Fatalf("next day: %d %s", w.Code, w.Body.String())
	}
	// Review of #188: a request still on the previous day's clock (before
	// midnight) counts toward the new day instead of moving the ledger back
	// and erasing it.
	day = time.Date(2026, 11, 25, 23, 59, 59, 0, time.UTC)
	if w := signCall(h, "POST", bitcoinSignPath, signBody(psbt65k(t), 0, 1), testToken); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "65000 sats signed today") {
		t.Fatalf("late request: %d %s", w.Code, w.Body.String())
	}
	if raw, _ := os.ReadFile(spendFile); !strings.Contains(string(raw), `"day":"2026-11-26"`) || !strings.Contains(string(raw), `"sats":65000`) {
		t.Fatalf("spend file: %s", raw)
	}
}

// Review of #188: two keyrings in one directory keep separate totals, also
// when their names differ only in the extension.
func TestBitcoinSpendPathFollowsTheStore(t *testing.T) {
	if a, b := BitcoinSpendPath("/k/keys.json"), BitcoinSpendPath("/k/other.json"); a != "/k/keys.json.bitcoin-spend.json" || b != "/k/other.json.bitcoin-spend.json" {
		t.Fatalf("%s %s", a, b)
	}
	if a, b := BitcoinSpendPath("/k/wallet.json"), BitcoinSpendPath("/k/wallet.sealed"); a == b {
		t.Fatalf("wallet.json and wallet.sealed share %s", a)
	}
	if got := BitcoinSpendPath("/k/state"); got != "/k/state.bitcoin-spend.json" {
		t.Fatal(got)
	}
}

// Without the file a daily limit cannot hold across restarts, so the grant
// signs nothing rather than start again from zero.
func TestBitcoinMaxSatsPerDayNeedsTheFile(t *testing.T) {
	h := New(bitcoinConfig(t, bitcoinTestPaths, policy.Access{BitcoinMaxSatsPerDay: 100_000}), map[string]string{"BTC_ORD": bitcointest.Master}, &bytes.Buffer{})
	w := signCall(h, "POST", bitcoinSignPath, signBody(psbt30k(t), 0), testToken)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "daily bitcoin total on disk, which is unavailable") {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	dir := t.TempDir()
	spendFile := BitcoinSpendPath(filepath.Join(dir, "keys.json"))
	if err := os.WriteFile(spendFile, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.OpenBitcoinSpend(spendFile); err == nil {
		t.Fatal("a corrupt spend file was accepted")
	}
	if w := signCall(h, "POST", bitcoinSignPath, signBody(psbt30k(t), 0), testToken); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("corrupt file: status %d", w.Code)
	}
	if raw, _ := os.ReadFile(spendFile); string(raw) != "{not json" {
		t.Fatal("the corrupt file was replaced")
	}
}

func TestBitcoinAddressesMatchBIPVectors(t *testing.T) {
	// Coin type 0' on regtest, so the BIP86 and BIP84 vectors apply: the
	// witness programs match, only the address prefix differs.
	var audit bytes.Buffer
	h := New(bitcoinConfig(t, `["m/86'/0'/0'/0/*","m/84'/0'/0'/0/*"]`, policy.Access{}), map[string]string{"BTC_ORD": bitcointest.Master}, &audit)
	for path, vectors := range map[string][]string{
		"m/86'/0'/0'/0": {"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"},
		"m/84h/0h/0h/0": {"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"},
	} {
		w := signCall(h, "GET", bitcoinAddressesPath+"?path="+path+"&from=0&count=2", "", testToken)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var list struct {
			Fingerprint string `json:"fingerprint"`
			Network     string `json:"network"`
			Addresses   []struct {
				Index   uint32 `json:"index"`
				Path    string `json:"path"`
				Address string `json:"address"`
			} `json:"addresses"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if list.Fingerprint != bitcointest.MasterFingerprint || list.Network != "regtest" || len(list.Addresses) != 2 {
			t.Fatalf("%s: %s", path, w.Body.String())
		}
		for i, vector := range vectors {
			got, err := address.DecodeAddress(list.Addresses[i].Address, &chaincfg.RegressionNetParams)
			if err != nil || !got.IsForNet(&chaincfg.RegressionNetParams) {
				t.Fatalf("%s/%d: %q is not a regtest address", path, i, list.Addresses[i].Address)
			}
			want, err := address.DecodeAddress(vector, &chaincfg.MainNetParams)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.ScriptAddress(), want.ScriptAddress()) || list.Addresses[i].Index != uint32(i) {
				t.Fatalf("%s/%d = %s, want the program of %s", path, i, list.Addresses[i].Address, vector)
			}
		}
	}
	refused := []struct {
		method, target string
		status         int
	}{
		{"GET", bitcoinAddressesPath + "?path=m/86'/0'/1'/0", 400},
		{"GET", bitcoinAddressesPath + "?path=m/86'/0'/0'/0/*", 400},
		{"GET", bitcoinAddressesPath + "?path=m/86'/0'/0'/0&count=1001", 400},
		{"GET", bitcoinAddressesPath + "?path=m/86'/0'/0'/0&from=2147483647&count=2", 400},
		{"GET", bitcoinAddressesPath + "?path=m/86'/0'/0'/0&xpub=1", 400},
		{"GET", bitcoinAddressesPath, 400},
		{"POST", bitcoinAddressesPath + "?path=m/86'/0'/0'/0", 405},
		{"GET", bitcoinSignPath, 405},
		{"POST", bitcoinSignPath + "?x=1", 400},
	}
	for _, c := range refused {
		if w := signCall(h, c.method, c.target, "", testToken); w.Code != c.status {
			t.Fatalf("%s %s: %d %s", c.method, c.target, w.Code, w.Body.String())
		}
	}
	assertNoBitcoinKey(t, audit.String())
}

// A grant's paths choose the action: /addresses only may not sign.
func TestBitcoinGrantPathLimitsActions(t *testing.T) {
	h := New(bitcoinConfig(t, bitcoinTestPaths, policy.Access{Methods: []string{"GET"}, Paths: []string{"/addresses"}}), map[string]string{"BTC_ORD": bitcointest.Master}, &bytes.Buffer{})
	if w := signCall(h, "POST", bitcoinSignPath, signBody(psbt30k(t), 0), testToken); w.Code != http.StatusForbidden {
		t.Fatalf("sign with an addresses-only grant: %d %s", w.Code, w.Body.String())
	}
	if w := signCall(h, "GET", bitcoinAddressesPath+"?path=m/84'/1'/0'/0", "", testToken); w.Code != 200 {
		t.Fatalf("addresses: %d %s", w.Code, w.Body.String())
	}
	// The service is sign-only: nothing is proxied under its name.
	if w := signCall(h, "GET", "/btc-ord/addresses", "", testToken); w.Code != http.StatusForbidden {
		t.Fatalf("proxy path: %d", w.Code)
	}
}

// A key for another network, or of the wrong kind, is never used and
// never named.
func TestBitcoinKeyThatDoesNotFit(t *testing.T) {
	cfg := bitcoinConfig(t, bitcoinTestPaths, policy.Access{})
	for _, value := range []string{bitcointest.MasterMainnet, bitcointest.WIF, "not a key"} {
		var audit bytes.Buffer
		h := New(cfg, map[string]string{"BTC_ORD": value}, &audit)
		w := signCall(h, "POST", bitcoinSignPath, signBody(psbt30k(t), 0), testToken)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "bitcoin key unavailable") {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), value) || strings.Contains(audit.String(), value) {
			t.Fatal("key in the answer or the audit")
		}
		assertNoBitcoinKey(t, w.Body.String(), audit.String())
	}
}
