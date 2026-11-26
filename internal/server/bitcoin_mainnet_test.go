package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
	"github.com/gitmoot/keyring/internal/policy"
)

const mainnetSignPath = "/_keyring/bitcoin/btc-main/sign-psbt"

// mainnetConfig is a mainnet bitcoin-psbt-sign service btc-main, a regtest
// one btc-ord, phobos's grants to both and notify_command.
func mainnetConfig(t *testing.T, grant policy.Access, notify []string) *policy.Config {
	t.Helper()
	var access policy.AccessList
	if err := json.Unmarshal([]byte(`{"services":{
		"btc-main":{"key":"BTC_MAIN","auth":"bitcoin-psbt-sign","bitcoin":{"network":"mainnet","paths":["m/86'/0'/0'/0/*","m/86'/0'/0'/1/*","m/84'/0'/0'/0/*","m/84'/0'/0'/1/*"]}},
		"btc-ord":{"key":"BTC_ORD","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","paths":`+bitcoinTestPaths+`}}},"roles":{}}`), &access); err != nil {
		t.Fatal(err)
	}
	grant.Methods, grant.Paths = []string{"GET", "POST"}, []string{"/"}
	access.Roles["phobos"] = policy.Role{TokenSHA256: tokenHash(testToken), Access: map[string]policy.Access{
		"btc-main": grant,
		"btc-ord":  {Methods: []string{"POST"}, Paths: []string{"/"}},
	}}
	cfg := &policy.Config{Rules: policy.Rules{Listen: "127.0.0.1:7701", AllowSources: []string{caller, "127.0.0.1"}, AuditLog: "audit.log", NotifyCommand: notify}, AccessList: access}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

var mainnetLimits = policy.Access{BitcoinMaxSatsPerTx: 200_000, BitcoinMaxSatsPerDay: 1_000_000}

// mainnetKeys holds different keys for the two services.
var mainnetKeys = map[string]string{"BTC_MAIN": bitcointest.MasterMainnet, "BTC_ORD": bitcointest.Foreign}

// startMainnet is a keyring with the daily total on disk in dir.
func startMainnet(t *testing.T, cfg *policy.Config, keys map[string]string, audit *lockedBuffer, dir string) *Handler {
	t.Helper()
	h := New(cfg, keys, audit)
	if err := h.OpenBitcoinSpend(BitcoinSpendPath(filepath.Join(dir, "keys.json"))); err != nil {
		t.Fatal(err)
	}
	return h
}

func mainTapCoin(i int, value int64) bitcointest.Coin {
	return bitcointest.Coin{Key: bitcointest.MasterMainnet, Kind: "p2tr", Path: fmt.Sprintf("m/86'/0'/0'/0/%d", i), Value: value}
}

var (
	mainWpkhCoin = bitcointest.Coin{Key: bitcointest.MasterMainnet, Kind: "p2wpkh", Path: "m/84'/0'/0'/0/0", Value: 30_000}
	mainChange   = bitcointest.Coin{Key: bitcointest.MasterMainnet, Kind: "p2tr", Path: "m/86'/0'/0'/1/0"}
)

// mainnet65k spends a taproot and a P2WPKH coin: 60000 out, 15000 proven
// change, fee 5000, so 65000 external sats.
func mainnet65k(t *testing.T) string {
	return bitcointest.Encode(t, bitcointest.Build(t, []bitcointest.Coin{mainTapCoin(0, 50_000), mainWpkhCoin}, []bitcointest.Out{{Value: 60_000, Script: bitcointest.External}, {Value: 15_000, Coin: &mainChange}}))
}

// notifyScript is a notify_command that writes its two arguments, the fixed
// one and the message keyring adds, as one line of the file it returns.
func notifyScript(t *testing.T) ([]string, string) {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "notified")
	script := filepath.Join(dir, "notify")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s|%s|%s\\n' \"$#\" \"$1\" \"$2\" >> '"+out+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return []string{script, "fixed"}, out
}

// notified waits for want lines in the hook's file and gives them, or the
// lines there after a short wait when want is 0.
func notified(t *testing.T, out string, want int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	if want == 0 {
		deadline = time.Now().Add(300 * time.Millisecond)
	}
	for {
		raw, _ := os.ReadFile(out)
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		if len(raw) == 0 {
			lines = nil
		}
		if (want > 0 && len(lines) >= want) || time.Now().After(deadline) {
			return lines
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Owner, 2026-11-26: every mainnet signature tells the owner, through
// notify_command, its txid, external sats, fee, fee rate, role and service;
// a refusal tells nothing.
func TestBitcoinMainnetSignsAndNotifiesOnce(t *testing.T) {
	notify, out := notifyScript(t)
	audit := &lockedBuffer{}
	h := startMainnet(t, mainnetConfig(t, mainnetLimits, notify), mainnetKeys, audit, t.TempDir())
	w := signCall(h, "POST", mainnetSignPath, signBody(mainnet65k(t), 0, 1), testToken)
	if w.Code != 200 {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	var reply bitcoinReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	tx := bitcointest.Verify(t, reply.PSBT)
	if reply.Txid != tx.TxHash().String() || reply.ExternalSats != 65_000 || reply.FeeSats != 5_000 || reply.VBytes < 1 {
		t.Fatalf("reply = %+v", reply)
	}
	rate := fmt.Sprintf("%.1f", 5_000/float64(reply.VBytes))
	want := fmt.Sprintf("2|fixed|keyring: mainnet signature by phobos on btc-main: txid %s, 65000 sats external, fee 5000 sats, %s sat/vB", reply.Txid, rate)
	if lines := notified(t, out, 1); len(lines) != 1 || lines[0] != want {
		t.Fatalf("notified %q, want %q", lines, want)
	}
	// Refused (over the fee cap): no signature, no notification.
	over := bitcointest.Encode(t, bitcointest.Build(t, []bitcointest.Coin{mainTapCoin(0, 150_000)}, []bitcointest.Out{{Value: 90_000, Script: bitcointest.External}}))
	if w := signCall(h, "POST", mainnetSignPath, signBody(over, 0), testToken); w.Code != http.StatusBadRequest {
		t.Fatalf("over the fee cap: %d %s", w.Code, w.Body.String())
	}
	if lines := notified(t, out, 0); len(lines) != 1 {
		t.Fatalf("notified %d times", len(lines))
	}
	if !strings.Contains(audit.String(), `"vbytes":`) {
		t.Fatal("the audit has no size")
	}
	assertNoBitcoinKey(t, w.Body.String(), audit.String())
}

// A notify_command that fails or hangs neither fails nor delays the
// signature; a failure is in the audit log.
func TestBitcoinMainnetNotifyNeverBlocks(t *testing.T) {
	dir := t.TempDir()
	failing := filepath.Join(dir, "failing")
	slow := filepath.Join(dir, "slow")
	if err := os.WriteFile(failing, []byte("#!/bin/sh\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(slow, []byte("#!/bin/sh\nexec sleep 12\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{failing, slow} {
		audit := &lockedBuffer{}
		h := startMainnet(t, mainnetConfig(t, mainnetLimits, []string{command}), mainnetKeys, audit, t.TempDir())
		start := time.Now()
		w := signCall(h, "POST", mainnetSignPath, signBody(mainnet65k(t), 0, 1), testToken)
		if w.Code != 200 || time.Since(start) > 3*time.Second {
			t.Fatalf("%s: %d after %s: %s", filepath.Base(command), w.Code, time.Since(start), w.Body.String())
		}
		if command == failing {
			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(audit.String(), `"note":"notify_command failed: exit status 3"`) {
				if time.Now().After(deadline) {
					t.Fatalf("no failure in the audit: %s", audit.String())
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !strings.Contains(audit.String(), `"method":"NOTIFY"`) {
				t.Fatalf("audit: %s", audit.String())
			}
		}
	}
}

// Test networks notify nothing, even with notify_command set.
func TestBitcoinTestNetworkDoesNotNotify(t *testing.T) {
	notify, out := notifyScript(t)
	h := startMainnet(t, mainnetConfig(t, mainnetLimits, notify), mainnetKeys, &lockedBuffer{}, t.TempDir())
	foreign := bitcointest.Coin{Key: bitcointest.Foreign, Kind: "p2tr", Path: "m/86'/1'/0'/0/0", Value: 50_000}
	p := bitcointest.Encode(t, bitcointest.Build(t, []bitcointest.Coin{foreign}, []bitcointest.Out{{Value: 45_000, Script: bitcointest.External}}))
	w := signCall(h, "POST", bitcoinSignPath, signBody(p, 0), testToken)
	if w.Code != 200 {
		t.Fatalf("regtest: %d %s", w.Code, w.Body.String())
	}
	if lines := notified(t, out, 0); len(lines) != 0 {
		t.Fatalf("regtest notified: %q", lines)
	}
}

// Owner, 2026-11-26: on mainnet a fee over 50000 sats, or over 200 sat/vB
// of the finished transaction's size, is refused before signing.
func TestBitcoinMainnetFeeCap(t *testing.T) {
	audit := &lockedBuffer{}
	h := startMainnet(t, mainnetConfig(t, mainnetLimits, nil), mainnetKeys, audit, t.TempDir())
	// Four taproot inputs: about 280 vbytes, so 50000 sats is under the
	// rate cap and only the fee cap applies.
	four := func(fee int64) string {
		var coins []bitcointest.Coin
		for i := range 4 {
			coins = append(coins, mainTapCoin(i, 50_000))
		}
		return bitcointest.Encode(t, bitcointest.Build(t, coins, []bitcointest.Out{{Value: 200_000 - fee, Script: bitcointest.External}}))
	}
	if w := signCall(h, "POST", mainnetSignPath, signBody(four(50_000), 0, 1, 2, 3), testToken); w.Code != 200 {
		t.Fatalf("fee 50000: %d %s", w.Code, w.Body.String())
	}
	if w := signCall(h, "POST", mainnetSignPath, signBody(four(50_001), 0, 1, 2, 3), testToken); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), policy.BitcoinFeeOverCap) {
		t.Fatalf("fee 50001: %d %s", w.Code, w.Body.String())
	}
	// One taproot input and one output: the size is exact, so 200 sat/vB of
	// it passes and one sat more is refused.
	one := func(fee int64) string {
		return bitcointest.Encode(t, bitcointest.Build(t, []bitcointest.Coin{mainTapCoin(0, 40_000)}, []bitcointest.Out{{Value: 40_000 - fee, Script: bitcointest.External}}))
	}
	w := signCall(h, "POST", mainnetSignPath, signBody(one(1_000), 0), testToken)
	var reply bitcoinReply
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil || w.Code != 200 {
		t.Fatalf("one input: %d %s", w.Code, w.Body.String())
	}
	tx := bitcointest.Verify(t, reply.PSBT)
	size := int64((tx.SerializeSizeStripped()*3 + tx.SerializeSize() + 3) / 4)
	if reply.VBytes != size {
		t.Fatalf("estimated %d vbytes, real %d", reply.VBytes, size)
	}
	if w := signCall(h, "POST", mainnetSignPath, signBody(one(200*size), 0), testToken); w.Code != 200 {
		t.Fatalf("200 sat/vB: %d %s", w.Code, w.Body.String())
	}
	w = signCall(h, "POST", mainnetSignPath, signBody(one(200*size+1), 0), testToken)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), policy.BitcoinFeeRateOverCap) {
		t.Fatalf("over 200 sat/vB: %d %s", w.Code, w.Body.String())
	}
	if rec := lastAuditOf(t, audit); rec.Status != http.StatusBadRequest || rec.Bitcoin != nil {
		t.Fatalf("refusal audit = %+v", rec)
	}
}

func lastAuditOf(t *testing.T, audit *lockedBuffer) auditRecord {
	t.Helper()
	var b bytes.Buffer
	b.WriteString(audit.String())
	return lastAudit(t, &b)
}

// Owner, 2026-11-26: mainnet and the test networks use different keys. The
// same seed as a tprv on a regtest service and an xprv on a mainnet one
// signs on neither.
func TestBitcoinKeyOnTwoNetworksSignsNothing(t *testing.T) {
	keys := map[string]string{"BTC_MAIN": bitcointest.MasterMainnet, "BTC_ORD": bitcointest.Master}
	h := startMainnet(t, mainnetConfig(t, mainnetLimits, nil), keys, &lockedBuffer{}, t.TempDir())
	for path, body := range map[string]string{mainnetSignPath: signBody(mainnet65k(t), 0, 1), bitcoinSignPath: signBody(psbt30k(t), 0)} {
		w := signCall(h, "POST", path, body, testToken)
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "signs with the same key on another network; mainnet and the test networks need different keys") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	// Different keys sign on both.
	h = startMainnet(t, mainnetConfig(t, mainnetLimits, nil), map[string]string{"BTC_MAIN": bitcointest.MasterMainnet, "BTC_ORD": bitcointest.Foreign}, &lockedBuffer{}, t.TempDir())
	if w := signCall(h, "POST", mainnetSignPath, signBody(mainnet65k(t), 0, 1), testToken); w.Code != 200 {
		t.Fatalf("mainnet with its own key: %d %s", w.Code, w.Body.String())
	}
}

// A mainnet grant whose limits validation would refuse (a config written
// before this check, or changed in memory) signs nothing.
func TestBitcoinMainnetGrantWithoutLimitsSignsNothing(t *testing.T) {
	cfg := mainnetConfig(t, mainnetLimits, nil)
	grant := cfg.Roles["phobos"].Access["btc-main"]
	grant.BitcoinMaxSatsPerDay = 0
	cfg.Roles["phobos"].Access["btc-main"] = grant
	h := startMainnet(t, cfg, mainnetKeys, &lockedBuffer{}, t.TempDir())
	if w := signCall(h, "POST", mainnetSignPath, signBody(mainnet65k(t), 0, 1), testToken); w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "bitcoin grant unavailable") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

// The mainnet daily limit counts across a restart.
func TestBitcoinMainnetDailyLimitSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := mainnetConfig(t, policy.Access{BitcoinMaxSatsPerTx: 100_000, BitcoinMaxSatsPerDay: 100_000}, nil)
	day := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	start := func() *Handler {
		h := startMainnet(t, cfg, mainnetKeys, &lockedBuffer{}, dir)
		h.now = func() time.Time { return day }
		return h
	}
	h := start()
	if w := signCall(h, "POST", mainnetSignPath, signBody(mainnet65k(t), 0, 1), testToken); w.Code != 200 {
		t.Fatalf("first: %d %s", w.Code, w.Body.String())
	}
	h = start()
	w := signCall(h, "POST", mainnetSignPath, signBody(mainnet65k(t), 0, 1), testToken)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "bitcoin_max_sats_per_day: 65000 sats signed today plus 65000 external sats is over the limit of 100000") {
		t.Fatalf("after restart: %d %s", w.Code, w.Body.String())
	}
}
