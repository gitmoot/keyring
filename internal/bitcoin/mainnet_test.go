package bitcoin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"

	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
)

// mainnetRules is a mainnet service signing for every MainnetPaths path.
func mainnetRules(t *testing.T, sighash ...string) *Rules {
	t.Helper()
	r, err := NewRules(Mainnet, MainnetPaths, "", sighash)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// vsize is a finished transaction's virtual size: weight / 4, rounded up.
func vsize(tx *wire.MsgTx) int64 {
	return int64((tx.SerializeSizeStripped()*3 + tx.SerializeSize() + 3) / 4)
}

var (
	// The first receive coins of the BIP86 and BIP84 vectors' seed on
	// mainnet, and a change coin.
	mainTap    = bitcointest.Coin{Key: bitcointest.MasterMainnet, Kind: "p2tr", Path: "m/86'/0'/0'/0/0", Value: 50_000}
	mainWpkh   = bitcointest.Coin{Key: bitcointest.MasterMainnet, Kind: "p2wpkh", Path: "m/84'/0'/0'/0/0", Value: 30_000}
	mainChange = bitcointest.Coin{Key: bitcointest.MasterMainnet, Kind: "p2tr", Path: "m/86'/0'/0'/1/0"}
	// otherWpkh and otherTap are coins of a wallet the keyring does not
	// hold, signed by their owner (regtest rules: scripts are the same on
	// every network).
	otherWpkh = bitcointest.Coin{Key: bitcointest.Foreign, Kind: "p2wpkh", Path: "m/84'/1'/0'/0/0", Value: 40_000}
	otherTap  = bitcointest.Coin{Key: bitcointest.Foreign, Kind: "p2tr", Path: "m/86'/1'/0'/0/0", Value: 40_000}
)

// A mainnet service signs the BIP86 and BIP84 vectors' coins, the script
// engine accepts the finished transaction, and the size it estimated for
// the fee cap is never below the real one (at most one vbyte above: a
// P2WPKH signature may come out a byte shorter than the largest).
func TestMainnetSignsBIPVectorCoins(t *testing.T) {
	for coin, vector := range map[bitcointest.Coin]string{
		mainTap:  "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
		mainWpkh: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
	} {
		addr, err := address.DecodeAddress(vector, &chaincfg.MainNetParams)
		if err != nil {
			t.Fatal(err)
		}
		script, err := txscript.PayToAddrScript(addr)
		if err != nil || !bytes.Equal(script, bitcointest.Script(t, coin)) {
			t.Fatalf("%s is not the coin at %s", vector, coin.Path)
		}
	}
	r := mainnetRules(t)
	k, err := ParseKey(bitcointest.MasterMainnet, r)
	if err != nil {
		t.Fatal(err)
	}
	p := bitcointest.Build(t, []bitcointest.Coin{mainTap, mainWpkh}, []bitcointest.Out{{Value: 60_000, Script: bitcointest.External}, {Value: 15_000, Coin: &mainChange}})
	plan, err := Prepare(k, r, bitcointest.Encode(t, p), []int{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Fee != 5_000 || plan.External != 65_000 {
		t.Fatalf("fee %d external %d", plan.Fee, plan.External)
	}
	signed, err := plan.Sign()
	if err != nil {
		t.Fatal(err)
	}
	tx := bitcointest.Verify(t, signed.PSBT)
	if got := vsize(tx); plan.VBytes < got || plan.VBytes > got+1 || signed.VBytes != plan.VBytes {
		t.Fatalf("estimated %d vbytes, real %d", plan.VBytes, got)
	}
	// A key for another network signs nothing here, and this one nothing
	// on a test network.
	if _, err := ParseKey(bitcointest.Master, r); err != ErrKeyNetwork {
		t.Fatalf("tprv on mainnet: %v", err)
	}
	if _, err := ParseKey(bitcointest.WIF, mainnetWIFRules(t)); err != ErrKeyNetwork {
		t.Fatalf("test network WIF on mainnet: %v", err)
	}
	if _, err := ParseKey(mainnetWIF(t), mainnetWIFRules(t)); err != nil {
		t.Fatalf("mainnet WIF: %v", err)
	}
}

func mainnetWIFRules(t *testing.T) *Rules {
	t.Helper()
	r, err := NewRules(Mainnet, nil, ScriptP2TR, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// mainnetWIF is bitcointest.WIF's secret written for mainnet.
func mainnetWIF(t *testing.T) string {
	t.Helper()
	w, err := btcutil.DecodeWIF(bitcointest.WIF)
	if err != nil {
		t.Fatal(err)
	}
	main, err := btcutil.NewWIF(w.PrivKey, &chaincfg.MainNetParams, true)
	if err != nil {
		t.Fatal(err)
	}
	return main.String()
}

// signOther signs input i, a coin of the other wallet, as its owner would.
func signOther(t *testing.T, encoded string, i int) string {
	t.Helper()
	r := regtestRules(t)
	k, err := ParseKey(bitcointest.Foreign, r)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Prepare(k, r, encoded, []int{i})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := plan.Sign()
	if err != nil {
		t.Fatal(err)
	}
	return signed.PSBT
}

// The size estimate counts the inputs keyring does not sign: a P2WPKH or
// taproot key-path one at its largest witness, a finalised one exactly.
func TestMainnetSizeCountsOtherInputs(t *testing.T) {
	r := mainnetRules(t)
	k, err := ParseKey(bitcointest.MasterMainnet, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []bitcointest.Coin{otherWpkh, otherTap} {
		p := bitcointest.Build(t, []bitcointest.Coin{mainTap, other}, []bitcointest.Out{{Value: 85_000, Script: bitcointest.External}})
		plan, err := Prepare(k, r, bitcointest.Encode(t, p), []int{0})
		if err != nil {
			t.Fatalf("%s: %v", other.Kind, err)
		}
		signed, err := plan.Sign()
		if err != nil {
			t.Fatal(err)
		}
		tx := bitcointest.Verify(t, signOther(t, signed.PSBT, 1))
		if got := vsize(tx); plan.VBytes < got || plan.VBytes > got+1 {
			t.Fatalf("%s: estimated %d vbytes, real %d", other.Kind, plan.VBytes, got)
		}
	}
	// The other input already finalised (a reveal's script-path commit
	// input is): its witness is counted as it is, so the estimate is exact.
	p := bitcointest.Decode(t, signOther(t, bitcointest.Encode(t, bitcointest.Build(t, []bitcointest.Coin{mainTap, otherWpkh}, []bitcointest.Out{{Value: 85_000, Script: bitcointest.External}})), 1))
	if err := psbt.Finalize(p, 1); err != nil {
		t.Fatal(err)
	}
	plan, err := Prepare(k, r, bitcointest.Encode(t, p), []int{0})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := plan.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if got := vsize(bitcointest.Verify(t, signed.PSBT)); plan.VBytes != got {
		t.Fatalf("estimated %d vbytes, real %d", plan.VBytes, got)
	}
}

// On mainnet an input keyring does not sign must have a size it can know,
// or the fee rate cap could not hold: one of another kind (P2SH here), or a
// taproot script-path spend not yet finalised, is refused. A test network
// signs it and reports no size.
func TestMainnetRefusesInputsOfUnknownSize(t *testing.T) {
	p2sh := append(append([]byte{txscript.OP_HASH160, txscript.OP_DATA_20}, bytes.Repeat([]byte{0x22}, 20)...), txscript.OP_EQUAL)
	cases := map[string]func(*psbt.PInput){
		"p2sh": func(in *psbt.PInput) { in.WitnessUtxo.PkScript = p2sh },
		"taproot script path": func(in *psbt.PInput) {
			in.TaprootLeafScript = []*psbt.TaprootTapLeafScript{{ControlBlock: append([]byte{0xc0}, bytes.Repeat([]byte{0x02}, 32)...), Script: []byte{txscript.OP_TRUE}, LeafVersion: 0xc0}}
		},
	}
	r := mainnetRules(t)
	k, err := ParseKey(bitcointest.MasterMainnet, r)
	if err != nil {
		t.Fatal(err)
	}
	testTap := bitcointest.Coin{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/0/0", Value: 50_000}
	for name, change := range cases {
		p := bitcointest.Build(t, []bitcointest.Coin{mainTap, otherTap}, []bitcointest.Out{{Value: 85_000, Script: bitcointest.External}})
		change(&p.Inputs[1])
		_, err := Prepare(k, r, bitcointest.Encode(t, p), []int{0})
		if err == nil || err.Error() != "input 1: on mainnet an input this key does not sign must be finalized, or a taproot key-path or P2WPKH input, so the fee rate is known" {
			t.Fatalf("%s: %v", name, err)
		}
		p = bitcointest.Build(t, []bitcointest.Coin{testTap, otherTap}, []bitcointest.Out{{Value: 85_000, Script: bitcointest.External}})
		change(&p.Inputs[1])
		plan, err := Prepare(masterKey(t, regtestRules(t)), regtestRules(t), bitcointest.Encode(t, p), []int{0})
		if err != nil || plan.VBytes != 0 {
			t.Fatalf("%s on regtest: %v", name, err)
		}
	}
}

// One secret is one key, whatever network it is written for.
func TestSameKey(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{bitcointest.Master, bitcointest.MasterMainnet, true},
		{bitcointest.WIF, mainnetWIF(t), true},
		{bitcointest.Master, bitcointest.Foreign, false},
		{bitcointest.Master, bitcointest.WIF, false},
		{"not a key", "not a key", false},
	} {
		if got := SameKey(c.a, c.b); got != c.want {
			t.Errorf("SameKey(%.8s..., %.8s...) = %v", c.a, c.b, got)
		}
	}
	if strings.HasPrefix(mainnetWIF(t), "c") {
		t.Fatal("mainnet WIF written for a test network")
	}
}
