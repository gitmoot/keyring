package bitcoin

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"

	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
)

var testPaths = []string{"m/86'/1'/0'/0/*", "m/86'/1'/0'/1/*", "m/84h/1h/0h/0/*", "m/84h/1h/0h/1/*"}

func regtestRules(t *testing.T, sighash ...string) *Rules {
	t.Helper()
	r, err := NewRules(Regtest, testPaths, "", sighash)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func masterKey(t *testing.T, r *Rules) *Key {
	t.Helper()
	k, err := ParseKey(bitcointest.Master, r)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var (
	tapIn     = bitcointest.Coin{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/0/0", Value: 50_000}
	wpkhIn    = bitcointest.Coin{Key: bitcointest.Master, Kind: "p2wpkh", Path: "m/84'/1'/0'/0/1", Value: 30_000}
	tapChange = bitcointest.Coin{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/1/0"}
)

// standard is a PSBT of a taproot and a P2WPKH input of the master key
// paying 60000 sats out and 15000 back as change; fee 5000.
func standard(t *testing.T) *psbt.Packet {
	return bitcointest.Build(t, []bitcointest.Coin{tapIn, wpkhIn}, []bitcointest.Out{{Value: 60_000, Script: bitcointest.External}, {Value: 15_000, Coin: &tapChange}})
}

// The vectors of BIP86 and BIP84 (mainnet, coin type 0'), derived through
// the code the addresses endpoint uses.
func TestAddressesMatchBIP86AndBIP84Vectors(t *testing.T) {
	r := &Rules{Network: Mainnet, params: &chaincfg.MainNetParams, sighash: map[txscript.SigHashType]bool{}}
	for _, s := range []string{"m/86'/0'/0'/0/*", "m/86'/0'/0'/1/*", "m/84'/0'/0'/0/*", "m/84'/0'/0'/1/*"} {
		p, err := ParsePath(s)
		if err != nil {
			t.Fatal(err)
		}
		r.paths = append(r.paths, p)
	}
	k, err := parseKey(bitcointest.MasterMainnet, r.params)
	if err != nil {
		t.Fatal(err)
	}
	if k.Fingerprint() != bitcointest.MasterFingerprint {
		t.Fatalf("fingerprint = %s", k.Fingerprint())
	}
	cases := []struct {
		path      string
		from      uint32
		address   string
		publicKey string // BIP84 pubkey, or BIP86 internal key (x-only)
	}{
		{"m/86'/0'/0'/0", 0, "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"},
		{"m/86'/0'/0'/0", 1, "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh", "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145"},
		{"m/86'/0'/0'/1", 0, "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef"},
		{"m/84'/0'/0'/0", 0, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"},
		{"m/84'/0'/0'/0", 1, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77"},
		{"m/84'/0'/0'/1", 0, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6"},
	}
	for _, c := range cases {
		list, err := Addresses(k, r, c.path, c.from, 1)
		if err != nil {
			t.Fatalf("%s/%d: %v", c.path, c.from, err)
		}
		got := list.Addresses[0]
		if got.Address != c.address || !strings.HasSuffix(got.PublicKey, c.publicKey) || got.Index != c.from {
			t.Fatalf("%s/%d = %+v, want %s (%s)", c.path, c.from, got, c.address, c.publicKey)
		}
	}
}

func TestSignTaprootAndP2WPKHInputsVerify(t *testing.T) {
	r := regtestRules(t)
	k := masterKey(t, r)
	p := standard(t)
	plan, err := Prepare(k, r, bitcointest.Encode(t, p), []int{1, 0})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Fee != 5_000 || plan.External != 65_000 {
		t.Fatalf("fee %d external %d, want 5000 and 65000 (the change is the key's)", plan.Fee, plan.External)
	}
	signed, err := plan.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if signed.Txid != p.UnsignedTx.TxHash().String() || len(signed.Signed) != 2 || signed.Signed[0] != 0 || signed.Signed[1] != 1 {
		t.Fatalf("signed = %+v", signed)
	}
	out := bitcointest.Decode(t, signed.PSBT)
	if len(out.Inputs[0].TaprootKeySpendSig) != 64 || len(out.Inputs[1].PartialSigs) != 1 {
		t.Fatal("want a 64-byte taproot key-path signature and one partial signature")
	}
	tx := bitcointest.Verify(t, signed.PSBT)
	if tx.TxHash().String() != signed.Txid {
		t.Fatal("txid changed by signing")
	}
}

// Only the listed inputs are signed; a PSBT with some inputs signed by
// another party still verifies once they sign theirs.
func TestSignsOnlyListedInputs(t *testing.T) {
	r := regtestRules(t)
	k := masterKey(t, r)
	plan, err := Prepare(k, r, bitcointest.Encode(t, standard(t)), []int{1})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := plan.Sign()
	if err != nil {
		t.Fatal(err)
	}
	out := bitcointest.Decode(t, signed.PSBT)
	if len(out.Inputs[0].TaprootKeySpendSig) != 0 || len(out.Inputs[1].PartialSigs) != 1 {
		t.Fatal("an input that was not listed was signed")
	}
}

func TestWIFKeySigns(t *testing.T) {
	for _, kind := range []string{ScriptP2WPKH, ScriptP2TR} {
		r, err := NewRules(Regtest, nil, kind, nil)
		if err != nil {
			t.Fatal(err)
		}
		k, err := ParseKey(bitcointest.WIF, r)
		if err != nil {
			t.Fatal(err)
		}
		in := bitcointest.Coin{Key: bitcointest.WIF, Kind: kind, Path: "m", Value: 10_000}
		p := bitcointest.Build(t, []bitcointest.Coin{in}, []bitcointest.Out{{Value: 9_000, Script: bitcointest.External}})
		plan, err := Prepare(k, r, bitcointest.Encode(t, p), []int{0})
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		signed, err := plan.Sign()
		if err != nil {
			t.Fatal(err)
		}
		bitcointest.Verify(t, signed.PSBT)
		if _, err := ParseKey(bitcointest.WIF, regtestRules(t)); !errors.Is(err, ErrKeyKind) {
			t.Fatalf("WIF key on a paths service: %v", err)
		}
	}
}

func TestRefusals(t *testing.T) {
	foreign := bitcointest.Coin{Key: bitcointest.Foreign, Kind: "p2tr", Path: "m/86'/1'/0'/0/0", Value: 50_000}
	cases := []struct {
		name    string
		sighash []string
		inputs  []int
		mutate  func(p *psbt.Packet)
		raw     string
		want    string
	}{
		{name: "psbt does not parse", raw: "cHNidP8BAA==", want: "psbt does not parse"},
		{name: "input out of range", inputs: []int{2}, want: "input 2 does not exist"},
		{name: "input listed twice", inputs: []int{0, 0}, want: "input 0 is listed twice"},
		{name: "foreign fingerprint", mutate: func(p *psbt.Packet) {
			f := bitcointest.Build(t, []bitcointest.Coin{foreign}, nil)
			p.Inputs[0] = f.Inputs[0]
		}, want: "input 0 has no derivation with this key's fingerprint 73c5da0a"},
		{name: "path outside allow-list (account 1)", mutate: func(p *psbt.Packet) {
			p.Inputs[0].TaprootBip32Derivation[0].Bip32Path[2] = 1 + hardened
		}, want: "input 0: derivation path is not allowed"},
		{name: "hardened last index", mutate: func(p *psbt.Packet) {
			p.Inputs[0].TaprootBip32Derivation[0].Bip32Path[4] = hardened
		}, want: "input 0: derivation path is not allowed"},
		{name: "p2wpkh path in a taproot derivation", mutate: func(p *psbt.Packet) {
			p.Inputs[0].TaprootBip32Derivation[0].Bip32Path[0] = 84 + hardened
		}, want: "input 0: derivation path is not allowed"},
		{name: "public key not the derived one", mutate: func(p *psbt.Packet) {
			p.Inputs[1].Bip32Derivation[0].Bip32Path[4] = 7
		}, want: "input 1: derivation public key is not this key's"},
		{name: "script mismatch", mutate: func(p *psbt.Packet) {
			p.Inputs[0].WitnessUtxo.PkScript = bitcointest.Script(t, bitcointest.Coin{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/0/9"})
		}, want: "input 0: witness_utxo script is not the derived key's script"},
		{name: "missing witness_utxo on a listed input", mutate: func(p *psbt.Packet) { p.Inputs[0].WitnessUtxo = nil }, want: "input 0 has no witness_utxo"},
		{name: "missing witness_utxo on another input", inputs: []int{0}, mutate: func(p *psbt.Packet) { p.Inputs[1].WitnessUtxo = nil }, want: "input 1 has no witness_utxo"},
		{name: "sighash none", mutate: func(p *psbt.Packet) { p.Inputs[0].SighashType = txscript.SigHashNone }, want: "input 0: sighash none is not allowed"},
		{name: "sighash single", mutate: func(p *psbt.Packet) { p.Inputs[1].SighashType = txscript.SigHashSingle }, want: "input 1: sighash single is not allowed"},
		{name: "sighash anyonecanpay", mutate: func(p *psbt.Packet) {
			p.Inputs[0].SighashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
		}, want: "input 0: sighash all|anyonecanpay is not allowed"},
		{name: "sighash all not listed", sighash: []string{"default"}, mutate: func(p *psbt.Packet) {}, want: "input 1: sighash all is not allowed"},
		{name: "invalid sighash", mutate: func(p *psbt.Packet) { p.Inputs[0].SighashType = 0x42 }, want: "input 0: sighash type is not valid"},
		{name: "OP_RETURN output", mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxOut[0].PkScript = []byte{txscript.OP_RETURN, 0x01, 0x00}
		}, want: "output 0 is not an address on regtest"},
		{name: "unknown witness version output", mutate: func(p *psbt.Packet) {
			p.UnsignedTx.TxOut[0].PkScript = append([]byte{txscript.OP_2, txscript.OP_DATA_32}, make([]byte, 32)...)
		}, want: "output 0 is not an address on regtest"},
		{name: "pay-to-pubkey output", mutate: func(p *psbt.Packet) {
			// P2PK has one public key but no address: refused like any
			// non-address script.
			g, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
			p.UnsignedTx.TxOut[0].PkScript = append(append([]byte{txscript.OP_DATA_33}, g...), txscript.OP_CHECKSIG)
		}, want: "output 0 is not an address on regtest"},
		{name: "outputs exceed inputs", mutate: func(p *psbt.Packet) { p.UnsignedTx.TxOut[0].Value = 70_000 }, want: "outputs exceed inputs"},
		{name: "taproot script tree", mutate: func(p *psbt.Packet) { p.Inputs[0].TaprootMerkleRoot = make([]byte, 32) }, want: "input 0: taproot script trees are not signed"},
		{name: "taproot leaf derivation", mutate: func(p *psbt.Packet) {
			p.Inputs[0].TaprootBip32Derivation[0].LeafHashes = [][]byte{make([]byte, 32)}
		}, want: "input 0: derivation path is not allowed"},
		{name: "already finalized", mutate: func(p *psbt.Packet) { p.Inputs[1].FinalScriptWitness = []byte{0} }, want: "input 1 is already finalized"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := regtestRules(t, c.sighash...)
			k := masterKey(t, r)
			raw := c.raw
			if raw == "" {
				p := standard(t)
				if c.mutate != nil {
					c.mutate(p)
				}
				raw = bitcointest.Encode(t, p)
			}
			inputs := c.inputs
			if inputs == nil {
				inputs = []int{0, 1}
			}
			plan, err := Prepare(k, r, raw, inputs)
			var refusal *Refusal
			if plan != nil || !errors.As(err, &refusal) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Prepare = %v, %v; want refusal %q", plan, err, c.want)
			}
			if strings.Contains(err.Error(), bitcointest.Master) || strings.Contains(err.Error(), raw) {
				t.Fatal("refusal carries the key or the PSBT")
			}
		})
	}
}

// bare drops the previous transactions of p's inputs.
func bare(p *psbt.Packet, inputs ...int) *psbt.Packet {
	for _, i := range inputs {
		p.Inputs[i].NonWitnessUtxo = nil
	}
	return p
}

// Review of #188: a P2WPKH signature, or a taproot one with anyonecanpay,
// commits only to its own input's amount and stays usable when another
// amount was understated, so every other input must prove its amount with
// the previous transaction; an understated amount would lower the fee and
// the external count. Only a call whose signatures all commit to every
// amount (taproot without anyonecanpay) needs no proof.
func TestUncommittedAmountsNeedThePreviousTransaction(t *testing.T) {
	r := regtestRules(t, "default", "all", "all|anyonecanpay")
	k := masterKey(t, r)
	refused := func(p *psbt.Packet, inputs []int, want string) {
		t.Helper()
		plan, err := Prepare(k, r, bitcointest.Encode(t, p), inputs)
		if plan != nil || err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Prepare = %v, %v; want %q", plan, err, want)
		}
	}
	// Only the P2WPKH input is signed: input 0's amount is not committed.
	p := bare(standard(t), 0)
	p.Inputs[0].WitnessUtxo.Value = 20_000 // understated by 30000
	refused(p, []int{1}, "input 0 amount is not committed by the signatures: add its non_witness_utxo")
	p = standard(t)
	p.Inputs[0].WitnessUtxo.Value = 20_000
	refused(p, []int{1}, "input 0: non_witness_utxo does not match its outpoint and witness_utxo")
	p = standard(t)
	p.UnsignedTx.TxIn[0].PreviousOutPoint.Index = 1
	refused(p, []int{1}, "input 0: non_witness_utxo does not match")
	plan, err := Prepare(k, r, bitcointest.Encode(t, bare(standard(t), 1)), []int{1})
	if err != nil || plan.External != 65_000 || plan.Fee != 5_000 {
		t.Fatalf("with the previous transaction: %v, %+v", err, plan)
	}
	// Both inputs signed: the P2WPKH signature of input 1 does not commit
	// to input 0's amount, though the taproot one does.
	p = bare(standard(t), 0, 1)
	p.Inputs[0].WitnessUtxo.Value = 45_000 // understated by 5000: the fee would read 0
	refused(p, []int{0, 1}, "input 0 amount is not committed by the signatures")
	if _, err := Prepare(k, r, bitcointest.Encode(t, bare(standard(t), 1)), []int{0, 1}); err != nil {
		t.Fatal(err)
	}
	// Two P2WPKH inputs: each signature commits only to its own amount.
	second := bitcointest.Coin{Key: bitcointest.Master, Kind: "p2wpkh", Path: "m/84'/1'/0'/0/2", Value: 50_000}
	two := func() *psbt.Packet {
		return bitcointest.Build(t, []bitcointest.Coin{second, wpkhIn}, []bitcointest.Out{{Value: 75_000, Script: bitcointest.External}})
	}
	p = bare(two(), 0, 1)
	p.Inputs[0].WitnessUtxo.Value = 45_000
	refused(p, []int{0, 1}, "input 0 amount is not committed by the signatures")
	refused(bare(two(), 1), []int{0, 1}, "input 1 amount is not committed by the signatures")
	if _, err := Prepare(k, r, bitcointest.Encode(t, two()), []int{0, 1}); err != nil {
		t.Fatal(err)
	}
	// A taproot signature with anyonecanpay commits only to its own amount.
	p = bare(standard(t), 1)
	p.Inputs[0].SighashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	refused(p, []int{0}, "input 1 amount is not committed by the signatures")
	// Without anyonecanpay it commits to every amount.
	if _, err := Prepare(k, r, bitcointest.Encode(t, bare(standard(t), 0, 1)), []int{0}); err != nil {
		t.Fatal(err)
	}
}

// A sighash the service lists is signed, and the signature still verifies.
func TestListedSighashSigns(t *testing.T) {
	r := regtestRules(t, "default", "all", "all|anyonecanpay")
	k := masterKey(t, r)
	p := standard(t)
	p.Inputs[0].SighashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	p.Inputs[1].SighashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	plan, err := Prepare(k, r, bitcointest.Encode(t, p), []int{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := plan.Sign()
	if err != nil {
		t.Fatal(err)
	}
	bitcointest.Verify(t, signed.PSBT)
}

func TestOwnChangeNeedsProof(t *testing.T) {
	r := regtestRules(t)
	k := masterKey(t, r)
	external := func(p *psbt.Packet) int64 {
		t.Helper()
		plan, err := Prepare(k, r, bitcointest.Encode(t, p), []int{0, 1})
		if err != nil {
			t.Fatal(err)
		}
		return plan.External
	}
	if got := external(standard(t)); got != 65_000 {
		t.Fatalf("proven change counted: external %d", got)
	}
	// The same script without derivation info is not proven the key's.
	p := standard(t)
	p.Outputs[1].TaprootBip32Derivation = nil
	if got := external(p); got != 80_000 {
		t.Fatalf("unproven change: external %d, want 80000", got)
	}
	// Derivation info naming a path outside the service's is no proof.
	p = standard(t)
	p.Outputs[1].TaprootBip32Derivation[0].Bip32Path[2] = 5 + hardened
	if got := external(p); got != 80_000 {
		t.Fatalf("change on a path outside the list: external %d, want 80000", got)
	}
	// Derivation info of this key whose script is not the output's is no
	// proof either (a lying PSBT).
	p = standard(t)
	p.UnsignedTx.TxOut[1].PkScript = bitcointest.External
	if got := external(p); got != 80_000 {
		t.Fatalf("change to another script: external %d, want 80000", got)
	}
}

func TestNewRules(t *testing.T) {
	if _, err := NewRules(Mainnet, testPaths, "", nil); !errors.Is(err, ErrMainnet) {
		t.Fatalf("mainnet: %v", err)
	}
	bad := []struct {
		network, script string
		paths, sighash  []string
	}{
		{network: "bitcoin", paths: testPaths},
		{network: Regtest},
		{network: Regtest, paths: testPaths, script: ScriptP2TR},
		{network: Regtest, script: "p2pkh"},
		{network: Regtest, paths: []string{"m/44'/1'/0'/0/*"}},
		{network: Regtest, paths: []string{"m/86'/1'/0'/0/*'"}},
		{network: Regtest, paths: []string{"m/86'/1'/*/0"}},
		{network: Regtest, paths: []string{"m/86'/1'/00'/0/*"}},
		{network: Regtest, paths: []string{"86'/1'/0'/0/*"}},
		{network: Regtest, paths: []string{"m/86'/1'/0'/0/*", "m/86h/1h/0h/0/*"}},
		// Review of #188: both answer the addresses path m/86'/1'/0'/0.
		{network: Regtest, paths: []string{"m/86'/1'/0'/0/*", "m/86'/1'/0'/0"}},
		{network: Regtest, paths: []string{"m/86'/1'/0'/0", "m/86'/1'/0'/0/*"}},
		{network: Regtest, paths: testPaths, sighash: []string{"ALL"}},
		{network: Regtest, paths: testPaths, sighash: []string{"all", "all"}},
	}
	for _, b := range bad {
		if _, err := NewRules(b.network, b.paths, b.script, b.sighash); err == nil {
			t.Fatalf("accepted %+v", b)
		}
	}
	for _, network := range []string{Regtest, Testnet, Signet} {
		if _, err := NewRules(network, testPaths, "", nil); err != nil {
			t.Fatalf("%s: %v", network, err)
		}
	}
}

func TestParseKey(t *testing.T) {
	r := regtestRules(t)
	master, err := hdkeychain.NewKeyFromString(bitcointest.Master)
	if err != nil {
		t.Fatal(err)
	}
	child, err := master.Derive(hardened) // m/0', depth 1
	if err != nil {
		t.Fatal(err)
	}
	for value, want := range map[string]error{
		bitcointest.MasterMainnet:      ErrKeyNetwork,
		"not a key":                    ErrKeyFormat,
		"":                             ErrKeyFormat,
		bitcointest.Master[:110] + "x": ErrKeyFormat,
		child.String():                 ErrKeyDepth,
	} {
		if _, err := ParseKey(value, r); !errors.Is(err, want) {
			t.Fatalf("ParseKey(%.8s...) = %v, want %v", value, err, want)
		}
	}
	if info, ok := Inspect(bitcointest.Master); !ok || info.Fingerprint != bitcointest.MasterFingerprint || info.Networks != "test networks" {
		t.Fatalf("Inspect = %+v, %v", info, ok)
	}
	if _, ok := Inspect("sk-ant-api03-notabitcoinkey"); ok {
		t.Fatal("an API key looks like a bitcoin key")
	}
}

// IsKey agrees with Inspect, and neither decodes a value longer than a key:
// every stored value is checked, and Base58 decoding takes time quadratic in
// the length (review of #204).
func TestIsKey(t *testing.T) {
	master, err := hdkeychain.NewKeyFromString(bitcointest.Master)
	if err != nil {
		t.Fatal(err)
	}
	public, err := master.Neuter()
	if err != nil {
		t.Fatal(err)
	}
	for value, want := range map[string]bool{
		bitcointest.Master:             true,
		bitcointest.MasterMainnet:      true,
		bitcointest.WIF:                true,
		" " + bitcointest.WIF + "\n":   true,
		public.String():                false,
		bitcointest.Master[:110] + "x": false,
		bitcointest.WIF + "1":          false,
		"sk-ant-api03-notabitcoinkey":  false,
		"":                             false,
	} {
		_, inspected := Inspect(value)
		if got := IsKey(value); got != want || inspected != want {
			t.Fatalf("IsKey(%.8s...) = %v, Inspect %v; want %v", value, got, inspected, want)
		}
	}
	long := strings.Repeat("z", 1<<14)
	found := false
	if n := testing.AllocsPerRun(3, func() {
		_, inspected := Inspect(long)
		found = found || inspected || IsKey(long)
	}); n != 0 || found {
		t.Fatalf("a %d-character credential was decoded (%v allocations, found %v)", len(long), n, found)
	}
}

func TestDescribe(t *testing.T) {
	d, err := Describe(bitcointest.Master+"\n", Regtest)
	if err != nil {
		t.Fatal(err)
	}
	if d.Fingerprint != bitcointest.MasterFingerprint || len(d.Addresses) != 2 || !strings.HasPrefix(d.Addresses[0].Address, "bcrt1p") || !strings.HasPrefix(d.Addresses[1].Address, "bcrt1q") {
		t.Fatalf("Describe = %+v", d)
	}
	if _, err := Describe(bitcointest.Master, Mainnet); !errors.Is(err, ErrMainnet) {
		t.Fatalf("mainnet: %v", err)
	}
}

func TestWatchOnly(t *testing.T) {
	r := regtestRules(t)
	watch, err := WatchOnly(masterKey(t, r), r)
	if err != nil {
		t.Fatal(err)
	}
	if len(watch) != 4 || !strings.HasPrefix(watch[0].Descriptor, "tr([73c5da0a/86h/1h/0h/0]tpub") || !strings.HasSuffix(watch[0].Descriptor, "/*)") {
		t.Fatalf("watch = %+v", watch)
	}
	for _, w := range watch {
		if strings.Contains(w.Descriptor, "tprv") {
			t.Fatal("private key in a watch-only descriptor")
		}
	}
}
