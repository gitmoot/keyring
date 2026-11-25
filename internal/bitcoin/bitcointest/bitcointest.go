// Package bitcointest builds regtest PSBTs for tests from fixed keys and
// checks signed ones by running the script engine over the finished
// transaction. It derives scripts through the address package, apart from
// the code under test.
package bitcointest

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// Test keys. Never real funds.
const (
	// Master is the BIP84/BIP86 test vector seed (mnemonic "abandon" x11
	// "about") as a test network master key; fingerprint 73c5da0a.
	Master            = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd"
	MasterFingerprint = "73c5da0a"
	// MasterMainnet is the same seed as BIP86 gives it (xprv).
	MasterMainnet = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
	// Foreign is another master key: inputs of a wallet the keyring does
	// not hold.
	Foreign = "tprv8ZgxMBicQKsPd9mvLAivFp1unRArCcjdQ1nrreLUMakcTpL7pCpWQBGTayu5Khc4ubP6nZtiKeS5DdhghwfPKmcN92wgVCAtgdEwuPdAKcS"
	// WIF is a single compressed regtest key (secret 0x0102...20).
	WIF = "cMcfH8sRgBgDMfpBNG6H3haaxLkaYXgqMRef8Nev6tWyBSNr6c3n"
)

// Coin is an output of Key at Path, of kind "p2tr" (BIP86) or "p2wpkh".
// Path is "m" for the WIF key.
type Coin struct {
	Key   string
	Kind  string
	Path  string
	Value int64
}

// Out is a transaction output: to Coin's script with its derivation (change
// the PSBT proves is the key's), or to Script with no derivation.
type Out struct {
	Value  int64
	Coin   *Coin
	Script []byte
}

// External is a regtest P2WPKH script of nobody here.
var External = append([]byte{txscript.OP_0, txscript.OP_DATA_20}, bytes.Repeat([]byte{0x11}, 20)...)

func parsePath(t testing.TB, s string) []uint32 {
	t.Helper()
	parts := strings.Split(s, "/")
	if parts[0] != "m" {
		t.Fatalf("path %q", s)
	}
	var out []uint32
	for _, p := range parts[1:] {
		h := strings.HasSuffix(p, "'")
		n, err := strconv.ParseUint(strings.TrimSuffix(p, "'"), 10, 32)
		if err != nil {
			t.Fatalf("path %q", s)
		}
		if h {
			n += hdkeychain.HardenedKeyStart
		}
		out = append(out, uint32(n))
	}
	return out
}

// key returns the private key of c and the fingerprint PSBTs list for it.
func key(t testing.TB, c Coin) (*btcec.PrivateKey, uint32, []uint32) {
	t.Helper()
	path := parsePath(t, c.Path)
	if c.Key == WIF {
		w, err := btcutil.DecodeWIF(c.Key)
		if err != nil {
			t.Fatal(err)
		}
		return w.PrivKey, binary.LittleEndian.Uint32(address.Hash160(w.SerializePubKey())[:4]), path
	}
	ext, err := hdkeychain.NewKeyFromString(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ext.ECPubKey()
	if err != nil {
		t.Fatal(err)
	}
	fp := binary.LittleEndian.Uint32(address.Hash160(pub.SerializeCompressed())[:4])
	for _, i := range path {
		if ext, err = ext.Derive(i); err != nil {
			t.Fatal(err)
		}
	}
	priv, err := ext.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, fp, path
}

// Script is the output script of c.
func Script(t testing.TB, c Coin) []byte {
	t.Helper()
	priv, _, _ := key(t, c)
	pub := priv.PubKey()
	var addr address.Address
	var err error
	if c.Kind == "p2tr" {
		addr, err = address.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(pub)), &chaincfg.RegressionNetParams)
	} else {
		addr, err = address.NewAddressWitnessPubKeyHash(address.Hash160(pub.SerializeCompressed()), &chaincfg.RegressionNetParams)
	}
	if err != nil {
		t.Fatal(err)
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func derivations(t testing.TB, c Coin) ([]*psbt.Bip32Derivation, []*psbt.TaprootBip32Derivation) {
	t.Helper()
	priv, fp, path := key(t, c)
	if c.Kind == "p2tr" {
		return nil, []*psbt.TaprootBip32Derivation{{XOnlyPubKey: schnorr.SerializePubKey(priv.PubKey()), MasterKeyFingerprint: fp, Bip32Path: path}}
	}
	return []*psbt.Bip32Derivation{{PubKey: priv.PubKey().SerializeCompressed(), MasterKeyFingerprint: fp, Bip32Path: path}}, nil
}

// Build makes a PSBT spending inputs (each with witness_utxo and derivation
// info) to outputs. Input i spends output 0 of a made-up transaction named
// after i, so builds are deterministic.
func Build(t testing.TB, inputs []Coin, outputs []Out) *psbt.Packet {
	t.Helper()
	tx := wire.NewMsgTx(2)
	for i := range inputs {
		hash := chainhash.Hash(sha256.Sum256([]byte("keyring test prevout " + strconv.Itoa(i))))
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&hash, 0), nil, nil))
	}
	for _, o := range outputs {
		script := o.Script
		if o.Coin != nil {
			script = Script(t, *o.Coin)
		}
		tx.AddTxOut(wire.NewTxOut(o.Value, script))
	}
	p, err := psbt.NewFromUnsignedTx(tx)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range inputs {
		p.Inputs[i].WitnessUtxo = wire.NewTxOut(c.Value, Script(t, c))
		p.Inputs[i].Bip32Derivation, p.Inputs[i].TaprootBip32Derivation = derivations(t, c)
	}
	for i, o := range outputs {
		if o.Coin != nil {
			p.Outputs[i].Bip32Derivation, p.Outputs[i].TaprootBip32Derivation = derivations(t, *o.Coin)
		}
	}
	return p
}

// Encode is p in base64.
func Encode(t testing.TB, p *psbt.Packet) string {
	t.Helper()
	s, err := p.B64Encode()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Decode reads a base64 PSBT.
func Decode(t testing.TB, s string) *psbt.Packet {
	t.Helper()
	p, err := psbt.NewFromRawBytes(strings.NewReader(s), true)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Verify finalizes a signed PSBT whose inputs are all signed, extracts the
// transaction and runs the script engine on every input, as a node would
// before accepting it. It returns the transaction.
func Verify(t testing.TB, signed string) *wire.MsgTx {
	t.Helper()
	p := Decode(t, signed)
	if err := psbt.MaybeFinalizeAll(p); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	tx, err := psbt.Extract(p)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	prevOuts := map[wire.OutPoint]*wire.TxOut{}
	for i, in := range tx.TxIn {
		prevOuts[in.PreviousOutPoint] = p.Inputs[i].WitnessUtxo
	}
	fetcher := txscript.NewMultiPrevOutFetcher(prevOuts)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	for i := range tx.TxIn {
		utxo := p.Inputs[i].WitnessUtxo
		engine, err := txscript.NewEngine(utxo.PkScript, tx, i, txscript.StandardVerifyFlags, nil, hashes, utxo.Value, fetcher)
		if err != nil {
			t.Fatalf("input %d: engine: %v", i, err)
		}
		if err := engine.Execute(); err != nil {
			t.Fatalf("input %d: spend does not verify: %v", i, err)
		}
	}
	return tx
}
