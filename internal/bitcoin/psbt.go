package bitcoin

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// Refusal is a PSBT the key will not sign. Its reason is fixed text with
// at most input or output indices and settings names; never PSBT content.
type Refusal struct{ reason string }

func (e *Refusal) Error() string { return e.reason }

func refuse(format string, args ...any) error {
	return &Refusal{reason: fmt.Sprintf(format, args...)}
}

// owned is a derivation of this key that pays to a script.
type owned struct {
	path []uint32
	kind string
}

// Why an input is not this key's.
const (
	notOursFingerprint = iota + 1
	notOursPath
	notOursPubKey
	notOursScript
)

// own finds a derivation of this key on an allowed path whose derived
// public key is the one listed and whose script is pkScript. Without one
// it says how close the best entry came.
func (k *Key) own(r *Rules, bip32 []*psbt.Bip32Derivation, tap []*psbt.TaprootBip32Derivation, pkScript []byte) (owned, int) {
	fp := k.fingerprint()
	why := notOursFingerprint
	worse := func(w int) {
		if w > why {
			why = w
		}
	}
	for _, d := range bip32 {
		if d.MasterKeyFingerprint != fp {
			continue
		}
		kind, ok := r.allowed(d.Bip32Path)
		if !ok || kind != ScriptP2WPKH {
			worse(notOursPath)
			continue
		}
		pub, err := k.pubAt(d.Bip32Path)
		if err != nil || !bytes.Equal(pub.SerializeCompressed(), d.PubKey) {
			worse(notOursPubKey)
			continue
		}
		if !bytes.Equal(scriptFor(kind, pub), pkScript) {
			worse(notOursScript)
			continue
		}
		return owned{path: d.Bip32Path, kind: kind}, 0
	}
	for _, d := range tap {
		if d.MasterKeyFingerprint != fp {
			continue
		}
		// A key with leaf hashes signs inside a script tree: not a BIP86
		// key-path spend.
		kind, ok := r.allowed(d.Bip32Path)
		if !ok || kind != ScriptP2TR || len(d.LeafHashes) != 0 {
			worse(notOursPath)
			continue
		}
		pub, err := k.pubAt(d.Bip32Path)
		if err != nil || !bytes.Equal(schnorr.SerializePubKey(pub), d.XOnlyPubKey) {
			worse(notOursPubKey)
			continue
		}
		if !bytes.Equal(scriptFor(kind, pub), pkScript) {
			worse(notOursScript)
			continue
		}
		return owned{path: d.Bip32Path, kind: kind}, 0
	}
	return owned{}, why
}

// sighashName names t for the refusal text; "" for a type that is not one.
func sighashName(t txscript.SigHashType) string {
	for name, v := range sighashNames {
		if v == t {
			return name
		}
	}
	return ""
}

// addressClasses are the outputs that decode to an address a person can be
// paid at; anything else (OP_RETURN, bare multisig, unknown witness
// versions, anchors) is refused.
var addressClasses = map[txscript.ScriptClass]bool{
	txscript.PubKeyHashTy:          true,
	txscript.ScriptHashTy:          true,
	txscript.WitnessV0PubKeyHashTy: true,
	txscript.WitnessV0ScriptHashTy: true,
	txscript.WitnessV1TaprootTy:    true,
}

// Plan is a PSBT that passed every check, ready to sign.
type Plan struct {
	key      *Key
	packet   *psbt.Packet
	inputs   []int
	matches  []owned
	types    []txscript.SigHashType
	Txid     string
	External int64 // sats of outputs not proven this key's, plus the fee
	Fee      int64
}

// Prepare checks a base64 PSBT and the inputs to sign. All must hold, or
// nothing is signed:
//   - every listed input exists, carries witness_utxo and a derivation of
//     this key (fingerprint) on an allowed path whose script is the
//     witness_utxo script, and its sighash type is allowed;
//   - every input carries witness_utxo, so the fee is known;
//   - every output is a standard address script.
//
// External counts every output not proven to pay back to this key (output
// derivation of this key on an allowed path, derived script equal to the
// output's), plus the fee.
//
// The input amounts come from the PSBT, so each must be committed by every
// signature returned: a taproot signature without anyonecanpay commits to
// every input's amount and script (BIP341), but a P2WPKH signature (BIP143)
// or a taproot anyonecanpay one commits only to its own input's amount and
// stays usable when another input's amount was understated. So when the
// call makes such a signature, every other input must prove its amount with
// non_witness_utxo, the previous transaction. An understated amount would
// lower the fee and so the external count.
func Prepare(k *Key, r *Rules, psbtBase64 string, inputs []int) (*Plan, error) {
	packet, err := psbt.NewFromRawBytes(strings.NewReader(psbtBase64), true)
	if err != nil || packet.UnsignedTx == nil {
		return nil, refuse("psbt does not parse")
	}
	tx := packet.UnsignedTx
	if len(packet.Inputs) != len(tx.TxIn) || len(packet.Outputs) != len(tx.TxOut) {
		return nil, refuse("psbt does not parse")
	}
	if len(inputs) == 0 {
		return nil, refuse("inputs is empty")
	}
	listed := map[int]bool{}
	for _, i := range inputs {
		if i < 0 || i >= len(packet.Inputs) {
			return nil, refuse("input %d does not exist", i)
		}
		if listed[i] {
			return nil, refuse("input %d is listed twice", i)
		}
		listed[i] = true
	}
	var in int64
	spent := map[wire.OutPoint]bool{}
	for i, pin := range packet.Inputs {
		if pin.WitnessUtxo == nil {
			return nil, refuse("input %d has no witness_utxo (every input needs one, so the fee is known)", i)
		}
		if spent[tx.TxIn[i].PreviousOutPoint] {
			return nil, refuse("input %d spends the same output as another input", i)
		}
		spent[tx.TxIn[i].PreviousOutPoint] = true
		var ok bool
		if !validAmount(pin.WitnessUtxo.Value) {
			return nil, refuse("input %d amount is out of range", i)
		}
		if in, ok = addSats(in, pin.WitnessUtxo.Value); !ok {
			return nil, refuse("input amounts are out of range")
		}
	}
	plan := &Plan{key: k, packet: packet, Txid: tx.TxHash().String()}
	plan.inputs = slices.Sorted(maps.Keys(listed))
	for _, i := range plan.inputs {
		pin := &packet.Inputs[i]
		if len(pin.FinalScriptSig) != 0 || len(pin.FinalScriptWitness) != 0 {
			return nil, refuse("input %d is already finalized", i)
		}
		m, why := k.own(r, pin.Bip32Derivation, pin.TaprootBip32Derivation, pin.WitnessUtxo.PkScript)
		switch why {
		case notOursFingerprint:
			return nil, refuse("input %d has no derivation with this key's fingerprint %s", i, k.Fingerprint())
		case notOursPath:
			return nil, refuse("input %d: derivation path is not allowed for this service", i)
		case notOursPubKey:
			return nil, refuse("input %d: derivation public key is not this key's at that path", i)
		case notOursScript:
			return nil, refuse("input %d: witness_utxo script is not the derived key's script", i)
		}
		t := pin.SighashType
		if m.kind == ScriptP2TR {
			if len(pin.TaprootMerkleRoot) != 0 {
				return nil, refuse("input %d: taproot script trees are not signed (BIP86 key path only)", i)
			}
			if len(pin.TaprootInternalKey) != 0 {
				pub, err := k.pubAt(m.path)
				if err != nil || !bytes.Equal(schnorr.SerializePubKey(pub), pin.TaprootInternalKey) {
					return nil, refuse("input %d: taproot internal key is not the derived key", i)
				}
			}
		} else {
			if len(pin.RedeemScript) != 0 || len(pin.WitnessScript) != 0 {
				return nil, refuse("input %d: redeem and witness scripts are not signed (native P2WPKH only)", i)
			}
			if t == txscript.SigHashDefault {
				t = txscript.SigHashAll // a P2WPKH input without a sighash field
			}
		}
		name := sighashName(t)
		if name == "" {
			return nil, refuse("input %d: sighash type is not valid", i)
		}
		if !r.sighash[t] {
			return nil, refuse("input %d: sighash %s is not allowed for this service", i, name)
		}
		if t&^txscript.SigHashAnyOneCanPay == txscript.SigHashSingle && i >= len(tx.TxOut) {
			return nil, refuse("input %d: sighash single needs an output at the same index", i)
		}
		plan.matches = append(plan.matches, m)
		plan.types = append(plan.types, t)
	}
	var narrow []int // inputs whose signature commits only to their own amount
	for n, i := range plan.inputs {
		if plan.matches[n].kind != ScriptP2TR || plan.types[n]&txscript.SigHashAnyOneCanPay != 0 {
			narrow = append(narrow, i)
		}
	}
	for i, pin := range packet.Inputs {
		if len(narrow) == 0 || len(narrow) == 1 && narrow[0] == i {
			continue
		}
		prev, nw := tx.TxIn[i].PreviousOutPoint, pin.NonWitnessUtxo
		if nw == nil {
			return nil, refuse("input %d amount is not committed by the signatures: add its non_witness_utxo (the previous transaction)", i)
		}
		if nw.TxHash() != prev.Hash || uint64(prev.Index) >= uint64(len(nw.TxOut)) ||
			nw.TxOut[prev.Index].Value != pin.WitnessUtxo.Value || !bytes.Equal(nw.TxOut[prev.Index].PkScript, pin.WitnessUtxo.PkScript) {
			return nil, refuse("input %d: non_witness_utxo does not match its outpoint and witness_utxo", i)
		}
	}
	var out, external int64
	for i, txOut := range tx.TxOut {
		class, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, r.params)
		if err != nil || len(addrs) != 1 || !addressClasses[class] || !addrs[0].IsForNet(r.params) {
			return nil, refuse("output %d is not an address on %s", i, r.Network)
		}
		var ok bool
		if !validAmount(txOut.Value) {
			return nil, refuse("output %d amount is out of range", i)
		}
		if out, ok = addSats(out, txOut.Value); !ok {
			return nil, refuse("output amounts are out of range")
		}
		pout := packet.Outputs[i]
		if _, why := k.own(r, pout.Bip32Derivation, pout.TaprootBip32Derivation, txOut.PkScript); why != 0 || len(pout.TaprootTapTree) != 0 {
			external += txOut.Value
		}
	}
	if out > in {
		return nil, refuse("outputs exceed inputs")
	}
	plan.Fee = in - out
	plan.External = external + plan.Fee
	return plan, nil
}

// Signed is a signed PSBT and what it does.
type Signed struct {
	PSBT     string `json:"psbt"`
	Txid     string `json:"txid"`
	Signed   []int  `json:"signed"`
	External int64  `json:"external_sats"`
	Fee      int64  `json:"fee_sats"`
}

// Sign signs the plan's inputs: a partial signature for a P2WPKH input, the
// taproot key-path signature (BIP86 tweak) for a taproot one. Inputs are not
// finalized.
func (p *Plan) Sign() (*Signed, error) {
	tx := p.packet.UnsignedTx
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(tx.TxIn))
	for i, txIn := range tx.TxIn {
		prevOuts[txIn.PreviousOutPoint] = p.packet.Inputs[i].WitnessUtxo
	}
	hashes := txscript.NewTxSigHashes(tx, txscript.NewMultiPrevOutFetcher(prevOuts))
	for n, i := range p.inputs {
		m, t := p.matches[n], p.types[n]
		pin := &p.packet.Inputs[i]
		priv, err := p.key.privAt(m.path)
		if err != nil {
			return nil, fmt.Errorf("input %d: derivation failed", i)
		}
		utxo := pin.WitnessUtxo
		if m.kind == ScriptP2TR {
			sig, err := txscript.RawTxInTaprootSignature(tx, hashes, i, utxo.Value, utxo.PkScript, nil, t, priv)
			if err != nil {
				return nil, fmt.Errorf("input %d: signing failed", i)
			}
			pin.TaprootKeySpendSig = sig
			continue
		}
		sig, err := txscript.RawTxInWitnessSignature(tx, hashes, i, utxo.Value, utxo.PkScript, t, priv)
		if err != nil {
			return nil, fmt.Errorf("input %d: signing failed", i)
		}
		pub := priv.PubKey().SerializeCompressed()
		pin.PartialSigs = slices.DeleteFunc(pin.PartialSigs, func(s *psbt.PartialSig) bool { return bytes.Equal(s.PubKey, pub) })
		pin.PartialSigs = append(pin.PartialSigs, &psbt.PartialSig{PubKey: pub, Signature: sig})
	}
	encoded, err := p.packet.B64Encode()
	if err != nil {
		return nil, fmt.Errorf("psbt does not serialize")
	}
	return &Signed{PSBT: encoded, Txid: p.Txid, Signed: slices.Clone(p.inputs), External: p.External, Fee: p.Fee}, nil
}
