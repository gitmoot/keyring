// Package bitcoin signs Bitcoin PSBTs with an imported key that never leaves
// the keyring (gitmoot/keyring#187). Phase 1 covers the test networks only:
// regtest, testnet and signet. A service names the paths the key may sign
// for: BIP86 taproot key-path spends (purpose 86) and BIP84 P2WPKH spends
// (purpose 84), or for a single WIF key the one script kind.
//
// Nothing here formats a key, a PSBT or any part of either into an error:
// every refusal is a fixed reason with at most input or output indices.
package bitcoin

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

// Networks a service may name. Mainnet is phase 2 (owner, 2026-11-25).
const (
	Regtest = "regtest"
	Testnet = "testnet"
	Signet  = "signet"
	Mainnet = "mainnet"
)

// Script kinds: what a key signs for.
const (
	ScriptP2TR   = "p2tr"   // BIP86 taproot key path, no script tree
	ScriptP2WPKH = "p2wpkh" // BIP84 native segwit v0
)

// sighashTypes are the sighash names a service may allow, in the order the
// dashboard offers them. "default" is the taproot-only SIGHASH_DEFAULT; a
// P2WPKH input without a sighash field signs ALL.
var sighashTypes = []struct {
	name string
	t    txscript.SigHashType
}{
	{"default", txscript.SigHashDefault},
	{"all", txscript.SigHashAll},
	{"none", txscript.SigHashNone},
	{"single", txscript.SigHashSingle},
	{"all|anyonecanpay", txscript.SigHashAll | txscript.SigHashAnyOneCanPay},
	{"none|anyonecanpay", txscript.SigHashNone | txscript.SigHashAnyOneCanPay},
	{"single|anyonecanpay", txscript.SigHashSingle | txscript.SigHashAnyOneCanPay},
}

// SighashChoices lists the sighash names a service may allow, in order.
func SighashChoices() []string {
	names := make([]string, len(sighashTypes))
	for i, s := range sighashTypes {
		names[i] = s.name
	}
	return names
}

// sighashType returns the type a sighash name stands for.
func sighashType(name string) (txscript.SigHashType, bool) {
	for _, s := range sighashTypes {
		if s.name == name {
			return s.t, true
		}
	}
	return 0, false
}

// DefaultSighash is what a service allows when it lists none.
var DefaultSighash = []string{"default", "all"}

// MaxPaths bounds a service's path list; MaxAddresses one addresses call.
const (
	MaxPaths     = 32
	MaxAddresses = 1000
	maxDepth     = 10
	hardened     = hdkeychain.HardenedKeyStart
)

// ErrMainnet is the phase 1 refusal of a mainnet service.
var ErrMainnet = errors.New("network mainnet is not supported yet: phase 1 signs on regtest, testnet and signet only")

// Key errors. They never include the value.
var (
	ErrKeyFormat  = errors.New("the value is not a BIP32 extended private key (tprv/xprv) or a WIF private key")
	ErrKeyNetwork = errors.New("the key is for another network than the service's")
	ErrKeyDepth   = errors.New("the extended key is not a master key (depth 0); import the master tprv")
	ErrKeyKind    = errors.New("the key does not fit the service: an extended key needs paths, a WIF key needs script and no paths")
	ErrKeyUncompr = errors.New("the WIF key is for an uncompressed public key; segwit needs a compressed one")
)

func params(network string) (*chaincfg.Params, error) {
	switch network {
	case Regtest:
		return &chaincfg.RegressionNetParams, nil
	case Testnet:
		return &chaincfg.TestNet3Params, nil
	case Signet:
		return &chaincfg.SigNetParams, nil
	case Mainnet:
		return nil, ErrMainnet
	}
	return nil, errors.New("network must be regtest, testnet or signet")
}

// Path is one allowed derivation path: fixed components and, with a
// trailing /*, any non-hardened last index.
type Path struct {
	fixed    []uint32
	wildcard bool
	kind     string
}

// parseComponents reads "m/86'/1'/0'/0" (hardened as ' or h). With
// allowWildcard a last "*" is accepted.
func parseComponents(s string, allowWildcard bool) (fixed []uint32, wildcard bool, err error) {
	parts := strings.Split(s, "/")
	if parts[0] != "m" {
		return nil, false, errors.New("path must start with m")
	}
	parts = parts[1:]
	if len(parts) > maxDepth {
		return nil, false, fmt.Errorf("path is deeper than %d", maxDepth)
	}
	for i, p := range parts {
		if p == "*" && allowWildcard && i == len(parts)-1 {
			wildcard = true
			break
		}
		h := strings.HasSuffix(p, "'") || strings.HasSuffix(p, "h") || strings.HasSuffix(p, "H")
		if h {
			p = p[:len(p)-1]
		}
		if p == "" || (len(p) > 1 && p[0] == '0') || strings.TrimLeft(p, "0123456789") != "" {
			return nil, false, errors.New("path components are decimal indices, hardened with ' or h, and only a last * (not hardened)")
		}
		n, convErr := strconv.ParseUint(p, 10, 32)
		if convErr != nil || n >= hardened {
			return nil, false, errors.New("path index out of range")
		}
		if h {
			n += hardened
		}
		fixed = append(fixed, uint32(n))
	}
	return fixed, wildcard, nil
}

// ParsePath reads an allowed path such as "m/86'/1'/0'/0/*". Its purpose
// (first component, hardened) must be 86 or 84.
func ParsePath(s string) (Path, error) {
	fixed, wildcard, err := parseComponents(s, true)
	if err != nil {
		return Path{}, err
	}
	if len(fixed) == 0 {
		return Path{}, errors.New("path needs a purpose: m/86'/... (taproot) or m/84'/... (P2WPKH)")
	}
	p := Path{fixed: fixed, wildcard: wildcard}
	switch fixed[0] {
	case 86 + hardened:
		p.kind = ScriptP2TR
	case 84 + hardened:
		p.kind = ScriptP2WPKH
	default:
		return Path{}, errors.New("path purpose must be 86' (taproot) or 84' (P2WPKH)")
	}
	return p, nil
}

func formatPath(components []uint32) string {
	var b strings.Builder
	b.WriteString("m")
	for _, c := range components {
		b.WriteByte('/')
		if c >= hardened {
			b.WriteString(strconv.FormatUint(uint64(c-hardened), 10))
			b.WriteByte('\'')
		} else {
			b.WriteString(strconv.FormatUint(uint64(c), 10))
		}
	}
	return b.String()
}

// String is the path in the ' form, with /* if it has one.
func (p Path) String() string {
	s := formatPath(p.fixed)
	if p.wildcard {
		s += "/*"
	}
	return s
}

// matches reports whether a full derivation path is one this template allows.
func (p Path) matches(path []uint32) bool {
	n := len(p.fixed)
	if p.wildcard {
		if len(path) != n+1 || path[n] >= hardened {
			return false
		}
	} else if len(path) != n {
		return false
	}
	return slices.Equal(path[:n], p.fixed)
}

// Rules are a service's checked bitcoin settings.
type Rules struct {
	Network string
	params  *chaincfg.Params
	paths   []Path
	script  string // a WIF key's one script kind
	sighash map[txscript.SigHashType]bool
}

// NewRules checks a service's settings: network, paths (for an extended
// key) or script (for a WIF key), and the sighash types it allows.
func NewRules(network string, paths []string, script string, sighash []string) (*Rules, error) {
	p, err := params(network)
	if err != nil {
		return nil, err
	}
	r := &Rules{Network: network, params: p, script: script, sighash: map[txscript.SigHashType]bool{}}
	switch {
	case len(paths) == 0 && script == "":
		return nil, errors.New("set paths (for a tprv) or script (for a WIF key)")
	case len(paths) != 0 && script != "":
		return nil, errors.New("set paths (for a tprv) or script (for a WIF key), not both")
	case script != "" && script != ScriptP2TR && script != ScriptP2WPKH:
		return nil, errors.New("script must be p2tr or p2wpkh")
	case len(paths) > MaxPaths:
		return nil, fmt.Errorf("at most %d paths", MaxPaths)
	}
	// The addresses call names a path by its fixed part, so no two paths may
	// share it (m/86'/1'/0'/0 and m/86'/1'/0'/0/* would make the answer
	// depend on their order).
	seen := map[string]int{}
	// Settings are named by their place in the list, never quoted: the
	// messages reach the dashboard, and a key pasted into the wrong field
	// must not be shown back.
	for i, s := range paths {
		path, err := ParsePath(s)
		if err != nil {
			return nil, fmt.Errorf("path %d: %w", i+1, err)
		}
		lookup := formatPath(path.fixed)
		if other, ok := seen[lookup]; ok {
			return nil, fmt.Errorf("paths %d and %d are both looked up as %s: list one", other, i+1, lookup)
		}
		seen[lookup] = i + 1
		r.paths = append(r.paths, path)
	}
	if len(sighash) == 0 {
		sighash = DefaultSighash
	}
	for i, name := range sighash {
		t, ok := sighashType(name)
		if !ok {
			return nil, fmt.Errorf("sighash %d: want default, all, none, single, or one of those three with |anyonecanpay", i+1)
		}
		if r.sighash[t] {
			return nil, fmt.Errorf("sighash %d is listed twice", i+1)
		}
		r.sighash[t] = true
	}
	return r, nil
}

// allowed returns the script kind a full derivation path signs for.
func (r *Rules) allowed(path []uint32) (string, bool) {
	if r.script != "" {
		return r.script, len(path) == 0
	}
	for _, p := range r.paths {
		if p.matches(path) {
			return p.kind, true
		}
	}
	return "", false
}

// Key is an imported private key: a BIP32 master key or one WIF key.
type Key struct {
	master *hdkeychain.ExtendedKey
	single *btcec.PrivateKey
	fp     [4]byte
}

// isExtended reports whether s is shaped like a serialized BIP32 key, so
// an extended key with a bad checksum is reported as one.
func isExtended(s string) bool {
	return len(s) == 111 && (strings.HasPrefix(s, "tprv") || strings.HasPrefix(s, "xprv") || strings.HasPrefix(s, "tpub") || strings.HasPrefix(s, "xpub"))
}

func parseKey(value string, p *chaincfg.Params) (*Key, error) {
	value = strings.TrimSpace(value)
	if isExtended(value) {
		ext, err := hdkeychain.NewKeyFromString(value)
		if err != nil || !ext.IsPrivate() {
			return nil, ErrKeyFormat
		}
		if !ext.IsForNet(p) {
			return nil, ErrKeyNetwork
		}
		if ext.Depth() != 0 {
			return nil, ErrKeyDepth
		}
		pub, err := ext.ECPubKey()
		if err != nil {
			return nil, ErrKeyFormat
		}
		k := &Key{master: ext}
		copy(k.fp[:], address.Hash160(pub.SerializeCompressed()))
		return k, nil
	}
	wif, err := btcutil.DecodeWIF(value)
	if err != nil {
		return nil, ErrKeyFormat
	}
	if !wif.IsForNet(p) {
		return nil, ErrKeyNetwork
	}
	if !wif.CompressPubKey {
		return nil, ErrKeyUncompr
	}
	k := &Key{single: wif.PrivKey}
	copy(k.fp[:], address.Hash160(wif.PrivKey.PubKey().SerializeCompressed()))
	return k, nil
}

// ParseKey reads a stored value as the key of a service with rules r.
func ParseKey(value string, r *Rules) (*Key, error) {
	k, err := parseKey(value, r.params)
	if err != nil {
		return nil, err
	}
	if (k.master != nil) != (len(r.paths) != 0) {
		return nil, ErrKeyKind
	}
	return k, nil
}

// Fingerprint is the key's master fingerprint as PSBTs carry it: the first
// four bytes of HASH160 of the master (or single) public key, in hex.
func (k *Key) Fingerprint() string { return hex.EncodeToString(k.fp[:]) }

func (k *Key) fingerprint() uint32 { return binary.LittleEndian.Uint32(k.fp[:]) }

// privAt derives the private key at path.
func (k *Key) privAt(path []uint32) (*btcec.PrivateKey, error) {
	if k.single != nil {
		if len(path) != 0 {
			return nil, errors.New("a WIF key has no derivation")
		}
		return k.single, nil
	}
	ext := k.master
	for _, c := range path {
		var err error
		if ext, err = ext.Derive(c); err != nil {
			return nil, err
		}
	}
	return ext.ECPrivKey()
}

// pubAt derives the public key at path.
func (k *Key) pubAt(path []uint32) (*btcec.PublicKey, error) {
	priv, err := k.privAt(path)
	if err != nil {
		return nil, err
	}
	return priv.PubKey(), nil
}

// scriptFor is the output script kind pays to for pub.
func scriptFor(kind string, pub *btcec.PublicKey) []byte {
	if kind == ScriptP2TR {
		out := schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(pub))
		return append([]byte{txscript.OP_1, txscript.OP_DATA_32}, out...)
	}
	return append([]byte{txscript.OP_0, txscript.OP_DATA_20}, address.Hash160(pub.SerializeCompressed())...)
}

// addressFor is the address of kind for pub on p.
func addressFor(kind string, pub *btcec.PublicKey, p *chaincfg.Params) (string, error) {
	var a address.Address
	var err error
	if kind == ScriptP2TR {
		a, err = address.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootKeyNoScript(pub)), p)
	} else {
		a, err = address.NewAddressWitnessPubKeyHash(address.Hash160(pub.SerializeCompressed()), p)
	}
	if err != nil {
		return "", err
	}
	return a.EncodeAddress(), nil
}

// MaxSats bounds any amount: 21 million bitcoin.
const MaxSats = int64(btcutil.MaxSatoshi)

func validAmount(v int64) bool { return v >= 0 && v <= MaxSats }

// addSats adds within MaxSats.
func addSats(a, b int64) (int64, bool) {
	if b < 0 || a > math.MaxInt64-b || a+b > MaxSats {
		return 0, false
	}
	return a + b, true
}

// Info is what may be shown about a stored value that is a bitcoin key.
type Info struct {
	Fingerprint string
	Kind        string // "BIP32 master key", "BIP32 key at depth N", "WIF key"
	Networks    string // "test networks" or "mainnet"
}

// Inspect reports whether value is a bitcoin private key (any network) and
// what may be shown about it. The dashboard never shows such a value.
func Inspect(value string) (Info, bool) {
	value = strings.TrimSpace(value)
	if isExtended(value) {
		ext, err := hdkeychain.NewKeyFromString(value)
		if err != nil || !ext.IsPrivate() {
			return Info{}, false
		}
		info := Info{Kind: "BIP32 master key", Networks: "mainnet"}
		if ext.Depth() != 0 {
			info.Kind = fmt.Sprintf("BIP32 key at depth %d", ext.Depth())
		}
		if ext.IsForNet(&chaincfg.TestNet3Params) {
			info.Networks = "test networks"
		}
		if pub, err := ext.ECPubKey(); err == nil {
			info.Fingerprint = hex.EncodeToString(address.Hash160(pub.SerializeCompressed())[:4])
		}
		return info, true
	}
	wif, err := btcutil.DecodeWIF(value)
	if err != nil {
		return Info{}, false
	}
	info := Info{Kind: "WIF key", Networks: "mainnet", Fingerprint: hex.EncodeToString(address.Hash160(wif.SerializePubKey())[:4])}
	if wif.IsForNet(&chaincfg.TestNet3Params) {
		info.Networks = "test networks"
	}
	return info, true
}

// Description is what the import command shows the owner to check.
type Description struct {
	Fingerprint string
	Kind        string
	Network     string
	Addresses   []Address
}

// Describe checks value as a key for network and lists its first receive
// addresses: m/86'/1'/0'/0/0 and m/84'/1'/0'/0/0 for an extended key, the
// key's own taproot and P2WPKH addresses for a WIF key.
func Describe(value, network string) (Description, error) {
	p, err := params(network)
	if err != nil {
		return Description{}, err
	}
	k, err := parseKey(value, p)
	if err != nil {
		return Description{}, err
	}
	d := Description{Fingerprint: k.Fingerprint(), Network: network, Kind: "BIP32 master key"}
	type spot struct {
		kind string
		path []uint32
	}
	spots := []spot{{ScriptP2TR, []uint32{86 + hardened, 1 + hardened, hardened, 0, 0}}, {ScriptP2WPKH, []uint32{84 + hardened, 1 + hardened, hardened, 0, 0}}}
	if k.single != nil {
		d.Kind = "WIF key"
		spots = []spot{{ScriptP2TR, nil}, {ScriptP2WPKH, nil}}
	}
	for _, s := range spots {
		pub, err := k.pubAt(s.path)
		if err != nil {
			return Description{}, err
		}
		addr, err := addressFor(s.kind, pub, p)
		if err != nil {
			return Description{}, err
		}
		d.Addresses = append(d.Addresses, Address{Path: formatPath(s.path), Script: s.kind, PublicKey: hex.EncodeToString(pub.SerializeCompressed()), Address: addr})
	}
	return d, nil
}

// Address is one derived receive address.
type Address struct {
	Index     uint32 `json:"index"`
	Path      string `json:"path"`
	Script    string `json:"script"`
	PublicKey string `json:"public_key"` // compressed SEC; taproot internal key is its last 32 bytes
	Address   string `json:"address"`
}

// AddressList answers an addresses call.
type AddressList struct {
	Fingerprint string    `json:"fingerprint"`
	Network     string    `json:"network"`
	Path        string    `json:"path"`
	Addresses   []Address `json:"addresses"`
}

// Addresses derives count addresses from index from below path, which must
// be one of the service's paths without its /* (or the whole path when it
// has none, or "m" for a WIF key).
func Addresses(k *Key, r *Rules, path string, from, count uint32) (*AddressList, error) {
	if count == 0 || count > MaxAddresses {
		return nil, fmt.Errorf("count must be 1-%d", MaxAddresses)
	}
	fixed, _, err := parseComponents(path, false)
	if err != nil {
		return nil, errors.New("path is not a derivation path such as m/86'/1'/0'/0")
	}
	list := &AddressList{Fingerprint: k.Fingerprint(), Network: r.Network, Path: formatPath(fixed), Addresses: []Address{}}
	single := func(kind string) (*AddressList, error) {
		if from != 0 {
			return nil, errors.New("this path has one address: from must be 0")
		}
		pub, err := k.pubAt(fixed)
		if err != nil {
			return nil, errors.New("the key cannot derive this path")
		}
		addr, err := addressFor(kind, pub, r.params)
		if err != nil {
			return nil, errors.New("the key cannot derive this path")
		}
		list.Addresses = append(list.Addresses, Address{Index: 0, Path: list.Path, Script: kind, PublicKey: hex.EncodeToString(pub.SerializeCompressed()), Address: addr})
		return list, nil
	}
	if r.script != "" {
		if len(fixed) != 0 {
			return nil, errors.New("a WIF key's only path is m")
		}
		return single(r.script)
	}
	for _, p := range r.paths {
		if !slices.Equal(p.fixed, fixed) {
			continue
		}
		if !p.wildcard {
			return single(p.kind)
		}
		if uint64(from)+uint64(count) > uint64(hardened) {
			return nil, errors.New("from + count must stay below 2^31 (non-hardened indices)")
		}
		parent := k.master
		for _, c := range fixed {
			if parent, err = parent.Derive(c); err != nil {
				return nil, errors.New("the key cannot derive this path")
			}
		}
		for i := from; i < from+count; i++ {
			child, err := parent.Derive(i)
			if err != nil {
				// BIP32: an index whose key is invalid is skipped.
				continue
			}
			pub, err := child.ECPubKey()
			if err != nil {
				continue
			}
			addr, err := addressFor(p.kind, pub, r.params)
			if err != nil {
				return nil, errors.New("the key cannot derive this path")
			}
			list.Addresses = append(list.Addresses, Address{Index: i, Path: formatPath(append(slices.Clone(fixed), i)), Script: p.kind, PublicKey: hex.EncodeToString(pub.SerializeCompressed()), Address: addr})
		}
		return list, nil
	}
	return nil, errors.New("path is not one of the service's paths (give it without the trailing /*)")
}

// Watch is the public side of one allowed path: a watch-only output
// descriptor (without checksum) and its first address.
type Watch struct {
	Path         string
	Descriptor   string
	FirstAddress string
}

// WatchOnly lists the public side of every path the service signs for, so
// the owner can check it or import it watch-only. Nothing private.
func WatchOnly(k *Key, r *Rules) ([]Watch, error) {
	fn := func(kind string) string {
		if kind == ScriptP2TR {
			return "tr"
		}
		return "wpkh"
	}
	if r.script != "" {
		pub := k.single.PubKey()
		addr, err := addressFor(r.script, pub, r.params)
		if err != nil {
			return nil, err
		}
		return []Watch{{Path: "m", Descriptor: fn(r.script) + "(" + hex.EncodeToString(pub.SerializeCompressed()) + ")", FirstAddress: addr}}, nil
	}
	var out []Watch
	for _, p := range r.paths {
		ext := k.master
		for _, c := range p.fixed {
			var err error
			if ext, err = ext.Derive(c); err != nil {
				return nil, errors.New("the key cannot derive this path")
			}
		}
		first := ext
		if p.wildcard {
			var err error
			if first, err = ext.Derive(0); err != nil {
				return nil, errors.New("the key cannot derive this path")
			}
		}
		pub, err := first.ECPubKey()
		if err != nil {
			return nil, err
		}
		addr, err := addressFor(p.kind, pub, r.params)
		if err != nil {
			return nil, err
		}
		origin := "[" + k.Fingerprint() + strings.TrimPrefix(strings.ReplaceAll(formatPath(p.fixed), "'", "h"), "m") + "]"
		var body string
		if p.wildcard {
			public, err := ext.Neuter()
			if err != nil {
				return nil, err
			}
			body = origin + public.String() + "/*"
		} else {
			body = origin + hex.EncodeToString(pub.SerializeCompressed())
		}
		out = append(out, Watch{Path: p.String(), Descriptor: fn(p.kind) + "(" + body + ")", FirstAddress: addr})
	}
	return out, nil
}
