package dashboard

import (
	"errors"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gitmoot/keyring/internal/bitcoin"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// Bitcoin keys (#187) are never shown, not even after the password: the
// owner keeps the backup. A value is a bitcoin key by its format (tprv/xprv
// or WIF), so a key pasted with Add key is covered before any service uses
// it, and every value of a key a bitcoin-psbt-sign service names is covered
// whatever its format. The key page shows its fingerprint and the service
// page the watch-only side of each path instead.

// neverShown reports whether row's values must never be shown, with what may
// be said about the first one that is a bitcoin key.
func neverShown(cfg *policy.Config, row keyRow, keys map[string]string) (*bitcoin.Info, bool) {
	never := false
	for _, svc := range cfg.Services {
		if base, _ := store.SplitPart(svc.Key); base == row.Name && svc.Auth == policy.AuthBitcoinPSBTSign {
			never = true
		}
	}
	for _, full := range row.valueNames() {
		if info, ok := bitcoin.Inspect(keys[full]); ok {
			return &info, true
		}
	}
	return nil, never
}

// bitcoinSignature is one row of a service's signatures table.
type bitcoinSignature struct {
	Time, Role string
	server.BitcoinAudit
}

// bitcoinSignatureDays and bitcoinSignatureRows bound the table.
const (
	bitcoinSignatureDays = 30
	bitcoinSignatureRows = 50
)

// bitcoinPage is what the service page shows for a bitcoin-psbt-sign
// service: its rules, the watch-only side of its paths and the recent
// signatures from the audit log; for a mainnet service the limits it
// enforces.
func (b *Backend) bitcoinPage(name string, svc policy.Service) map[string]any {
	data := map[string]any{"Bitcoin": svc.Bitcoin, "Mainnet": svc.BitcoinMainnet(),
		"MainnetMaxTx": policy.BitcoinMainnetMaxSatsPerTx, "MainnetMaxDay": policy.BitcoinMainnetMaxSatsPerDay,
		"MainnetMaxFee": policy.BitcoinMainnetMaxFeeSats, "MainnetMaxFeeRate": policy.BitcoinMainnetMaxFeeRate}
	keys, err := store.Load(b.StorePath)
	if err != nil {
		data["BitcoinKeyError"] = "The key store could not be read."
	} else if rules, err := svc.Bitcoin.Rules(); err != nil {
		data["BitcoinKeyError"] = err.Error()
	} else if k, err := bitcoin.ParseKey(keys[svc.Key], rules); err != nil {
		// Fixed texts; never the value.
		data["BitcoinKeyError"] = err.Error()
	} else if watch, err := bitcoin.WatchOnly(k, rules); err != nil {
		data["BitcoinKeyError"] = "The key cannot derive the service's paths."
	} else {
		data["BitcoinFingerprint"], data["BitcoinWatch"] = k.Fingerprint(), watch
		if other := b.Proxy.Config().BitcoinKeyOnOtherNetwork(name, keys); other != "" {
			data["BitcoinKeyError"] = sameKeyMessage(svc.Key, other)
		}
	}
	now := b.Now()
	rows, _, err := server.SearchAudit(b.rules().AuditLog, now.Add(-bitcoinSignatureDays*24*time.Hour), now.Add(time.Minute), server.AuditFilter{Service: name, Bitcoin: true})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		data["SignaturesError"] = "The audit log could not be read."
	}
	var signatures []bitcoinSignature
	for _, row := range rows[:min(len(rows), bitcoinSignatureRows)] {
		signatures = append(signatures, bitcoinSignature{Time: row.Time, Role: row.Role, BitcoinAudit: *row.Bitcoin})
	}
	data["Signatures"], data["SignatureDays"] = signatures, bitcoinSignatureDays
	return data
}

// The Bitcoin fields of Connect and of a service's edit form (#201). A new
// service starts on its key's side of mainnet, with BIP86 receive and change
// paths there; the page's script swaps those paths when the network is
// changed between the test networks and mainnet.
var bitcoinNetworks = []string{bitcoin.Mainnet, bitcoin.Regtest, bitcoin.Testnet, bitcoin.Signet}

// bitcoinChoice is one option, select entry or checkbox of the form.
type bitcoinChoice struct {
	Value string
	On    bool
}

// bitcoinForm is what the forms show: paths for an extended key, the script
// for a WIF key. Mainnet is the network shown; Test and Main are each
// side's presets (the script swaps the taproot ones into Paths, and shows
// the side's SegWit hint); the Max fields are the mainnet ceilings and fee
// cap the mainnet notice names.
type bitcoinForm struct {
	WIF                               bool
	Mainnet                           bool
	Paths                             string
	Test, Main                        bitcoinPresets
	Networks, Scripts, Sighash        []bitcoinChoice
	MaxTx, MaxDay, MaxFee, MaxFeeRate int
}

// bitcoinFormOf fills the form from settings, or with the defaults for a new
// service when s is nil: on mainnet for a mainnet key (mainnetKey), on
// regtest otherwise. Only lines that are paths are shown again: a refused
// form may hold a key typed into the wrong field.
func bitcoinFormOf(s *policy.Bitcoin, wif, mainnetKey bool) *bitcoinForm {
	if s == nil {
		s = &policy.Bitcoin{Network: bitcoin.Regtest, Paths: bitcoin.TestPresets.Taproot, Script: bitcoin.ScriptP2TR}
		if mainnetKey {
			s.Network, s.Paths = bitcoin.Mainnet, bitcoin.MainnetPresets.Taproot
		}
	}
	sighash := s.Sighash
	if len(sighash) == 0 {
		sighash = bitcoin.DefaultSighash
	}
	var paths []string
	for _, p := range s.Paths {
		if _, err := bitcoin.ParsePath(p); err == nil {
			paths = append(paths, p)
		}
	}
	mainnet := s.Network == bitcoin.Mainnet
	f := &bitcoinForm{WIF: wif, Mainnet: mainnet, Paths: strings.Join(paths, "\n"),
		Test: presetsOf("test", bitcoin.TestPresets, mainnet), Main: presetsOf("mainnet", bitcoin.MainnetPresets, !mainnet),
		MaxTx: policy.BitcoinMainnetMaxSatsPerTx, MaxDay: policy.BitcoinMainnetMaxSatsPerDay,
		MaxFee: policy.BitcoinMainnetMaxFeeSats, MaxFeeRate: policy.BitcoinMainnetMaxFeeRate}
	for _, n := range bitcoinNetworks {
		f.Networks = append(f.Networks, bitcoinChoice{n, n == s.Network})
	}
	for _, script := range []string{bitcoin.ScriptP2TR, bitcoin.ScriptP2WPKH} {
		f.Scripts = append(f.Scripts, bitcoinChoice{script, script == s.Script})
	}
	for _, h := range bitcoin.SighashChoices() {
		f.Sighash = append(f.Sighash, bitcoinChoice{h, slices.Contains(sighash, h)})
	}
	return f
}

// bitcoinPresets is one side's bitcoin.Presets as the form writes it: the
// taproot paths one per line, the SegWit ones for the hint, which shows
// only for the side of the network shown (Hidden otherwise).
type bitcoinPresets struct {
	Side    string
	Hidden  bool
	Taproot string
	SegWit  []string
}

func presetsOf(side string, p bitcoin.Presets, hidden bool) bitcoinPresets {
	return bitcoinPresets{Side: side, Hidden: hidden, Taproot: strings.Join(p.Taproot, "\n"), SegWit: p.SegWit}
}

// bitcoinFromForm reads the posted Bitcoin fields, with the message to show
// if they cannot be used. The default sighash pair is stored as no list, as
// access.json may write it.
func bitcoinFromForm(r *http.Request) (*policy.Bitcoin, string) {
	s := &policy.Bitcoin{Network: r.PostFormValue("network"), Script: strings.TrimSpace(r.PostFormValue("script"))}
	for line := range strings.Lines(r.PostFormValue("paths")) {
		if path := strings.TrimSpace(line); path != "" {
			s.Paths = append(s.Paths, path)
		}
	}
	s.Sighash = r.PostForm["sighash"]
	if len(s.Sighash) == 0 {
		return s, "Tick at least one sighash type; default and all are the usual ones."
	}
	if slices.Equal(s.Sighash, bitcoin.DefaultSighash) {
		s.Sighash = nil
	}
	return s, ""
}

// sameKeyMessage refuses key, which service other on the other side of
// mainnet also signs with (policy.AccessList.BitcoinKeyOnOtherNetwork).
func sameKeyMessage(key, other string) string {
	return key + " is the same key as service " + other + "'s on another network; mainnet and the test networks need different keys."
}

// bitcoinKeyProblem returns why the key service name of next names, in the
// store snapshot keys, cannot sign for it, or "": it does not fit the
// service, or service is on the other side of mainnet from another one with
// the same key. The texts are fixed and never carry the value. Callers have
// validated next, so the rules are good.
func bitcoinKeyProblem(next policy.AccessList, name string, keys map[string]string) string {
	svc := next.Services[name]
	rules, err := svc.Bitcoin.Rules()
	if err != nil {
		return "bitcoin: " + err.Error()
	}
	if _, err := bitcoin.ParseKey(keys[svc.Key], rules); err != nil {
		return svc.Key + " cannot sign for this service: " + err.Error() + "."
	}
	if other := next.BitcoinKeyOnOtherNetwork(name, keys); other != "" {
		return sameKeyMessage(svc.Key, other)
	}
	return ""
}

// bitcoinChanges names the Bitcoin settings an edit changed. No sighash
// list is the default pair.
func bitcoinChanges(old, now *policy.Bitcoin) []string {
	if old == nil {
		old = &policy.Bitcoin{}
	}
	if now == nil {
		now = &policy.Bitcoin{}
	}
	sighash := func(s *policy.Bitcoin) []string {
		if len(s.Sighash) == 0 {
			return bitcoin.DefaultSighash
		}
		return s.Sighash
	}
	var changed []string
	for _, c := range []struct {
		name string
		diff bool
	}{
		{"bitcoin.network", old.Network != now.Network}, {"bitcoin.paths", !slices.Equal(old.Paths, now.Paths)},
		{"bitcoin.script", old.Script != now.Script}, {"bitcoin.sighash", !slices.Equal(sighash(old), sighash(now))},
	} {
		if c.diff {
			changed = append(changed, c.name)
		}
	}
	return changed
}

// raisesMainnetGrant reports whether replacing a role's grant before (had:
// it had one) with after creates or raises it: a new grant, one that had
// ended, or a higher sats limit. Those take the typed confirmation.
func raisesMainnetGrant(before policy.Access, had bool, after policy.Access, now time.Time) bool {
	return !had || before.Expired(now) ||
		after.BitcoinMaxSatsPerTx > before.BitcoinMaxSatsPerTx || after.BitcoinMaxSatsPerDay > before.BitcoinMaxSatsPerDay
}

// mainnetConfirmProblem is the message when the service name or the daily
// limit typed to confirm a mainnet grant is not exactly service and daily
// (spaces around them aside), "" when both are.
func mainnetConfirmProblem(service string, daily int64, typedService, typedDaily string) string {
	want := strconv.FormatInt(daily, 10)
	if strings.TrimSpace(typedService) == service && strings.TrimSpace(typedDaily) == want {
		return ""
	}
	return "This grant signs real bitcoin on mainnet: to confirm it, type the service name (" + service + ") and the daily limit in sats (" + want + ") exactly. Nothing was saved."
}

// mainnetGrantFromForm is the grant approving an access request gives for
// mainnet service: full access within the sats limits posted for it, which
// the posted service name and daily limit must confirm. It returns the
// message to show when they do not.
func mainnetGrantFromForm(r *http.Request, service string) (policy.Access, string) {
	acc := fullAccess()
	for _, limit := range []struct {
		field string
		into  *int64
	}{{"max_sats_tx." + service, &acc.BitcoinMaxSatsPerTx}, {"max_sats_day." + service, &acc.BitcoinMaxSatsPerDay}} {
		n, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue(limit.field)), 10, 64)
		if err != nil || n <= 0 {
			return acc, service + " signs on mainnet: give both sats limits, per PSBT and per day, as whole numbers above 0."
		}
		*limit.into = n
	}
	if err := policy.CheckBitcoinMainnetGrant(acc); err != nil {
		return acc, service + ": " + err.Error() + "."
	}
	return acc, mainnetConfirmProblem(service, acc.BitcoinMaxSatsPerDay, r.PostFormValue("confirm_service."+service), r.PostFormValue("confirm_daily."+service))
}
