package dashboard

import (
	"errors"
	"net/http"
	"os"
	"slices"
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
// signatures from the audit log.
func (b *Backend) bitcoinPage(name string, svc policy.Service) map[string]any {
	data := map[string]any{"Bitcoin": svc.Bitcoin}
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

// The Bitcoin fields of Connect and of a service's edit form (#201). The
// networks are the test ones; mainnet is phase 2 and refused by validation
// whatever is posted.
var (
	bitcoinNetworks = []string{bitcoin.Regtest, bitcoin.Testnet, bitcoin.Signet}
	// defaultBitcoinPaths: BIP86 receive and change on test networks.
	defaultBitcoinPaths = []string{"m/86'/1'/0'/0/*", "m/86'/1'/0'/1/*"}
)

// bitcoinChoice is one option, select entry or checkbox of the form.
type bitcoinChoice struct {
	Value string
	On    bool
}

// bitcoinForm is what the forms show: paths for an extended key, the script
// for a WIF key.
type bitcoinForm struct {
	WIF                        bool
	Paths                      string
	Networks, Scripts, Sighash []bitcoinChoice
}

// bitcoinFormOf fills the form from settings, or with the defaults for a new
// service when s is nil. Only lines that are paths are shown again: a
// refused form may hold a key typed into the wrong field.
func bitcoinFormOf(s *policy.Bitcoin, wif bool) *bitcoinForm {
	if s == nil {
		s = &policy.Bitcoin{Network: bitcoin.Regtest, Paths: defaultBitcoinPaths, Script: bitcoin.ScriptP2TR}
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
	f := &bitcoinForm{WIF: wif, Paths: strings.Join(paths, "\n")}
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

// bitcoinKeyProblem returns why the key svc names, in the store snapshot
// keys, cannot sign for it, or "". The texts are fixed and never carry the
// value. Callers have validated the config, so the rules are good.
func bitcoinKeyProblem(svc policy.Service, keys map[string]string) string {
	rules, err := svc.Bitcoin.Rules()
	if err != nil {
		return "bitcoin: " + err.Error()
	}
	if _, err := bitcoin.ParseKey(keys[svc.Key], rules); err != nil {
		return svc.Key + " cannot sign for this service: " + err.Error() + "."
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
