package dashboard

import (
	"errors"
	"os"
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
