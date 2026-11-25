package server

// Bitcoin PSBT signing (auth "bitcoin-psbt-sign", #187): the keyring signs
// PSBT inputs with an imported key that never leaves it, on the service's
// test network and paths, within the grant's sats limits.
//
// Routes: "/_keyring/bitcoin/<service>/<action>".
//   POST sign-psbt {"psbt": "<base64>", "inputs": [0, 2]}
//        -> {"psbt", "txid", "signed", "external_sats", "fee_sats"}
//   GET  addresses?path=m/86'/1'/0'/0&from=0&count=20
//        -> {"fingerprint", "network", "path", "addresses": [...]}

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gitmoot/keyring/internal/bitcoin"
	"github.com/gitmoot/keyring/internal/fileutil"
	"github.com/gitmoot/keyring/internal/policy"
)

const (
	bitcoinPrefix          = "/_keyring/bitcoin/"
	bitcoinSignAction      = "sign-psbt"
	bitcoinAddressesAction = "addresses"
	// bitcoinBodyLimit bounds a sign-psbt body: a reveal PSBT may carry a
	// whole inscription in its tapscript leaf.
	bitcoinBodyLimit = 4 << 20
)

// bitcoinRoute resolves "/_keyring/bitcoin/<service>/<action>" to the
// service and action, or "".
func bitcoinRoute(path string) (service, action string) {
	rest, found := strings.CutPrefix(path, bitcoinPrefix)
	if !found {
		return "", ""
	}
	service, action, found = strings.Cut(rest, "/")
	if !found || service == "" || action != bitcoinSignAction && action != bitcoinAddressesAction {
		return "", ""
	}
	for _, r := range service {
		if r == '%' || r == '?' || r < 33 || r > 126 {
			return "", ""
		}
	}
	return service, action
}

// BitcoinSpendPath is where the daily bitcoin totals of the keyring whose
// store (or instance state) is base are kept: keys.json ->
// keys.json.bitcoin-spend.json. The whole name is kept, so two keyrings
// sharing a directory (even wallet.json and wallet.sealed) keep separate
// totals, and a restart does not reset bitcoin_max_sats_per_day.
func BitcoinSpendPath(base string) string {
	return base + ".bitcoin-spend.json"
}

// bitcoinKeyRefused is the note of a call refused because its service, not
// a Bitcoin signing service, would send a stored Bitcoin key.
const bitcoinKeyRefused = "bitcoin key refused"

// bitcoinValues are the values of keys that are Bitcoin private keys, nil
// when there are none; Swap finds them once per snapshot.
func bitcoinValues(keys map[string]string) map[string]bool {
	var found map[string]bool
	for _, value := range keys {
		if bitcoin.IsKey(value) {
			if found == nil {
				found = map[string]bool{}
			}
			found[value] = true
		}
	}
	return found
}

// sendsBitcoinKey reports whether svc, other than a Bitcoin signing service,
// would send a stored Bitcoin key: key, a value of pool, or a value it names
// (extra headers, OAuth client secret). The settings put in force are
// checked for this first (policy.CheckBitcoinKeys); this is the last line
// before anything goes upstream.
func (s *snapshot) sendsBitcoinKey(svc policy.Service, key string, pool []string) bool {
	if len(s.bitcoinValues) == 0 || svc.Auth == policy.AuthBitcoinPSBTSign {
		return false
	}
	if s.bitcoinValues[key] {
		return true
	}
	for _, name := range pool {
		if s.bitcoinValues[s.keys[name]] {
			return true
		}
	}
	for _, name := range svc.KeyNames() {
		if s.bitcoinValues[s.keys[name]] {
			return true
		}
	}
	return false
}

type bitcoinSignRequest struct {
	PSBT   string `json:"psbt"`
	Inputs []int  `json:"inputs"`
}

var errBitcoinBody = errors.New(`body must be one JSON object {"psbt": "<base64>", "inputs": [0, ...]} of at most 4 MiB`)

func decodeBitcoinSign(body io.Reader) (bitcoinSignRequest, error) {
	// Inputs decode as pointers: encoding/json leaves an int at 0 for null,
	// which would select input 0 (review of #188).
	var raw struct {
		PSBT   string `json:"psbt"`
		Inputs []*int `json:"inputs"`
	}
	var in bitcoinSignRequest
	decoder := json.NewDecoder(io.LimitReader(body, bitcoinBodyLimit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return in, errBitcoinBody
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return in, errBitcoinBody
	}
	if raw.PSBT == "" || len(raw.Inputs) == 0 {
		return in, errors.New("psbt and inputs are required")
	}
	in.PSBT = raw.PSBT
	for _, i := range raw.Inputs {
		if i == nil {
			return in, errors.New("inputs must be input indices, not null")
		}
		in.Inputs = append(in.Inputs, *i)
	}
	return in, nil
}

type bitcoinAddressQuery struct {
	path        string
	from, count uint32
}

func decodeBitcoinAddresses(raw string) (bitcoinAddressQuery, error) {
	q := bitcoinAddressQuery{count: 20}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return q, errors.New("query must be path, from and count")
	}
	for name, v := range values {
		if len(v) != 1 {
			return q, errors.New("give each of path, from and count once")
		}
		switch name {
		case "path":
			q.path = v[0]
		case "from", "count":
			n, err := strconv.ParseUint(v[0], 10, 32)
			if err != nil {
				return q, errors.New(name + " must be a whole number")
			}
			if name == "from" {
				q.from = uint32(n)
			} else {
				q.count = uint32(n)
			}
		default:
			return q, errors.New("query must be path, from and count")
		}
	}
	if q.path == "" {
		return q, errors.New("path is required, e.g. path=m/86'/1'/0'/0")
	}
	return q, nil
}

// BitcoinAudit is what the audit records about one signature: never the
// PSBT or the key.
type BitcoinAudit struct {
	Network      string `json:"network"`
	Txid         string `json:"txid"`
	Inputs       []int  `json:"inputs"`
	ExternalSats int64  `json:"external_sats"`
	FeeSats      int64  `json:"fee_sats"`
}

// bitcoinSpend is each role's and service's sats signed on day.
type bitcoinSpend struct {
	mu   sync.Mutex
	path string
	// unavailable: the file could not be read; a grant with a daily limit
	// signs nothing until it can.
	unavailable bool
	day         string
	sats        map[[2]string]int64
}

type bitcoinSpendFile struct {
	Version int            `json:"version"`
	Day     string         `json:"day"`
	Spent   []bitcoinSpent `json:"spent"`
}

type bitcoinSpent struct {
	Role    string `json:"role"`
	Service string `json:"service"`
	Sats    int64  `json:"sats"`
}

const bitcoinSpendBytes = 1 << 20

// OpenBitcoinSpend keeps the daily bitcoin totals in path; call it once
// before serving. A file that cannot be trusted is left as it is and every
// grant with bitcoin_max_sats_per_day is refused until it is fixed.
func (h *Handler) OpenBitcoinSpend(path string) error {
	b := &h.bitcoinSpend
	b.mu.Lock()
	defer b.mu.Unlock()
	b.path, b.unavailable = path, true
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return errors.New("bitcoin spend directory is unavailable or writable by other users")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		b.unavailable = false
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > bitcoinSpendBytes {
		return errors.New("bitcoin spend file is unavailable, unsafe or oversized")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return errors.New("bitcoin spend file cannot be read")
	}
	var file bitcoinSpendFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&file) != nil || file.Version != 1 {
		return errors.New("bitcoin spend file is not valid")
	}
	if _, err := time.Parse(time.DateOnly, file.Day); err != nil {
		return errors.New("bitcoin spend file is not valid")
	}
	sats := map[[2]string]int64{}
	for _, s := range file.Spent {
		if s.Sats < 0 {
			return errors.New("bitcoin spend file is not valid")
		}
		sats[[2]string{s.Role, s.Service}] = s.Sats
	}
	b.day, b.sats, b.unavailable = file.Day, sats, false
	return nil
}

// save writes the totals; callers hold b.mu.
func (b *bitcoinSpend) save() error {
	file := bitcoinSpendFile{Version: 1, Day: b.day, Spent: []bitcoinSpent{}}
	for k, n := range b.sats {
		file.Spent = append(file.Spent, bitcoinSpent{Role: k[0], Service: k[1], Sats: n})
	}
	raw, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return fileutil.WriteAtomic(b.path, append(raw, '\n'), 0o600)
}

// sign signs plan if the day's total stays within limit (0: no limit), and
// counts it. With a limit, the signature is returned only once the new
// total is on disk.
func (b *bitcoinSpend) sign(role, service string, limit int64, plan *bitcoin.Plan, now func() time.Time) (*bitcoin.Signed, int, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// The day is read under the lock and never goes back: a request that
	// started before midnight counts toward the new day rather than reset it.
	if day := now().UTC().Format(time.DateOnly); day > b.day {
		b.day, b.sats = day, nil
	}
	if b.sats == nil {
		b.sats = map[[2]string]int64{}
	}
	k := [2]string{role, service}
	persisted := b.path != "" && !b.unavailable
	if limit > 0 {
		if !persisted {
			return nil, http.StatusServiceUnavailable, "bitcoin_max_sats_per_day needs the daily bitcoin total on disk, which is unavailable"
		}
		if plan.External > limit-b.sats[k] {
			return nil, http.StatusBadRequest, fmt.Sprintf("bitcoin_max_sats_per_day: %d sats signed today plus %d external sats is over the limit of %d", b.sats[k], plan.External, limit)
		}
	}
	signed, err := plan.Sign()
	if err != nil {
		return nil, http.StatusServiceUnavailable, "bitcoin signing failed"
	}
	before := b.sats[k]
	b.sats[k] = min(before, math.MaxInt64-plan.External) + plan.External
	if persisted {
		if err := b.save(); err != nil && limit > 0 {
			b.sats[k] = before
			return nil, http.StatusServiceUnavailable, "the daily bitcoin total could not be saved"
		}
	}
	return signed, http.StatusOK, ""
}

// serveBitcoin answers a bitcoin-psbt-sign call after access and the daily
// request limit were checked.
func (h *Handler) serveBitcoin(w http.ResponseWriter, svc policy.Service, key, role, service string, access policy.Access,
	action string, signReq bitcoinSignRequest, query bitcoinAddressQuery, start time.Time, rec *auditRecord, fail func(int, string)) {
	rules, err := svc.Bitcoin.Rules()
	if err != nil {
		h.refund(role, service, access.DailyRequests, start)
		fail(http.StatusServiceUnavailable, "bitcoin settings unavailable")
		return
	}
	k, err := bitcoin.ParseKey(key, rules)
	if err != nil {
		// The key errors are fixed texts; never the value.
		h.refund(role, service, access.DailyRequests, start)
		fail(http.StatusServiceUnavailable, "bitcoin key unavailable: "+err.Error())
		return
	}
	var reply any
	if action == bitcoinAddressesAction {
		list, err := bitcoin.Addresses(k, rules, query.path, query.from, query.count)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		rec.Note, reply = "addresses", list
	} else {
		plan, err := bitcoin.Prepare(k, rules, signReq.PSBT, signReq.Inputs)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		if max := access.BitcoinMaxSatsPerTx; max > 0 && plan.External > max {
			fail(http.StatusBadRequest, fmt.Sprintf("bitcoin_max_sats_per_tx: %d external sats is over the limit of %d", plan.External, max))
			return
		}
		signed, status, why := h.bitcoinSpend.sign(role, service, access.BitcoinMaxSatsPerDay, plan, h.now)
		if signed == nil {
			fail(status, why)
			return
		}
		rec.Bitcoin = &BitcoinAudit{Network: rules.Network, Txid: signed.Txid, Inputs: signed.Signed, ExternalSats: signed.External, FeeSats: signed.Fee}
		reply = signed
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	rec.Status = http.StatusOK
	sink := &countingWriter{w: w}
	_ = json.NewEncoder(sink).Encode(reply)
	rec.Bytes = sink.n
}
