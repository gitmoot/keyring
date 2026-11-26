package server

// Bitcoin PSBT signing (auth "bitcoin-psbt-sign", #187): the keyring signs
// PSBT inputs with an imported key that never leaves it, on the service's
// network and paths, within the grant's sats limits. On mainnet a grant has
// both limits (policy.CheckBitcoinMainnetGrant), the fee is capped
// (policy.BitcoinMainnetFeeRefusal) and every signature runs the rules'
// notify_command.
//
// Routes: "/_keyring/bitcoin/<service>/<action>".
//   POST sign-psbt {"psbt": "<base64>", "inputs": [0, 2]}
//        -> {"psbt", "txid", "signed", "external_sats", "fee_sats", "vbytes"}
//   GET  addresses?path=m/86'/1'/0'/0&from=0&count=20
//        -> {"fingerprint", "network", "path", "addresses": [...]}

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
var bitcoinKeyRefused = policy.ErrBitcoinKeyRefused.Error()

// refusedValues are the values of keys that policy.RefuseBitcoinKeys refuses
// to send, nil when there are none; Swap finds them once per snapshot, so a
// call only looks its values up.
func refusedValues(keys map[string]string) map[string]bool {
	var refused map[string]bool
	for _, value := range keys {
		if policy.RefuseBitcoinKeys(value) != nil {
			if refused == nil {
				refused = map[string]bool{}
			}
			refused[value] = true
		}
	}
	return refused
}

// sendsBitcoinKey reports whether svc, other than a Bitcoin signing service,
// would send a value policy.RefuseBitcoinKeys refuses: key, a value of pool,
// or a value it names (extra headers, OAuth client secret).
func (s *snapshot) sendsBitcoinKey(svc policy.Service, key string, pool []string) bool {
	if len(s.refusedValues) == 0 || svc.Auth == policy.AuthBitcoinPSBTSign {
		return false
	}
	if s.refusedValues[key] {
		return true
	}
	for _, name := range pool {
		if s.refusedValues[s.keys[name]] {
			return true
		}
	}
	for _, name := range svc.KeyNames() {
		if s.refusedValues[s.keys[name]] {
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
// PSBT or the key. VBytes is the estimated size of the finalised
// transaction, 0 when unknown (bitcoin.Plan.VBytes).
type BitcoinAudit struct {
	Network      string `json:"network"`
	Txid         string `json:"txid"`
	Inputs       []int  `json:"inputs"`
	ExternalSats int64  `json:"external_sats"`
	FeeSats      int64  `json:"fee_sats"`
	VBytes       int64  `json:"vbytes,omitempty"`
}

// FeeRate is the fee per estimated vbyte with one decimal ("12.5"), "" when
// the size is unknown.
func (a BitcoinAudit) FeeRate() string {
	if a.VBytes <= 0 {
		return ""
	}
	return strconv.FormatFloat(float64(a.FeeSats)/float64(a.VBytes), 'f', 1, 64)
}

// bitcoinNotifyTimeout bounds one run of notify_command.
const bitcoinNotifyTimeout = 10 * time.Second

// notifyBitcoin runs command (the rules' notify_command) with msg as its
// last argument, in the background: the signature is already answered and
// never waits for it. A command that fails or runs past
// bitcoinNotifyTimeout is killed and written to the audit log.
func (h *Handler) notifyBitcoin(command []string, role, service, msg string) {
	if len(command) == 0 {
		return
	}
	args := append(slices.Clone(command[1:]), msg)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), bitcoinNotifyTimeout)
		defer cancel()
		// No stdin, stdout or stderr: Run returns as soon as the command
		// ends or is killed.
		err := exec.CommandContext(ctx, command[0], args...).Run()
		if err == nil {
			return
		}
		note := "notify_command failed: " + err.Error()
		if ctx.Err() != nil {
			note = "notify_command timed out after 10s"
		}
		h.writeAudit(auditRecord{Time: h.now().UTC().Format(time.RFC3339), Source: "keyring", Role: role, Service: service,
			Method: "NOTIFY", Path: "/" + bitcoinSignAction, Note: note})
	}()
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
func (h *Handler) serveBitcoin(w http.ResponseWriter, snap *snapshot, svc policy.Service, key, role, service string, access policy.Access,
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
	mainnet := rules.Network == bitcoin.Mainnet
	var reply any
	if action == bitcoinAddressesAction {
		list, err := bitcoin.Addresses(k, rules, query.path, query.from, query.count)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		rec.Note, reply = "addresses", list
	} else {
		// The key check needs the store, which validation does not read;
		// the grant check repeats validation's (policy.Config.Validate).
		if other := snap.config.BitcoinKeyOnOtherNetwork(service, snap.keys); other != "" {
			h.refund(role, service, access.DailyRequests, start)
			fail(http.StatusServiceUnavailable, "bitcoin key unavailable: service "+other+" signs with the same key on another network; mainnet and the test networks need different keys")
			return
		}
		if mainnet {
			if err := policy.CheckBitcoinMainnetGrant(access); err != nil {
				h.refund(role, service, access.DailyRequests, start)
				fail(http.StatusServiceUnavailable, "bitcoin grant unavailable: "+err.Error())
				return
			}
		}
		plan, err := bitcoin.Prepare(k, rules, signReq.PSBT, signReq.Inputs)
		if err != nil {
			fail(http.StatusBadRequest, err.Error())
			return
		}
		if max := access.BitcoinMaxSatsPerTx; max > 0 && plan.External > max {
			fail(http.StatusBadRequest, fmt.Sprintf("bitcoin_max_sats_per_tx: %d external sats is over the limit of %d", plan.External, max))
			return
		}
		if mainnet {
			if why := policy.BitcoinMainnetFeeRefusal(plan.Fee, plan.VBytes); why != "" {
				fail(http.StatusBadRequest, why)
				return
			}
		}
		signed, status, why := h.bitcoinSpend.sign(role, service, access.BitcoinMaxSatsPerDay, plan, h.now)
		if signed == nil {
			fail(status, why)
			return
		}
		rec.Bitcoin = &BitcoinAudit{Network: rules.Network, Txid: signed.Txid, Inputs: signed.Signed, ExternalSats: signed.External, FeeSats: signed.Fee, VBytes: signed.VBytes}
		reply = signed
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	rec.Status = http.StatusOK
	sink := &countingWriter{w: w}
	_ = json.NewEncoder(sink).Encode(reply)
	rec.Bytes = sink.n
	if mainnet && rec.Bitcoin != nil {
		b := rec.Bitcoin
		h.notifyBitcoin(snap.config.NotifyCommand, role, service, fmt.Sprintf("keyring: mainnet signature by %s on %s: txid %s, %d sats external, fee %d sats, %s sat/vB",
			role, service, b.Txid, b.ExternalSats, b.FeeSats, b.FeeRate()))
	}
}
