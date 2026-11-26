package dashboard

import (
	"bytes"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/bitcoin"
	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/requests"
	"github.com/gitmoot/keyring/internal/store"
)

// addMainnet adds a mainnet service btc-main with the BIP86 vectors' xprv
// and no grant.
func addMainnet(e *env) {
	e.t.Helper()
	if err := store.Set(e.backend.StorePath, "BTC_MAIN", bitcointest.MasterMainnet); err != nil {
		e.t.Fatal(err)
	}
	cfg := e.proxy.Config()
	access := cfg.AccessList
	access.Services["btc-main"] = policy.Service{Key: "BTC_MAIN", Auth: policy.AuthBitcoinPSBTSign,
		Bitcoin: &policy.Bitcoin{Network: "mainnet", Paths: bitcoin.MainnetPaths[:2]}}
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		e.t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(next, keys)
}

func mainnetGrant(tx, day string, confirm ...string) url.Values {
	form := url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}, "max_sats_tx": {tx}, "max_sats_day": {day}}
	if len(confirm) == 2 {
		form.Set("confirm_service", confirm[0])
		form.Set("confirm_daily", confirm[1])
	}
	return form
}

// Owner, 2026-11-26: a grant on a mainnet service has both sats limits
// within the ceilings, and creating or raising one takes the service name
// and the daily limit typed out; lowering or removing one the password only.
func TestMainnetGrantNeedsLimitsAndTypedConfirm(t *testing.T) {
	e := newEnv(t)
	addMainnet(e)
	page := e.request("GET", "/access/phobos/btc-main", nil).Body.String()
	if !strings.Contains(page, "Mainnet: real bitcoin. Both sats limits are required") || !strings.Contains(page, `name="confirm_service"`) || !strings.Contains(page, `name="confirm_daily"`) {
		t.Fatal("the mainnet grant form asks for no limits or confirmation")
	}
	before := e.accessBytes()
	for _, tc := range []struct {
		name, want string
		form       url.Values
	}{
		{"no limits", "needs bitcoin_max_sats_per_tx and bitcoin_max_sats_per_day, both above 0", mainnetGrant("", "", "btc-main", "0")},
		{"no daily limit", "needs bitcoin_max_sats_per_tx and bitcoin_max_sats_per_day, both above 0", mainnetGrant("1000", "", "btc-main", "0")},
		{"per PSBT over the ceiling", "bitcoin_max_sats_per_tx is above the mainnet ceiling of 200000 sats", mainnetGrant("200001", "1000000", "btc-main", "1000000")},
		{"per day over the ceiling", "bitcoin_max_sats_per_day is above the mainnet ceiling of 1000000 sats", mainnetGrant("1000", "1000001", "btc-main", "1000001")},
		{"per PSBT over per day", "bitcoin_max_sats_per_tx is above bitcoin_max_sats_per_day", mainnetGrant("50000", "40000", "btc-main", "40000")},
		{"no confirmation", "type the service name (btc-main) and the daily limit in sats (500000) exactly. Nothing was saved.", mainnetGrant("100000", "500000")},
		{"wrong service typed", "Nothing was saved.", mainnetGrant("100000", "500000", "btc-ord", "500000")},
		{"wrong daily limit typed", "Nothing was saved.", mainnetGrant("100000", "500000", "btc-main", "50000")},
	} {
		if w := e.saveCell("phobos", "btc-main", tc.form); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("%s: %d, want 400 with %q", tc.name, w.Code, tc.want)
		}
		if !bytes.Equal(e.accessBytes(), before) {
			t.Fatalf("%s: a refused grant changed the access file", tc.name)
		}
	}
	// The typed values must match; the password is still required.
	form := mainnetGrant("100000", "500000", " btc-main ", "500000")
	form.Set("password", "wrong")
	if w := e.saveCell("phobos", "btc-main", form); w.Code != http.StatusForbidden || !bytes.Equal(e.accessBytes(), before) {
		t.Fatalf("wrong password: %d", w.Code)
	}
	if w := e.saveCell("phobos", "btc-main", mainnetGrant("100000", "500000", " btc-main ", "500000")); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatalf("confirmed: %d %s", w.Code, w.Body.String())
	}
	limits := func() [2]int64 {
		g, ok := e.proxy.Config().Roles["phobos"].Access["btc-main"]
		if !ok {
			return [2]int64{-1, -1}
		}
		return [2]int64{g.BitcoinMaxSatsPerTx, g.BitcoinMaxSatsPerDay}
	}
	if got := limits(); got != [2]int64{100_000, 500_000} {
		t.Fatalf("limits = %v", got)
	}
	// Lowering takes the password only.
	if w := e.saveCell("phobos", "btc-main", mainnetGrant("50000", "400000")); w.Header().Get("Location") != "/access?done=saved" || limits() != [2]int64{50_000, 400_000} {
		t.Fatalf("lower: %d %s", w.Code, w.Body.String())
	}
	// Raising either limit takes the confirmation again.
	for _, form := range []url.Values{mainnetGrant("60000", "400000"), mainnetGrant("50000", "400001"), mainnetGrant("50000", "400001", "btc-main", "400000")} {
		if w := e.saveCell("phobos", "btc-main", form); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Nothing was saved.") || limits() != [2]int64{50_000, 400_000} {
			t.Fatalf("raise %v: %d", form, w.Code)
		}
	}
	// Removing takes the password only.
	if w := e.saveCell("phobos", "btc-main", url.Values{}); w.Header().Get("Location") != "/access?done=saved" || limits() != [2]int64{-1, -1} {
		t.Fatalf("remove: %d %s", w.Code, w.Body.String())
	}
}

// A project grant never reaches a mainnet service, so switching off the
// role's own grant revokes that service alone while the project grant
// stays (review of #206).
func TestRevokingAMainnetGrantBesideAProjectGrant(t *testing.T) {
	e := newEnv(t)
	addMainnet(e)
	cfg := e.proxy.Config()
	access := cfg.AccessList
	svc := access.Services["btc-main"]
	svc.Project = "ord"
	access.Services["btc-main"] = svc
	access.Projects = map[string]policy.Project{"ord": {}}
	role := access.Roles["phobos"]
	role.Projects = map[string]policy.Access{"ord": fullAccess()}
	role.Access["btc-main"] = policy.Access{Methods: []string{"GET", "POST"}, Paths: []string{"/"}, BitcoinMaxSatsPerTx: 1000, BitcoinMaxSatsPerDay: 1000}
	access.Roles["phobos"] = role
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(next, keys)
	if w := e.saveCell("phobos", "btc-main", url.Values{}); w.Header().Get("Location") != "/access?done=saved" {
		t.Fatalf("remove: %d %s", w.Code, w.Body.String())
	}
	now := e.proxy.Config()
	if _, ok := now.AccessFor(now.Roles["phobos"], "btc-main"); ok {
		t.Fatal("the mainnet service is still reachable")
	}
	if _, ok := now.Roles["phobos"].Projects["ord"]; !ok {
		t.Fatal("revoking the mainnet grant dropped the project grant")
	}
}

// Owner, 2026-11-26: approving an access request for a mainnet service
// takes both sats limits and the typed confirmation; without them the
// request stays and nothing is granted.
func TestApprovingAMainnetRequestNeedsLimits(t *testing.T) {
	e := newEnv(t)
	addMainnet(e)
	e.backend.Requests = requests.Open(filepath.Join(t.TempDir(), "requests.json"))
	_, sha, _ := policy.NewToken()
	req, err := e.backend.Requests.File(requests.Request{Role: "ordinals", Fingerprint: sha, Services: []string{"btc-main"}, Note: "inscriptions"},
		e.proxy.Config().AccessList, "100.64.0.20", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	page := e.request("GET", "/access", nil).Body.String()
	for _, want := range []string{`name="max_sats_tx.btc-main"`, `name="max_sats_day.btc-main"`, `name="confirm_service.btc-main"`, `name="confirm_daily.btc-main"`} {
		if !strings.Contains(page, want) {
			t.Fatalf("the request card lacks %s", want)
		}
	}
	before := e.accessBytes()
	approve := func(tx, day, service, daily string) url.Values {
		return url.Values{"answer": {"approve"}, "password": {password}, "max_sats_tx.btc-main": {tx}, "max_sats_day.btc-main": {day},
			"confirm_service.btc-main": {service}, "confirm_daily.btc-main": {daily}}
	}
	for _, tc := range []struct {
		name, want string
		form       url.Values
	}{
		{"no limits", "btc-main signs on mainnet: give both sats limits", url.Values{"answer": {"approve"}, "password": {password}}},
		{"one limit", "btc-main signs on mainnet: give both sats limits", approve("1000", "", "btc-main", "")},
		{"over the ceiling", "bitcoin_max_sats_per_day is above the mainnet ceiling of 1000000 sats", approve("1000", "2000000", "btc-main", "2000000")},
		{"per PSBT over per day", "bitcoin_max_sats_per_tx is above bitcoin_max_sats_per_day", approve("5000", "4000", "btc-main", "4000")},
		{"not confirmed", "Nothing was saved.", approve("100000", "300000", "", "")},
		{"wrong daily limit typed", "Nothing was saved.", approve("100000", "300000", "btc-main", "30000")},
	} {
		w := e.request("POST", "/requests/"+req.ID, tc.form)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "Cannot approve: ") || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("%s: %d, want 409 with %q", tc.name, w.Code, tc.want)
		}
		if !bytes.Equal(e.accessBytes(), before) {
			t.Fatalf("%s: a refused approval changed the access file", tc.name)
		}
	}
	if w := e.request("POST", "/requests/"+req.ID, approve("100000", "300000", "btc-main", "300000")); w.Header().Get("Location") != "/access?done=approved" {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	if g := e.proxy.Config().Roles["ordinals"].Access["btc-main"]; g.BitcoinMaxSatsPerTx != 100_000 || g.BitcoinMaxSatsPerDay != 300_000 {
		t.Fatalf("grant = %+v", g)
	}
	if !strings.Contains(e.audit.String(), `"bitcoin_limits":{"btc-main":[100000,300000]}`) {
		t.Fatal("the approval audit has no limits")
	}
}

// A mainnet service's page says so in words, with the limits it enforces
// and that every signature goes to notify_command.
func TestMainnetServicePageWarns(t *testing.T) {
	e := newEnv(t)
	addMainnet(e)
	page := e.request("GET", "/services/btc-main", nil).Body.String()
	for _, want := range []string{`<span class="pill warn">mainnet · real bitcoin</span>`, "<dd>mainnet (real bitcoin)</dd>", "sent to notify_command",
		"a PSBT with a fee over 50000 sats or 200 sat/vB is refused"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the mainnet service page lacks %q", want)
		}
	}
	addBitcoin(e)
	if page := e.request("GET", "/services/btc-ord", nil).Body.String(); strings.Contains(page, "· real bitcoin") || strings.Contains(page, "This service signs real bitcoin") || !strings.Contains(page, "<dd>regtest (test network)</dd>") {
		t.Fatal("a regtest service page reads as mainnet")
	}
}

// The Connect form of an xprv offers a mainnet service with the mainnet
// paths and the real-bitcoin notice; the same seed as a tprv cannot then
// serve a test network.
func TestBitcoinConnectFormForAnXprv(t *testing.T) {
	e := newEnv(t)
	addBitcoinKey(e, "BTC_MAIN", bitcointest.MasterMainnet)
	page := e.request("GET", "/keys/BTC_MAIN", nil).Body.String()
	for _, want := range []string{`<option selected>mainnet</option>`, "m/86&#39;/0&#39;/0&#39;/0/*\nm/86&#39;/0&#39;/0&#39;/1/*</textarea>", `<p class="warnbox" data-mainnetnotice>Mainnet signs real bitcoin.`} {
		if !strings.Contains(page, want) {
			t.Fatalf("the xprv Connect form lacks %q", want)
		}
	}
	assertNoBitcoinKey(t, page)
	w := e.request("POST", "/keys/BTC_MAIN/connect", url.Values{"auth": {"bitcoin-psbt-sign"}, "service": {"btc-main"}, "network": {"mainnet"},
		"paths": {"m/86'/0'/0'/0/*\nm/86'/0'/0'/1/*"}, "sighash": {"default", "all"}, "password": {password}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("connect mainnet: %d %s", w.Code, w.Body.String())
	}
	if s := e.proxy.Config().Services["btc-main"]; !s.BitcoinMainnet() {
		t.Fatalf("service = %+v", s)
	}
	addBitcoinKey(e, "BTC_SAME", bitcointest.Master)
	before := e.accessBytes()
	w = e.request("POST", "/keys/BTC_SAME/connect", url.Values{"auth": {"bitcoin-psbt-sign"}, "service": {"btc-test"}, "network": {"regtest"},
		"paths": {"m/86'/1'/0'/0/*"}, "sighash": {"default", "all"}, "password": {password}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "BTC_SAME is the same key as service btc-main&#39;s on another network") || !bytes.Equal(e.accessBytes(), before) {
		t.Fatalf("same seed on regtest: %d", w.Code)
	}
	assertNoBitcoinKey(t, w.Body.String())
}
