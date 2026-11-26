package dashboard

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/bitcoin/bitcointest"
	"github.com/gitmoot/keyring/internal/policy"
	"github.com/gitmoot/keyring/internal/server"
	"github.com/gitmoot/keyring/internal/store"
)

// addBitcoin stores the test master key as BTC_ORD, adds the regtest
// service btc-ord and grants it to phobos with a per-PSBT limit.
func addBitcoin(e *env) {
	e.t.Helper()
	if err := store.Set(e.backend.StorePath, "BTC_ORD", bitcointest.Master); err != nil {
		e.t.Fatal(err)
	}
	cfg := e.proxy.Config()
	access := cfg.AccessList
	access.Services["btc-ord"] = policy.Service{Key: "BTC_ORD", Auth: policy.AuthBitcoinPSBTSign,
		Bitcoin: &policy.Bitcoin{Network: "regtest", Paths: []string{"m/86'/1'/0'/0/*", "m/86'/1'/0'/1/*", "m/84'/1'/0'/0/*"}}}
	access.Roles["phobos"].Access["btc-ord"] = policy.Access{Paths: []string{"/"}, BitcoinMaxSatsPerTx: 70_000}
	next, err := policy.SaveAccess(cfg.Rules, access)
	if err != nil {
		e.t.Fatal(err)
	}
	keys, _ := store.Load(e.backend.StorePath)
	e.proxy.Swap(next, keys)
}

func assertNoBitcoinKey(t *testing.T, outputs ...string) {
	t.Helper()
	for _, out := range outputs {
		for _, secret := range []string{bitcointest.Master[:20], bitcointest.Master[len(bitcointest.Master)-20:], bitcointest.WIF[:20],
			bitcointest.MasterMainnet[:20], bitcointest.MasterMainnet[len(bitcointest.MasterMainnet)-20:]} {
			if strings.Contains(out, secret) {
				t.Fatal("bitcoin key material in output")
			}
		}
	}
}

// A bitcoin key is never shown: not when a service uses it, and not when it
// was only pasted with Add key; its page shows the fingerprint instead.
func TestBitcoinKeyIsNeverShown(t *testing.T) {
	e := newEnv(t)
	addBitcoin(e)
	if w := e.request("POST", "/keys", url.Values{"name": {"LOOSE_WIF"}, "value": {bitcointest.WIF}, "password": {password}}); w.Code != http.StatusSeeOther {
		t.Fatalf("paste a WIF key with Add key: %d", w.Code)
	}
	var outputs []string
	for _, name := range []string{"BTC_ORD", "LOOSE_WIF"} {
		page := e.request("GET", "/keys/"+name, nil).Body.String()
		if strings.Contains(page, `action="/keys/`+name+`/reveal"`) || !strings.Contains(page, "Bitcoin key") || !strings.Contains(page, "fingerprint <code>") {
			t.Fatalf("%s: the key page offers Show or lacks the fingerprint", name)
		}
		w := e.request("POST", "/keys/"+name+"/reveal", url.Values{"password": {password}})
		if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "error=never-shown") {
			t.Fatalf("%s: reveal answered %d", name, w.Code)
		}
		outputs = append(outputs, page, w.Body.String())
	}
	if strings.Contains(e.audit.String(), "key_revealed") {
		t.Fatal("a bitcoin key was audited as shown")
	}
	if page := e.request("GET", "/keys/BTC_ORD", nil).Body.String(); !strings.Contains(page, "73c5da0a") {
		t.Fatal("the master fingerprint is not on the key page")
	}
	assertNoBitcoinKey(t, append(outputs, e.audit.String())...)
}

// The service page shows the watch-only side of the key and the signatures
// from the audit log, never the key or a PSBT.
func TestBitcoinServicePageListsSignatures(t *testing.T) {
	e := newEnv(t)
	addBitcoin(e)
	change := bitcointest.Coin{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/1/0"}
	unsigned := bitcointest.Encode(t, bitcointest.Build(t,
		[]bitcointest.Coin{{Key: bitcointest.Master, Kind: "p2tr", Path: "m/86'/1'/0'/0/0", Value: 50_000}, {Key: bitcointest.Master, Kind: "p2wpkh", Path: "m/84'/1'/0'/0/1", Value: 30_000}},
		[]bitcointest.Out{{Value: 60_000, Script: bitcointest.External}, {Value: 15_000, Coin: &change}}))
	body, _ := json.Marshal(map[string]any{"psbt": unsigned, "inputs": []int{0, 1}})
	r := httptest.NewRequest("POST", "/_keyring/bitcoin/btc-ord/sign-psbt", strings.NewReader(string(body)))
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set(server.TokenHeader, token)
	w := httptest.NewRecorder()
	e.proxy.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("sign: %d %s", w.Code, w.Body.String())
	}
	var reply struct {
		PSBT string `json:"psbt"`
		Txid string `json:"txid"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	// The proxy's audit goes to a buffer here; the page reads the log file.
	// Review of #188: more than server.AuditLimit newer calls of the service
	// that sign nothing do not push the signature out of the table.
	var signedAt time.Time
	for dec := json.NewDecoder(bytes.NewReader(e.audit.Bytes())); dec.More(); {
		var rec struct {
			Time time.Time `json:"time"`
		}
		if err := dec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
		if rec.Time.After(signedAt) {
			signedAt = rec.Time
		}
	}
	log := bytes.Clone(e.audit.Bytes())
	later := signedAt.Add(time.Second).UTC().Format(time.RFC3339)
	for range server.AuditLimit + 10 {
		log = append(log, `{"time":"`+later+`","role":"phobos","service":"btc-ord","method":"GET","path":"/_keyring/bitcoin/btc-ord/addresses","status":200}`+"\n"...)
	}
	if err := os.WriteFile(e.proxy.Config().AuditLog, log, 0o600); err != nil {
		t.Fatal(err)
	}
	page := e.request("GET", "/services/btc-ord", nil).Body.String()
	for _, want := range []string{reply.Txid, "<td class=\"num\">65000</td>", "<td class=\"num\">5000</td>", "phobos", "regtest", "0, 1", "tr([73c5da0a/86h/1h/0h/0]tpub", "wpkh([73c5da0a/84h/1h/0h/0]tpub", "bcrt1p", "Signatures"} {
		if !strings.Contains(page, want) {
			t.Fatalf("service page lacks %q", want)
		}
	}
	if strings.Contains(page, unsigned) || strings.Contains(page, reply.PSBT) || strings.Contains(page, "tprv") {
		t.Fatal("the service page carries a PSBT or a private key")
	}
	assertNoBitcoinKey(t, page, e.audit.String())
}

// Saving a bitcoin grant on the dashboard keeps and edits its sats limits.
func TestBitcoinGrantFormKeepsSatsLimits(t *testing.T) {
	e := newEnv(t)
	addBitcoin(e)
	page := e.request("GET", "/access/phobos/btc-ord", nil).Body.String()
	if !strings.Contains(page, `name="max_sats_tx" inputmode="numeric" value="70000"`) {
		t.Fatal("the grant form does not show the per-PSBT limit")
	}
	w := e.request("POST", "/access/phobos/btc-ord", url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}, "max_sats_tx": {"70000"}, "max_sats_day": {"200000"}, "password": {password}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	got := e.proxy.Config().Roles["phobos"].Access["btc-ord"]
	if got.BitcoinMaxSatsPerTx != 70_000 || got.BitcoinMaxSatsPerDay != 200_000 {
		t.Fatalf("grant = %+v", got)
	}
	if page := e.request("GET", "/access/phobos/api", nil).Body.String(); strings.Contains(page, "max_sats_tx") {
		t.Fatal("sats limits offered for a service that is not bitcoin")
	}
}

// addBitcoinKey pastes a bitcoin key with Add key, as the owner does.
func addBitcoinKey(e *env, name, value string) {
	e.t.Helper()
	if w := e.request("POST", "/keys", url.Values{"name": {name}, "value": {value}, "password": {password}}); w.Code != http.StatusSeeOther {
		e.t.Fatalf("add %s: %d", name, w.Code)
	}
}

// grantBitcoin gives phobos the whole service with sats limits through the
// grant form and checks they were kept.
func grantBitcoin(e *env, service string) {
	e.t.Helper()
	w := e.request("POST", "/access/phobos/"+service, url.Values{"on": {"yes"}, "mode": {"full"}, "paths": {"/"}, "max_sats_tx": {"100000"}, "max_sats_day": {"1000000"}, "password": {password}})
	if w.Code != http.StatusSeeOther {
		e.t.Fatalf("grant %s: %d %s", service, w.Code, w.Body.String())
	}
	if got := e.proxy.Config().Roles["phobos"].Access[service]; got.BitcoinMaxSatsPerTx != 100_000 || got.BitcoinMaxSatsPerDay != 1_000_000 {
		e.t.Fatalf("grant limits = %+v", got)
	}
}

// addresses calls the service's addresses action as phobos.
func addresses(e *env, service, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/_keyring/bitcoin/"+service+"/addresses?"+url.Values{"path": {path}, "count": {"2"}}.Encode(), nil)
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set(server.TokenHeader, token)
	w := httptest.NewRecorder()
	e.proxy.ServeHTTP(w, r)
	return w
}

// The Connect form of a Bitcoin key makes a bitcoin-psbt-sign service that
// answers once an agent is granted it (#201). A tprv cannot make a mainnet
// service.
func TestBitcoinConnectFormMakesAWorkingService(t *testing.T) {
	e := newEnv(t)
	addBitcoinKey(e, "BTC_ORD", bitcointest.Master)
	page := e.request("GET", "/keys/BTC_ORD", nil).Body.String()
	for _, want := range []string{`name="auth" value="bitcoin-psbt-sign"`, `<option selected>regtest</option>`, "m/86&#39;/1&#39;/0&#39;/0/*\nm/86&#39;/1&#39;/0&#39;/1/*</textarea>",
		`value="default" checked`, `value="all" checked`, `value="none">`, `value="single|anyonecanpay">`, "add <span class=\"mono\">m/84'/1'/0'/0/*</span>"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the Connect form of a bitcoin key lacks %q", want)
		}
	}
	if strings.Contains(page, `class="presetpick"`) || strings.Contains(page, `name="base"`) || strings.Contains(page, `name="script"`) || !strings.Contains(page, `<p class="warnbox" data-mainnetnotice hidden>`) {
		t.Fatal("the bitcoin Connect form of a tprv offers the API form or a WIF script, or shows the mainnet notice")
	}
	before := e.accessBytes()
	form := func(network string, sighash ...string) url.Values {
		return url.Values{"auth": {"bitcoin-psbt-sign"}, "service": {"btc-new"}, "network": {network}, "paths": {"m/86'/1'/0'/0/*\r\nm/86'/1'/0'/1/*\r\n"}, "sighash": sighash, "password": {password}}
	}
	for _, tc := range []struct {
		name, want string
		form       url.Values
	}{
		{"mainnet with test paths", "a mainnet service signs only for", form("mainnet", "default", "all")},
		{"no sighash", "Tick at least one sighash type", form("regtest")},
	} {
		if w := e.request("POST", "/keys/BTC_ORD/connect", tc.form); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("%s: %d, want 400 with %q", tc.name, w.Code, tc.want)
		}
		if !bytes.Equal(e.accessBytes(), before) {
			t.Fatalf("%s: a refused connect changed the access file", tc.name)
		}
	}
	if w := e.request("POST", "/keys/BTC_ORD/connect", form("regtest", "default", "all")); w.Header().Get("Location") != "/keys/BTC_ORD?done=connected" {
		t.Fatalf("connect: %d %s", w.Code, w.Body.String())
	}
	svc := e.proxy.Config().Services["btc-new"]
	if svc.Auth != policy.AuthBitcoinPSBTSign || svc.Key != "BTC_ORD" || svc.Bitcoin == nil || svc.Bitcoin.Network != "regtest" ||
		!slices.Equal(svc.Bitcoin.Paths, []string{"m/86'/1'/0'/0/*", "m/86'/1'/0'/1/*"}) || svc.Bitcoin.Script != "" || svc.Bitcoin.Sighash != nil {
		t.Fatalf("saved service = %+v %+v", svc, svc.Bitcoin)
	}
	if !strings.Contains(e.audit.String(), `"admin":"key_connected"`) {
		t.Fatal("the connect is not audited")
	}
	grantBitcoin(e, "btc-new")
	w := addresses(e, "btc-new", "m/86'/1'/0'/0")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "73c5da0a") || !strings.Contains(w.Body.String(), "bcrt1p") {
		t.Fatalf("addresses: %d %s", w.Code, w.Body.String())
	}
	assertNoBitcoinKey(t, page, e.audit.String(), e.request("GET", "/keys/BTC_ORD", nil).Body.String())
}

// A WIF key's Connect form asks for the script and no paths.
func TestBitcoinConnectFormForAWIFKey(t *testing.T) {
	e := newEnv(t)
	addBitcoinKey(e, "BTC_WIF", bitcointest.WIF)
	page := e.request("GET", "/keys/BTC_WIF", nil).Body.String()
	if !strings.Contains(page, `<select name="script"><option selected>p2tr</option><option>p2wpkh</option>`) || strings.Contains(page, `name="paths"`) {
		t.Fatal("the Connect form of a WIF key does not ask for the script alone")
	}
	w := e.request("POST", "/keys/BTC_WIF/connect", url.Values{"auth": {"bitcoin-psbt-sign"}, "service": {"btc-wif"}, "network": {"regtest"}, "script": {"p2wpkh"}, "sighash": {"all"}, "password": {password}})
	if w.Header().Get("Location") != "/keys/BTC_WIF?done=connected" {
		t.Fatalf("connect: %d %s", w.Code, w.Body.String())
	}
	if b := e.proxy.Config().Services["btc-wif"].Bitcoin; b == nil || b.Script != "p2wpkh" || b.Paths != nil || !slices.Equal(b.Sighash, []string{"all"}) {
		t.Fatalf("saved = %+v", b)
	}
	grantBitcoin(e, "btc-wif")
	if w := addresses(e, "btc-wif", "m"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "bcrt1q") {
		t.Fatalf("addresses: %d %s", w.Code, w.Body.String())
	}
}

// The paste box takes a bitcoin service as settings and as access.json
// writes it, including the owner's paste from 554234 and the line copied
// from docs/bitcoin.md.
func TestBitcoinConnectTakesPastedSettingsInBothShapes(t *testing.T) {
	const rules = `"bitcoin":{"network":"regtest","paths":["m/86'/1'/0'/0/*","m/86'/1'/0'/1/*"],"sighash":["default","all"]}`
	for name, tc := range map[string]struct{ service, pasted string }{
		"settings":         {"btc-ord", `{"service":"btc-ord","auth":"bitcoin-psbt-sign",` + rules + `}`},
		"access.json":      {"btc-ord", `{"btc-ord":{"auth":"bitcoin-psbt-sign","key":"BTC_ORD",` + rules + `}}`},
		"access.json line": {"btc-ord", `"btc-ord": {"auth": "bitcoin-psbt-sign", "key": "BTC_ORD", ` + rules + `},`},
		// Review of #204: a service may be named like a settings field.
		"named bitcoin": {"bitcoin", `{"bitcoin":{"auth":"bitcoin-psbt-sign","key":"BTC_ORD",` + rules + `}}`},
		"named auth":    {"auth", `"auth": {"auth": "bitcoin-psbt-sign", ` + rules + `}`},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			addBitcoinKey(e, "BTC_ORD", bitcointest.Master)
			w := e.request("POST", "/keys/BTC_ORD/connect", url.Values{"pasted": {tc.pasted}, "password": {password}})
			if w.Header().Get("Location") != "/keys/BTC_ORD?done=connected" {
				t.Fatalf("connect: %d %s", w.Code, w.Body.String())
			}
			svc := e.proxy.Config().Services[tc.service]
			if svc.Key != "BTC_ORD" || svc.Bitcoin == nil || len(svc.Bitcoin.Paths) != 2 || !slices.Equal(svc.Bitcoin.Sighash, []string{"default", "all"}) {
				t.Fatalf("saved service = %+v", svc)
			}
			grantBitcoin(e, tc.service)
			if w := addresses(e, tc.service, "m/86'/1'/0'/1"); w.Code != http.StatusOK {
				t.Fatalf("addresses: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

// A refused paste says what is wrong in plain text, never a Go type error,
// and names no pasted value.
func TestBitcoinPasteRefusalsArePlainText(t *testing.T) {
	e := newEnv(t)
	addBitcoinKey(e, "BTC_ORD", bitcointest.Master)
	before := e.accessBytes()
	for _, tc := range []struct{ name, pasted, want string }{
		{"another key", `{"btc-ord":{"auth":"bitcoin-psbt-sign","key":"API_KEY","bitcoin":{"network":"regtest","paths":["m/86'/1'/0'/0/*"]}}}`, "name another key"},
		{"unknown field", `{"service":"btc-ord","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","pathz":["m/86'/1'/0'/0/*"]}}`, "unknown field &#34;pathz&#34;"},
		{"wrong type", `{"service":"btc-ord","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","paths":"m/86'/1'/0'/0/*"}}`, "&#34;bitcoin.paths&#34; has the wrong type"},
		{"a bare name", `"btc-ord"`, "Paste one service&#39;s settings as JSON"},
		{"mainnet for a tprv", `{"service":"btc-ord","auth":"bitcoin-psbt-sign","bitcoin":{"network":"mainnet","paths":["m/86'/0'/0'/0/*"]}}`, "the key is for another network than the service"},
		{"WIF rules for a tprv", `{"service":"btc-ord","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","script":"p2tr"}}`, "does not fit the service"},
		// Review of #204: a key pasted into the wrong field is not shown back.
		{"key in paths", `{"service":"btc-ord","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","paths":["m/86'/1'/0'/0/*","` + bitcointest.Master + `"]}}`, "path 2: path must start with m"},
		{"key as sighash", `{"service":"btc-ord","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","paths":["m/86'/1'/0'/0/*"],"sighash":["` + bitcointest.WIF + `"]}}`, "sighash 1: want default"},
		{"a test method", `{"btc-ord":{"auth":"bitcoin-psbt-sign","test_method":"POST","bitcoin":{"network":"regtest","paths":["m/86'/1'/0'/0/*"]}}}`, "test method is set in access.json"},
		{"a service named auth with a bad field", `{"auth":{"auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","pathz":["m/86'/1'/0'/0/*"]}}}`, "unknown field &#34;pathz&#34;"},
		{"a service named auth with AUTH and a bad field", `{"auth":{"AUTH":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","pathz":["m/86'/1'/0'/0/*"]}}}`, "unknown field &#34;pathz&#34;"},
	} {
		w := e.request("POST", "/keys/BTC_ORD/connect", url.Values{"pasted": {tc.pasted}, "password": {password}})
		body := w.Body.String()
		if w.Code != http.StatusBadRequest || !strings.Contains(body, tc.want) || strings.Contains(body, "Go value") || strings.Contains(body, "cannot unmarshal") {
			t.Fatalf("%s: %d, want 400 with %q:\n%s", tc.name, w.Code, tc.want, body)
		}
		if !bytes.Equal(e.accessBytes(), before) {
			t.Fatalf("%s: a refused paste changed the access file", tc.name)
		}
		assertNoBitcoinKey(t, body)
	}
	// Typed into the form by mistake: refused, and the form shows only the
	// lines that are paths.
	w := e.request("POST", "/keys/BTC_ORD/connect", url.Values{"auth": {"bitcoin-psbt-sign"}, "service": {"btc-ord"}, "network": {"regtest"},
		"paths": {"m/86'/1'/0'/0/*\n" + bitcointest.Master}, "sighash": {"default", "all"}, "password": {password}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "m/86&#39;/1&#39;/0&#39;/0/*</textarea>") {
		t.Fatalf("typed key in paths: %d", w.Code)
	}
	assertNoBitcoinKey(t, w.Body.String())
	// A refused paste is one unit (review of #204): the form shows none of
	// it, so sending the form again does not save part of it.
	w = e.request("POST", "/keys/BTC_ORD/connect", url.Values{"pasted": {`{"service":"btc-pasted","auth":"bitcoin-psbt-sign","bitcoin":{"network":"mainnet","paths":["m/84'/1'/0'/0/*"]}}`}, "password": {password}})
	if body := w.Body.String(); w.Code != http.StatusBadRequest || strings.Contains(body, `value="btc-pasted"`) || strings.Contains(body, "m/84&#39;/1&#39;/0&#39;/0/*</textarea>") {
		t.Fatalf("a refused paste fills the form: %d", w.Code)
	}
	// Sending what that form shows saves nothing: it names no service.
	w = e.request("POST", "/keys/BTC_ORD/connect", url.Values{"auth": {"bitcoin-psbt-sign"}, "service": {""}, "network": {"regtest"},
		"paths": {"m/86'/1'/0'/0/*\nm/86'/1'/0'/1/*"}, "sighash": {"default", "all"}, "password": {password}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Name the service.") || !bytes.Equal(e.accessBytes(), before) {
		t.Fatalf("the form after a refused paste saved: %d", w.Code)
	}
}

// A key with several values keeps the API form, whatever its values are
// (review of #204): the Bitcoin form would not know which value it is for.
func TestBitcoinFormOnlyForAOneValueKey(t *testing.T) {
	e := newEnv(t)
	for name, value := range map[string]string{"MIXED.1": bitcointest.Master, "MIXED.2": bitcointest.WIF} {
		if err := store.Set(e.backend.StorePath, name, value); err != nil {
			t.Fatal(err)
		}
	}
	page := e.request("GET", "/keys/MIXED", nil).Body.String()
	if strings.Contains(page, `name="network"`) || !strings.Contains(page, `class="presetpick"`) {
		t.Fatal("a key with several values got the Bitcoin form")
	}
	assertNoBitcoinKey(t, page)
	// A refused paste leaves no preset behind: what the form shows then
	// saves nothing (review of #204).
	before := e.accessBytes()
	w := e.request("POST", "/keys/MIXED/connect", url.Values{"preset": {"anthropic"}, "key_part": {"2"},
		"pasted": {`{"service":"btc-mixed","auth":"bitcoin-psbt-sign","bitcoin":{"network":"mainnet","script":"p2tr"}}`}, "password": {password}})
	if body := w.Body.String(); w.Code != http.StatusBadRequest || strings.Contains(body, "api.anthropic.com") || !strings.Contains(body, `<option value="" selected>Other`) {
		t.Fatalf("a refused paste kept the preset: %d", w.Code)
	}
	w = e.request("POST", "/keys/MIXED/connect", url.Values{"preset": {""}, "service": {""}, "base": {""}, "auth": {"bearer"}, "key_part": {"2"}, "password": {password}})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Name the service.") || !bytes.Equal(e.accessBytes(), before) {
		t.Fatalf("the form after a refused paste saved: %d", w.Code)
	}
	// One named value is still one value: the form sends its name, also
	// while a service names a value that is not stored.
	e.withService("solo-api", policy.Service{Base: e.proxy.Config().Services["api"].Base, Key: "SOLO.missing", Auth: policy.AuthBearer})
	if err := store.Set(e.backend.StorePath, "SOLO.only", bitcointest.WIF); err != nil {
		t.Fatal(err)
	}
	page = e.request("GET", "/keys/SOLO", nil).Body.String()
	if !strings.Contains(page, `name="script"`) || !strings.Contains(page, `<input type="hidden" name="key_part" value="only">`) || !strings.Contains(page, `"key":"SOLO.only"`) {
		t.Fatal("a key with one named bitcoin value lacks the Bitcoin form")
	}
	w = e.request("POST", "/keys/SOLO/connect", url.Values{"auth": {"bitcoin-psbt-sign"}, "key_part": {"only"}, "service": {"btc-solo"}, "network": {"regtest"}, "script": {"p2tr"}, "sighash": {"default"}, "password": {password}})
	if w.Header().Get("Location") != "/keys/SOLO?done=connected" || e.proxy.Config().Services["btc-solo"].Key != "SOLO.only" {
		t.Fatalf("connect the named value: %d %s", w.Code, w.Body.String())
	}
	// Both paste examples work as shown: settings that leave the value out
	// mean the one stored value. A signing key backs one service, so each
	// example gets its own key.
	for key, pasted := range map[string]string{
		"SOLA": `{"service":"btc-sola","auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","script":"p2tr"}}`,
		"SOLB": `{"btc-solb":{"auth":"bitcoin-psbt-sign","key":"SOLB.only","bitcoin":{"network":"regtest","script":"p2tr"}}}`,
	} {
		if err := store.Set(e.backend.StorePath, key+".only", bitcointest.WIF); err != nil {
			t.Fatal(err)
		}
		w := e.request("POST", "/keys/"+key+"/connect", url.Values{"pasted": {pasted}, "password": {password}})
		if w.Header().Get("Location") != "/keys/"+key+"?done=connected" || e.proxy.Config().Services["btc-"+strings.ToLower(key)].Key != key+".only" {
			t.Fatalf("paste for %s: %d %s", key, w.Code, w.Body.String())
		}
	}
	// A plain value is one value too, while a service names a value of
	// the key that is not stored: the form, and a paste naming the key,
	// connect it (review of #204).
	for _, key := range []string{"PLAIN", "PLAINB"} {
		e.withService(strings.ToLower(key)+"-api", policy.Service{Base: e.proxy.Config().Services["api"].Base, Key: key + ".missing", Auth: policy.AuthBearer})
		if err := store.Set(e.backend.StorePath, key, bitcointest.WIF); err != nil {
			t.Fatal(err)
		}
	}
	if page = e.request("GET", "/keys/PLAIN", nil).Body.String(); !strings.Contains(page, `name="script"`) || strings.Contains(page, `name="key_part"`) {
		t.Fatal("a key with one plain bitcoin value lacks the Bitcoin form")
	}
	for key, v := range map[string]url.Values{
		"PLAIN":  {"auth": {"bitcoin-psbt-sign"}, "service": {"btc-plain"}, "network": {"regtest"}, "script": {"p2tr"}, "sighash": {"default"}},
		"PLAINB": {"pasted": {`{"btc-plainb":{"auth":"bitcoin-psbt-sign","key":"PLAINB","bitcoin":{"network":"regtest","script":"p2tr"}}}`}},
	} {
		v.Set("password", password)
		w := e.request("POST", "/keys/"+key+"/connect", v)
		if w.Header().Get("Location") != "/keys/"+key+"?done=connected" || e.proxy.Config().Services["btc-"+strings.ToLower(key)].Key != key {
			t.Fatalf("connect %s: %d %s", key, w.Code, w.Body.String())
		}
	}
}

// A service copied whole from access.json pastes with its own test method,
// and only with it: the method is changed in access.json (review of #204).
func TestPastedTestMethodIsKept(t *testing.T) {
	e := newEnv(t)
	base := e.proxy.Config().Services["api"].Base
	entry := func(method string) string {
		return `{"api":{"base":"` + base + `","key":"API_KEY","auth":"bearer","test_path":"/v1/check","test_method":"` + method + `"}}`
	}
	if w := e.edit("api", url.Values{"pasted": {entry("GET")}}); w.Header().Get("Location") != "/services/api?done=saved" {
		t.Fatalf("paste with the kept method: %d %s", w.Code, w.Body.String())
	}
	before := e.accessBytes()
	if w := e.edit("api", url.Values{"pasted": {entry("POST")}}); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "test method is set in access.json") {
		t.Fatalf("paste with another method: %d", w.Code)
	}
	if !bytes.Equal(e.accessBytes(), before) {
		t.Fatal("a refused paste changed the access file")
	}
}

// The service page edits a bitcoin service's rules; the edit is audited by
// the names of what changed and agents keep their grant and its limits.
func TestBitcoinServiceEditChangesRules(t *testing.T) {
	e := newEnv(t)
	addBitcoin(e)
	page := e.request("GET", "/services/btc-ord", nil).Body.String()
	if !strings.Contains(page, `name="paths"`) || !strings.Contains(page, "m/84&#39;/1&#39;/0&#39;/0/*</textarea>") || !strings.Contains(page, `<option selected>regtest</option>`) || strings.Contains(page, "changed in access.json") ||
		!strings.Contains(page, "without sats limits") {
		t.Fatal("the service page offers no edit of the bitcoin rules")
	}
	before := e.accessBytes()
	twoPaths := "m/86'/1'/0'/0/*\nm/86'/1'/0'/1/*"
	for _, tc := range []struct {
		name, want string
		form       url.Values
	}{
		{"mainnet with test paths", "a mainnet service signs only for", url.Values{"auth": {"bitcoin-psbt-sign"}, "network": {"mainnet"}, "paths": {twoPaths}, "sighash": {"default", "all"}}},
		{"becomes a proxy", "stays one", url.Values{"auth": {"bearer"}, "base": {"https://api.example.com"}}},
		{"pasted for another key", "another key", url.Values{"pasted": {`{"auth":"bitcoin-psbt-sign","key":"API_KEY","bitcoin":{"network":"regtest","paths":["m/86'/1'/0'/0/*"]}}`}}},
		{"pasted without rules", "bitcoin", url.Values{"pasted": {`{"auth":"bitcoin-psbt-sign"}`}}},
		{"key typed in paths", "path 3: path must start with m", url.Values{"auth": {"bitcoin-psbt-sign"}, "network": {"regtest"}, "paths": {twoPaths + "\n" + bitcointest.Master}, "sighash": {"default", "all"}}},
		{"key pasted in paths", "path 1: path must start with m", url.Values{"pasted": {`{"auth":"bitcoin-psbt-sign","bitcoin":{"network":"regtest","paths":["` + bitcointest.Master + `"]}}`}}},
	} {
		w := e.edit("btc-ord", tc.form)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), tc.want) {
			t.Fatalf("%s: %d, want 400 with %q", tc.name, w.Code, tc.want)
		}
		assertNoBitcoinKey(t, w.Body.String())
		if !bytes.Equal(e.accessBytes(), before) {
			t.Fatalf("%s: a refused edit changed the access file", tc.name)
		}
	}
	// A refused paste is one unit (review of #204): the form shows the
	// stored settings, not the pasted project, so sending it again saves
	// nothing of the paste.
	w := e.edit("btc-ord", url.Values{"pasted": {`{"auth":"bitcoin-psbt-sign","project":"elsewhere","bitcoin":{"network":"mainnet","paths":["m/86'/1'/0'/0/*"]}}`}})
	if body := w.Body.String(); w.Code != http.StatusBadRequest || strings.Contains(body, `value="elsewhere"`) || !strings.Contains(body, "m/84&#39;/1&#39;/0&#39;/0/*</textarea>") {
		t.Fatalf("a refused paste fills the edit form: %d", w.Code)
	}
	w = e.edit("btc-ord", url.Values{"key": {"BTC_ORD"}, "auth": {"bitcoin-psbt-sign"}, "network": {"regtest"}, "paths": {twoPaths}, "sighash": {"default", "all"}})
	if w.Header().Get("Location") != "/services/btc-ord?done=saved" {
		t.Fatalf("edit: %d %s", w.Code, w.Body.String())
	}
	if got := e.proxy.Config().Services["btc-ord"].Bitcoin; !slices.Equal(got.Paths, []string{"m/86'/1'/0'/0/*", "m/86'/1'/0'/1/*"}) {
		t.Fatalf("paths = %v", got.Paths)
	}
	if !strings.Contains(e.audit.String(), `"changed":["bitcoin.paths"]`) {
		t.Fatalf("the edit is not audited by what changed: %s", e.audit.String())
	}
	pasted := `{"btc-ord":{"auth":"bitcoin-psbt-sign","key":"BTC_ORD","bitcoin":{"network":"regtest","paths":["m/86'/1'/0'/0/*","m/86'/1'/0'/1/*"],"sighash":["default","all","all|anyonecanpay"]}}}`
	if w := e.edit("btc-ord", url.Values{"pasted": {pasted}}); w.Header().Get("Location") != "/services/btc-ord?done=saved" {
		t.Fatalf("pasted edit: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(e.audit.String(), `"changed":["bitcoin.sighash"]`) {
		t.Fatal("the pasted edit is not audited by what changed")
	}
	if got := e.proxy.Config().Roles["phobos"].Access["btc-ord"]; got.BitcoinMaxSatsPerTx != 70_000 {
		t.Fatalf("the grant lost its limit: %+v", got)
	}
	if w := addresses(e, "btc-ord", "m/84'/1'/0'/0"); w.Code == http.StatusOK {
		t.Fatal("a path removed by the edit still answers")
	}
	if w := addresses(e, "btc-ord", "m/86'/1'/0'/1"); w.Code != http.StatusOK {
		t.Fatalf("addresses after the edit: %d %s", w.Code, w.Body.String())
	}
}

// A Bitcoin key goes only to a Bitcoin signing service (review of #204):
// every form that would give one to another service is refused and saves
// nothing. First the review's resubmission: the API form of a key with a
// tprv and a WIF value, with the Cloudflare preset, on the WIF value.
func TestBitcoinKeyOnlyForABitcoinSigningService(t *testing.T) {
	e := newEnv(t)
	for name, value := range map[string]string{"MIXED.1": bitcointest.Master, "MIXED.2": bitcointest.WIF, "POOLED.1": "sk-pooled-0123456789"} {
		if err := store.Set(e.backend.StorePath, name, value); err != nil {
			t.Fatal(err)
		}
	}
	base := e.proxy.Config().Services["api"].Base
	e.withService("pooled", policy.Service{Base: base, Key: "POOLED", Auth: policy.AuthBearer, KeyPool: true})
	e.withService("waiting", policy.Service{Base: base, Key: "LATER", Auth: policy.AuthBearer})
	access := e.accessBytes()
	keys, _ := store.Load(e.backend.StorePath)
	unchanged := func(what string) {
		t.Helper()
		if now, _ := store.Load(e.backend.StorePath); !bytes.Equal(e.accessBytes(), access) || !maps.Equal(now, keys) {
			t.Fatalf("%s: saved", what)
		}
	}
	refused := func(what string, w *httptest.ResponseRecorder, name string) {
		t.Helper()
		if body := w.Body.String(); w.Code != http.StatusBadRequest || !strings.Contains(body, name+" is a Bitcoin key; it can only be used by a Bitcoin signing service") {
			t.Fatalf("%s: %d %s", what, w.Code, body)
		}
		assertNoBitcoinKey(t, w.Body.String())
		unchanged(what)
	}
	refused("the review's resubmission", e.request("POST", "/keys/MIXED/connect", url.Values{"preset": {"cloudflare"}, "service": {"cloudflare"},
		"base": {"https://api.cloudflare.com"}, "auth": {"bearer"}, "test_path": {"/client/v4/user/tokens/verify"}, "key_part": {"2"}, "password": {password}}), "MIXED.2")
	refused("the service page", e.edit("api", url.Values{"key": {"MIXED.2"}, "base": {base}, "auth": {"bearer"}, "test_path": {"/v1/check"}}), "MIXED.2")
	refused("Add key for a name a service waits for", e.request("POST", "/keys", url.Values{"name": {"LATER"}, "value": {bitcointest.WIF}, "password": {password}}), "LATER")
	refused("upload over a proxy service's key", e.upload(map[string]string{"name": "API_KEY", "replace": "yes", "password": password}, "key.txt", []byte(bitcointest.WIF), e.csrf), "API_KEY")
	// The key page's forms go back to the page, which says why.
	for what, c := range map[string]struct {
		path, service, value string
	}{
		"a value added to a key pool":      {"/keys/POOLED/add-value", "pooled", "POOLED.2"},
		"Replace on a proxy service's key": {"/keys/API_KEY/replace", "api", "API_KEY"},
	} {
		w := e.request("POST", c.path, url.Values{"value": {bitcointest.Master}, "password": {password}})
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil || w.Code != http.StatusSeeOther || loc.Query().Get("error") != "bitcoin-key" {
			t.Fatalf("%s: %d %s", what, w.Code, w.Header().Get("Location"))
		}
		page := e.request("GET", loc.String(), nil).Body.String()
		if !strings.Contains(page, "Service "+c.service+" would use "+c.value+", which is a Bitcoin key") {
			t.Fatalf("%s: the page does not say why:\n%s", what, page)
		}
		assertNoBitcoinKey(t, page)
		unchanged(what)
	}
}

// A Bitcoin key a proxy service already uses when the keyring loads (stored
// before v0.15.3, or by hand) is refused at request time; it blocks no other
// change and can be replaced, while a change adding another such use is
// still refused (round 5 of #204).
func TestBitcoinKeyInForceBlocksNoOtherChange(t *testing.T) {
	e := newEnv(t)
	base := e.proxy.Config().Services["api"].Base
	e.withService("waiting", policy.Service{Base: base, Key: "LATER", Auth: policy.AuthBearer})
	if err := store.Set(e.backend.StorePath, "API_KEY", bitcointest.WIF); err != nil {
		t.Fatal(err)
	}
	e.backend.Mu.Lock()
	err := e.backend.apply()
	e.backend.Mu.Unlock()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if w := e.request("POST", "/keys", url.Values{"name": {"OTHER"}, "value": {"sk-other-0123456789"}, "password": {password}}); w.Code != http.StatusSeeOther {
		t.Fatalf("an unrelated key: %d %s", w.Code, w.Body.String())
	}
	if w := e.request("POST", "/keys", url.Values{"name": {"LATER"}, "value": {bitcointest.WIF}, "password": {password}}); w.Code != http.StatusBadRequest {
		t.Fatalf("a Bitcoin key for another proxy service: %d", w.Code)
	}
	w := e.request("POST", "/keys/API_KEY/replace", url.Values{"value": {bitcointest.Master}, "password": {password}})
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.Contains(loc, "error=bitcoin-key") {
		t.Fatalf("another Bitcoin key for api: %d %s", w.Code, loc)
	}
	w = e.request("POST", "/keys/API_KEY/replace", url.Values{"value": {"sk-api-0123456789"}, "password": {password}})
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || strings.Contains(loc, "error=") {
		t.Fatalf("the fix: %d %s", w.Code, loc)
	}
	if keys, _ := store.Load(e.backend.StorePath); keys["API_KEY"] != "sk-api-0123456789" || keys["OTHER"] == "" || keys["LATER"] != "" {
		t.Fatal("wrong keys stored")
	}
}
