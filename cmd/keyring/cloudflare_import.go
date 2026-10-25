package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const scopedClientBinding = "OAUTH_CLIENT_SECRETS_BY_INSTANCE"

// This is an initial import, not a read/modify/write of an opaque Worker secret.
// Cloudflare offers no compare-and-set here: the operator must exclude competing
// deployment/secret writers until the command finishes. An existing destination
// binding of any type is refused rather than overwriting unknown entries.
func runCloudflareClientImport(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cloudflare-import-client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	base := fs.String("relay-base", "", "existing loopback Keyring relay URL for the Cloudflare API")
	account := fs.String("account", "", "confirmed Cloudflare account ID")
	worker := fs.String("worker", "", "confirmed existing Worker name")
	id := fs.String("keyring-id", "", "pilot ID confirmed from the authenticated person's canonical mapping")
	shared := fs.Bool("shared", false, "initial shared-client overlay import instead of a per-instance binding")
	checkOnly := fs.Bool("check-only", false, "check destination and binding absence without reading a secret or writing")
	exclusive := fs.Bool("exclusive-writer", false, "operator has excluded other Worker deployment/secret writers during import")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, "Usage: keyring cloudflare-import-client [options]")
			fs.SetOutput(stdout)
			fs.PrintDefaults()
			return 0
		}
		fmt.Fprintln(stderr, "cloudflare-import-client: invalid arguments; use --help")
		return 2
	}
	fail := func(message string) int {
		fmt.Fprintln(stderr, "cloudflare-import-client: "+message)
		return 1
	}
	if fs.NArg() != 0 || !lowerHexID(*account) || !workerName(*worker) || (*shared && *id != "") || (!*shared && !lowerHexID(*id)) {
		return fail("pass confirmed --account, --worker and exactly one of --keyring-id or --shared; no positional secret or file arguments")
	}
	binding := scopedClientBinding
	if *shared {
		binding = "OAUTH_CLIENT_SECRETS_SHARED"
	}
	u, err := url.Parse(*base)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || !net.ParseIP(u.Hostname()).IsLoopback() || u.Path == "" || strings.Contains(u.Path, "..") {
		return fail("--relay-base must be an existing numeric-loopback HTTP relay API URL without credentials, query or fragment")
	}
	if !*checkOnly {
		if !*exclusive {
			return fail("--exclusive-writer is required; coordinate with the deployment owner before importing")
		}
		f, ok := stdin.(*os.File)
		if !ok {
			return fail("secret input requires an inherited anonymous pipe")
		}
		info, statErr := f.Stat()
		if statErr != nil || info.Mode()&os.ModeNamedPipe == 0 {
			return fail("secret input requires an inherited anonymous pipe, not a terminal or file")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		anonymous := false
		if ok {
			switch runtime.GOOS {
			case "linux":
				// Linux anonymous pipes have one pseudo-filesystem link;
				// unlike a named FIFO their proc descriptor names the pipe.
				target, readErr := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
				anonymous = readErr == nil && target == fmt.Sprintf("pipe:[%d]", stat.Ino)
			case "darwin":
				anonymous = stat.Nlink == 0
			}
		}
		if !anonymous {
			return fail("named FIFOs are not supported; use an inherited anonymous pipe")
		}
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	root := strings.TrimRight(u.String(), "/") + "/accounts/" + *account + "/workers/scripts/" + *worker
	before, err := cloudflareBindings(client, root)
	if err != nil {
		return fail("could not verify existing Worker bindings; no write attempted")
	}
	if _, exists := before[binding]; exists {
		return fail("target binding already exists; refuse to overwrite unknown entries")
	}
	if *checkOnly {
		return cloudflareImportReceipt(stdout, stderr, *account, *worker, *id, binding, false)
	}
	// Reuse the native Linux/Darwin private-pipe and bounded-input checks. Neither
	// the pipe contents nor provider response bodies are ever printed or saved.
	secret, err := readSecretFile("/dev/stdin", stdin)
	if err != nil {
		return fail("could not read bounded private secret input")
	}
	if !utf8.ValidString(secret) || strings.TrimSpace(secret) != secret || strings.ContainsAny(secret, "\r\n\x00") {
		return fail("expected an exact UTF-8 client-secret value without surrounding whitespace or line breaks")
	}
	var value []byte
	if *shared {
		value, err = json.Marshal(map[string]string{"GOOGLE_CLIENT_SECRET": secret})
	} else {
		value, err = json.Marshal(map[string]map[string]string{*id: {"GOOGLE_CLIENT_SECRET": secret}})
	}
	if err != nil {
		return fail("could not encode client secret")
	}
	body, err := json.Marshal(struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Text string `json:"text"`
	}{binding, "secret_text", string(value)})
	if err != nil {
		return fail("could not encode binding")
	}
	// The producer may have taken time to supply the secret. Recheck immediately
	// before submission, in addition to the required exclusive-writer agreement.
	current, err := cloudflareBindings(client, root)
	if err != nil || !sameBindings(before, current) {
		return fail("Worker binding metadata changed or could not be rechecked; no write attempted")
	}
	var accepted struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := cloudflareImportRequest(client, http.MethodPut, root+"/secrets", body, &accepted); err != nil || accepted.Name != binding || accepted.Type != "secret_text" {
		return fail("submission was not confirmed; binding state may have changed; do not retry blindly")
	}
	after, err := cloudflareBindings(client, root)
	if err != nil || after[binding] != "secret_text" {
		return fail("write acknowledged but binding metadata verification failed; do not retry blindly")
	}
	delete(after, binding)
	if !sameBindings(before, after) {
		return fail("write acknowledged but unrelated binding metadata changed; stop and reconcile with the deployment owner")
	}
	return cloudflareImportReceipt(stdout, stderr, *account, *worker, *id, binding, true)
}

func lowerHexID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := range s {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

func workerName(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i := range s {
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z' || s[i] >= '0' && s[i] <= '9' || s[i] == '-' || s[i] == '_') {
			return false
		}
	}
	return true
}

func sameBindings(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for name, kind := range a {
		if b[name] != kind {
			return false
		}
	}
	return true
}

func cloudflareBindings(client *http.Client, root string) (map[string]string, error) {
	var settings struct {
		Bindings *[]struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"bindings"`
	}
	if err := cloudflareImportRequest(client, http.MethodGet, root+"/settings", nil, &settings); err != nil {
		return nil, err
	}
	if settings.Bindings == nil {
		return nil, errors.New("missing binding metadata")
	}
	bindings := make(map[string]string, len(*settings.Bindings))
	for _, binding := range *settings.Bindings {
		if binding.Name == "" || binding.Type == "" {
			return nil, errors.New("incomplete binding metadata")
		}
		if _, duplicate := bindings[binding.Name]; duplicate {
			return nil, errors.New("duplicate binding metadata")
		}
		bindings[binding.Name] = binding.Type
	}
	return bindings, nil
}

func cloudflareImportRequest(client *http.Client, method, target string, body []byte, result any) error {
	// Static errors only: transport/JSON/provider diagnostics can contain data
	// supplied in the request. Even the provider's error array is not surfaced.
	fail := errors.New("Cloudflare request not confirmed")
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		return fail
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer keyring-relay-placeholder")
	resp, err := client.Do(req)
	if err != nil {
		return fail
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fail
	}
	const limit = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(raw) > limit {
		return fail
	}
	envelope := struct {
		Success bool `json:"success"`
		Result  any  `json:"result"`
	}{Result: result}
	if json.Unmarshal(raw, &envelope) != nil || !envelope.Success || envelope.Result == nil {
		return fail
	}
	return nil
}

func cloudflareImportReceipt(stdout, stderr io.Writer, account, worker, id, binding string, written bool) int {
	receipt := struct {
		Account        string `json:"account"`
		Worker         string `json:"worker"`
		KeyringID      string `json:"keyring_id,omitempty"`
		Binding        string `json:"binding"`
		Ready          bool   `json:"ready"`
		Written        bool   `json:"write_acknowledged"`
		ValueReadback  bool   `json:"value_readback"`
		RuntimeChecked bool   `json:"runtime_import_verified"`
	}{account, worker, id, binding, !written, written, false, false}
	if json.NewEncoder(stdout).Encode(receipt) != nil {
		fmt.Fprintln(stderr, "cloudflare-import-client: receipt output failed; inspect binding metadata before retrying")
		return 1
	}
	return 0
}
