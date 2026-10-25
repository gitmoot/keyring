package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

func TestCloudflareClientImport(t *testing.T) {
	const account = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const pilot = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const binding = "OAUTH_CLIENT_SECRETS_BY_INSTANCE"
	const secret = "synthetic-private-pilot-client-secret"
	const originalGlobal = `{"OTHER_CLIENT":"synthetic-unrelated"}`
	const root = "/operator/cloudflare/client/v4/accounts/" + account + "/workers/scripts/keyring-instances"
	for _, mode := range []string{"import", "existing-secret", "existing-plain-binding", "changed-before-write", "provider-error", "redirect", "malformed-settings", "private-file", "private-fifo", "no-exclusive-writer", "invalid-option"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			kinds := map[string]string{"MASTER_KEY": "secret_text", "OAUTH_CLIENT_SECRETS": "secret_text", "KEYRING": "durable_object_namespace", "PUBLIC_BASE": "plain_text"}
			values := map[string]string{"MASTER_KEY": "synthetic-master", "OAUTH_CLIENT_SECRETS": originalGlobal}
			if mode == "existing-secret" || mode == "existing-plain-binding" {
				kinds[binding] = "secret_text"
				if mode == "existing-plain-binding" {
					kinds[binding] = "plain_text"
				}
				values[binding] = `{"cccccccccccccccccccccccccccccccc":{"GOOGLE_CLIENT_SECRET":"other-person"}}`
			}
			var redirected atomic.Int32
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer receiver.Close()
			gets, puts := 0, 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == "GET" && r.URL.Path == root+"/settings":
					gets++
					if mode == "malformed-settings" {
						io.WriteString(w, `{"success":true,"result":{}}`)
						return
					}
					if mode == "changed-before-write" && gets == 2 {
						kinds[binding] = "secret_text"
						values[binding] = "concurrent-operator-value"
					}
					bindings := make([]map[string]string, 0, len(kinds))
					for name, kind := range kinds {
						bindings = append(bindings, map[string]string{"name": name, "type": kind})
					}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"bindings": bindings}})
				case r.Method == "PUT" && r.URL.Path == root+"/secrets":
					puts++
					var input struct{ Name, Type, Text string }
					if json.NewDecoder(r.Body).Decode(&input) != nil {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if mode == "provider-error" {
						// Even a provider that echoes the submitted secret must not
						// put it in a diagnostic or falsely acknowledge the write.
						json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []string{input.Text}})
						return
					}
					if mode == "redirect" {
						w.Header().Set("Location", receiver.URL)
						w.WriteHeader(http.StatusTemporaryRedirect)
						return
					}
					kinds[input.Name], values[input.Name] = input.Type, input.Text
					json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"name": input.Name, "type": input.Type}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer api.Close()
			args := []string{"cloudflare-import-client", "--relay-base", api.URL + "/operator/cloudflare/client/v4", "--account", account, "--worker", "keyring-instances", "--keyring-id", pilot}
			if mode == "import" {
				var out, diagnostics bytes.Buffer
				if code := run(append(append([]string{}, args...), "--check-only"), strings.NewReader(""), &out, &diagnostics); code != 0 {
					t.Fatalf("destination preflight failed: code=%d", code)
				}
				var receipt struct{ Ready bool }
				if json.Unmarshal(out.Bytes(), &receipt) != nil || !receipt.Ready {
					t.Fatal("preflight did not report readiness")
				}
				mu.Lock()
				if puts != 0 || len(values) != 2 {
					t.Error("preflight mutated the Worker")
				}
				mu.Unlock()
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if _, err := io.WriteString(writer, secret); err != nil {
				writer.Close()
				t.Fatal(err)
			}
			writer.Close()
			var input io.Reader = reader
			if mode == "private-file" {
				path := filepath.Join(t.TempDir(), "synthetic-secret")
				if err := os.WriteFile(path, []byte(secret), 0600); err != nil {
					t.Fatal(err)
				}
				f, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				input = f
			}
			if mode == "private-fifo" {
				path := filepath.Join(t.TempDir(), "synthetic.fifo")
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				input = f
			}
			if mode != "no-exclusive-writer" {
				args = append(args, "--exclusive-writer")
			}
			if mode == "invalid-option" {
				args = append(args, "--"+secret)
			}
			var out, diagnostics bytes.Buffer
			code := run(args, input, &out, &diagnostics)
			if strings.Contains(out.String()+diagnostics.String(), secret) || strings.Contains(out.String()+diagnostics.String(), "other-person") {
				t.Fatal("secret material appeared in command output")
			}
			mu.Lock()
			defer mu.Unlock()
			if values["MASTER_KEY"] != "synthetic-master" || values["OAUTH_CLIENT_SECRETS"] != originalGlobal {
				t.Fatal("unrelated Worker secrets changed")
			}
			if mode == "import" {
				if code != 0 || puts != 1 {
					t.Fatalf("private import failed: code=%d writes=%d", code, puts)
				}
				var scoped map[string]map[string]string
				if json.Unmarshal([]byte(values[binding]), &scoped) != nil || len(scoped) != 1 || len(scoped[pilot]) != 1 || scoped[pilot]["GOOGLE_CLIENT_SECRET"] != secret {
					t.Fatal("secret was not scoped exclusively to the confirmed pilot/key")
				}
				var receipt struct {
					KeyringID string `json:"keyring_id"`
					Written   bool   `json:"write_acknowledged"`
					Readback  bool   `json:"value_readback"`
					Runtime   bool   `json:"runtime_import_verified"`
				}
				if json.Unmarshal(out.Bytes(), &receipt) != nil || receipt.KeyringID != pilot || !receipt.Written || receipt.Readback || receipt.Runtime {
					t.Fatal("receipt overclaims verification or reports a wrong target")
				}
			} else {
				if code == 0 || out.Len() != 0 {
					t.Fatal("unsafe or unconfirmed import was acknowledged")
				}
				wantPuts := 0
				if mode == "provider-error" || mode == "redirect" {
					wantPuts = 1
				}
				if puts != wantPuts {
					t.Fatalf("unexpected write/retry count: got%d want%d", puts, wantPuts)
				}
				if mode == "private-file" || mode == "private-fifo" || mode == "no-exclusive-writer" || mode == "invalid-option" {
					if gets != 0 {
						t.Fatal("invalid input crossed the local boundary")
					}
				}
			}
			if redirected.Load() != 0 {
				t.Fatal("secret-bearing request followed a redirect")
			}
			if mode == "existing-secret" || mode == "existing-plain-binding" {
				if values[binding] != `{"cccccccccccccccccccccccccccccccc":{"GOOGLE_CLIENT_SECRET":"other-person"}}` {
					t.Fatal("existing per-person secret map was overwritten")
				}
			}
			if mode == "changed-before-write" && values[binding] != "concurrent-operator-value" {
				t.Fatal("intervening operator value was overwritten")
			}
		})
	}
}

func TestCloudflareSharedClientImport(t *testing.T) {
	const binding = "OAUTH_CLIENT_SECRETS_SHARED"
	const secret = "synthetic-new-shared-secret"
	const global = `{"EXISTING_CLIENT":"synthetic-global"}`
	const pilot = `{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"GOOGLE_CLIENT_SECRET":"synthetic-pilot"}}`
	for _, mode := range []string{"import", "existing", "ambiguous-scope"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			values := map[string]string{"OAUTH_CLIENT_SECRETS": global, scopedClientBinding: pilot}
			if mode == "existing" {
				values[binding] = `{"OTHER":"already-installed"}`
			}
			writes := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/settings"):
					bindings := make([]map[string]string, 0, len(values))
					for name := range values {
						bindings = append(bindings, map[string]string{"name": name, "type": "secret_text"})
					}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"bindings": bindings}})
				case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/secrets"):
					writes++
					var input struct{ Name, Type, Text string }
					if json.NewDecoder(r.Body).Decode(&input) != nil || input.Name != binding || input.Type != "secret_text" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					values[input.Name] = input.Text
					json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]string{"name": input.Name, "type": input.Type}})
				default:
					http.NotFound(w, r)
				}
			}))
			defer api.Close()
			args := []string{"cloudflare-import-client", "--relay-base", api.URL + "/operator/cloudflare/client/v4", "--account", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--worker", "keyring-instances", "--shared", "--exclusive-writer"}
			if mode == "ambiguous-scope" {
				args = append(args, "--keyring-id", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
			}
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if _, err := io.WriteString(writer, secret); err != nil {
				writer.Close()
				t.Fatal(err)
			}
			writer.Close()
			var out, diagnostics bytes.Buffer
			code := run(args, reader, &out, &diagnostics)
			mu.Lock()
			defer mu.Unlock()
			if values["OAUTH_CLIENT_SECRETS"] != global || values[scopedClientBinding] != pilot {
				t.Fatal("existing global or pilot secret map changed")
			}
			if strings.Contains(out.String()+diagnostics.String(), secret) {
				t.Fatal("shared secret appeared in output")
			}
			if mode == "import" {
				var imported map[string]string
				if code != 0 || writes != 1 || json.Unmarshal([]byte(values[binding]), &imported) != nil || len(imported) != 1 || imported["GOOGLE_CLIENT_SECRET"] != secret {
					t.Fatal("shared secret did not reach the independent overlay")
				}
				var receipt struct {
					Binding   string `json:"binding"`
					KeyringID string `json:"keyring_id"`
					Written   bool   `json:"write_acknowledged"`
				}
				if json.Unmarshal(out.Bytes(), &receipt) != nil || receipt.Binding != binding || receipt.KeyringID != "" || !receipt.Written {
					t.Fatal("shared import receipt misidentifies its scope")
				}
			} else if code == 0 || writes != 0 || (mode == "existing" && values[binding] != `{"OTHER":"already-installed"}`) {
				t.Fatal("unsafe shared import changed protected settings")
			}
		})
	}
}
