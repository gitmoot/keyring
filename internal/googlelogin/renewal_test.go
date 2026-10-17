package googlelogin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gitmoot/keyring/internal/gcloudexec"
)

func TestTokenRenewalDiagnostics(t *testing.T) {
	for _, mode := range []string{"queue", "sdk-timeout", "sdk-error", "persistence", "success"} {
		t.Run(mode, func(t *testing.T) {
			c, _, failSave := controllerFixture(t)
			t.Cleanup(c.Close)
			s := &Snapshot{Generation: strings.Repeat("a", 32), Account: "person@example.test", Project: "fixture-project", Ready: true,
				Files: map[string][]byte{"credentials.db": []byte("synthetic-private-db")}}
			if err := c.Restore(s); err != nil {
				t.Fatal(err)
			}
			if err := c.save(context.Background(), "", s); err != nil {
				t.Fatal(err)
			}
			duration := 3 * time.Second
			phase, outcome := "complete", "success"
			switch mode {
			case "queue":
				if err := c.acquire(context.Background()); err != nil {
					t.Fatal(err)
				}
				defer func() { <-c.ops }()
				duration, phase, outcome = 30*time.Millisecond, "controller_wait", "timeout"
			case "sdk-timeout":
				if err := os.WriteFile(filepath.Join(c.root, "block"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				duration, phase, outcome = time.Second, "sdk_execution", "timeout"
			case "sdk-error":
				if err := os.WriteFile(filepath.Join(c.root, "failure"), []byte("synthetic-secret-stderr"), 0600); err != nil {
					t.Fatal(err)
				}
				phase, outcome = "sdk_execution", "error"
			case "persistence":
				*failSave = true
				phase, outcome = "persistence", "error"
			}
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			defer cancel()
			var trace gcloudexec.RenewalTrace
			trace.Begin()
			token, err := c.Token(ctx, s.Binding(), &trace)
			trace.Finish(err)
			r, ok := trace.Snapshot()
			if !ok || r.Phase != phase || r.Outcome != outcome || r.CompletedAt.IsZero() {
				t.Fatalf("wrong failure attribution: %+v", r)
			}
			if mode == "success" {
				if err != nil || token != "fixture-access-token" {
					t.Fatal("successful renewal changed")
				}
			} else if err == nil || token != "" {
				t.Fatal("failed renewal returned a token")
			}
			if mode == "queue" {
				if r.Process.Available || r.Steps[gcloudexec.RenewalSDK].Outcome != "not_run" {
					t.Fatal("queue timeout was misreported as an SDK attempt")
				}
			} else if !r.Process.Available || (mode == "sdk-error" && r.Process.ExitCode != 1) {
				t.Fatalf("terminal SDK metadata missing: %+v", r.Process)
			}
			if mode == "sdk-error" && r.Steps[gcloudexec.RenewalPersistence].Outcome != "success" {
				t.Fatal("post-error snapshot handling lost its own result")
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"synthetic-private-db", "fixture-access-token", "synthetic-secret-stderr", s.Account, c.root} {
				if strings.Contains(string(encoded), secret) {
					t.Fatal("private material entered diagnostics")
				}
			}
		})
	}
}
