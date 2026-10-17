package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestGoogleRenewalObservation(t *testing.T) {
	h, _, _, checks, _ := googleFixture(t)
	if _, ok := h.GoogleRenewal("personal"); ok {
		t.Fatal("observation started a renewal")
	}
	if w := call(h, "GET", "/personal/files", "role-personal", nil); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	first, ok := h.GoogleRenewal("personal")
	if !ok || first.Outcome != "success" || first.Phase != "complete" || !first.Process.Available {
		t.Fatalf("missing successful attempt: %+v", first)
	}
	if _, ok := h.GoogleRenewal("business"); ok {
		t.Fatal("another account inherited the attempt")
	}
	for range 3 {
		observed, ok := h.GoogleRenewal("personal")
		if !ok || observed != first {
			t.Fatal("reading diagnostics changed the completed attempt")
		}
		if w := call(h, "GET", "/personal/files", "role-personal", nil); w.Code != http.StatusOK {
			t.Fatal(w.Code)
		}
	}
	if checks.Load() != 1 {
		t.Fatal("diagnostics or cache hits initiated renewal")
	}
	last, _ := h.GoogleRenewal("personal")
	if last != first {
		t.Fatal("a cache hit replaced the actual renewal record")
	}
	encoded, err := json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"synthetic-personal", "personal@example.com", "quota-personal", "googleapis.com"} {
		if strings.Contains(string(encoded), private) {
			t.Fatal("diagnostics disclosed private renewal data")
		}
	}
}

func TestGoogleRenewalValidationTimeout(t *testing.T) {
	h, _, _, _, _ := googleFixture(t)
	entered := make(chan struct{})
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer fixture.Close()
	target, err := url.Parse(fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	h.client = &http.Client{Transport: googleTestTransport{target: target, transport: fixture.Client().Transport}, Timeout: 100 * time.Millisecond}
	done := make(chan int, 1)
	go func() { done <- call(h, "GET", "/personal/files", "role-personal", nil).Code }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("token validation never reached the fixture")
	}
	active, ok := h.GoogleRenewal("personal")
	if !ok || active.Phase != "token_validation" || active.Outcome != "running" {
		t.Fatalf("wrong active phase: %+v", active)
	}
	if code := <-done; code != http.StatusBadGateway {
		t.Fatal(code)
	}
	completed, _ := h.GoogleRenewal("personal")
	if completed.Phase != "token_validation" || completed.Outcome != "timeout" || completed.CompletedAt.IsZero() {
		t.Fatalf("validation timeout attributed to SDK: %+v", completed)
	}
	if completed.Steps[2].Outcome != "success" || completed.Steps[4].Outcome != "timeout" {
		t.Fatalf("stage outcomes lost: %+v", completed.Steps)
	}
}
