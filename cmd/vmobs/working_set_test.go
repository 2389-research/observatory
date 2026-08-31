// ABOUTME: CLI tests for the poll loop: vmobs situation / attention / attention
// ABOUTME: ack against a real daemon surface, human and --json parity, typed exits.
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/store"
)

// breakTelemetry provokes a real telemetry health event via the ingest
// rejection path, which the trigger engine turns into attention.
func breakTelemetry(t *testing.T, st *store.Store, seq string) {
	t.Helper()
	vm, boot := testUUID(1), testUUID(2)
	env := &events.Envelope{
		SchemaVersion: 1, VMID: &vm, BootID: &boot,
		SourceInstanceID: testUUID(91), SourceSeq: seq,
		Kind: "made.up_kind", Provenance: events.GuestReported, Sensor: "fanotify",
		HostReceivedAt: events.Timestamp{Time: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)},
		Quality: events.Quality{
			PathResolution: events.PathExactAtCapture,
			Attribution:    events.AttributionExact,
		},
		Data: map[string]any{"path_display": "/workspace/app.py"},
	}
	if _, err := st.Append(t.Context(), env); err == nil {
		t.Fatal("expected unregistered-kind rejection")
	}
}

func TestSituationQuietShowsWatchScope(t *testing.T) {
	srv, _ := newServer(t)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "situation")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for _, want := range []string{"quiet=true", "as_of=0", "telemetry_degraded", "vms: 0/0"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}

	code, stdout, _ = runCLI(t, "--api", srv.URL, "--json", "situation")
	if code != exitOK {
		t.Fatal(code)
	}
	var js struct {
		AsOfCursor string `json:"as_of_cursor"`
		Quiet      bool   `json:"quiet"`
	}
	if err := json.Unmarshal([]byte(stdout), &js); err != nil {
		t.Fatalf("json parity: %v\n%s", err, stdout)
	}
	if js.AsOfCursor != "0" || !js.Quiet {
		t.Errorf("json = %+v", js)
	}
}

func TestSituationSinceFlagFlowsThrough(t *testing.T) {
	srv, st := newServer(t)
	seedEvent(t, st, "1")
	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "situation", "--since", "1")
	if code != exitOK {
		t.Fatal(code)
	}
	var js struct {
		SinceCursor string `json:"since_cursor"`
		Quiet       bool   `json:"quiet"`
	}
	if err := json.Unmarshal([]byte(stdout), &js); err != nil {
		t.Fatal(err)
	}
	if js.SinceCursor != "1" || !js.Quiet {
		t.Errorf("since delta = %+v", js)
	}

	// A bad cursor is a structured API failure: exit 1, not a stack trace.
	code, _, stderr := runCLI(t, "--api", srv.URL, "situation", "--since", "banana")
	if code != exitAPIError || !strings.Contains(stderr, "malformed_request") {
		t.Errorf("exit %d, stderr: %s", code, stderr)
	}
}

func TestAttentionPollAckLoop(t *testing.T) {
	srv, st := newServer(t)
	breakTelemetry(t, st, "1")

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "attention")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "att-000001") || !strings.Contains(stdout, "needs_decision") ||
		!strings.Contains(stdout, "telemetry_degraded") {
		t.Errorf("list output:\n%s", stdout)
	}

	code, stdout, stderr = runCLI(t, "--api", srv.URL, "attention", "ack", "att-000001")
	if code != exitOK {
		t.Fatalf("ack exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "att-000001") || !strings.Contains(stdout, "acked") {
		t.Errorf("ack output:\n%s", stdout)
	}

	code, stdout, _ = runCLI(t, "--api", srv.URL, "attention")
	if code != exitOK || strings.Contains(stdout, "att-000001") {
		t.Errorf("acked item still in default view (exit %d):\n%s", code, stdout)
	}
	code, stdout, _ = runCLI(t, "--api", srv.URL, "attention", "--all")
	if code != exitOK || !strings.Contains(stdout, "att-000001") {
		t.Errorf("--all hides acked item (exit %d):\n%s", code, stdout)
	}

	code, _, stderr = runCLI(t, "--api", srv.URL, "attention", "ack", "att-999999")
	if code != exitAPIError || !strings.Contains(stderr, "not_found") {
		t.Errorf("unknown ack exit %d: %s", code, stderr)
	}

	code, _, stderr = runCLI(t, "--api", srv.URL, "attention", "ack")
	if code != exitUsage {
		t.Errorf("missing id exit %d: %s", code, stderr)
	}
}

func TestAttentionJSONParity(t *testing.T) {
	srv, st := newServer(t)
	breakTelemetry(t, st, "1")
	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "attention")
	if code != exitOK {
		t.Fatal(code)
	}
	var js struct {
		Items []struct {
			AttentionID string `json:"attention_id"`
			Count       string `json:"count"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(stdout), &js); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if len(js.Items) != 1 || js.Items[0].AttentionID != "att-000001" || js.Items[0].Count != "1" {
		t.Errorf("json = %+v", js)
	}
}
