// ABOUTME: End-to-end CLI tests against a real store behind httptest: --json
// ABOUTME: parity, typed exit codes, human rendering of the same data.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

func newServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{"telemetry_degraded": true},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})
	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{},
		VMDefaults: config.VMDefaults{},
		Owner:      "local_operator",
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}))
	t.Cleanup(srv.Close)
	return srv, st
}

func testUUID(n int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
}

func seedEvent(t *testing.T, st *store.Store, seq string) {
	t.Helper()
	vm, boot := testUUID(1), testUUID(2)
	env := &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vm,
		BootID:           &boot,
		SourceInstanceID: testUUID(9),
		SourceSeq:        seq,
		Kind:             "fs.modify",
		Provenance:       events.GuestReported,
		Sensor:           "fanotify",
		HostReceivedAt:   events.Timestamp{Time: time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)},
		Quality: events.Quality{
			PathResolution: events.PathExactAtCapture,
			Attribution:    events.AttributionExact,
		},
		Data: map[string]any{"path_display": "/workspace/app.py"},
	}
	if _, err := st.Append(t.Context(), env); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestMetaJSON(t *testing.T) {
	srv, _ := newServer(t)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "meta")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var meta struct {
		Service  string          `json:"service"`
		Features map[string]bool `json:"features"`
	}
	if err := json.Unmarshal([]byte(stdout), &meta); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, stdout)
	}
	if meta.Service != "vmobsd" || !meta.Features["events"] {
		t.Errorf("meta = %+v", meta)
	}
}

func TestMetaHuman(t *testing.T) {
	srv, _ := newServer(t)
	code, stdout, _ := runCLI(t, "--api", srv.URL, "meta")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "vmobsd") || !strings.Contains(stdout, "events") {
		t.Errorf("human meta output missing identity/features:\n%s", stdout)
	}
}

func TestEventsJSONAndFilters(t *testing.T) {
	srv, st := newServer(t)
	seedEvent(t, st, "1")
	seedEvent(t, st, "2")

	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "events", "--kind", "fs.modify")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var resp struct {
		Events        []json.RawMessage `json:"events"`
		NextAfter     string            `json:"next_after"`
		LatestEventID string            `json:"latest_event_id"`
	}
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if len(resp.Events) != 2 || resp.LatestEventID != "2" {
		t.Errorf("events response: %d events, latest %q", len(resp.Events), resp.LatestEventID)
	}
}

func TestEventsHumanShowsCursors(t *testing.T) {
	srv, st := newServer(t)
	seedEvent(t, st, "1")
	code, stdout, _ := runCLI(t, "--api", srv.URL, "events")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "fs.modify") || !strings.Contains(stdout, "next_after=1") {
		t.Errorf("human events output:\n%s", stdout)
	}
}

func TestStructuredAPIFailureExitsOne(t *testing.T) {
	srv, _ := newServer(t)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "events", "--kind", "no.such_kind")
	if code != exitAPIError {
		t.Fatalf("exit %d, want %d", code, exitAPIError)
	}
	if !strings.Contains(stderr, "malformed_request") {
		t.Errorf("human error should show the code:\n%s", stderr)
	}
	if stdout != "" {
		t.Errorf("human error must not write stdout: %q", stdout)
	}

	code, stdout, _ = runCLI(t, "--api", srv.URL, "--json", "events", "--kind", "no.such_kind")
	if code != exitAPIError {
		t.Fatalf("json mode exit %d", code)
	}
	var e api.Error
	if err := json.Unmarshal([]byte(stdout), &e); err != nil || e.Code != "malformed_request" {
		t.Errorf("--json failure body: %v, %s", err, stdout)
	}
}

func TestTransportFailureExitsTwo(t *testing.T) {
	// Port 1 on loopback: nothing listens there.
	code, _, stderr := runCLI(t, "--api", "http://127.0.0.1:1", "meta")
	if code != exitTransport {
		t.Fatalf("exit %d, want %d\nstderr: %s", code, exitTransport, stderr)
	}
	if stderr == "" {
		t.Error("transport failure must explain itself on stderr")
	}
}

func TestUsageErrorsExitThree(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"bogus"},
		{"api", "GET"},         // missing path
		{"api", "GET", "meta"}, // path must start with /
		{"--api", "not a url", "meta"},
	} {
		code, _, stderr := runCLI(t, args...)
		if code != exitUsage {
			t.Errorf("args %v: exit %d, want %d (stderr: %s)", args, code, exitUsage, stderr)
		}
	}
}

func TestRawAPIEscapeHatch(t *testing.T) {
	srv, _ := newServer(t)
	code, stdout, _ := runCLI(t, "--api", srv.URL, "api", "GET", "/api/v1/meta")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, `"service"`) {
		t.Errorf("raw api output:\n%s", stdout)
	}

	// A specced-but-unbuilt endpoint is a structured failure, not transport.
	// /runs is now built; probe a different unbuilt endpoint.
	code, _, stderr := runCLI(t, "--api", srv.URL, "api", "GET", "/api/v1/events/stream")
	if code != exitAPIError {
		t.Fatalf("501 probe: exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stderr, "missing_capability") {
		t.Errorf("501 stderr:\n%s", stderr)
	}
}
