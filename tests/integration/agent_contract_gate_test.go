// ABOUTME: Walks the discoverable bounded agent slice through real Firecracker HTTP.
// ABOUTME: Persists a cursor handoff and resumes without reconstructing mutation paths.

//go:build linux

package integration_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestKataAgentContractGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 inside scripts/vmobs-gate")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)
	d := startDaemon(t, findRepoRoot(t), buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd"), buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner"), "kata-agent-contract", withRequiredAuth(m1bOperator, m1bPassword))
	// The configured transport already includes /api/v1. All paths after this
	// bootstrap come from the manifest or resource links, never fixture constants.
	meta := d.apiGet(t, "/meta")
	rawRoutes, ok := meta["routes"].([]any)
	if !ok {
		t.Fatal("manifest lacks route discovery")
	}
	routes := map[string]map[string]any{}
	for _, raw := range rawRoutes {
		r := raw.(map[string]any)
		if purpose, ok := r["purpose"].(string); ok {
			routes[purpose] = r
		}
	}
	path := func(purpose string) string {
		t.Helper()
		r := routes[purpose]
		if r == nil {
			t.Fatalf("manifest lacks purpose %s", purpose)
		}
		return strings.TrimPrefix(stringField(r, "path"), "/api/v1")
	}
	get := func(full string) map[string]any {
		t.Helper()
		code, result := d.apiGetCode(t, strings.TrimPrefix(full, "/api/v1"))
		if code != 200 {
			t.Fatalf("GET %s = %d: %v", full, code, result)
		}
		return result
	}
	link := func(resource map[string]any, name string) string {
		t.Helper()
		links, ok := resource["links"].(map[string]any)
		if !ok {
			t.Fatalf("resource lacks links: %v", resource)
		}
		value := stringField(links, name)
		if value == "" {
			t.Fatalf("missing %s link: %v", name, resource)
		}
		return value
	}
	example := func(purpose string) map[string]any {
		t.Helper()
		raw, ok := routes[purpose]["request_example"].(map[string]any)
		if !ok {
			t.Fatalf("%s lacks request shape", purpose)
		}
		return raw
	}
	capacity := get(path("capacity"))
	if capacity["capacity"] == nil {
		t.Fatalf("capacity absent: %v", capacity)
	}
	templates := get(path("templates"))["templates"].([]any)
	if len(templates) == 0 {
		t.Fatal("no launch template")
	}
	snapshot := get(path("snapshot"))
	cursor := stringField(snapshot, "as_of_cursor")
	if cursor == "" || snapshot["omitted"] == nil {
		t.Fatalf("snapshot lacks bounded resume evidence: %v", snapshot)
	}
	request := example("launch")
	request["name"] = "cold-agent"
	request["template_id"] = stringField(templates[0].(map[string]any), "template_id")
	request["idempotency_key"] = "cold-agent-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	request["run"].(map[string]any)["goal"] = "verify a discovered launch, assessment and safe resume"
	handoffPath := filepath.Join(t.TempDir(), "agent-handoff.json")
	save := func(v any) {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(handoffPath, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	save(map[string]any{"cursor": cursor, "request": request})
	code, created := d.apiPost(t, path("launch"), request)
	if code != 201 {
		t.Fatalf("discovered launch: %d %v", code, created)
	}
	vm := created["vm"].(map[string]any)
	vmID := stringField(vm, "vm_id")
	d.trackVMID(vmID)
	code, replay := d.apiPost(t, path("launch"), request)
	if code != 201 || replay["is_replay"] != true || stringField(replay["vm"].(map[string]any), "vm_id") != vmID {
		t.Fatalf("exact launch replay: %d %v", code, replay)
	}
	operation := created["operation"].(map[string]any)
	if stringField(replay["operation"].(map[string]any), "operation_id") != stringField(operation, "operation_id") {
		t.Fatal("launch replay created a second operation")
	}
	operationURL := link(operation, "self")
	vmURL := link(vm, "self")
	deadline := time.Now().Add(90 * time.Second)
	for {
		op := get(operationURL)
		state := stringField(op, "state")
		if state == "succeeded" {
			break
		}
		if state == "failed" || time.Now().After(deadline) {
			t.Fatalf("operation did not succeed: %v", op)
		}
		time.Sleep(100 * time.Millisecond)
	}
	vm = get(vmURL)
	if stringField(vm, "observed_state") != "running" {
		t.Fatalf("launch did not run: %v", vm)
	}
	runs := get(link(vm, "runs"))["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("expected one attached run: %v", runs)
	}
	run := runs[0].(map[string]any)
	runURL := link(run, "self")
	verdict := example("conclude")
	verdict["reason"] = "observed the real VM running and its launch operation succeeded"
	code, concluded := d.apiPost(t, strings.TrimPrefix(link(run, "conclude"), "/api/v1"), verdict)
	if code != 200 {
		t.Fatalf("conclude: %d %v", code, concluded)
	}
	run = get(runURL)
	outcome := run["outcome"].(map[string]any)
	if stringField(outcome, "status") != "succeeded" || stringField(outcome, "evaluated_by") != "operator" {
		t.Fatalf("operator result provenance: %v", outcome)
	}
	deadline = time.Now().Add(30 * time.Second)
	for {
		report := get(link(run, "report"))
		if stringField(report, "status") == "generated" {
			if stringField(report, "digest") == "" {
				t.Fatal("report lacks digest")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("report not generated: %v", report)
		}
		time.Sleep(100 * time.Millisecond)
	}
	vm = get(vmURL)
	action := example("action")
	action["expected_revision"] = stringField(vm, "revision")
	correctRevision := action["expected_revision"]
	action["expected_revision"] = "0"
	code, stale := d.apiPost(t, strings.TrimPrefix(link(vm, "actions"), "/api/v1"), action)
	if code != 409 || stringField(stale, "retry_strategy") != "after_refresh" {
		t.Fatalf("stale action recovery: %d %v", code, stale)
	}
	action["expected_revision"] = correctRevision
	code, stopped := d.apiPost(t, strings.TrimPrefix(link(vm, "actions"), "/api/v1"), action)
	if code != 200 || stringField(stopped["vm"].(map[string]any), "observed_state") != "stopped" {
		t.Fatalf("revision-bound stop: %d %v", code, stopped)
	}

	// Save only a completely processed page's cursor, then discard the in-memory
	// handoff and load it from disk as the next agent session would.
	eventsURL := path("events")
	first := get(eventsURL + "?after=" + cursor + "&limit=2")
	seen := map[string]bool{}
	for _, raw := range first["events"].([]any) {
		seen[stringField(raw.(map[string]any), "event_id")] = true
	}
	save(map[string]any{"cursor": stringField(first, "next_after"), "operation": operationURL, "vm": vmURL, "run": runURL})
	var handoff map[string]string
	raw, err := os.ReadFile(handoffPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &handoff); err != nil {
		t.Fatal(err)
	}
	get(handoff["operation"])
	get(handoff["vm"])
	get(handoff["run"])
	cursor = handoff["cursor"]
	upper := stringField(first, "latest_event_id")
	pages := 0
	for {
		page := get(fmt.Sprintf("%s?after=%s&until=%s&limit=2", eventsURL, cursor, upper))
		rows := page["events"].([]any)
		if len(rows) == 0 {
			if stringField(page, "next_after") != cursor {
				t.Fatal("empty page moved cursor")
			}
			break
		}
		for _, raw := range rows {
			id := stringField(raw.(map[string]any), "event_id")
			if seen[id] {
				t.Fatalf("resume duplicated event %s", id)
			}
			seen[id] = true
		}
		cursor = stringField(page, "next_after")
		pages++
		if pages > 1000 {
			t.Fatal("bounded replay failed to finish")
		}
	}
	if pages == 0 {
		t.Fatal("fixture did not require a resume page")
	}
	// Compare a complete bounded replay of the same interval, proving no skip as
	// well as no duplicate. New guest heartbeats cannot move the frozen bound.
	full := get(eventsURL + "?after=" + stringField(snapshot, "as_of_cursor") + "&until=" + upper + "&limit=" + fmt.Sprint(int(meta["limits"].(map[string]any)["events_page_max"].(float64))))
	if len(full["events"].([]any)) != len(seen) {
		t.Fatalf("resume lost rows: full=%d seen=%d", len(full["events"].([]any)), len(seen))
	}
	d.deleteVM(t, vmID)
	t.Logf("V2-AGENT-001/003/004: discovered launch/replay, operation, run verdict/report, revision stop and %d resumed event pages", pages)
}
