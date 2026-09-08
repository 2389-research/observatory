// ABOUTME: Proves the served daemon generates reports using its actual startup wiring.
// ABOUTME: Seeds durable terminal work and reads the report through real HTTP after restart.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/store"
)

func TestServeGeneratesReportsForDurableTerminalRuns(t *testing.T) {
	cfg := testConfig(t, "127.0.0.1:0")
	if err := os.MkdirAll(filepath.Dir(cfg.Storage.Database), 0700); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.Storage.Database)
	if err != nil {
		t.Fatal(err)
	}
	const vmID = "00000000-0000-4000-8000-000000000321"
	_, _, _, err = st.CreateVMWithOperation(t.Context(), store.CreateVMInput{VMID: vmID, Name: "report-wiring", Owner: "local_operator", TemplateID: "fixture", TemplateDigest: "sha256:fixture", Kind: "vm.create", Admit: func(store.ReservationTotals) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{VMID: vmID, To: "failed", Reason: "fixture ended", ReleaseAll: true}); err != nil {
		t.Fatal(err)
	}
	run, _, err := st.CreateRun(t.Context(), store.CreateRunInput{VMID: vmID, Owner: "local_operator", Goal: "inspect durable outcome", CriteriaType: "operator_verdict", OnCompletion: "keep_running", InitialPhase: "running", RequestHash: "fixture-report"})
	if err != nil {
		t.Fatal(err)
	}
	for _, transition := range []store.RunTransitionInput{{RunID: run.RunID, From: "running", To: "concluding"}, {RunID: run.RunID, From: "concluding", To: "succeeded", EvaluatedBy: "operator", Reason: "fixture evidence"}} {
		if _, err := st.TransitionRun(t.Context(), transition); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	finished := make(chan error, 1)
	go func() { finished <- serve(ctx, cfg, quietLogger(), func(addr string) { ready <- addr }) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-finished:
			if err != nil {
				t.Errorf("daemon shutdown: %v", err)
			}
		case <-time.After(shutdownWait):
			t.Error("daemon failed to shut down")
		}
	})
	var addr string
	select {
	case addr = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not become ready")
	}
	resp, err := http.Get("http://" + addr + "/api/v1/runs/" + run.RunID + "/report")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || result["status"] != "generated" || result["digest"] == "" {
		t.Fatalf("durable terminal run has no generated report: %d %v", resp.StatusCode, result)
	}
}
