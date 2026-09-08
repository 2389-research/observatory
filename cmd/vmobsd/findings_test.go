// ABOUTME: Covers the startup scan's three outcomes reaching the two maps the
// ABOUTME: lifecycle manager reads, and the one that deliberately reaches neither.
package main

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/2389-research/observatory/internal/jailer"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/store"
)

func TestAdapterFindingHandoffPreservesAmbiguousCompute(t *testing.T) {
	for _, state := range []string{"running", "paused"} {
		t.Run(state, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "findings.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			vm, _, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{VMID: "uncertain", Name: "uncertain", Owner: "test", TemplateID: "test", TemplateDigest: "sha256:test", VCPUCount: 1, MemoryMiB: 128, MemoryTotalMiB: 128, RootDiskMiB: 64, Kind: "vm.create", Admit: func(store.ReservationTotals) error { return nil }})
			if err != nil {
				t.Fatal(err)
			}
			states := []string{"starting", "running"}
			if state == "paused" {
				states = append(states, "paused")
			}
			for _, to := range states {
				if _, err := st.TransitionVM(t.Context(), store.TransitionInput{VMID: vm.VMID, To: to, Reason: "fixture"}); err != nil {
					t.Fatal(err)
				}
			}
			findings := []jailer.Finding{{VMID: vm.VMID, Outcome: "ambiguous", Detail: "runner identity mismatch"}}
			adopted, ambiguous := classifyFindings(findings)
			mgr, err := runtime.NewManager(st, runtime.ForHost(), runtime.ManagerConfig{AdoptedVMs: adopted, AmbiguousVMs: ambiguous})
			if err != nil {
				t.Fatal(err)
			}
			defer mgr.Close()
			applyAdapterFindings(t.Context(), mgr, findings, slog.New(slog.NewTextHandler(io.Discard, nil)))
			got, err := st.GetVM(t.Context(), vm.VMID)
			if err != nil {
				t.Fatal(err)
			}
			totals, err := st.ReservationTotals(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if got.ObservedState != state || totals.MemoryMiB != 128 || totals.VCPU != 1 {
				t.Fatalf("ambiguous handoff changed state/compute: state=%s totals=%+v", got.ObservedState, totals)
			}
		})
	}
}

func TestClassifyFindingsCarriesAnUnclassifiableVMAndItsReason(t *testing.T) {
	adopted, ambiguous := classifyFindings([]jailer.Finding{
		{VMID: "vm-live", Outcome: "adopted", Detail: "runner 900 attached to vmm 41"},
		{VMID: "vm-unknown", Outcome: "ambiguous", Detail: "unreadable manifest: unexpected end of JSON input"},
		{VMID: "vm-dead", Outcome: "vmm_gone", Detail: "no process at pid 41"},
	})

	if !adopted["vm-live"] {
		t.Fatalf("adopted finding did not reach the adopted set: %v", adopted)
	}
	if adopted["vm-unknown"] {
		t.Fatal("an ambiguous VM was reported as adopted, which claims a liveness nobody observed")
	}
	// The whole point of the map: without the detail, Reconcile holds the row
	// but nothing tells an operator what on the host could not be read.
	if got := ambiguous["vm-unknown"]; got != "unreadable manifest: unexpected end of JSON input" {
		t.Fatalf("ambiguous detail = %q, want the runtime's own account", got)
	}
	if _, held := ambiguous["vm-live"]; held {
		t.Fatal("an adopted VM was held as ambiguous")
	}

	// vmm_gone reaches neither map: it is the default Reconcile already handles,
	// and a second listing of it here would be a second place to keep in step.
	if adopted["vm-dead"] {
		t.Fatal("a VM the scan proved gone was reported as adopted")
	}
	if _, held := ambiguous["vm-dead"]; held {
		t.Fatal("a VM the scan proved gone was held as ambiguous, so its compute is never reclaimed")
	}
}

func TestClassifyFindingsOnNoFindingsReturnsUsableMaps(t *testing.T) {
	// NewManager reads both maps on every row; nil ones would work today only
	// because Go reads nil maps, and that is not a contract worth resting on.
	adopted, ambiguous := classifyFindings(nil)
	if adopted == nil || ambiguous == nil {
		t.Fatalf("classifyFindings(nil) returned a nil map: adopted=%v ambiguous=%v", adopted, ambiguous)
	}
	if len(adopted) != 0 || len(ambiguous) != 0 {
		t.Fatalf("classifyFindings(nil) invented entries: adopted=%v ambiguous=%v", adopted, ambiguous)
	}
}
