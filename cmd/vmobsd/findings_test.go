// ABOUTME: Covers the startup scan's three outcomes reaching the two maps the
// ABOUTME: lifecycle manager reads, and the one that deliberately reaches neither.
package main

import (
	"testing"

	"github.com/2389-research/observatory-v2/internal/jailer"
)

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
