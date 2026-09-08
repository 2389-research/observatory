// ABOUTME: Tests the owner-checked VM coverage route against real store records.
// ABOUTME: The response distinguishes healthy delivery from absent collectors.
package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

func seedCoverageVM(t *testing.T, st *store.Store, vmID, owner string) *store.VM {
	t.Helper()
	_, op, _, err := st.CreateVMWithOperation(t.Context(), store.CreateVMInput{
		VMID: vmID, Name: "coverage", Owner: owner, TemplateID: "tmpl", TemplateDigest: "sha256:abc",
		VCPUCount: 1, MemoryMiB: 128, RootDiskMiB: 64, WorkspaceDiskMiB: 64,
		MemoryTotalMiB: 256, NetworkProfile: "transport", NetworkPolicyID: "public-web",
		Labels: map[string]string{}, Kind: "vm.create", RequestHash: strings.Repeat("a", 64),
		Admit: func(store.ReservationTotals) error { return nil },
	})
	if err != nil {
		t.Fatalf("create VM: %v", err)
	}
	boot := testUUID(101)
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{VMID: vmID, To: "starting", Reason: "test", OperationID: op.OperationID, BootID: &boot}); err != nil {
		t.Fatalf("start VM: %v", err)
	}
	vm, err := st.TransitionVM(t.Context(), store.TransitionInput{VMID: vmID, To: "running", Reason: "test", OperationID: op.OperationID})
	if err != nil {
		t.Fatalf("run VM: %v", err)
	}
	return vm
}

func TestCoverageRouteReportsAbsentCapture(t *testing.T) {
	srv, st := newServer(t)
	vm := seedCoverageVM(t, st, testUUID(1), "local_operator")
	var got situation.Coverage
	getJSON(t, srv.URL+"/api/v1/vms/"+vm.VMID+"/coverage", http.StatusOK, &got)
	if got.VMID != vm.VMID || got.BootID != vm.CurrentBootID {
		t.Errorf("coverage scope = %s/%s, want %s/%s", got.VMID, got.BootID, vm.VMID, vm.CurrentBootID)
	}
	if len(got.Collectors) != 6 || got.Collectors[0].State != situation.CoverageUnavailable {
		t.Errorf("collectors = %+v, want six explicit unavailable/disabled records", got.Collectors)
	}
}

func TestCoverageRouteHidesForeignVM(t *testing.T) {
	srvURL, st, secret := newScopeServer(t)
	vm := seedCoverageVM(t, st, testUUID(8), otherOwner)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srvURL+"/api/v1/vms/"+vm.VMID+"/coverage", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("foreign coverage = %d, want 404", resp.StatusCode)
	}
}
