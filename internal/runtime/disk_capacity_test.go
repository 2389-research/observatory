// ABOUTME: Dynamic admission preserves pending disk reservations and scratch space.
// ABOUTME: Observation failures refuse admission instead of using stale startup data.
package runtime_test

import (
	"errors"
	"fmt"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/store"
)

func TestAdmissionRefreshesDiskAndCreditsOnlyMaterializedReservations(t *testing.T) {
	p := runtime.Policy{Admission: baseAdmission(), Host: runtime.HostResources{TotalMemoryMiB: 32768, CPUCores: 16, StateDiskFreeMiB: 21000}}
	free, allocated := int64(24000), int64(3072)
	p.ObserveDisk = func([]store.DiskReservation) (runtime.DiskObservation, error) {
		return runtime.DiskObservation{FreeMiB: free, MaterializedMiB: allocated}, nil
	}
	totals := store.ReservationTotals{DiskMiB: 3072}
	if err := p.Admit(totals, 1, 1, 3072); err != nil {
		t.Fatalf("existing materialized disk charged twice: %v", err)
	}
	allocated = 0
	if err := p.Admit(totals, 1, 1, 3072); err == nil {
		t.Fatal("pending disk reservation was ignored")
	}
	totals.DiskMiB = 0
	free = 23000
	if err := p.Admit(totals, 1, 1, 3072); err == nil {
		t.Fatal("inspection scratch was consumed")
	}
	free = 27000
	if err := p.Admit(totals, 1, 1, 3072); err != nil {
		t.Fatalf("reclamation not observed: %v", err)
	}
	p.ObserveDisk = func([]store.DiskReservation) (runtime.DiskObservation, error) {
		return runtime.DiskObservation{}, errors.New("filesystem unavailable")
	}
	if err := p.Admit(totals, 1, 1, 3072); err == nil {
		t.Fatal("failed observation admitted VM")
	}
}

// diskRuntime supplies controlled filesystem observations at the same boundary
// as the real adapter; lifecycle work still uses the standard test runtime.
type diskRuntime struct {
	*runtimetest.Fake
	free atomic.Int64
}

func (r *diskRuntime) ObserveDisk([]store.DiskReservation) (runtime.DiskObservation, error) {
	return runtime.DiskObservation{FreeMiB: r.free.Load()}, nil
}

func TestManagerSerializesPendingDiskAdmissionAndRefreshesCapacity(t *testing.T) {
	st := openStoreForManager(t)
	rt := &diskRuntime{Fake: runtimetest.NewFake()}
	cfg := defaultCfg()
	cfg.Admission.ReserveInspectorScratchMiB = 20
	cfg.VMDefaults.RootDiskMiB = 1
	cfg.VMDefaults.WorkspaceDiskMiB = 2
	rt.free.Store(23)
	mgr, err := runtime.NewManager(st, rt, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _, err := mgr.CreateVM(t.Context(), "test-owner", createReq(fmt.Sprintf("disk-%d", i)))
			if err == nil {
				admitted.Add(1)
			} else {
				var refusal *store.AdmissionRefusal
				if !errors.As(err, &refusal) {
					t.Errorf("unexpected admission failure: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()
	if got := admitted.Load(); got != 1 {
		t.Fatalf("admitted %d, want 1 pending disk allocation", got)
	}
	cap, err := mgr.Capacity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if cap.FreeDiskMiB != 0 || cap.ReservedDiskMiB != 3 {
		t.Fatalf("capacity diverged from admission: %+v", cap)
	}
	rt.free.Store(26)
	cap, err = mgr.Capacity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if cap.FreeDiskMiB != 3 {
		t.Fatalf("capacity did not refresh: %+v", cap)
	}
}
