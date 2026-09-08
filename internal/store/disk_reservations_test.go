// ABOUTME: Disk ownership snapshots share the SQLite admission transaction.
// ABOUTME: Rows preserve each outstanding reservation for filesystem accounting.
package store_test

import (
	"github.com/2389-research/observatory/internal/store"
	"testing"
)

func TestAdmissionIncludesDiskReservationOwners(t *testing.T) {
	st := openStore(t)
	mustCreateVM(t, st, "disk-owner", "one", nil)
	mustCreateVM(t, st, "disk-next", "two", func(totals store.ReservationTotals) error {
		if len(totals.Disks) != 1 || totals.Disks[0].VMID != "disk-owner" || totals.Disks[0].DiskMiB != totals.DiskMiB {
			t.Fatalf("inconsistent disk owners: %+v", totals)
		}
		return nil
	})
	err := st.WithReservationTotals(t.Context(), func(totals store.ReservationTotals) error {
		if len(totals.Disks) != 2 {
			t.Fatalf("capacity snapshot: %+v", totals)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
