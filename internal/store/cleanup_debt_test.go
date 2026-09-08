// ABOUTME: Durable stopped cleanup debt survives migration and lifecycle changes.
// ABOUTME: These tests use real SQLite files and real registry transitions.
package store_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/2389-research/observatory/internal/store"
)

func TestCleanupDebtMigrationSeedsOnlyStoppedFailures(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cleanup.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, vmID := range []string{"debt", "clean"} {
		mustCreateVM(t, st, vmID, vmID, nil)
		for _, state := range []string{"starting", "running", "stopping", "stopped"} {
			if _, err := st.TransitionVM(t.Context(), store.TransitionInput{VMID: vmID, To: state, Reason: "fixture"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := st.RecordCleanupFailure(t.Context(), "debt", "stopped", "jail busy"); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the previous schema while preserving its historical evidence.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE cleanup_debt; DELETE FROM schema_migrations WHERE version = 10`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for vmID, want := range map[string]bool{"debt": true, "clean": false} {
		pending, err := st.HasCleanupDebt(t.Context(), vmID)
		if err != nil || pending != want {
			t.Fatalf("%s debt = %v, %v; want %v", vmID, pending, err, want)
		}
	}
	if _, err := st.TransitionVM(t.Context(), store.TransitionInput{VMID: "debt", To: "starting", Reason: "restart"}); err != nil {
		t.Fatal(err)
	}
	pending, err := st.HasCleanupDebt(t.Context(), "debt")
	if err != nil || pending {
		t.Fatalf("new lifecycle kept stale marker: %v %v", pending, err)
	}
}
