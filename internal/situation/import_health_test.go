// ABOUTME: Ensures host import failure overrides an otherwise fresh heartbeat.
// ABOUTME: Uses real spool files and the store rather than a synthetic health provider.
package situation_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/spool"
	"github.com/2389-research/observatory/internal/store"
)

func TestImporterFailureDegradesTelemetry(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "health.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	root := t.TempDir()
	id := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	dir := filepath.Join(root, id)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "seg-0000000000000000.vmsp"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	imp := spool.NewImporter(st, root, time.Second, nil)
	eng := situation.New(st, situation.Config{})
	eng.SetImporter(imp)
	if _, err := imp.ImportOnce(t.Context()); err == nil {
		t.Fatal("missing import failure")
	}
	h, err := eng.VMTelemetryHealth(t.Context(), &store.VM{VMID: id, ObservedState: "running"})
	if err != nil || h.State != situation.TelemetryDegraded {
		t.Fatalf("health = %+v, %v", h, err)
	}
	if eng.ImporterStatus(id).ConsecutiveFailures != "1" {
		t.Fatal("diagnostics unavailable")
	}
}

func TestImportAttentionHonorsEnginePolicy(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "health.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			root := t.TempDir()
			for _, id := range []string{"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"} {
				dir := filepath.Join(root, id)
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "bad.vmsp"), []byte("broken"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			imp := spool.NewImporter(st, root, time.Second, nil)
			eng := situation.New(st, situation.Config{Triggers: map[string]bool{"telemetry_degraded": enabled}, QueueMaxItems: 1, CollapseDuplicates: true})
			eng.SetImporter(imp)
			for range 3 {
				if _, err := imp.ImportOnce(t.Context()); err == nil {
					t.Fatal("failure missing")
				}
			}
			items, err := st.ListAttention(t.Context(), store.AttentionQuery{Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if enabled {
				want = 1
			}
			if len(items) != want {
				t.Fatalf("queue = %d, want %d", len(items), want)
			}
			overflow, err := st.Query(t.Context(), store.Query{Kind: "attention.queue_overflow", Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			if len(overflow.Events) != want {
				t.Fatalf("overflow events = %d, want %d for one episode", len(overflow.Events), want)
			}

		})
	}
}
