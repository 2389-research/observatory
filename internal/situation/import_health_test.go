// ABOUTME: Ensures host import failure overrides an otherwise fresh heartbeat.
// ABOUTME: Uses real spool files and the store rather than a synthetic health provider.
package situation_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/events"
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
	if err := os.WriteFile(filepath.Join(dir, "seg-0000000000000000.vmsp"), []byte("broken\n"), 0600); err != nil {
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
				if err := os.WriteFile(filepath.Join(dir, "seg-0000000000000000.vmsp"), []byte("broken\n"), 0600); err != nil {
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

// A failing spool writer degrades the VM's telemetry while its heartbeat is
// fresh and, when the policy enables telemetry_degraded, raises one attention
// for its outage however many cycles read it failing.
func TestWriterFailureDegradesTelemetryAndRaisesAttention(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			st := openStore(t)
			id, boot := testUUID(1), testUUID(2)
			vm, _ := runningVM(t, st, id, boot)
			heartbeat(t, st, id, boot, testUUID(201), "1", time.Now().UTC(), nil, "10000000000")
			root := t.TempDir()
			dir := filepath.Join(root, id)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			record := func(kind, source string, data map[string]any) *events.Envelope {
				return &events.Envelope{
					SchemaVersion: 1, VMID: &id, SourceInstanceID: source, SourceSeq: "1", Kind: kind,
					Provenance: events.HostObserved, Sensor: "runner", HostReceivedAt: events.Timestamp{Time: time.Now().UTC()},
					Quality: events.Quality{PathResolution: events.PathNotApplicable, Attribution: events.AttributionNotApplicable},
					Data:    data,
				}
			}
			// A one-byte quota refuses every append.
			w, err := spool.OpenWriter(dir, spool.WriterCfg{
				VMID: id, InstanceID: testUUID(3), MaxSegmentBytes: 4 << 20, MaxSpoolBytes: 1,
				LossRecord: func(o spool.Outage) *events.Envelope { return record("telemetry.loss", testUUID(4), o.Data()) },
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = w.Close() })
			imp := spool.NewImporter(st, root, time.Second, nil)
			eng := situation.New(st, situation.Config{Triggers: map[string]bool{"telemetry_degraded": enabled}, QueueMaxItems: 10, CollapseDuplicates: true})
			eng.SetImporter(imp)
			if _, err := imp.ImportOnce(t.Context()); err != nil {
				t.Fatal(err)
			}
			if h := healthOf(t, eng, vm); h.State != situation.TelemetryHealthy {
				t.Fatalf("with a healthy writer the telemetry is %+v, want healthy", h)
			}
			if err := w.Append(record("vm.state_changed", testUUID(3), map[string]any{})); !errors.Is(err, spool.ErrSpoolFull) {
				t.Fatalf("append over a one-byte quota: %v, want ErrSpoolFull", err)
			}
			for range 3 {
				if _, err := imp.ImportOnce(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if h := healthOf(t, eng, vm); h.State != situation.TelemetryDegraded {
				t.Errorf("with a failing writer the telemetry is %+v, want degraded", h)
			}
			items, err := st.ListAttention(t.Context(), store.AttentionQuery{Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			if !enabled {
				if len(items) != 0 {
					t.Fatalf("with telemetry_degraded off the queue holds %d items, want none", len(items))
				}
				return
			}
			if len(items) != 1 {
				t.Fatalf("the queue holds %d items, want one for the outage", len(items))
			}
			item, link := items[0], "/api/v1/vms/"+id+"/telemetry/import"
			if item.TriggerClass != "telemetry_degraded" || item.Severity != store.SeverityNeedsDecision || item.VMID == nil || *item.VMID != id || item.Count != 1 {
				t.Errorf("attention %+v, want one telemetry_degraded needing a decision about %s", item, id)
			}
			if want := fmt.Sprintf("runner spool writer failing since %s: %s", eng.ImporterStatus(id).Writer.Since, spool.ErrSpoolFull); item.Summary != want {
				t.Errorf("summary %q, want %q", item.Summary, want)
			}
			if want := "refusing records the spool cannot make durable; the runner retries on every append and writes a telemetry.loss record once an append succeeds"; item.SystemAction != want {
				t.Errorf("system action %q, want %q", item.SystemAction, want)
			}
			if len(item.EvidenceLinks) != 1 || item.EvidenceLinks[0] != link {
				t.Errorf("evidence links %q, want [%s]", item.EvidenceLinks, link)
			}
			rationale := "Free space or repair permissions on the spool filesystem; the writer resumes on its next append and records the loss."
			if len(item.SuggestedActions) != 1 || item.SuggestedActions[0].Action != "inspect_spool_import" || item.SuggestedActions[0].Params["url"] != link || item.SuggestedActions[0].Rationale != rationale {
				t.Errorf("suggested actions %+v, want inspect_spool_import at %s with the rationale %q", item.SuggestedActions, link, rationale)
			}
		})
	}
}

// TestImporterStatusUnobservedCarriesWriterOnlyForAVM: with no importer
// wired, a VM's status must still carry a writer of state unknown — the same
// shape Importer.Status gives every VM before its first cycle reads its
// status file — and the root status must carry no writer at all.
func TestImporterStatusUnobservedCarriesWriterOnlyForAVM(t *testing.T) {
	st := openStore(t)
	eng := situation.New(st, situation.Config{})
	id := testUUID(1)
	if got := eng.ImporterStatus(id); got.Writer == nil || got.Writer.State != "unknown" {
		t.Fatalf("ImporterStatus(%q).Writer = %+v, want a writer with state unknown", id, got.Writer)
	}
	if got := eng.ImporterStatus(""); got.Writer != nil {
		t.Fatalf(`ImporterStatus("").Writer = %+v, want none`, got.Writer)
	}
}
