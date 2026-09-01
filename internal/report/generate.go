// ABOUTME: Deterministic run-report generation: rollups of durable records only,
// ABOUTME: never invented values (SPEC §8.7, P4 Task 7).
package report

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/store"
)

// Generate builds a canonical run report from durable store records.
// Returns (canonicalJSON, "sha256:<hex>", error).
// Returns an error if runID is not a terminal run — the manager only calls
// post-terminal, but this guard enforces evidence honesty.
func Generate(ctx context.Context, st *store.Store, runID string, opts Options) (json.RawMessage, string, error) {
	run, err := st.GetRun(ctx, runID)
	if err != nil {
		return nil, "", fmt.Errorf("get run: %w", err)
	}

	// Honesty guard: only terminal runs generate.
	terminalPhases := map[string]bool{
		"succeeded": true, "failed": true, "inconclusive": true, "aborted": true,
	}
	if !terminalPhases[run.Phase] {
		return nil, "", fmt.Errorf("run %s is in phase %q — only terminal runs generate reports: %w", runID, run.Phase, ErrNotTerminal)
	}
	if run.ConcludedEventID == 0 {
		return nil, "", fmt.Errorf("run %s: concluded_event_id is 0 in a terminal phase — store inconsistency", runID)
	}

	vm, err := st.GetVM(ctx, run.VMID)
	if err != nil {
		return nil, "", fmt.Errorf("get vm: %w", err)
	}

	after := run.CreatedEventID
	until := run.ConcludedEventID

	// --- boot_ids: distinct non-empty data.boot_id on vm.state_changed in window ---
	bootIDs, err := collectBootIDs(ctx, st, run.VMID, run.RunID, after, until)
	if err != nil {
		return nil, "", fmt.Errorf("collect boot ids: %w", err)
	}

	// --- outcome ---
	evidenceLinks := []string{
		// The terminal record: the run.state_changed event at conclusion.
		// Uses family=run (not kind=) so the API narrows to run-family kinds
		// while vm_id= applies the unconditional two-clause match (column OR
		// data.vm_id), which is required for run.* events that ride the
		// host-wide stream with a NULL vm_id column.
		fmt.Sprintf("/api/v1/events?family=run&vm_id=%s&after=%d&until=%d",
			run.VMID, run.ConcludedEventID-1, run.ConcludedEventID),
	}
	if run.ResultJSON != "" {
		evidenceLinks = append(evidenceLinks, "/api/v1/runs/"+runID)
	}
	outcome := OutcomeBlock{
		Status:        run.Phase,
		EvaluatedBy:   run.EvaluatedBy,
		Reason:        run.Reason,
		EvidenceLinks: evidenceLinks,
	}

	// --- timing ---
	timing := TimingBlock{
		CreatedAt:   run.CreatedAt,
		ConcludedAt: run.ConcludedAt,
	}
	if run.StartedAt != "" {
		s := run.StartedAt
		timing.StartedAt = &s
	}

	// --- event rollup: per family present in window, count > 0, sorted by family ---
	rollup, err := buildEventRollup(ctx, st, run.VMID, runID, after, until)
	if err != nil {
		return nil, "", fmt.Errorf("build event rollup: %w", err)
	}

	// --- coverage ---
	coverage := CoverageBlock{
		TelemetryHealthFinal: "unavailable",
		Gaps: []CoverageGap{
			{
				Kind:         "guest_channel_not_built",
				Detail:       "no guest telemetry channel exists in this build; guest-side facts limited to explicit submissions",
				EvidenceLink: "/api/v1/meta",
			},
		},
	}

	// --- network summary ---
	afterStr := strconv.FormatInt(after, 10)
	untilStr := strconv.FormatInt(until, 10)
	flowCount, err := st.CountEventsForReport(ctx, run.VMID, runID, "net.flow", after, until)
	if err != nil {
		return nil, "", fmt.Errorf("count net.flow: %w", err)
	}
	dnsCount, err := st.CountEventsForReport(ctx, run.VMID, runID, "dns", after, until)
	if err != nil {
		return nil, "", fmt.Errorf("count dns: %w", err)
	}
	policyCount, err := st.CountEventsForReport(ctx, run.VMID, runID, "policy", after, until)
	if err != nil {
		return nil, "", fmt.Errorf("count policy: %w", err)
	}
	network := NetworkBlock{
		Profile: vm.NetworkProfile,
		Flows: Counted{
			Count:          flowCount,
			ReproduceQuery: fmt.Sprintf("/api/v1/events?vm_id=%s&family=net.flow&after=%s&until=%s", run.VMID, afterStr, untilStr),
		},
		DNSQueries: Counted{
			Count:          dnsCount,
			ReproduceQuery: fmt.Sprintf("/api/v1/events?vm_id=%s&family=dns&after=%s&until=%s", run.VMID, afterStr, untilStr),
		},
		PolicyDenials: Counted{
			Count:          policyCount,
			ReproduceQuery: fmt.Sprintf("/api/v1/events?vm_id=%s&family=policy&after=%s&until=%s", run.VMID, afterStr, untilStr),
		},
	}

	// --- filesystem summary ---
	fsCount, err := st.CountEventsForReport(ctx, run.VMID, runID, "fs", after, until)
	if err != nil {
		return nil, "", fmt.Errorf("count fs: %w", err)
	}
	filesystem := FilesystemBlock{
		LiveMutationEvents: Counted{
			Count:          fsCount,
			ReproduceQuery: fmt.Sprintf("/api/v1/events?vm_id=%s&family=fs&after=%s&until=%s", run.VMID, afterStr, untilStr),
		},
		FinalDiff: FinalDiff{Status: "not_requested"},
	}

	// --- attention: run_id=<run> OR (vm_id=<vm> AND raised_event_id in window) ---
	attentionRows, truncated, err := collectAttention(ctx, st, run.VMID, runID, after, until)
	if err != nil {
		return nil, "", fmt.Errorf("collect attention: %w", err)
	}

	// --- quality ---
	var qualityNotes []string
	if truncated {
		qualityNotes = append(qualityNotes, "attention list capped at 128 items")
	}
	quality := QualityBlock{
		Truncated: truncated,
		Redacted:  false,
		Notes:     qualityNotes,
	}

	// --- links ---
	links := LinksBlock{
		Run:    "/api/v1/runs/" + runID,
		VM:     "/api/v1/vms/" + run.VMID,
		Events: fmt.Sprintf("/api/v1/events?vm_id=%s&after=%s&until=%s", run.VMID, afterStr, untilStr),
	}

	r := Report{
		SchemaVersion:     1,
		RunID:             runID,
		VMID:              run.VMID,
		BootIDs:           bootIDs,
		Goal:              run.Goal,
		SuccessCriteria:   run.CriteriaType,
		Outcome:           outcome,
		Timing:            timing,
		Execs:             []ExecBlock{},
		EventRollup:       rollup,
		Coverage:          coverage,
		NetworkSummary:    network,
		FilesystemSummary: filesystem,
		Artifacts:         []ArtifactBlock{},
		Attention:         attentionRows,
		Quality:           quality,
		Links:             links,
	}

	canonical, err := json.Marshal(r)
	if err != nil {
		return nil, "", fmt.Errorf("marshal report: %w", err)
	}
	sum := sha256.Sum256(canonical)
	digest := "sha256:" + fmt.Sprintf("%x", sum[:])

	return json.RawMessage(canonical), digest, nil
}

// collectBootIDs returns distinct non-empty boot_id values from vm.state_changed
// events in the run window.
//
// vm.state_changed events are store-synthesized via systemEnvelope, which does
// not set the envelope VMID field — so they ride the host-wide stream with a
// NULL vm_id column. VM linkage lives in data.vm_id. store.Query applies the
// unconditional two-clause match (vm_id column OR data.vm_id) whenever VMID is
// set, so no extra flag is needed here.
func collectBootIDs(ctx context.Context, st *store.Store, vmID, _ string, after, until int64) ([]string, error) {
	seen := map[string]bool{}
	var ids []string
	afterCursor := strconv.FormatInt(after, 10)
	untilStr := strconv.FormatInt(until, 10)
	for {
		res, err := st.Query(ctx, store.Query{
			VMID:  &vmID,
			Kind:  "vm.state_changed",
			After: afterCursor,
			Until: untilStr,
			Limit: 1000,
		})
		if err != nil {
			return nil, fmt.Errorf("query vm.state_changed: %w", err)
		}
		for _, ev := range res.Events {
			// boot_id lives in event data, not the envelope header; the store writes
			// it into stateData["boot_id"] when TransitionVM is called with BootID set.
			if bid, ok := ev.Data["boot_id"].(string); ok && bid != "" && !seen[bid] {
				seen[bid] = true
				ids = append(ids, bid)
			}
		}
		if len(res.Events) < 1000 {
			break
		}
		afterCursor = res.NextAfter
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil
}

// buildEventRollup counts events per family in the run window, using
// CountEventsForReport so the vm-or-data matching is consistent with the API.
// Families with zero count are omitted. Result is sorted by family name.
func buildEventRollup(ctx context.Context, st *store.Store, vmID, runID string, after, until int64) ([]EventRollupRow, error) {
	afterStr := strconv.FormatInt(after, 10)
	untilStr := strconv.FormatInt(until, 10)

	// All registered families (deduplicated from the event registry via store).
	families := registeredFamilies(st)

	var rows []EventRollupRow
	for _, family := range families {
		count, err := st.CountEventsForReport(ctx, vmID, runID, family, after, until)
		if err != nil {
			return nil, fmt.Errorf("count family %s: %w", family, err)
		}
		if count == 0 {
			continue
		}
		rows = append(rows, EventRollupRow{
			Family:         family,
			Count:          count,
			ReproduceQuery: fmt.Sprintf("/api/v1/events?vm_id=%s&family=%s&after=%s&until=%s", vmID, family, afterStr, untilStr),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Family < rows[j].Family })
	if rows == nil {
		rows = []EventRollupRow{}
	}
	return rows, nil
}

// registeredFamilies returns all distinct family names from the event registry,
// sorted alphabetically. Driven by events.Families() so a newly registered
// family is automatically included in every report's rollup enumeration.
func registeredFamilies(_ *store.Store) []string {
	return events.Families()
}

// collectAttention returns up to 128 attention items relevant to this run:
// items where run_id=<run> OR (vm_id=<vm> AND raised_event_id in window).
// truncated is true when the raw count exceeds 128.
func collectAttention(ctx context.Context, st *store.Store, vmID, runID string, after, until int64) ([]AttentionRow, bool, error) {
	items, err := st.ListAttentionForReport(ctx, vmID, runID, after, until)
	if err != nil {
		return nil, false, err
	}
	const cap128 = 128
	truncated := false
	if len(items) > cap128 {
		items = items[:cap128]
		truncated = true
	}
	rows := make([]AttentionRow, 0, len(items))
	for _, it := range items {
		row := AttentionRow{
			AttentionID: strconv.FormatInt(it.AttentionID, 10),
			Kind:        it.TriggerClass,
			Severity:    it.Severity,
			Acked:       it.Acked,
			Link:        fmt.Sprintf("/api/v1/attention/%d", it.AttentionID),
		}
		rows = append(rows, row)
	}
	return rows, truncated, nil
}

// ErrNotTerminal is returned when Generate is called on a non-terminal run.
var ErrNotTerminal = errors.New("run is not in a terminal phase")

// MakeReportGenFn returns a func(runID string) that is safe to assign to
// manager.reportGen. When called, it creates a run.report_generate operation,
// generates the report, stores it, and finalises the operation. This function
// is the real generator — it must never be called in tests that use the fake
// runtime in a "served mode" (it operates over a real store). See SPEC §18.
func MakeReportGenFn(st *store.Store, owner string, opts Options) func(runID string) {
	return func(runID string) {
		ctx := context.Background()

		run, err := st.GetRun(ctx, runID)
		if err != nil {
			// Run disappeared — nothing to do.
			return
		}

		// Check for an already-running report op (guard from Task 7 / R7).
		hasOp, err := st.HasRunningReportOp(ctx, runID)
		if err != nil || hasOp {
			// Skip: either query failed (best-effort) or an op is already in flight.
			return
		}

		// Create the operation row.
		opID, err := st.InsertReportOperation(ctx, owner, run.VMID, runID)
		if err != nil {
			// Can't record the op — skip generation; reconcile will retry.
			return
		}

		// Generate the report.
		raw, digest, err := Generate(ctx, st, runID, opts)

		if err != nil {
			// Mark the operation failed.
			cause := "report_generation_failed"
			msg := err.Error()
			_, _ = st.UpdateOperation(ctx, store.OperationUpdate{
				OperationID:  opID,
				IfState:      "running",
				Phase:        "generating",
				State:        "failed",
				ErrorCause:   &cause,
				ErrorMessage: &msg,
			})
			return
		}

		// Store the report — immutable: if it already exists (double-generate),
		// PutRunReport returns an error naming the existing digest. That is fine;
		// the existing report is correct (R7: generation is deterministic).
		putErr := st.PutRunReport(ctx, runID, string(raw), digest, opID)
		if putErr != nil {
			// Report already stored by a concurrent generator — that is the R7
			// idempotent case. Mark the op as succeeded anyway (the report exists).
			if errors.Is(putErr, store.ErrReportImmutable) {
				_, _ = st.UpdateOperation(ctx, store.OperationUpdate{
					OperationID: opID,
					IfState:     "running",
					Phase:       "done",
					State:       "succeeded",
				})
			} else {
				cause := "report_generation_failed"
				msg := putErr.Error()
				_, _ = st.UpdateOperation(ctx, store.OperationUpdate{
					OperationID:  opID,
					IfState:      "running",
					Phase:        "storing",
					State:        "failed",
					ErrorCause:   &cause,
					ErrorMessage: &msg,
				})
			}
			return
		}

		// Success.
		_, _ = st.UpdateOperation(ctx, store.OperationUpdate{
			OperationID: opID,
			IfState:     "running",
			Phase:       "done",
			State:       "succeeded",
		})
	}
}
