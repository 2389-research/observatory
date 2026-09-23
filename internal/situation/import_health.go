// ABOUTME: Delivers spool import and writer failures through the configured attention policy.
// ABOUTME: Live error and retry details stay in the importer's bounded status record.
package situation

import (
	"context"
	"fmt"

	"github.com/2389-research/observatory/internal/spool"
	"github.com/2389-research/observatory/internal/store"
)

func (e *Engine) reportImportFailure(ctx context.Context, id string, h spool.ImportStatus) error {
	if !e.cfg.Triggers["telemetry_degraded"] {
		return nil
	}
	var vmID *string
	link := "/api/v1/telemetry/import"
	if id != "" {
		vmID = &id
		link = "/api/v1/vms/" + id + "/telemetry/import"
	}
	_, err := e.st.RaiseAttention(ctx, store.RaiseInput{
		TriggerClass: "telemetry_degraded", Severity: store.SeverityNeedsDecision, VMID: vmID,
		Summary:          fmt.Sprintf("spool import failed: %s", h.LastError),
		SystemAction:     "kept uncommitted segments; retrying with per-VM backoff capped at one minute",
		EvidenceLinks:    []string{link},
		SuggestedActions: []store.SuggestedAction{{Action: "inspect_spool_import", Params: map[string]any{"url": link}, Rationale: "Inspect the current error; repair spool permissions, cursor or storage availability, then allow the next retry."}},
		Collapse:         e.cfg.CollapseDuplicates, QueueMax: e.cfg.QueueMaxItems,
	})
	return err
}

// reportWriterFailure raises attention for a VM's spool writer outage. The
// importer calls it when a cycle reads the writer failing with a Since it has
// not reported yet, so each outage raises once.
func (e *Engine) reportWriterFailure(ctx context.Context, id string, h spool.WriterHealth) error {
	if !e.cfg.Triggers["telemetry_degraded"] {
		return nil
	}
	link := "/api/v1/vms/" + id + "/telemetry/import"
	_, err := e.st.RaiseAttention(ctx, store.RaiseInput{
		TriggerClass: "telemetry_degraded", Severity: store.SeverityNeedsDecision, VMID: &id,
		Summary:          fmt.Sprintf("runner spool writer failing since %s: %s", h.Since, h.Cause),
		SystemAction:     "refusing records the spool cannot make durable; the runner retries on every append and writes a telemetry.loss record once an append succeeds",
		EvidenceLinks:    []string{link},
		SuggestedActions: []store.SuggestedAction{{Action: "inspect_spool_import", Params: map[string]any{"url": link}, Rationale: "Free space or repair permissions on the spool filesystem; the writer resumes on its next append and records the loss."}},
		Collapse:         e.cfg.CollapseDuplicates, QueueMax: e.cfg.QueueMaxItems,
	})
	return err
}
