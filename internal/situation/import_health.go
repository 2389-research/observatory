// ABOUTME: Delivers importer incidents through the configured attention policy.
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
