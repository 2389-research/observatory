// ABOUTME: Recover the process identity of a start whose socket reply was lost.
// ABOUTME: Pending and unknown results retain the manifest, staged files, and resource leases.
package jailer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/2389-research/observatory/internal/privd"
)

func (a *Adapter) resolveStartOutcome(ctx context.Context, m *Manifest) error {
	if m.StartOpID == "" || m.VMMPID > 0 {
		return nil
	}
	query, ok := a.pc.(interface {
		QueryOperation(context.Context, string) (privd.OperationOutcome, error)
	})
	if !ok {
		return &privd.UnknownOutcomeError{OpID: m.StartOpID, Err: fmt.Errorf("operation query unavailable; retain ownership")}
	}
	outcome, err := query.QueryOperation(ctx, m.StartOpID)
	if err != nil {
		return &privd.UnknownOutcomeError{OpID: m.StartOpID, Err: err}
	}
	switch outcome.State {
	case "failed":
		return nil
	case "succeeded":
		var start privd.StartVMResp
		if outcome.Response == nil || !outcome.Response.OK || json.Unmarshal(outcome.Response.Payload, &start) != nil || start.PID <= 0 || start.StartTime == "" {
			return &privd.UnknownOutcomeError{OpID: m.StartOpID, Err: fmt.Errorf("invalid committed start response")}
		}
		m.VMMPID, m.VMMStart = start.PID, start.StartTime
		m.Stages = append(m.Stages, "vmm_started")
		return writeManifest(a.cfg.StateDir, *m)
	default:
		return &privd.UnknownOutcomeError{OpID: m.StartOpID, Err: fmt.Errorf("start is %s; query again before cleanup", outcome.State)}
	}
}
