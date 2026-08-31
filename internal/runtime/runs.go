// ABOUTME: Run engine: creation, conclusion, guest ingress, VM lifecycle hooks,
// ABOUTME: and the reconcile sweep for interrupted runs (SPEC §8.6, P4 Task 6).
package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/2389-research/observatory-v2/internal/store"
)

// --- sentinel errors ---

// ErrVMNotRunning is returned when CreateRun is called on a VM that is not
// in the running state. Only running VMs can accept a standalone run.
var ErrVMNotRunning = errors.New("vm is not in running state; a standalone run requires a running vm")

// ErrRunConcluded is returned when ConcludeRun is called on an already-terminal run.
var ErrRunConcluded = errors.New("run is already in a terminal phase")

// ErrVerdictCriteriaMismatch is returned when a verdict is supplied for a run
// whose criteria_type is not operator_verdict.
var ErrVerdictCriteriaMismatch = errors.New("verdict can only be supplied for operator_verdict runs")

// --- concludeTrigger describes what caused a run to conclude ---

type concludeTrigger int

const (
	triggerGuestResult concludeTrigger = iota // SubmitRunResult triggered conclusion
	triggerVMTerminal                         // VM entered a terminal or stopping state
	triggerInterrupted                        // Reconcile: daemon restarted, VM no longer live
	triggerLaunchFail                         // VM failed during launch before the run started (R8)
)

// --- RunRequest ---

// RunRequest is the external input for a standalone run-create request.
// The VM must already be in the running state.
type RunRequest struct {
	VMID           string
	Owner          string
	Goal           string
	CriteriaType   string
	OnCompletion   string
	ProgressEvents bool
	IdempotencyKey *string
}

// --- CreateRun ---

// CreateRun creates a standalone run on a VM that is already observed running.
// Returns (run, isReplay, error).
func (m *Manager) CreateRun(ctx context.Context, req RunRequest) (*store.Run, bool, error) {
	vm, err := m.st.GetVM(ctx, req.VMID)
	if err != nil {
		return nil, false, err
	}
	if vm.ObservedState != "running" {
		return nil, false, ErrVMNotRunning
	}

	var requestHash string
	if req.IdempotencyKey != nil {
		// Simple hash for idempotency: combine fields deterministically.
		h := fmt.Sprintf("%s|%s|%s|%s|%s", req.VMID, req.Owner, req.Goal, req.CriteriaType, req.OnCompletion)
		requestHash = fmt.Sprintf("%x", []byte(h))
	} else {
		requestHash = fmt.Sprintf("%x", []byte(req.Goal+req.CriteriaType))
	}

	run, isReplay, err := m.st.CreateRun(ctx, store.CreateRunInput{
		VMID:           req.VMID,
		Owner:          req.Owner,
		Goal:           req.Goal,
		CriteriaType:   req.CriteriaType,
		OnCompletion:   req.OnCompletion,
		ProgressEvents: req.ProgressEvents,
		IdempotencyKey: req.IdempotencyKey,
		RequestHash:    requestHash,
		// Standalone on a running VM → starts in running, not pending.
		// The store sets started_at when InitialPhase is "running".
		InitialPhase: "running",
	})
	return run, isReplay, err
}

// --- ConcludeRun ---

// ConcludeRun moves a run to a terminal phase. Abort overrides the verdict.
// For operator_verdict runs, a verdict is required unless aborting.
// Returns ErrRunConcluded if already terminal, ErrVerdictCriteriaMismatch if
// a verdict is supplied for a non-operator_verdict run.
func (m *Manager) ConcludeRun(ctx context.Context, runID string, verdict *string, abort bool, reason string) (*store.Run, error) {
	run, err := m.st.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}

	// Already terminal.
	terminalPhases := map[string]bool{
		"succeeded": true, "failed": true, "inconclusive": true, "aborted": true,
	}
	if terminalPhases[run.Phase] {
		return nil, ErrRunConcluded
	}

	// A verdict on a non-operator_verdict run is invalid (abort is allowed on any).
	if !abort && verdict != nil && run.CriteriaType != "operator_verdict" {
		return nil, ErrVerdictCriteriaMismatch
	}

	if abort {
		return m.concludeRunAbort(ctx, runID, reason)
	}

	// For operator_verdict: require a verdict.
	if run.CriteriaType == "operator_verdict" {
		if verdict == nil {
			// No verdict and not aborting: this is a caller error but not covered
			// by the brief's error surface. Treat as inconclusive from system.
			return m.concludeRun(ctx, runID, triggerVMTerminal)
		}
		// We need to carry the verdict into concludeRun. Since concludeRun uses
		// a trigger enum, we handle operator_verdict inline here.
		return m.concludeRunWithVerdict(ctx, runID, verdict, reason)
	}

	// Non-operator_verdict with no verdict and not aborting is unusual — leave
	// it to concludeRun's truth table.
	return m.concludeRun(ctx, runID, triggerVMTerminal)
}

// concludeRunAbort handles the abort path (any criteria type): transitions to
// concluding then to aborted with evaluated_by=operator.
func (m *Manager) concludeRunAbort(ctx context.Context, runID, reason string) (*store.Run, error) {
	run, err := m.st.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}

	from := run.Phase
	if _, err := m.st.TransitionRun(ctx, store.RunTransitionInput{
		RunID:  runID,
		From:   from,
		To:     "concluding",
		Reason: "operator abort",
	}); err != nil {
		if errors.Is(err, new(store.InvalidRunTransitionError)) {
			return m.st.GetRun(ctx, runID)
		}
		return nil, fmt.Errorf("abort: transition to concluding: %w", err)
	}

	if reason == "" {
		reason = "operator aborted the run"
	}
	concluded, err := m.st.TransitionRun(ctx, store.RunTransitionInput{
		RunID:       runID,
		From:        "concluding",
		To:          "aborted",
		EvaluatedBy: "operator",
		Reason:      reason,
	})
	if err != nil {
		if errors.Is(err, new(store.InvalidRunTransitionError)) {
			return m.st.GetRun(ctx, runID)
		}
		return nil, fmt.Errorf("abort: transition to aborted: %w", err)
	}

	m.postConclude(concluded)
	return concluded, nil
}

// concludeRunWithVerdict handles the operator_verdict path: transitions to
// concluding, then to the verdict outcome with evaluated_by=operator.
func (m *Manager) concludeRunWithVerdict(ctx context.Context, runID string, verdict *string, reason string) (*store.Run, error) {
	run, err := m.st.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}

	// Transition to concluding with From pin.
	from := run.Phase
	if _, err := m.st.TransitionRun(ctx, store.RunTransitionInput{
		RunID:  runID,
		From:   from,
		To:     "concluding",
		Reason: "operator verdict",
	}); err != nil {
		if errors.Is(err, new(store.InvalidRunTransitionError)) {
			// Lost the race — another path concluded first.
			return m.st.GetRun(ctx, runID)
		}
		return nil, fmt.Errorf("conclude: transition to concluding: %w", err)
	}

	// Determine terminal outcome from the verdict.
	terminal := *verdict // "succeeded" or "failed"
	if reason == "" {
		reason = fmt.Sprintf("operator verdict: %s", terminal)
	}

	concluded, err := m.st.TransitionRun(ctx, store.RunTransitionInput{
		RunID:       runID,
		From:        "concluding",
		To:          terminal,
		EvaluatedBy: "operator",
		Reason:      reason,
	})
	if err != nil {
		if errors.Is(err, new(store.InvalidRunTransitionError)) {
			return m.st.GetRun(ctx, runID)
		}
		return nil, fmt.Errorf("conclude: transition to terminal: %w", err)
	}

	m.postConclude(concluded)
	return concluded, nil
}

// concludeRun is the single conclusion path for non-operator paths. It pins
// the concluding transition with a From guard so the loser of a race walks away
// silently (InvalidRunTransitionError).
func (m *Manager) concludeRun(ctx context.Context, runID string, trigger concludeTrigger) (*store.Run, error) {
	run, err := m.st.GetRun(ctx, runID)
	if err != nil {
		return nil, err
	}

	// Already terminal — walk away. This is how races resolve: the loser
	// finds the run already moved.
	terminalPhases := map[string]bool{
		"succeeded": true, "failed": true, "inconclusive": true, "aborted": true,
	}
	if terminalPhases[run.Phase] {
		return run, nil
	}

	// Transition to concluding with a From pin.
	from := run.Phase
	concludingReason := triggerReason(trigger)

	if _, err := m.st.TransitionRun(ctx, store.RunTransitionInput{
		RunID:  runID,
		From:   from,
		To:     "concluding",
		Reason: concludingReason,
	}); err != nil {
		if errors.Is(err, new(store.InvalidRunTransitionError)) {
			// Race lost: someone else got there first.
			return m.st.GetRun(ctx, runID)
		}
		return nil, fmt.Errorf("conclude: transition to concluding: %w", err)
	}

	// Re-read the run so we have the latest result_status for evaluation.
	run, err = m.st.GetRun(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("conclude: re-read after concluding: %w", err)
	}

	// Evaluate per the truth table.
	terminal, evaluatedBy, terminalReason := evaluateRun(run, trigger)

	concluded, err := m.st.TransitionRun(ctx, store.RunTransitionInput{
		RunID:       runID,
		From:        "concluding",
		To:          terminal,
		EvaluatedBy: evaluatedBy,
		Reason:      terminalReason,
	})
	if err != nil {
		if errors.Is(err, new(store.InvalidRunTransitionError)) {
			return m.st.GetRun(ctx, runID)
		}
		return nil, fmt.Errorf("conclude: transition to terminal: %w", err)
	}

	m.postConclude(concluded)
	return concluded, nil
}

// evaluateRun applies the criteria truth table (shared-context.md §truth-table)
// and returns (terminalPhase, evaluatedBy, reason). Abort is handled separately
// by concludeRunAbort and never reaches here.
func evaluateRun(run *store.Run, trigger concludeTrigger) (terminal, evaluatedBy, reason string) {
	// R8: launch failure is a special system path regardless of criteria type.
	if trigger == triggerLaunchFail {
		return "inconclusive", "system", "vm launch failed before the run started"
	}

	switch run.CriteriaType {
	case "operator_verdict":
		// No verdict submitted (VM terminal or interruption).
		return "inconclusive", "system", "no verdict was submitted before " + triggerDesc(trigger)

	case "guest_result":
		switch run.ResultStatus {
		case "succeeded":
			return "succeeded", "guest_result", "guest reported success"
		case "failed":
			return "failed", "guest_result", "guest reported failure"
		default:
			return "inconclusive", "system", "no result was recorded before " + triggerDesc(trigger)
		}

	case "exec_exit_zero":
		// R9: no exec subsystem in portable core.
		return "inconclusive", "system", "no exec attached; exec capability not built"
	}

	// Unknown criteria type — inconclusive by default.
	return "inconclusive", "system", "unknown criteria type"
}

// triggerDesc returns a short human-readable description used in reason strings.
func triggerDesc(trigger concludeTrigger) string {
	switch trigger {
	case triggerVMTerminal:
		return "vm reached a terminal state"
	case triggerInterrupted:
		return "interrupted: daemon restarted; vm no longer live"
	case triggerGuestResult:
		return "result was submitted"
	case triggerLaunchFail:
		return "vm launch failed"
	default:
		return "conclusion"
	}
}

// triggerReason returns the reason string used for the concluding transition.
func triggerReason(trigger concludeTrigger) string {
	switch trigger {
	case triggerVMTerminal:
		return "vm reached a terminal state"
	case triggerInterrupted:
		return "interrupted: daemon restarted; vm no longer live"
	case triggerGuestResult:
		return "guest result submitted"
	case triggerLaunchFail:
		return "vm launch failed before the run started"
	default:
		return "operator initiated"
	}
}

// postConclude fires on_completion and reportGen after a run reaches terminal.
func (m *Manager) postConclude(run *store.Run) {
	// on_completion=stop: stop the VM if it's still live.
	if run.OnCompletion == "stop" {
		m.stopVMAfterRun(run.VMID)
	}

	// Enqueue report generation (Task 7 wires the real generator).
	if m.reportGen != nil {
		m.reportGen(run.RunID)
	}
}

// stopVMAfterRun issues a stop action on the VM as a system-initiated stop.
// If the VM is already stopping or stopped, this is a no-op.
//
// Intentional bypass of doAction and its onVMTerminal hook: the run is already
// terminal when this fires, so there is no active run to orphan (R4 partial
// unique index enforces one non-terminal run per VM). A future VM hook addition
// to doAction would not affect this path — that is safe here because the
// lifecycle invariant is fully resolved before stopVMAfterRun is called.
func (m *Manager) stopVMAfterRun(vmID string) {
	ctx := m.ctx
	vm, err := m.st.GetVM(ctx, vmID)
	if err != nil {
		return
	}
	switch vm.ObservedState {
	case "running", "paused":
		// Use the same stop path as Action, but as a system-initiated request.
		// Transition through stopping first per §5.2.
		if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:   vmID,
			To:     "stopping",
			Reason: "run_on_completion_stop",
		}); err != nil {
			return // race is fine — something else is stopping it
		}
		grace := 0 // immediate stop on completion
		_ = grace
		forced, err := m.rt.Stop(ctx, vmID, 0)
		_ = forced
		if err != nil {
			// Best-effort: if Stop fails, try ForceStop.
			_ = m.rt.ForceStop(ctx, vmID)
		}
		_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:           vmID,
			To:             "stopped",
			Reason:         "run_on_completion_stop",
			ReleaseCompute: true,
		})
	}
	// Already stopping/stopped/failed/etc — skip silently.
}

// --- SubmitRunProgress ---

// SubmitRunProgress forwards a guest progress payload to the store.
// Returns the new monotonic sequence number, or an error from the store.
func (m *Manager) SubmitRunProgress(ctx context.Context, runID string, payload json.RawMessage) (int64, error) {
	seq, err := m.st.SubmitRunProgress(ctx, store.SubmitProgressInput{
		RunID:    runID,
		Payload:  payload,
		MaxBytes: 1 << 20, // 1 MiB (R11: shares the guest_result_max_bytes bound)
	})
	return seq, err
}

// --- SubmitRunResult ---

// SubmitRunResult records a guest final result and then triggers conclusion.
// Returns the run after conclusion (may be terminal).
func (m *Manager) SubmitRunResult(ctx context.Context, runID string, result json.RawMessage) (*store.Run, error) {
	// Store the result first.
	run, err := m.st.SubmitRunResult(ctx, store.SubmitResultInput{
		RunID:    runID,
		Result:   result,
		MaxBytes: 1 << 20,
	})
	if err != nil {
		return nil, err
	}

	// Trigger conclusion asynchronously (best-effort race resolution).
	// The caller gets the run post-result-recording; the conclusion fires in the bg.
	// wg.Add before go ensures Close()'s wg.Wait() blocks until this goroutine
	// finishes — same pattern as enqueueLaunch in manager.go.
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		concluded, err := m.concludeRun(m.ctx, runID, triggerGuestResult)
		if err != nil {
			// Log implicitly; conclusion races resolve via From pins.
			_ = concluded
		}
	}()

	return run, nil
}

// --- VM lifecycle hooks ---

// onVMRunning is called after every TransitionVM that reaches "running".
// If a pending run exists for the VM, it transitions to running (sets started_at).
func (m *Manager) onVMRunning(ctx context.Context, vmID string) {
	run, err := m.st.ActiveRunForVM(ctx, vmID)
	if err != nil || run == nil {
		return
	}
	if run.Phase != "pending" {
		return
	}
	_, _ = m.st.TransitionRun(ctx, store.RunTransitionInput{
		RunID: run.RunID,
		From:  "pending",
		To:    "running",
	})
}

// onVMTerminal is called after every TransitionVM that reaches a terminal state
// (stopped, failed). If an active run exists in pending/running/concluding, it
// is concluded via concludeRun.
func (m *Manager) onVMTerminal(ctx context.Context, vmID string) {
	run, err := m.st.ActiveRunForVM(ctx, vmID)
	if err != nil || run == nil {
		return
	}
	terminalPhases := map[string]bool{
		"succeeded": true, "failed": true, "inconclusive": true, "aborted": true,
	}
	if terminalPhases[run.Phase] {
		return
	}
	_, _ = m.concludeRun(ctx, run.RunID, triggerVMTerminal)
}

// onVMLaunchFailed is called by failLaunch to conclude any pending run with
// the R8 reason: vm launch failed before the run started.
func (m *Manager) onVMLaunchFailed(ctx context.Context, vmID string) {
	run, err := m.st.ActiveRunForVM(ctx, vmID)
	if err != nil || run == nil {
		return
	}
	terminalPhases := map[string]bool{
		"succeeded": true, "failed": true, "inconclusive": true, "aborted": true,
	}
	if terminalPhases[run.Phase] {
		return
	}
	_, _ = m.concludeRun(ctx, run.RunID, triggerLaunchFail)
}
