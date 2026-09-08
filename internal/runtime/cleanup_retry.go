// ABOUTME: Retries bounded host cleanup without running startup operation repair.
// ABOUTME: Per-VM claims keep retries outside foreground and queued lifecycle work.
package runtime

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/2389-research/observatory/internal/store"
)

const cleanupRetryInterval = 30 * time.Second
const cleanupRetryPage = 16

type lifecycleClaim struct {
	users     int
	retryDone chan struct{}
	cancel    context.CancelFunc
}

type cleanupController struct {
	mu     sync.Mutex
	claims map[string]*lifecycleClaim
	pass   sync.Mutex
	after  int64
	timer  *time.Timer // protected by Manager.closeMu
}

// claimLifecycle preserves ordinary lifecycle concurrency while excluding recovery.
// Foreground work cancels a retry before waiting; it never inherits its observation.
func (m *Manager) claimLifecycle(ctx context.Context, vmID string) (func(), error) {
	for {
		m.cleanup.mu.Lock()
		claim := m.cleanup.claims[vmID]
		if claim == nil {
			claim = &lifecycleClaim{}
			m.cleanup.claims[vmID] = claim
		}
		if claim.retryDone == nil {
			claim.users++
			m.cleanup.mu.Unlock()
			return func() {
				m.cleanup.mu.Lock()
				claim.users--
				if claim.users == 0 {
					delete(m.cleanup.claims, vmID)
				}
				m.cleanup.mu.Unlock()
			}, nil
		}
		done := claim.retryDone
		claim.cancel()
		m.cleanup.mu.Unlock()
		select {
		case <-done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (m *Manager) claimCleanup(ctx context.Context, vmID string) (context.Context, func(), bool) {
	m.cleanup.mu.Lock()
	defer m.cleanup.mu.Unlock()
	if m.cleanup.claims[vmID] != nil {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	claim := &lifecycleClaim{retryDone: make(chan struct{}), cancel: cancel}
	m.cleanup.claims[vmID] = claim
	return ctx, func() {
		cancel()
		m.cleanup.mu.Lock()
		delete(m.cleanup.claims, vmID)
		close(claim.retryDone)
		m.cleanup.mu.Unlock()
	}, true
}

func (m *Manager) scheduleCleanup() {
	m.closeMu.Lock()
	defer m.closeMu.Unlock()
	if m.closed {
		return
	}
	m.cleanup.timer = time.AfterFunc(cleanupRetryInterval, func() {
		m.GoTracked(func() {
			_ = m.RetryCleanup(m.ctx)
			m.scheduleCleanup()
		})
	})
}

// RetryCleanup inspects one bounded page of stalled work. It never repairs
// operation rows or relies on host observations saved during startup.
func (m *Manager) RetryCleanup(parent context.Context) error {
	if err := m.beginMutation(); err != nil {
		return err
	}
	defer m.wg.Done()
	if !m.cleanup.pass.TryLock() {
		return nil
	}
	defer m.cleanup.pass.Unlock()
	ctx, cancel := m.mutationContext(parent, cleanupRetryInterval)
	defer cancel()
	vms, err := m.st.ListVMs(ctx, store.VMQuery{After: m.cleanup.after, Limit: cleanupRetryPage, States: []string{"stopping", "deleting", "failed"}, IncludeStoppedCleanup: true})
	if err != nil {
		return err
	}
	for _, candidate := range vms {
		if err := ctx.Err(); err != nil {
			return err
		}
		m.cleanup.after = candidate.RowID
		claimCtx, release, ok := m.claimCleanup(ctx, candidate.VMID)
		if !ok {
			continue
		}
		err := m.retryVM(claimCtx, candidate.VMID)
		release()
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if len(vms) < cleanupRetryPage {
		m.cleanup.after = 0
	}
	return nil
}

func (m *Manager) retryVM(ctx context.Context, vmID string) error {
	vm, err := m.st.GetVM(ctx, vmID)
	if err != nil {
		return err
	}
	switch vm.ObservedState {
	case "stopping", "deleting", "failed", "stopped":
	default:
		return nil
	}
	if vm.ObservedState == "stopped" {
		pending, err := m.st.HasCleanupDebt(ctx, vmID)
		if err != nil || !pending {
			return err
		}
	}
	if vm.ObservedState == "failed" {
		reservation, err := m.st.GetReservation(ctx, vmID)
		if err != nil {
			return err
		}
		if reservation.Released {
			return nil
		}
	}
	// ForceStop observes current process identity, including detached launch work;
	// neither a saved adopted flag nor an unavailable adapter proves absence.
	err = m.rt.ForceStop(ctx, vmID)
	if err != nil && cleanupDebt(err) == nil {
		return m.recordRetryFailure(ctx, vm, err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if vm.ObservedState == "stopped" {
		if err != nil {
			return m.recordRetryFailure(ctx, vm, err)
		}
		return m.st.ClearCleanupDebt(ctx, vmID)
	}
	if vm.ObservedState == "stopping" && vm.DesiredState != "deleted" {
		if err != nil {
			return m.recordRetryFailure(ctx, vm, err)
		}
		_, err = m.st.TransitionVM(ctx, store.TransitionInput{VMID: vmID, From: &vm.ObservedState, ExpectedRevision: &vm.Revision, To: "stopped", Reason: "cleanup_retry", ReleaseCompute: true})
		if err == nil {
			m.onVMTerminal(ctx, vmID)
		}
		return err
	}
	if err = m.rt.Release(ctx, vmID); err != nil {
		return m.recordRetryFailure(ctx, vm, err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if vm.ObservedState == "failed" {
		return m.st.ReleaseVMReservations(ctx, vmID)
	}
	if vm.ObservedState == "stopping" {
		vm, err = m.st.TransitionVM(ctx, store.TransitionInput{VMID: vmID, From: &vm.ObservedState, ExpectedRevision: &vm.Revision, To: "stopped", Reason: "cleanup_retry", ReleaseCompute: true})
		if err != nil {
			return err
		}
		vm, err = m.st.TransitionVM(ctx, store.TransitionInput{VMID: vmID, From: &vm.ObservedState, To: "deleting", Reason: "cleanup_retry"})
		if err != nil {
			return err
		}
	}
	_, err = m.st.TransitionVM(ctx, store.TransitionInput{VMID: vmID, From: &vm.ObservedState, ExpectedRevision: &vm.Revision, To: "deleted", Reason: "cleanup_retry", ReleaseAll: true})
	return err
}

func (m *Manager) recordRetryFailure(ctx context.Context, vm *store.VM, err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	reason := "automatic cleanup remains queued (30-second sweep delay); manual DELETE remains available: " + err.Error()

	return errors.Join(err, m.st.RecordCleanupFailure(ctx, vm.VMID, vm.ObservedState, reason))
}
