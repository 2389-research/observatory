// ABOUTME: Context-bounded launch admission with one retained host worker.
// ABOUTME: Uninterruptible filesystem work keeps lifecycle authority until it ends.
package jailer

import (
	"context"
	"time"

	"github.com/2389-research/observatory/internal/lock"
	"github.com/2389-research/observatory/internal/runtime"
)

// acquireLifecycle waits without spawning a goroutine per mutex waiter. Stop
// and release use this same gate so they cannot overtake a late launch effect.
func (a *Adapter) acquireLifecycle(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if a.launchMu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (a *Adapter) launchBounded(ctx context.Context, spec runtime.VMSpec, launch func(context.Context, runtime.VMSpec) (*lock.Images, error)) (*lock.Images, error) {
	if err := a.acquireLifecycle(ctx); err != nil {
		return nil, err
	}
	type outcome struct {
		images *lock.Images
		err    error
	}
	done := make(chan outcome, 1)
	// Only the lock owner can create a worker. Cancellation leaves that worker
	// owning the lock, and every durable manifest publication stays in launch.
	// It never accesses the controller's store or calls back into the manager.
	go func() { defer a.launchMu.Unlock(); images, err := launch(ctx, spec); done <- outcome{images, err} }()
	select {
	case result := <-done:
		return result.images, result.err
	case <-ctx.Done():
		// Prefer a completed observation when completion raced cancellation.
		select {
		case result := <-done:
			return result.images, result.err
		default:
		}
		return nil, &runtime.ErrLaunchPending{VMID: spec.VMID, BootID: spec.BootID, Err: ctx.Err()}
	}
}
