// ABOUTME: Launch cancellation preserves a bounded host worker and its late result.
// ABOUTME: A held lifecycle lock never creates a detached waiter per request.
package jailer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/lock"
	"github.com/2389-research/observatory/internal/runtime"
)

func TestLaunchBudgetRetainsLateHostAuthority(t *testing.T) {
	a := &Adapter{}
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := a.launchBounded(ctx, runtime.VMSpec{VMID: "vm", BootID: "boot"}, func(context.Context, runtime.VMSpec) (*lock.Images, error) {
			close(entered)
			<-release
			close(finished)
			return &lock.Images{}, nil
		})
		result <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-result:
		var pending *runtime.ErrLaunchPending
		if !errors.As(err, &pending) {
			t.Errorf("error=%v", err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("uninterruptible host launch prevented return")
	}
	if a.launchMu.TryLock() {
		a.launchMu.Unlock()
		t.Fatal("host worker released authority before finishing")
	}
	queued, cancelQueued := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancelQueued()
	_, err := a.launchBounded(queued, runtime.VMSpec{}, func(context.Context, runtime.VMSpec) (*lock.Images, error) {
		t.Error("queued host launch started")
		return nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("queue error=%v", err)
	}
	close(release)
	<-finished
	waitCtx, waitCancel := context.WithTimeout(t.Context(), time.Second)
	defer waitCancel()
	if err := a.acquireLifecycle(waitCtx); err != nil {
		t.Fatal(err)
	}
	a.launchMu.Unlock()
}
