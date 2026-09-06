// ABOUTME: Fake runtime for unit tests only (SPEC §18). Never import this from
// ABOUTME: cmd/ or any served binary; the scripts/check tripwire enforces this.
package runtimetest

import (
	"context"
	"sync"
	"time"

	"github.com/2389-research/observatory-v2/internal/lock"
	"github.com/2389-research/observatory-v2/internal/runtime"
)

// Call records one invocation of a runtime method.
type Call struct {
	Method string
	VMID   string

	// Deadline is the deadline carried by the context the call was handed, zero
	// if it had none. It is the only way a test can see which budget a manager
	// gave a runtime call; the alternative is waiting the budget out.
	Deadline time.Time
}

// Fake is the SPEC §18-sanctioned test double. It records every call, returns
// injectable errors, and can block individual calls until a test releases them —
// useful for exercising concurrent-launch caps and stop-during-launch races.
type Fake struct {
	mu sync.Mutex

	// Calls is every method invocation in arrival order.
	Calls []Call

	// failNext maps (method, vmID) → error for the next call matching that pair.
	// Consumed on first match; the key is "method:vmID".
	failNext map[string]error

	// blocks maps (method, vmID) → channel that must be closed before the call
	// returns. Tests hold a reference to each channel and close it when ready.
	blocks map[string]chan struct{}

	// uninterruptible holds the keys whose block ignores context cancellation.
	// Consumed with the block itself.
	uninterruptible map[string]bool

	// failCalls maps method → {n, err}: the nth call of method (1-based, any
	// vmID, counted from Fake creation) returns err. For call sites where the
	// VM ID is server-generated and unknowable at injection time.
	failCalls map[string]callFailure
	counts    map[string]int

	// staged is what Launch reports having staged for a boot; nil reports none.
	staged *lock.Images
}

type callFailure struct {
	n   int
	err error
}

// NewFake returns an idle fake with no injected failures or blocks.
func NewFake() *Fake {
	return &Fake{
		failNext:        map[string]error{},
		blocks:          map[string]chan struct{}{},
		uninterruptible: map[string]bool{},
		failCalls:       map[string]callFailure{},
		counts:          map[string]int{},
	}
}

func key(method, vmID string) string { return method + ":" + vmID }

// FailNext injects err for exactly one call of method on vmID.
func (f *Fake) FailNext(method, vmID string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[key(method, vmID)] = err
}

// FailCall injects err for the nth call of method (1-based, counted from Fake
// creation), regardless of which VM the call targets.
func (f *Fake) FailCall(method string, n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failCalls[method] = callFailure{n: n, err: err}
}

// Block returns a channel that must be closed before the next call of method on
// vmID returns. The caller holds the channel and closes it when ready to unblock.
func (f *Fake) Block(method, vmID string) chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan struct{})
	f.blocks[key(method, vmID)] = ch
	return ch
}

// BlockUninterruptible is Block for a call whose work no context can interrupt:
// it returns its own result when the test releases it even if the context died
// while it ran. The real launch path is built that way — most of it is file IO
// through helpers that take no context at all (internal/jailer/launch.go
// copyVerified) — so this is the shape that exercises bookkeeping which has to run
// after the call's own budget is spent.
func (f *Fake) BlockUninterruptible(method, vmID string) chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan struct{})
	f.blocks[key(method, vmID)] = ch
	f.uninterruptible[key(method, vmID)] = true
	return ch
}

func (f *Fake) record(ctx context.Context, method, vmID string) (block chan struct{}, ignoreCtx bool, err error) {
	deadline, _ := ctx.Deadline()
	f.mu.Lock()
	f.Calls = append(f.Calls, Call{Method: method, VMID: vmID, Deadline: deadline})
	f.counts[method]++
	k := key(method, vmID)
	err = f.failNext[k]
	delete(f.failNext, k)
	if err == nil {
		if fc, ok := f.failCalls[method]; ok && f.counts[method] == fc.n {
			delete(f.failCalls, method)
			err = fc.err
		}
	}
	block = f.blocks[k]
	delete(f.blocks, k)
	ignoreCtx = f.uninterruptible[k]
	delete(f.uninterruptible, k)
	f.mu.Unlock()
	return block, ignoreCtx, err
}

// wait blocks until ch is closed, or until ctx is done unless ignoreCtx.
func wait(ctx context.Context, ch chan struct{}, ignoreCtx bool) error {
	if ch == nil {
		return nil
	}
	if ignoreCtx {
		<-ch
		return nil
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CallsFor returns all recorded calls for vmID, in order.
func (f *Fake) CallsFor(vmID string) []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Call
	for _, c := range f.Calls {
		if c.VMID == vmID {
			out = append(out, c)
		}
	}
	return out
}

// MethodCalls returns the ordered list of method names called (any vmID).
func (f *Fake) MethodCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.Calls))
	for i, c := range f.Calls {
		out[i] = c.Method
	}
	return out
}

// Availability always returns nil — the fake host can always launch.
func (f *Fake) Availability(ctx context.Context) error {
	_, _, err := f.record(ctx, "Availability", "")
	return err
}

func (f *Fake) Launch(ctx context.Context, spec runtime.VMSpec) (*lock.Images, error) {
	ch, ignoreCtx, err := f.record(ctx, "Launch", spec.VMID)
	if waitErr := wait(ctx, ch, ignoreCtx); waitErr != nil {
		return nil, waitErr
	}
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.staged, nil
}

// SetStagedImages sets what Launch reports having staged. Nil, the default, is a
// runtime that stages no images of its own.
func (f *Fake) SetStagedImages(img *lock.Images) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staged = img
}

func (f *Fake) Pause(ctx context.Context, vmID string) error {
	ch, ignoreCtx, err := f.record(ctx, "Pause", vmID)
	if waitErr := wait(ctx, ch, ignoreCtx); waitErr != nil {
		return waitErr
	}
	return err
}

func (f *Fake) Resume(ctx context.Context, vmID string) error {
	ch, ignoreCtx, err := f.record(ctx, "Resume", vmID)
	if waitErr := wait(ctx, ch, ignoreCtx); waitErr != nil {
		return waitErr
	}
	return err
}

// Stop returns (forced, err) where forced is controlled by FailNext("Stop", vmID).
// Inject a *ForcedStop sentinel to signal that the grace period elapsed.
func (f *Fake) Stop(ctx context.Context, vmID string, _ time.Duration) (bool, error) {
	ch, ignoreCtx, err := f.record(ctx, "Stop", vmID)
	if waitErr := wait(ctx, ch, ignoreCtx); waitErr != nil {
		return false, waitErr
	}
	if err != nil {
		if isForcedStop(err) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (f *Fake) ForceStop(ctx context.Context, vmID string) error {
	ch, ignoreCtx, err := f.record(ctx, "ForceStop", vmID)
	if waitErr := wait(ctx, ch, ignoreCtx); waitErr != nil {
		return waitErr
	}
	return err
}

// Release records the call and returns the injected error (or nil).
// Idempotent: unknown vmID returns nil in the real adapter; the fake does the same.
func (f *Fake) Release(ctx context.Context, vmID string) error {
	ch, ignoreCtx, err := f.record(ctx, "Release", vmID)
	if waitErr := wait(ctx, ch, ignoreCtx); waitErr != nil {
		return waitErr
	}
	return err
}

// ForcedStop is a sentinel error injected via FailNext("Stop", vmID) to make
// the fake report forced=true, as if the grace period elapsed.
type ForcedStop struct{}

func (*ForcedStop) Error() string { return "fake: grace period elapsed, forced" }

func isForcedStop(err error) bool {
	_, ok := err.(*ForcedStop)
	return ok
}
