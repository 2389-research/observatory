// ABOUTME: Fake runtime for unit tests only (SPEC §18). Never import this from
// ABOUTME: cmd/ or any served binary; the scripts/check tripwire enforces this.
package runtimetest

import (
	"context"
	"sync"
	"time"

	"github.com/2389-research/observatory-v2/internal/runtime"
)

// Call records one invocation of a runtime method.
type Call struct {
	Method string
	VMID   string
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

	// failCalls maps method → {n, err}: the nth call of method (1-based, any
	// vmID, counted from Fake creation) returns err. For call sites where the
	// VM ID is server-generated and unknowable at injection time.
	failCalls map[string]callFailure
	counts    map[string]int
}

type callFailure struct {
	n   int
	err error
}

// NewFake returns an idle fake with no injected failures or blocks.
func NewFake() *Fake {
	return &Fake{
		failNext:  map[string]error{},
		blocks:    map[string]chan struct{}{},
		failCalls: map[string]callFailure{},
		counts:    map[string]int{},
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

func (f *Fake) record(method, vmID string) (block chan struct{}, err error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, Call{Method: method, VMID: vmID})
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
	f.mu.Unlock()
	return block, err
}

// wait blocks until ch is closed or ctx is done.
func wait(ctx context.Context, ch chan struct{}) error {
	if ch == nil {
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
func (f *Fake) Availability(_ context.Context) error {
	_, err := f.record("Availability", "")
	return err
}

func (f *Fake) Launch(ctx context.Context, spec runtime.VMSpec) error {
	ch, err := f.record("Launch", spec.VMID)
	if waitErr := wait(ctx, ch); waitErr != nil {
		return waitErr
	}
	return err
}

func (f *Fake) Pause(ctx context.Context, vmID string) error {
	ch, err := f.record("Pause", vmID)
	if waitErr := wait(ctx, ch); waitErr != nil {
		return waitErr
	}
	return err
}

func (f *Fake) Resume(ctx context.Context, vmID string) error {
	ch, err := f.record("Resume", vmID)
	if waitErr := wait(ctx, ch); waitErr != nil {
		return waitErr
	}
	return err
}

// Stop returns (forced, err) where forced is controlled by FailNext("Stop", vmID).
// Inject a *ForcedStop sentinel to signal that the grace period elapsed.
func (f *Fake) Stop(ctx context.Context, vmID string, _ time.Duration) (bool, error) {
	ch, err := f.record("Stop", vmID)
	if waitErr := wait(ctx, ch); waitErr != nil {
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
	ch, err := f.record("ForceStop", vmID)
	if waitErr := wait(ctx, ch); waitErr != nil {
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
