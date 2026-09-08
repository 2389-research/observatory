// ABOUTME: Runtime interface and host adapter: the only path to Firecracker operations.
// ABOUTME: ForHost returns Unavailable until the Linux track (L0) builds the real adapter.
package runtime

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/2389-research/observatory/internal/lock"
)

// VMSpec is everything a runtime needs to launch a VM. Allocated by the caller
// (manager) before any external call so the spec is durable even if the launch
// is interrupted.
type VMSpec struct {
	VMID             string
	BootID           string
	VCPUCount        int
	MemoryMiB        int64
	RootDiskMiB      int64
	WorkspaceDiskMiB int64
	NetworkProfile   string
	NetworkPolicyID  string
	TemplateID       string
	TemplateDigest   string
}

// Runtime is the lifecycle boundary between the controller and the VMM layer.
// Every method runs in the caller's context and returns a typed error on failure.
// Availability should be checked before any create attempt; all other methods
// may be called on a known-live VM even if Availability later returns an error.
type Runtime interface {
	// Availability returns nil when this host can launch a VM right now.
	// A non-nil return is an *UnavailableError with a reason that is safe to
	// surface to the operator (AT-001: rejected with the failed check).
	Availability(ctx context.Context) error

	// Launch starts the VM and reports the images it staged for this boot: the
	// kernel and root filesystem it copied in and verified. Nil when this runtime
	// stages no images of its own — an absence, not an empty answer. Only the
	// launch can say, because the lock it reads at stage time may already differ
	// from the one this daemon loaded at startup.
	Launch(ctx context.Context, spec VMSpec) (*lock.Images, error)
	Pause(ctx context.Context, vmID string) error
	Resume(ctx context.Context, vmID string) error

	// Stop requests graceful shutdown with a bounded grace period, then forces.
	// forced=true when the grace period elapsed and the VMM was killed.
	// §5.4: records graceful versus forced outcome separately.
	Stop(ctx context.Context, vmID string, grace time.Duration) (forced bool, err error)

	// ForceStop immediately terminates the VMM without waiting for the guest.
	// Must work on running, paused, and stopping VMs (§5.2).
	ForceStop(ctx context.Context, vmID string) error

	// Release performs a full resource release for the delete path: removes jail,
	// network, manifest, state dir, and stage dir. The spool dir is left intact
	// (the importer reads it independently). Idempotent: unknown vmID returns nil.
	// Called by Manager.Delete on every delete path; a non-*UnavailableError return
	// fails the delete so a VM row never reaches "deleted" while jail resources remain.
	Release(ctx context.Context, vmID string) error
}

// UnavailableError is the typed failure from Availability and every Unavailable
// method. Callers use errors.As to extract the reason for operator-facing messages.
type UnavailableError struct {
	Reason string
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("runtime unavailable: %s", e.Reason)
}

// ErrLaunchPending means the caller stopped waiting while a host launch still
// owns its lifecycle lock. Reservations remain held until cleanup proves absence.
type ErrLaunchPending struct {
	VMID   string
	BootID string
	Err    error
}

func (e *ErrLaunchPending) Error() string {
	return fmt.Sprintf("launch outcome pending for %s boot %s: %v", e.VMID, e.BootID, e.Err)
}
func (e *ErrLaunchPending) Unwrap() error { return e.Err }

// ErrStopNotProven is what Stop and ForceStop return when the VMM they were
// asked to end could not be observed to die.
//
// It exists because every other signal in a stop is a claim rather than an
// observation. A SignalVM call that returns nil says privd accepted the request,
// not that the kernel reaped anything -- SIGKILL cannot reap a task in
// uninterruptible sleep, and a ledger entry privd has lost signals nothing at
// all. The runner's terminal phase is a claim too: two of the three places that
// write "finalized" never look at the VMM (internal/runner/runner.go).
//
// Callers must not settle a VM on this error. "stopped" with ReleaseCompute
// hands the VM's memory and vCPU back to admission, which then hands them to
// another VM while this one is still running on them. Leaving the row at
// "stopping" costs a retry; releasing the compute of a live microVM costs the
// host.
type ErrStopNotProven struct {
	VMID   string
	Reason string
}

func (e *ErrStopNotProven) Error() string {
	return fmt.Sprintf("stop of %s not proven: %s", e.VMID, e.Reason)
}

// ErrCleanupPending is what Stop and ForceStop return when the VMM is proven
// gone and a host resource the stop owns could not be reclaimed.
//
// The two halves of a stop settle on different evidence and so deserve
// different answers. Compute is freed by the process ending, and that has been
// observed here: the row belongs at "stopped" with its reservation released, or
// admission holds memory nothing is using until the next restart. Disk and the
// privileged ledger entry are freed by a call that failed, and that failure is
// real and has to be recorded -- it used to go to stderr and nowhere else, so
// the leak was invisible to every surface an operator reads.
//
// Callers on the stop path treat it as success carrying a debt: settle the VM
// and record the cleanup failure beside it. Callers on the delete path must
// not: a "deleted" row promises every resource is gone, which is a higher bar
// than a stopped one has to clear.
type ErrCleanupPending struct {
	VMID     string
	Resource string
	Reason   string
}

func (e *ErrCleanupPending) Error() string {
	return fmt.Sprintf("%s stopped, but its %s could not be reclaimed: %s", e.VMID, e.Resource, e.Reason)
}

// unavailableRuntime implements Runtime by refusing all operations. Every
// method returns *UnavailableError so callers can errors.As-check the reason.
type unavailableRuntime struct {
	reason           string
	preflightSummary func() string
}

func (u *unavailableRuntime) Availability(_ context.Context) error {
	reason := u.reason
	if u.preflightSummary != nil {
		if s := u.preflightSummary(); s != "" {
			reason = reason + "; preflight: " + s
		}
	}
	return &UnavailableError{Reason: reason}
}
func (u *unavailableRuntime) Launch(_ context.Context, _ VMSpec) (*lock.Images, error) {
	return nil, &UnavailableError{Reason: u.reason}
}
func (u *unavailableRuntime) Pause(_ context.Context, _ string) error {
	return &UnavailableError{Reason: u.reason}
}
func (u *unavailableRuntime) Resume(_ context.Context, _ string) error {
	return &UnavailableError{Reason: u.reason}
}
func (u *unavailableRuntime) Stop(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return false, &UnavailableError{Reason: u.reason}
}
func (u *unavailableRuntime) ForceStop(_ context.Context, _ string) error {
	return &UnavailableError{Reason: u.reason}
}
func (u *unavailableRuntime) Release(_ context.Context, _ string) error {
	return &UnavailableError{Reason: u.reason}
}

// ForHost returns the host-appropriate runtime. On macOS, KVM is absent. On
// Linux, the Firecracker adapter is not built until the Linux track (L0).
// ForHost never returns anything that fakes a launch: Unavailable is the only
// honest answer on a host without a working adapter.
//
// When preflightSummary is non-nil and returns a non-empty string, that string
// is appended to the unavailability reason (L0-R12: preflight summary in errors).
func ForHost(preflightSummary ...func() string) Runtime {
	var pfSummary func() string
	if len(preflightSummary) > 0 {
		pfSummary = preflightSummary[0]
	}

	reason := "firecracker adapter not built until the Linux track (L0)"
	switch runtime.GOOS {
	case "darwin":
		reason = "no KVM on this platform"
	}

	return &unavailableRuntime{reason: reason, preflightSummary: pfSummary}
}
