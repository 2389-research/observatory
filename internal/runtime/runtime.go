// ABOUTME: Runtime interface and host adapter: the only path to Firecracker operations.
// ABOUTME: ForHost returns Unavailable until the Linux track (L0) builds the real adapter.
package runtime

import (
	"context"
	"fmt"
	"runtime"
	"time"
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

	Launch(ctx context.Context, spec VMSpec) error
	Pause(ctx context.Context, vmID string) error
	Resume(ctx context.Context, vmID string) error

	// Stop requests graceful shutdown with a bounded grace period, then forces.
	// forced=true when the grace period elapsed and the VMM was killed.
	// §5.4: records graceful versus forced outcome separately.
	Stop(ctx context.Context, vmID string, grace time.Duration) (forced bool, err error)

	// ForceStop immediately terminates the VMM without waiting for the guest.
	// Must work on running, paused, and stopping VMs (§5.2).
	ForceStop(ctx context.Context, vmID string) error
}

// UnavailableError is the typed failure from Availability and every Unavailable
// method. Callers use errors.As to extract the reason for operator-facing messages.
type UnavailableError struct {
	Reason string
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("runtime unavailable: %s", e.Reason)
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
func (u *unavailableRuntime) Launch(_ context.Context, _ VMSpec) error {
	return &UnavailableError{Reason: u.reason}
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
