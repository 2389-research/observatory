// ABOUTME: Stub Launch for non-Linux builds — the real implementation is launch.go (linux only).
// ABOUTME: Returns UnavailableError; satisfies runtime.Runtime on all build targets.

//go:build !linux

package jailer

import (
	"context"

	"github.com/2389-research/observatory/internal/lock"
	"github.com/2389-research/observatory/internal/runtime"
)

// Launch is not supported on non-Linux hosts — Firecracker requires KVM.
func (a *Adapter) Launch(_ context.Context, _ runtime.VMSpec) (*lock.Images, error) {
	a.launchMu.Lock()
	defer a.launchMu.Unlock()
	return nil, &runtime.UnavailableError{Reason: "Launch requires Linux/KVM; not supported on this platform"}
}

// Ensure Adapter satisfies runtime.Runtime on non-Linux builds.
var _ runtime.Runtime = (*Adapter)(nil)
