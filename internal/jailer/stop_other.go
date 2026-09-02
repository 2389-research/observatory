// ABOUTME: Non-Linux stubs for Stop, ForceStop, Release, and Reconcile.
// ABOUTME: All return UnavailableError — Firecracker/jailer requires Linux/KVM.

//go:build !linux

package jailer

import (
	"context"
	"time"

	"github.com/2389-research/observatory-v2/internal/runtime"
)

// Stop is not supported on non-Linux hosts.
func (a *Adapter) Stop(_ context.Context, _ string, _ time.Duration) (bool, error) {
	return false, &runtime.UnavailableError{Reason: "Stop requires Linux/KVM; not supported on this platform"}
}

// ForceStop is not supported on non-Linux hosts.
func (a *Adapter) ForceStop(_ context.Context, _ string) error {
	return &runtime.UnavailableError{Reason: "ForceStop requires Linux/KVM; not supported on this platform"}
}

// Release is not supported on non-Linux hosts.
func (a *Adapter) Release(_ context.Context, _ string) error {
	return &runtime.UnavailableError{Reason: "Release requires Linux/KVM; not supported on this platform"}
}

// Reconcile is not supported on non-Linux hosts.
func (a *Adapter) Reconcile(_ context.Context) ([]Finding, error) {
	return nil, nil
}
