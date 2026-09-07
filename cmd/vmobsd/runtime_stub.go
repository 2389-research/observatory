// ABOUTME: Non-Linux stub for buildFirecrackerRuntime: firecracker mode is Linux-only.
// ABOUTME: Returns a config error on darwin (or any non-Linux OS) naming the field.

//go:build !linux

package main

import (
	"context"
	"fmt"

	"github.com/2389-research/observatory/internal/config"
	"github.com/2389-research/observatory/internal/preflight"
	"github.com/2389-research/observatory/internal/runtime"
)

// buildFirecrackerRuntime is unavailable on non-Linux platforms. Firecracker
// requires Linux KVM; runtime.mode firecracker is a config error here.
func buildFirecrackerRuntime(
	_ *config.Config,
	_ func(ctx context.Context, refresh bool) preflight.Report,
) (runtime.Runtime, error) {
	return nil, fmt.Errorf("runtime.mode firecracker is only supported on Linux; this platform cannot run Firecracker VMs")
}
