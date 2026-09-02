// ABOUTME: Test-only exports for linux-only symbols used in jailer_test package.
// ABOUTME: Exports unexported helpers so external test package can use them.

//go:build linux

package jailer

import (
	"context"

	"github.com/2389-research/observatory-v2/internal/runner"
)

// PollRunnerPhase is the exported test alias of pollRunnerPhase.
func PollRunnerPhase(ctx context.Context, stateFile string, wantPhases ...string) (runner.State, error) {
	return pollRunnerPhase(ctx, stateFile, wantPhases...)
}
