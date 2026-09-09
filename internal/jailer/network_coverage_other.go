// ABOUTME: Reports host network coverage as unavailable on non-Linux systems.
// ABOUTME: Firecracker runner process and Unix peer proof only exist on Linux.

//go:build !linux

package jailer

import (
	"context"
	"fmt"

	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

func (a *Adapter) Coverage(context.Context, *store.VM) ([]situation.CollectorCoverage, error) {
	return nil, fmt.Errorf("jailer: live host network coverage is unavailable on this platform")
}
