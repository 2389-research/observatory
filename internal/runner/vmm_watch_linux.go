// ABOUTME: Linux VMM identity watch using /proc/<pid>/stat via privd helpers.
// ABOUTME: PIDAliveFunc is set to privd.PIDAlive at init; tests can replace it.

//go:build linux

package runner

import "github.com/2389-research/observatory/internal/privd"

// PIDAliveFunc is the function used to check VMM process liveness.
// Set to privd.PIDAlive on linux; replaceable in tests.
var PIDAliveFunc = func(pid int, starttime string) bool {
	return privd.PIDAlive(pid, starttime)
}
