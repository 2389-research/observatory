// ABOUTME: Non-linux stubs for PID liveness helpers (linux-only feature).
// ABOUTME: These exist so the package compiles on macOS and other platforms.

//go:build !linux

package privd

import "fmt"

// ProcStatPath is a no-op stub on non-linux platforms.
func ProcStatPath(pid int) string { return "" }

// ParseStartTime is a no-op stub on non-linux platforms.
func ParseStartTime(statLine string) string { return "" }

// ParseComm is a no-op stub on non-linux platforms.
func ParseComm(statLine string) string { return "" }

// PIDAlive always returns false on non-linux platforms (no /proc).
func PIDAlive(pid int, starttime string) bool { return false }

// entryAlive refuses to infer process death on a platform without Linux procfs.
func entryAlive(entry VMEntry) (bool, error) {
	if entry.PID == 0 {
		return false, nil
	}
	return false, fmt.Errorf("process ownership requires Linux procfs")
}
