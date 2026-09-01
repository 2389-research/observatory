// ABOUTME: Non-linux stubs for PID liveness helpers (linux-only feature).
// ABOUTME: These exist so the package compiles on macOS and other platforms.

//go:build !linux

package privd

// ProcStatPath is a no-op stub on non-linux platforms.
func ProcStatPath(pid int) string { return "" }

// ParseStartTime is a no-op stub on non-linux platforms.
func ParseStartTime(statLine string) string { return "" }

// PIDAlive always returns false on non-linux platforms (no /proc).
func PIDAlive(pid int, starttime string) bool { return false }
