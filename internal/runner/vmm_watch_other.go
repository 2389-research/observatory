// ABOUTME: Non-linux stub for VMM identity watch (always reports dead).
// ABOUTME: The real implementation is in vmm_watch_linux.go using /proc/<pid>/stat.

//go:build !linux

package runner

// PIDAliveFunc always returns false on non-linux (no /proc).
// Tests on non-linux inject their own implementation via Config.PIDAlive.
var PIDAliveFunc = func(pid int, starttime string) bool {
	return false
}
