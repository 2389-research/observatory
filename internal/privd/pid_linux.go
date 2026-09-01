// ABOUTME: Linux PID liveness and identity probe via /proc/<pid>/stat.
// ABOUTME: Used by the server to confirm a VM process is still alive before rejecting release_vm.

//go:build linux

package privd

import (
	"fmt"
	"os"
	"strings"
)

// ProcStatPath returns the /proc/<pid>/stat path for a process.
// Exported so tests can read starttime before the process exits.
func ProcStatPath(pid int) string {
	return fmt.Sprintf("/proc/%d/stat", pid)
}

// ParseStartTime extracts the starttime (field 22, 1-based) from a /proc/<pid>/stat line.
// Returns "" if the line cannot be parsed.
// Field 2 is the comm in parens (may contain spaces), so we find the last ')' and count from there.
func ParseStartTime(statLine string) string {
	// Find the last ')' which ends the comm field.
	idx := strings.LastIndex(statLine, ")")
	if idx < 0 {
		return ""
	}
	// Fields after the closing ')' are space-separated; field 22 is at offset 20 from field 3.
	rest := strings.TrimSpace(statLine[idx+1:])
	fields := strings.Fields(rest)
	// fields[0] = field3 (state), ... fields[19] = field22 (starttime)
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}

// PIDAlive reports whether the process at pid is still running with the given starttime.
// A missing /proc entry, or a mismatched starttime, means not alive.
func PIDAlive(pid int, starttime string) bool {
	data, err := os.ReadFile(ProcStatPath(pid))
	if err != nil {
		return false
	}
	cur := ParseStartTime(string(data))
	return cur != "" && cur == starttime
}
