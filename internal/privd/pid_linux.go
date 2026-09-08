// ABOUTME: Linux PID liveness and identity probe via /proc/<pid>/stat.
// ABOUTME: Used by the server to confirm a VM process is still alive before rejecting release_vm.

//go:build linux

package privd

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
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

// ParseComm extracts the comm (field 2, 1-based) from a /proc/<pid>/stat line —
// the executable name the kernel records for the process, without a path.
// Returns "" if the line cannot be parsed. Field 2 is wrapped in parens and may
// itself contain spaces and parens, so the first '(' and the last ')' bound it.
func ParseComm(statLine string) string {
	lparen := strings.Index(statLine, "(")
	rparen := strings.LastIndex(statLine, ")")
	if lparen < 0 || rparen <= lparen {
		return ""
	}
	return statLine[lparen+1 : rparen]
}

// processAlive distinguishes a dead process from an unreadable identity. Only
// absence or a different starttime proves the owned process is gone.
func processAlive(pid int, starttime string) (bool, error) {
	if pid <= 0 {
		return false, fmt.Errorf("invalid process ID")
	}
	if _, err := strconv.ParseUint(starttime, 10, 64); err != nil {
		return false, fmt.Errorf("invalid process starttime")
	}
	data, err := os.ReadFile(ProcStatPath(pid))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read process identity: %w", err)
	}
	cur := ParseStartTime(string(data))
	if _, err := strconv.ParseUint(cur, 10, 64); err != nil {
		return false, fmt.Errorf("unreadable process starttime")
	}
	if cur != starttime {
		return false, nil
	}
	fields := strings.Fields(string(data)[strings.LastIndex(string(data), ")")+1:])
	// A zombie has exited and cannot use its jail or identities.
	return fields[0] != "Z" && fields[0] != "X", nil
}

// PIDAlive reports whether a process with this starttime is alive. Callers that
// authorize cleanup must use entryAlive, which preserves observation failures.
func PIDAlive(pid int, starttime string) bool {
	alive, err := processAlive(pid, starttime)
	return err == nil && alive
}

var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var pidNamespacePattern = regexp.MustCompile(`^pid:\[[0-9]+\]$`)

func hostIdentity() (string, string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", "", fmt.Errorf("read host boot identity: %w", err)
	}
	boot := strings.TrimSpace(string(data))
	ns, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return "", "", fmt.Errorf("read PID namespace identity: %w", err)
	}
	if !bootIDPattern.MatchString(boot) || !pidNamespacePattern.MatchString(ns) {
		return "", "", fmt.Errorf("invalid kernel identity")
	}
	return boot, ns, nil
}

// entryAlive never treats an unknown ownership context as proof of death. A
// different host boot proves the predecessor exited; a different PID namespace
// on the same boot cannot prove anything about a process outside our view.
func entryAlive(entry VMEntry) (bool, error) {
	if entry.PID == 0 {
		return false, nil
	}
	if !bootIDPattern.MatchString(entry.BootID) || !pidNamespacePattern.MatchString(entry.PIDNamespace) {
		return false, fmt.Errorf("missing or malformed trusted process ownership")
	}
	boot, ns, err := hostIdentity()
	if err != nil {
		return false, err
	}
	if entry.BootID != boot {
		return false, nil
	}
	if entry.PIDNamespace != ns {
		return false, fmt.Errorf("process PID namespace differs; ownership cannot be observed")
	}
	return processAlive(entry.PID, entry.StartTime)
}
