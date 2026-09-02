// ABOUTME: Non-Linux preflight stubs: arch_kvm fails honestly, syscall helpers
// ABOUTME: return platform-appropriate values so portable tests always compile.
//go:build !linux

package preflight

import (
	"fmt"
	"runtime"
	"syscall"
)

// guestChannelCheck is not_implemented on non-Linux (vsock + privd require Linux).
func guestChannelCheck(_ Config) Check {
	return Check{
		ID:      "guest_channel",
		Status:  StatusNotImplemented,
		Summary: "guest channel not implemented on non-Linux (vsock + privd require Linux/KVM)",
		Evidence: []string{
			fmt.Sprintf("GOOS=%s: guest_channel requires Linux", runtime.GOOS),
		},
	}
}

// checkArchKVM fails honestly on non-Linux hosts: KVM requires Linux.
func (r *Runner) checkArchKVM() Check {
	return Check{
		ID:      "arch_kvm",
		Status:  StatusFail,
		Summary: fmt.Sprintf("KVM requires Linux (this host is GOOS=%s)", runtime.GOOS),
		Evidence: []string{
			fmt.Sprintf("GOOS=%s: KVM requires Linux", runtime.GOOS),
		},
		Remediation: &Remediation{
			Cause:  "not_linux",
			Action: "run vmobsd on a Linux host with KVM support",
		},
	}
}

// kernelRelease returns a platform-honest value on non-Linux hosts.
func kernelRelease() string {
	return runtime.GOOS + " (no uname)"
}

// diskFreeStatfs returns free disk in MiB using syscall.Statfs (available on darwin).
func diskFreeStatfs(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	// Bavail is blocks available to non-root; Bsize is block size in bytes.
	freeMiB := int64(st.Bavail) * int64(st.Bsize) / (1024 * 1024)
	return freeMiB, nil
}
