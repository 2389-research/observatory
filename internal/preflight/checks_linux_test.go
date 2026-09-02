// ABOUTME: Linux-specific preflight test: asserts the honesty of arch_kvm for
// ABOUTME: BOTH real outcomes (open success → full hlt sequence; EACCES → check fails).
//go:build linux

package preflight_test

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/preflight"
)

// TestArchKVMHonest asserts the EITHER-real-outcome contract mandated by the
// task brief: the test must NOT skip and must NOT fake. When /dev/kvm opens
// successfully the full hlt sequence must produce pass. When the process lacks
// kvm group membership (EACCES), the check must fail with the re-login
// remediation. Both are valid real outcomes on the current test host.
func TestArchKVMHonest(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	kvm := findCheck(report.Checks, "arch_kvm")
	if kvm == nil {
		t.Fatal("arch_kvm check absent from report")
	}

	switch kvm.Status {
	case preflight.StatusPass:
		// /dev/kvm opened and the hlt sequence completed.
		evHasAPIVersion := false
		evHasExitReason := false
		for _, ev := range kvm.Evidence {
			if strings.Contains(ev, "kvm_api_version") {
				evHasAPIVersion = true
			}
			if strings.Contains(ev, "kvm_exit_reason") {
				evHasExitReason = true
			}
		}
		if !evHasAPIVersion {
			t.Errorf("pass evidence missing kvm_api_version: %v", kvm.Evidence)
		}
		if !evHasExitReason {
			t.Errorf("pass evidence missing kvm_exit_reason: %v", kvm.Evidence)
		}
		t.Logf("arch_kvm: PASS — %s", kvm.Summary)

	case preflight.StatusFail:
		// Acceptable failure modes: ENOENT (no kvm module), EACCES (not in group),
		// or other genuine KVM errors. All must have a non-empty summary.
		if kvm.Summary == "" {
			t.Error("arch_kvm fail: summary must not be empty")
		}
		if kvm.Remediation == nil {
			t.Error("arch_kvm fail: remediation must be set on failure")
		}
		// If it looks like a permission error the remediation must mention re-login.
		for _, ev := range kvm.Evidence {
			if strings.Contains(ev, "permission denied") {
				if !strings.Contains(kvm.Remediation.Action, "re-login") &&
					!strings.Contains(kvm.Remediation.Action, "kvm group") {
					t.Errorf("EACCES remediation should mention re-login/kvm group: %q", kvm.Remediation.Action)
				}
			}
		}
		t.Logf("arch_kvm: FAIL (honest) — %s", kvm.Summary)

	default:
		t.Errorf("arch_kvm status = %q; want pass or fail (not warn/not_implemented)", kvm.Status)
	}

	// Regardless of outcome, report.Overall must be honest.
	if kvm.Status == preflight.StatusFail && report.Overall != preflight.StatusFail {
		t.Errorf("Overall=%q but arch_kvm=fail; Overall must be fail", report.Overall)
	}
}

// TestKernelReleaseNonEmpty verifies that kernelRelease() (exercised inside Run)
// produces a non-empty, non-error string on a Linux host.
func TestKernelReleaseNonEmpty(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	if report.KernelRelease == "" {
		t.Error("KernelRelease is empty on Linux")
	}
	if report.KernelRelease == "uname failed" {
		t.Error("KernelRelease reports uname failure on Linux")
	}
	t.Logf("KernelRelease: %s", report.KernelRelease)
}

// TestCgroupV2OnLinux verifies the cgroup_v2 check produces a pass on Ubuntu 24.04
// (cgroup v2 unified) or an honest fail with remediation on a v1 kernel.
func TestCgroupV2OnLinux(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	cg := findCheck(report.Checks, "cgroup_v2")
	if cg == nil {
		t.Fatal("cgroup_v2 not in report")
	}
	switch cg.Status {
	case preflight.StatusPass:
		t.Logf("cgroup_v2: PASS — %s", cg.Summary)
	case preflight.StatusFail:
		if cg.Remediation == nil {
			t.Error("cgroup_v2 fail must have remediation")
		}
		t.Logf("cgroup_v2: FAIL (honest) — %s", cg.Summary)
	default:
		t.Errorf("cgroup_v2 status = %q; want pass or fail", cg.Status)
	}
}

// TestGuestChannelPassWithLiveTempSocket verifies that guest_channel passes when
// the privd socket is reachable (connect + close succeeds within 1s) and the stage
// root exists and is writable.
func TestGuestChannelPassWithLiveTempSocket(t *testing.T) {
	// Listen on a temp unix socket to act as the "privd" endpoint.
	sockPath := filepath.Join(t.TempDir(), "privd.sock")
	stageRoot := t.TempDir()

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept and close connections (we just need connect+close to succeed).
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	r := preflight.New(preflight.Config{
		DataDir:     t.TempDir(),
		PrivdSocket: sockPath,
		StageRoot:   stageRoot,
	})
	report := r.Run(t.Context())

	gc := findCheck(report.Checks, "guest_channel")
	if gc == nil {
		t.Fatal("guest_channel not in report")
	}
	if gc.Status != preflight.StatusPass {
		t.Errorf("guest_channel = %q, want pass (summary: %s, evidence: %v)", gc.Status, gc.Summary, gc.Evidence)
	}
}

// TestGuestChannelFailWhenSocketAbsent verifies that guest_channel fails with
// remediation naming setup.sh when the privd socket does not exist.
func TestGuestChannelFailWhenSocketAbsent(t *testing.T) {
	r := preflight.New(preflight.Config{
		DataDir:     t.TempDir(),
		PrivdSocket: filepath.Join(t.TempDir(), "no-such-socket.sock"),
		StageRoot:   t.TempDir(),
	})
	report := r.Run(t.Context())

	gc := findCheck(report.Checks, "guest_channel")
	if gc == nil {
		t.Fatal("guest_channel not in report")
	}
	if gc.Status != preflight.StatusFail {
		t.Errorf("guest_channel = %q, want fail", gc.Status)
	}
	if gc.Remediation == nil {
		t.Fatal("guest_channel fail: remediation must be set")
	}
	if !strings.Contains(gc.Remediation.Action, "setup.sh") {
		t.Errorf("remediation must name setup.sh: %q", gc.Remediation.Action)
	}
}

// TestGuestChannelFailWhenNotConfigured verifies that empty PrivdSocket → fail.
func TestGuestChannelFailWhenNotConfigured(t *testing.T) {
	r := preflight.New(preflight.Config{
		DataDir:     t.TempDir(),
		PrivdSocket: "", // not configured
		StageRoot:   "",
	})
	report := r.Run(t.Context())

	gc := findCheck(report.Checks, "guest_channel")
	if gc == nil {
		t.Fatal("guest_channel not in report")
	}
	if gc.Status != preflight.StatusFail {
		t.Errorf("guest_channel = %q, want fail when not configured", gc.Status)
	}
}

// TestNetPrereqsOnLinux verifies net_prereqs checks ip and nft on Linux.
func TestNetPrereqsOnLinux(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	np := findCheck(report.Checks, "net_prereqs")
	if np == nil {
		t.Fatal("net_prereqs not in report")
	}
	switch np.Status {
	case preflight.StatusPass:
		t.Logf("net_prereqs: PASS — ip and nft found")
	case preflight.StatusFail:
		// Honest result if tools aren't installed.
		if np.Remediation == nil {
			t.Error("net_prereqs fail must have remediation")
		}
		t.Logf("net_prereqs: FAIL (honest) — %s", np.Summary)
	default:
		t.Errorf("net_prereqs status = %q; want pass or fail", np.Status)
	}
}
