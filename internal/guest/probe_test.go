// ABOUTME: Tests for ProbeCapabilities: honesty (Present agrees with independent stat), Evidence non-empty.
// ABOUTME: On non-linux asserts all-false-with-GOOS evidence; on linux asserts honest host facts.
package guest_test

import (
	"os"
	"runtime"
	"testing"

	"github.com/2389-research/observatory-v2/internal/guest"
)

func TestProbeCapabilitiesReturnsManifest(t *testing.T) {
	m := guest.ProbeCapabilities()
	if m.Schema != "vmobs.guest_capability.v1" {
		t.Errorf("Schema: got %q, want vmobs.guest_capability.v1", m.Schema)
	}
	if m.KernelRelease == "" {
		t.Error("KernelRelease: want non-empty")
	}
	if len(m.Features) == 0 {
		t.Error("Features: want at least one entry")
	}
}

func TestProbeCapabilitiesEvidenceNonEmpty(t *testing.T) {
	m := guest.ProbeCapabilities()
	for _, f := range m.Features {
		if f.Evidence == "" {
			t.Errorf("feature %q: Evidence is empty", f.ID)
		}
	}
}

func TestProbeCapabilitiesNonLinuxAllFalse(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("linux-specific behavior tested separately")
	}
	m := guest.ProbeCapabilities()
	for _, f := range m.Features {
		if f.Present {
			t.Errorf("feature %q: want Present=false on %s, got true", f.ID, runtime.GOOS)
		}
		if f.Evidence != runtime.GOOS {
			t.Errorf("feature %q: want Evidence=%q, got %q", f.ID, runtime.GOOS, f.Evidence)
		}
	}
}

func TestProbeCapabilitiesLinuxHonest(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only")
	}
	m := guest.ProbeCapabilities()

	// Build an index for quick lookup.
	byID := make(map[string]bool)
	for _, f := range m.Features {
		byID[f.ID] = f.Present
	}

	// btf: /sys/kernel/btf/vmlinux exists iff Present=true.
	if p, ok := byID["btf"]; ok {
		_, err := os.Stat("/sys/kernel/btf/vmlinux")
		expect := (err == nil)
		if p != expect {
			t.Errorf("btf: Present=%v but stat says exists=%v", p, expect)
		}
	}

	// cgroup_v2: /sys/fs/cgroup/cgroup.controllers readable iff Present=true.
	if p, ok := byID["cgroup_v2"]; ok {
		f, err := os.Open("/sys/fs/cgroup/cgroup.controllers")
		if err == nil {
			f.Close()
		}
		expect := (err == nil)
		if p != expect {
			t.Errorf("cgroup_v2: Present=%v but check says exists=%v", p, expect)
		}
	}

	// vsock: /dev/vsock exists iff Present=true.
	if p, ok := byID["vsock"]; ok {
		_, err := os.Stat("/dev/vsock")
		expect := (err == nil)
		if p != expect {
			t.Errorf("vsock: Present=%v but stat says exists=%v", p, expect)
		}
	}
}
