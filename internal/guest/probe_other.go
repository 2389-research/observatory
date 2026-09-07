// ABOUTME: Non-linux capability probe stub: all features absent, Evidence is GOOS.
// ABOUTME: Real probes live in probe_linux.go and require kernel syscalls.
//go:build !linux

package guest

import (
	"runtime"

	"github.com/2389-research/observatory/internal/guest/proto"
)

// allFeatureIDs lists every capability this system knows how to probe on linux.
var allFeatureIDs = []string{
	"btf",
	"bpf_syscall",
	"fanotify",
	"fanotify_report_fid",
	"cgroup_v2",
	"devpts",
	"ext4",
	"vsock",
	"virtio_net",
	"virtio_blk",
}

func probeCapabilities() proto.CapabilityManifest {
	goos := runtime.GOOS
	features := make([]proto.Feature, len(allFeatureIDs))
	for i, id := range allFeatureIDs {
		features[i] = proto.Feature{
			ID:       id,
			Present:  false,
			Evidence: goos,
		}
	}
	return proto.CapabilityManifest{
		Schema:        capabilitySchema,
		KernelRelease: goos,
		Features:      features,
	}
}
