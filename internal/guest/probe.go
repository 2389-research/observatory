// ABOUTME: ProbeCapabilities: returns a CapabilityManifest describing this guest's kernel features.
// ABOUTME: Portable interface; platform-specific probes are in probe_linux.go / probe_other.go.
package guest

import (
	"github.com/2389-research/observatory-v2/internal/guest/proto"
)

// capabilitySchema is the fixed schema identifier for the manifest.
const capabilitySchema = "vmobs.guest_capability.v1"

// ProbeCapabilities probes for guest kernel capabilities and returns a
// CapabilityManifest. Each Feature carries honest Present/Evidence values;
// no feature panics on error — errno strings are used as Evidence when Present=false.
func ProbeCapabilities() proto.CapabilityManifest {
	return probeCapabilities()
}
