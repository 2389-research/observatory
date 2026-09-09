// ABOUTME: Exposes immutable live health for each host network acquisition boundary.
// ABOUTME: Keeps persistence failures visible even when the spool cannot record them.
package runner

import (
	"fmt"
	"strconv"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/netobserve"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/privd"
)

// MaxNetworkReasonBytes bounds every reason string a collector publishes, on the
// live status, in the durable record and in the coverage API.
const MaxNetworkReasonBytes = 256

type NetworkStatus struct {
	VMID              string                   `json:"vm_id"`
	BootID            string                   `json:"boot_id"`
	InstanceID        string                   `json:"instance_id"`
	AcquisitionID     string                   `json:"acquisition_id"`
	GatewayGeneration string                   `json:"gateway_generation"`
	HostBootID        string                   `json:"host_boot_id"`
	NamespaceDevice   string                   `json:"namespace_device"`
	NamespaceInode    string                   `json:"namespace_inode"`
	PolicyID          string                   `json:"policy_id"`
	PolicyDigest      string                   `json:"policy_digest"`
	Profile           string                   `json:"profile"`
	UpdatedAt         time.Time                `json:"updated_at"`
	Collectors        []NetworkCollectorStatus `json:"collectors"`
}

type NetworkCollectorStatus struct {
	ID               string     `json:"id"`
	SourceInstanceID string     `json:"source_instance_id"`
	Boundary         string     `json:"boundary"`
	State            string     `json:"state"`
	Reason           string     `json:"reason"`
	LastEventAt      *time.Time `json:"last_event_at,omitempty"`
	LastSuccessAt    *time.Time `json:"last_success_at,omitempty"`
	// DroppedCount counts measured queued observations and missing NFLOG records, not packets.
	DroppedCount string `json:"dropped_count"`
	// UnknownIntervals counts measured intervals of unknown size only: an
	// interrupted kernel dump, a read failure or an NFLOG sequence discontinuity.
	// The interval before acquisition is declared in ScopeLimitations instead.
	UnknownIntervals      string `json:"unknown_intervals"`
	NFLogUnknownIntervals string `json:"nflog_unknown_intervals"`
	ForgottenEntries      string `json:"forgotten_entries"`
	// UntrackedFlowIdentities counts flows observed but not correlatable, and
	// UnsupportedFamilyMessages counts kernel messages outside the declared IPv4
	// scope. Both bound what correlation can claim; neither is loss.
	UntrackedFlowIdentities   string   `json:"untracked_flow_identities"`
	UnsupportedFamilyMessages string   `json:"unsupported_family_messages"`
	ScopeLimitations          []string `json:"scope_limitations"`
}

// networkCollectorPlan declares the boundaries every runner reports, in the
// socket order privd guarantees for an acquisition.
var networkCollectorPlan = []struct{ ID, Boundary, Kind string }{
	{ID: "flow", Boundary: "namespace_gateway", Kind: string(netobserve.SourceConntrack)},
	{ID: "denial", Boundary: "namespace_gateway", Kind: string(netobserve.SourceNFLog)},
	{ID: "denial", Boundary: "host_veth", Kind: string(netobserve.SourceNFLog)},
}

// networkScopeLimitations states what a boundary can never observe. These hold
// for every acquisition; the observation start is added per acquisition.
func networkScopeLimitations(id, boundary string) []string {
	out := []string{"IPv4 conntrack only; no exact process or flow lifetime attribution; no HTTP request evidence"}
	if id == "denial" {
		out = []string{
			"NFLOG records are rate limited to 10/second with burst 20; not aggregate firewall counters",
			"Tuple fields may be absent for unsupported packet scope",
		}
	}
	if boundary == "host_veth" {
		out = append(out, "Namespace identity names the owned VM gateway; this socket observes the host veth boundary")
	}
	return out
}

// NetworkDenialPrefixes returns the NFLOG prefixes a source may accept. They are
// the strings the installed gateway policy writes, so a record with any other
// prefix is evidence the reader is bound to the wrong rules.
func NetworkDenialPrefixes(kind, boundary string) []string {
	if kind != string(netobserve.SourceNFLog) {
		return nil
	}
	if boundary == "host_veth" {
		return []string{network.HostDenialPrefix}
	}
	return []string{network.NamespaceDenialPrefix, network.NamespaceIngressDenialPrefix}
}

// BoundNetworkReason keeps every published reason within MaxNetworkReasonBytes.
func BoundNetworkReason(reason string) string {
	return events.BoundString(reason, MaxNetworkReasonBytes)
}

// NewNetworkStatus returns the health a runner publishes before it owns any
// observer: one declared collector per boundary, none of them observing.
func NewNetworkStatus(vmID, bootID, instanceID, reason string, at time.Time) NetworkStatus {
	out := NetworkStatus{VMID: vmID, BootID: bootID, InstanceID: instanceID, UpdatedAt: at.UTC()}
	for _, declared := range networkCollectorPlan {
		out.Collectors = append(out.Collectors, NetworkCollectorStatus{
			ID: declared.ID, Boundary: declared.Boundary, State: "unavailable", Reason: BoundNetworkReason(reason),
			DroppedCount: "0", UnknownIntervals: "0", NFLogUnknownIntervals: "0", ForgottenEntries: "0",
			UntrackedFlowIdentities: "0", UnsupportedFamilyMessages: "0",
			ScopeLimitations: networkScopeLimitations(declared.ID, declared.Boundary),
		})
	}
	return out
}

// NetworkStatusAtAcquisition returns the health a runner publishes the moment it
// owns the acquired sockets. Acquisition starts observation; it does not measure
// the traffic that came before, so each collector declares its start instead of
// counting an unknown interval it never observed.
func NetworkStatusAtAcquisition(base NetworkStatus, bundle *privd.NetworkObserverBundle, sourceIDs []string, at time.Time) (NetworkStatus, error) {
	if bundle == nil || len(bundle.Sockets) != len(networkCollectorPlan) || len(sourceIDs) != len(networkCollectorPlan) || len(base.Collectors) != len(networkCollectorPlan) {
		return NetworkStatus{}, fmt.Errorf("acquisition does not carry one socket per declared network boundary")
	}
	out := base
	out.Collectors = make([]NetworkCollectorStatus, 0, len(networkCollectorPlan))
	b := bundle.Binding
	out.AcquisitionID, out.GatewayGeneration, out.HostBootID = b.AcquisitionID, b.GatewayGeneration, b.HostBootID
	out.NamespaceDevice, out.NamespaceInode = b.NamespaceDevice, b.NamespaceInode
	out.PolicyID, out.PolicyDigest, out.Profile = b.PolicyID, b.PolicyDigest, b.Profile
	out.UpdatedAt = at.UTC()
	started := "observation began at " + at.UTC().Format(events.TimestampLayout) + "; earlier traffic unobserved"
	for i, declared := range networkCollectorPlan {
		socket := bundle.Sockets[i]
		if socket.Kind != declared.Kind || socket.Boundary != declared.Boundary {
			return NetworkStatus{}, fmt.Errorf("acquisition socket %d is %s/%s, not the declared %s/%s", i, socket.Kind, socket.Boundary, declared.Kind, declared.Boundary)
		}
		out.Collectors = append(out.Collectors, NetworkCollectorStatus{
			ID: declared.ID, Boundary: declared.Boundary, SourceInstanceID: sourceIDs[i],
			State: "starting", Reason: "awaiting reader readiness",
			DroppedCount: "0", UnknownIntervals: "0", NFLogUnknownIntervals: "0", ForgottenEntries: "0",
			UntrackedFlowIdentities: "0", UnsupportedFamilyMessages: "0",
			ScopeLimitations: append(networkScopeLimitations(declared.ID, declared.Boundary), started),
		})
	}
	return out, nil
}

// NetworkCollectorFromSource maps one live reader source onto its collector.
// The bool reports that this acquisition can no longer observe and must be
// re-established. Counts carry only what the reader measured.
func NetworkCollectorFromSource(collector NetworkCollectorStatus, source netobserve.SourceStatus) (NetworkCollectorStatus, bool) {
	out := collector
	out.DroppedCount = networkCountSum(source.QueueDrops, source.NFLogSequenceDrops)
	out.UnknownIntervals = networkCountSum(source.KernelUnknownIntervals, source.NFLogUnknownIntervals)
	out.NFLogUnknownIntervals = strconv.FormatUint(source.NFLogUnknownIntervals, 10)
	out.ForgottenEntries = strconv.FormatUint(source.TrackerEntriesForgotten, 10)
	out.UntrackedFlowIdentities = strconv.FormatUint(source.FlowIdentityUntracked, 10)
	out.UnsupportedFamilyMessages = strconv.FormatUint(source.UnsupportedFamilyMessages, 10)
	if !source.LastSuccess.IsZero() {
		v := source.LastSuccess
		out.LastSuccessAt = &v
	}
	failed := false
	switch {
	case source.ReadState == netobserve.ReadStopped:
		out.State, out.Reason, failed = "unavailable", "runner stopped", true
	case source.ReadState == netobserve.ReadFailed || source.Baseline == netobserve.BaselineFailed:
		out.State, out.Reason, failed = "degraded", BoundNetworkReason(source.LastError), true
		if out.Reason == "" {
			out.Reason = "reader failed without a recorded error"
		}
	case source.ReadState == netobserve.ReadHealthy && (source.Baseline == netobserve.BaselineReady || source.Baseline == netobserve.BaselineNotApplicable):
		out.State, out.Reason = "healthy", "reader ready"
		// Measured loss is the only thing that downgrades a reader that is
		// otherwise reading. A stopped or failed reader already names what
		// happened, and its counters stay published either way.
		if source.QueueDrops > 0 || source.NFLogSequenceDrops > 0 || source.KernelUnknownIntervals > 0 || source.NFLogUnknownIntervals > 0 {
			out.State, out.Reason = "degraded", "capture loss in this acquisition"
		}
	default:
		out.State, out.Reason = "starting", "awaiting conntrack baseline or reader readiness"
	}
	return out, failed
}

func (r *runner) initNetworkStatus() {
	r.networkMu.Lock()
	defer r.networkMu.Unlock()
	r.network = NewNetworkStatus(r.cfg.VMID, r.cfg.BootID, r.cfg.InstanceID, "network observer not acquired", time.Now())
}

func (r *runner) networkStatus() NetworkStatus {
	r.networkMu.RLock()
	defer r.networkMu.RUnlock()
	out := r.network
	out.Collectors = append([]NetworkCollectorStatus(nil), out.Collectors...)
	for i := range out.Collectors {
		c := &out.Collectors[i]
		c.ScopeLimitations = append([]string(nil), c.ScopeLimitations...)
		if c.LastEventAt != nil {
			v := *c.LastEventAt
			c.LastEventAt = &v
		}
		if c.LastSuccessAt != nil {
			v := *c.LastSuccessAt
			c.LastSuccessAt = &v
		}
	}
	return out
}

func (r *runner) networkUnavailable(reason string) {
	reason = BoundNetworkReason(reason)
	r.networkMu.Lock()
	r.network.UpdatedAt = time.Now().UTC()
	for i := range r.network.Collectors {
		r.network.Collectors[i].State = "unavailable"
		r.network.Collectors[i].Reason = reason
	}
	r.networkMu.Unlock()
	if r.sw == nil {
		return
	}
	status := r.networkStatus()
	// One record per collector, the same shape a live reader publishes. A missing
	// acquisition has no reader source, so the runner owns these sequences.
	for _, c := range status.Collectors {
		if err := r.sw.Append(r.newEnvelope("net.collector.health", networkHealthData(status, c))); err != nil {
			r.networkMu.Lock()
			r.networkSpoolError = true
			r.networkMu.Unlock()
			return
		}
	}
}
