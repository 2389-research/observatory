// ABOUTME: Validates runner network health and maps it into VM coverage records.
// ABOUTME: Aggregates denial boundaries without hiding loss, scope, or failed sources.
package jailer

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/runner"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

const (
	networkStatusMaxAge     = 3 * time.Second
	networkStatusFutureSkew = 2 * time.Second
)

type networkSourceKey struct{ id, boundary string }

var expectedNetworkSources = []networkSourceKey{
	{id: "flow", boundary: "namespace_gateway"},
	{id: "denial", boundary: "namespace_gateway"},
	{id: "denial", boundary: "host_veth"},
}

func coverageFromNetworkStatus(status runner.NetworkStatus, vm *store.VM, now time.Time) ([]situation.CollectorCoverage, error) {
	if status.VMID != vm.VMID || status.BootID != vm.CurrentBootID {
		return nil, fmt.Errorf("runner network status names another VM or boot")
	}
	if !events.UUIDString(status.InstanceID) {
		return nil, fmt.Errorf("runner network status has an invalid runner instance identity")
	}
	// A runner privd refused, or whose inherited descriptors failed adoption,
	// owns no acquisition: it has no profile, policy or namespace to check and
	// only its own reason to report. Refusing it at the policy check told the
	// operator a mismatch that does not exist.
	acquired := status.AcquisitionID != ""
	if !acquired && !neverAcquiredShape(status) {
		return nil, fmt.Errorf("runner reports observation without an acquisition")
	}
	if acquired {
		if status.Profile != vm.NetworkProfile || status.PolicyID != vm.NetworkPolicyID {
			return nil, fmt.Errorf("runner network status names another network policy")
		}
		if !events.UUIDString(status.AcquisitionID) || !events.UUIDString(status.HostBootID) ||
			!canonicalHex(status.GatewayGeneration, 32) || !canonicalHex(status.PolicyDigest, 64) ||
			!positiveDecimal(status.NamespaceDevice) || !positiveDecimal(status.NamespaceInode) {
			return nil, fmt.Errorf("runner network status has invalid immutable source identity")
		}
	}
	if status.UpdatedAt.IsZero() || now.Sub(status.UpdatedAt) > networkStatusMaxAge || status.UpdatedAt.Sub(now) > networkStatusFutureSkew {
		return nil, fmt.Errorf("runner network status timestamp is stale or in the future")
	}

	sources := make(map[networkSourceKey]runner.NetworkCollectorStatus, len(status.Collectors))
	seenInstances := make(map[string]bool, len(status.Collectors))
	for _, source := range status.Collectors {
		key := networkSourceKey{id: source.ID, boundary: source.Boundary}
		if !expectedNetworkSource(key) || sources[key].ID != "" || (acquired && (!events.UUIDString(source.SourceInstanceID) || seenInstances[source.SourceInstanceID])) {
			return nil, fmt.Errorf("runner network status has an unexpected or duplicate source")
		}
		if !runnerNetworkState(source.State) || !decimal(source.DroppedCount) || !decimal(source.UnknownIntervals) || !decimal(source.ForgottenEntries) ||
			!decimal(source.UntrackedFlowIdentities) || !decimal(source.UnsupportedFamilyMessages) {
			return nil, fmt.Errorf("runner network source %s/%s has invalid health", source.ID, source.Boundary)
		}
		if !validSourceTime(source.LastEventAt, status.UpdatedAt) || !validSourceTime(source.LastSuccessAt, status.UpdatedAt) {
			return nil, fmt.Errorf("runner network source %s/%s has an invalid timestamp", source.ID, source.Boundary)
		}
		sources[key], seenInstances[source.SourceInstanceID] = source, true
	}
	if len(sources) != len(expectedNetworkSources) {
		return nil, fmt.Errorf("runner network status is missing a required source")
	}

	flow, err := aggregateNetworkCoverage(status, vm, []runner.NetworkCollectorStatus{sources[expectedNetworkSources[0]]})
	if err != nil {
		return nil, err
	}
	denial, err := aggregateNetworkCoverage(status, vm, []runner.NetworkCollectorStatus{sources[expectedNetworkSources[1]], sources[expectedNetworkSources[2]]})
	if err != nil {
		return nil, err
	}
	return []situation.CollectorCoverage{flow, denial}, nil
}

func aggregateNetworkCoverage(status runner.NetworkStatus, vm *store.VM, sources []runner.NetworkCollectorStatus) (situation.CollectorCoverage, error) {
	id := sources[0].ID
	out := situation.CollectorCoverage{
		ID: id, VMID: vm.VMID, BootID: vm.CurrentBootID, State: situation.CoverageHealthy, Enabled: true,
		EventClasses: []string{"net.flow.observed"}, Exclusions: []string{}, Limitations: []string{},
		CaptureMode: "conntrack", Source: "host", Provenance: string(events.HostObserved),
	}
	if id == "denial" {
		out.EventClasses, out.CaptureMode = []string{"policy.denial"}, "nflog"
	}
	// Scope names only what the runner acquired: without an acquisition there
	// is no namespace, generation or policy to claim, only the boundaries.
	baseScope := []string{}
	if status.AcquisitionID != "" {
		baseScope = []string{
			"profile=" + status.Profile,
			"network_namespace=" + status.NamespaceDevice + ":" + status.NamespaceInode,
			"acquisition_id=" + status.AcquisitionID,
			"gateway_generation=" + status.GatewayGeneration,
			"host_boot_id=" + status.HostBootID,
			"policy_id=" + status.PolicyID,
			"policy_digest=" + status.PolicyDigest,
		}
	} else {
		// A runner publishes this same shape in the window between its first
		// status and a successful acquisition, so the limitation states only what
		// is true when it is published: unobserved up to now, not for the boot.
		// The collector reason is what separates a startup window from a refusal.
		out.Limitations = append(out.Limitations, "no observer acquisition binds this status; traffic so far in this boot is unobserved")
	}
	dropped, unknown := new(big.Int), new(big.Int)
	var reasons []string
	// An aggregate is only as live as its weakest boundary. A source that has
	// never succeeded leaves the pair with no common success time to report.
	successKnown := true
	for _, source := range sources {
		out.Scope = append(out.Scope, "boundary="+source.Boundary)
		out.Limitations = appendUnique(out.Limitations, source.ScopeLimitations...)
		addDecimal(dropped, source.DroppedCount)
		addDecimal(unknown, source.UnknownIntervals)
		out.LastEventAt = laterTimestamp(out.LastEventAt, source.LastEventAt)
		if source.LastSuccessAt == nil {
			successKnown = false
		} else {
			out.LastSuccessAt = earlierTimestamp(out.LastSuccessAt, *source.LastSuccessAt)
		}
		if severity(source.State) > severity(out.State) {
			out.State = source.State
		}
		if source.State != situation.CoverageHealthy || source.Reason != "" {
			reasons = append(reasons, source.Boundary+": "+source.Reason)
		}
		if source.ForgottenEntries != "0" {
			out.Limitations = appendUnique(out.Limitations, source.Boundary+" tracker forgot "+source.ForgottenEntries+" completed entries; this is not packet loss")
		}
		if source.UntrackedFlowIdentities != "0" {
			out.Limitations = appendUnique(out.Limitations, source.Boundary+" could not correlate "+source.UntrackedFlowIdentities+" observed flows by identity; this is not packet loss")
		}
		if source.UnsupportedFamilyMessages != "0" {
			out.Limitations = appendUnique(out.Limitations, source.Boundary+" skipped "+source.UnsupportedFamilyMessages+" kernel messages outside the declared IPv4 scope")
		}
	}
	if !successKnown {
		out.LastSuccessAt = ""
	}
	out.Scope = append(baseScope, out.Scope...)
	dropString := dropped.String()
	out.ObservedDropped = &dropString
	if unknown.IsInt64() && unknown.Int64() >= 0 && unknown.Int64() <= situation.MaxSafeCoverageCount && uint64(unknown.Int64()) <= uint64(^uint(0)>>1) {
		value := int(unknown.Int64())
		out.UnknownLossIntervals = &value
	} else {
		out.State = situation.CoverageDegraded
		reasons = append(reasons, "unknown loss interval count cannot be represented by the coverage API")
	}
	// Measured loss is named whatever state the aggregate is in: a source still
	// awaiting its baseline, or one that stopped, keeps the drops it measured,
	// and a reader skimming state and reason must not miss them.
	if dropped.Sign() != 0 || unknown.Sign() != 0 {
		if out.State == situation.CoverageHealthy {
			out.State = situation.CoverageDegraded
		}
		reasons = append(reasons, "capture source reports observed loss")
	}
	out.Reason = strings.Join(reasons, "; ")
	return out, nil
}

// neverAcquiredShape reports whether status is exactly what a runner without an
// acquisition can honestly publish: no acquisition identity, and every collector
// unavailable with no source, no counts and no timestamps. A runner that owns no
// observers cannot have read, counted or identified anything.
func neverAcquiredShape(status runner.NetworkStatus) bool {
	if status.Profile != "" || status.PolicyID != "" || status.PolicyDigest != "" || status.HostBootID != "" ||
		status.GatewayGeneration != "" || status.NamespaceDevice != "" || status.NamespaceInode != "" {
		return false
	}
	for _, source := range status.Collectors {
		if source.State != situation.CoverageUnavailable || source.SourceInstanceID != "" || source.LastEventAt != nil || source.LastSuccessAt != nil ||
			source.DroppedCount != "0" || source.UnknownIntervals != "0" || source.NFLogUnknownIntervals != "0" || source.ForgottenEntries != "0" ||
			source.UntrackedFlowIdentities != "0" || source.UnsupportedFamilyMessages != "0" {
			return false
		}
	}
	return true
}

func expectedNetworkSource(key networkSourceKey) bool {
	for _, expected := range expectedNetworkSources {
		if key == expected {
			return true
		}
	}
	return false
}

func runnerNetworkState(state string) bool {
	return state == situation.CoverageUnavailable || state == situation.CoverageStarting || state == situation.CoverageHealthy || state == situation.CoverageDegraded
}

func severity(state string) int {
	switch state {
	case situation.CoverageUnavailable:
		return 3
	case situation.CoverageDegraded:
		return 2
	case situation.CoverageStarting:
		return 1
	default:
		return 0
	}
}

func decimal(value string) bool { return events.DecimalString(value) }

func positiveDecimal(value string) bool {
	if !decimal(value) || value == "0" {
		return false
	}
	_, ok := new(big.Int).SetString(value, 10)
	return ok
}

func addDecimal(sum *big.Int, value string) {
	v, _ := new(big.Int).SetString(value, 10)
	sum.Add(sum, v)
}

func canonicalHex(value string, chars int) bool {
	if len(value) != chars || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validSourceTime(value *time.Time, updatedAt time.Time) bool {
	return value == nil || (!value.IsZero() && !value.After(updatedAt.Add(networkStatusFutureSkew)))
}

func laterTimestamp(current string, candidate *time.Time) string {
	if candidate == nil {
		return current
	}
	formatted := candidate.UTC().Format(events.TimestampLayout)
	if current == "" || formatted > current {
		return formatted
	}
	return current
}

func earlierTimestamp(current string, candidate time.Time) string {
	formatted := candidate.UTC().Format(events.TimestampLayout)
	if current == "" || formatted < current {
		return formatted
	}
	return current
}

// appendUnique keeps an aggregate's declared limits bounded: two boundaries that
// share a limitation state it once.
func appendUnique(out []string, values ...string) []string {
	for _, value := range values {
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}
