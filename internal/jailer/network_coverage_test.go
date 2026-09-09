// ABOUTME: Tests conversion of authenticated runner network health into API coverage.
// ABOUTME: Missing boundaries and unrepresentable loss never become healthy claims.
package jailer

import (
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/netobserve"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

// validNetworkStatus is built by the runner's own status code, not written by
// hand: a change to what a healthy runner reports has to fail this package too.
func validNetworkStatus(now time.Time) runner.NetworkStatus {
	last := now.Add(-time.Second)
	bundle := &privd.NetworkObserverBundle{
		Binding: privd.NetworkObserverBinding{
			VMID: "00000000-0000-4000-8000-000000000001", GuestBootID: "00000000-0000-4000-8000-000000000002",
			HostBootID: "00000000-0000-4000-8000-000000000005", AcquisitionID: "00000000-0000-4000-8000-000000000004",
			GatewayGeneration: strings.Repeat("a", 32), PolicyDigest: strings.Repeat("b", 64),
			NamespaceDevice: "4", NamespaceInode: "4026532000", PolicyID: "transport-public-web", Profile: "transport",
		},
		Sockets: []privd.ObserverSocket{
			{Kind: "conntrack", Boundary: "namespace_gateway", PortID: 11, SnapshotSequence: 7},
			{Kind: "nflog", Boundary: "namespace_gateway", PortID: 12, Group: network.NamespaceNFLogGroup},
			{Kind: "nflog", Boundary: "host_veth", PortID: 13, Group: network.MinHostNFLogGroup},
		},
	}
	sourceIDs := []string{"00000000-0000-4000-8000-000000000011", "00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013"}
	base := runner.NewNetworkStatus(bundle.Binding.VMID, bundle.Binding.GuestBootID, "00000000-0000-4000-8000-000000000003", "network observer not acquired", now)
	status, err := runner.NetworkStatusAtAcquisition(base, bundle, sourceIDs, now)
	if err != nil {
		panic(err)
	}
	baselines := []netobserve.BaselineState{netobserve.BaselineReady, netobserve.BaselineNotApplicable, netobserve.BaselineNotApplicable}
	for i := range status.Collectors {
		status.Collectors[i], _ = runner.NetworkCollectorFromSource(status.Collectors[i], netobserve.SourceStatus{
			ID: sourceIDs[i], ReadState: netobserve.ReadHealthy, Baseline: baselines[i], LastSuccess: last,
		})
	}
	status.UpdatedAt = now
	return status
}

func TestNetworkCoverageMapsQuietHealthySourcesAndAggregatesDenialBoundaries(t *testing.T) {
	now := time.Now().UTC()
	status := validNetworkStatus(now)
	got, err := coverageFromNetworkStatus(status, &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != "flow" || got[1].ID != "denial" {
		t.Fatalf("collectors = %+v, want flow and one aggregated denial", got)
	}
	for _, collector := range got {
		if collector.State != situation.CoverageHealthy || collector.ObservedDropped == nil || *collector.ObservedDropped != "0" || collector.UnknownLossIntervals == nil || *collector.UnknownLossIntervals != 0 {
			t.Errorf("quiet collector = %+v, want fresh healthy liveness and known zero loss", collector)
		}
	}
	if !strings.Contains(strings.Join(got[1].Scope, " "), "host_veth") || !strings.Contains(strings.Join(got[1].Scope, " "), "namespace_gateway") {
		t.Fatalf("denial scope lost a boundary: %v", got[1].Scope)
	}
}

func TestNetworkCoveragePreservesLargeDropsAndRefusesUnsafeUnknownCount(t *testing.T) {
	now := time.Now().UTC()
	status := validNetworkStatus(now)
	status.Collectors[1].State = "degraded"
	status.Collectors[1].DroppedCount = "18446744073709551615"
	status.Collectors[2].DroppedCount = "18446744073709551615"
	status.Collectors[1].UnknownIntervals = "9223372036854775808"
	got, err := coverageFromNetworkStatus(status, &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID}, now)
	if err != nil {
		t.Fatal(err)
	}
	denial := got[1]
	if denial.ObservedDropped == nil || *denial.ObservedDropped != "36893488147419103230" {
		t.Fatalf("observed drops = %v, want exact sum beyond uint64", denial.ObservedDropped)
	}
	if denial.UnknownLossIntervals != nil || denial.State != situation.CoverageDegraded || !strings.Contains(denial.Reason, "cannot be represented") {
		t.Fatalf("unknown intervals = %+v, want unknown degraded result", denial)
	}
	_ = math.MaxInt // pins this test's overflow intent on 32- and 64-bit hosts.
}

func TestNetworkCoverageRejectsMissingBoundaryInvalidCountsAndStaleTime(t *testing.T) {
	now := time.Now().UTC()
	for name, change := range map[string]func(*runner.NetworkStatus){
		"missing boundary": func(s *runner.NetworkStatus) { s.Collectors = s.Collectors[:2] },
		"invalid count":    func(s *runner.NetworkStatus) { s.Collectors[0].DroppedCount = "01" },
		"stale":            func(s *runner.NetworkStatus) { s.UpdatedAt = now.Add(-10 * time.Second) },
		"future":           func(s *runner.NetworkStatus) { s.UpdatedAt = now.Add(10 * time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			status := validNetworkStatus(now)
			change(&status)
			if _, err := coverageFromNetworkStatus(status, &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID}, now); err == nil {
				t.Fatal("invalid runner status was accepted")
			}
		})
	}
}

func TestNetworkCoverageOneFailedDenialBoundaryCannotAggregateHealthy(t *testing.T) {
	now := time.Now().UTC()
	status := validNetworkStatus(now)
	status.Collectors[2].State = "unavailable"
	status.Collectors[2].Reason = "NFLOG socket failed"
	got, err := coverageFromNetworkStatus(status, &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID}, now)
	if err != nil {
		t.Fatal(err)
	}
	if denial := got[1]; denial.State != situation.CoverageUnavailable || !strings.Contains(denial.Reason, "host_veth") {
		t.Fatalf("denial = %+v, want failed boundary named", denial)
	}
}

// An aggregate is only as live as its weakest boundary: a source that has never
// succeeded leaves the pair with no common success time to report.
func TestNetworkCoverageAggregateWithoutCommonSuccessReportsNone(t *testing.T) {
	now := time.Now().UTC()
	status := validNetworkStatus(now)
	status.Collectors[2].LastSuccessAt = nil
	status.Collectors[2].State = "starting"
	status.Collectors[2].Reason = "awaiting reader readiness"
	got, err := coverageFromNetworkStatus(status, &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID}, now)
	if err != nil {
		t.Fatal(err)
	}
	if denial := got[1]; denial.LastSuccessAt != "" {
		t.Fatalf("denial last_success_at = %q; the host_veth boundary never succeeded", denial.LastSuccessAt)
	}
}

// A JSON number cannot carry a count above 2^53-1 exactly, whatever the host word size.
func TestNetworkCoverageRefusesUnknownCountBeyondJSONSafeInteger(t *testing.T) {
	now := time.Now().UTC()
	status := validNetworkStatus(now)
	status.Collectors[1].State = "degraded"
	status.Collectors[1].Reason = "capture loss in this acquisition"
	status.Collectors[1].UnknownIntervals = "9007199254740992"
	got, err := coverageFromNetworkStatus(status, &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID}, now)
	if err != nil {
		t.Fatal(err)
	}
	if denial := got[1]; denial.UnknownLossIntervals != nil || !strings.Contains(denial.Reason, "cannot be represented") {
		t.Fatalf("unknown intervals = %+v, want a refusal above the JSON safe integer", denial)
	}
}

// Correlation limits reach the API as limitations, never as loss and never silently.
func TestNetworkCoverageDeclaresUntrackedAndUnsupportedCountsAsLimitations(t *testing.T) {
	now := time.Now().UTC()
	status := validNetworkStatus(now)
	status.Collectors[0].UntrackedFlowIdentities = "4"
	status.Collectors[0].UnsupportedFamilyMessages = "7"
	got, err := coverageFromNetworkStatus(status, &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID}, now)
	if err != nil {
		t.Fatal(err)
	}
	flow := got[0]
	limits := strings.Join(flow.Limitations, " | ")
	if flow.State != situation.CoverageHealthy || *flow.ObservedDropped != "0" || *flow.UnknownLossIntervals != 0 {
		t.Fatalf("flow = %+v, want healthy: correlation limits are not loss", flow)
	}
	if !strings.Contains(limits, "could not correlate 4 observed flows") || !strings.Contains(limits, "skipped 7 kernel messages") {
		t.Fatalf("limitations = %q, want both correlation limits named with their counts", limits)
	}
}

func TestNetworkCoverageRejectsInvalidLimitationCounts(t *testing.T) {
	now := time.Now().UTC()
	for name, change := range map[string]func(*runner.NetworkStatus){
		"untracked":   func(s *runner.NetworkStatus) { s.Collectors[0].UntrackedFlowIdentities = "-1" },
		"unsupported": func(s *runner.NetworkStatus) { s.Collectors[0].UnsupportedFamilyMessages = "01" },
	} {
		t.Run(name, func(t *testing.T) {
			status := validNetworkStatus(now)
			change(&status)
			if _, err := coverageFromNetworkStatus(status, &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID}, now); err == nil {
				t.Fatal("an invalid limitation count was accepted")
			}
		})
	}
}

// neverAcquiredStatus is the shape a runner publishes when privd refused its
// acquisition or adoption failed, built by the runner's own constructor: no
// acquisition identity at all, every collector unavailable with the reason.
func neverAcquiredStatus(now time.Time) runner.NetworkStatus {
	return runner.NewNetworkStatus("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002",
		"00000000-0000-4000-8000-000000000003", "network observer acquisition refused: privd said no", now)
}

// A runner that never acquired observers has no policy to name. Refusing its
// status at the profile check told the operator a policy mismatch that does not
// exist; the runner's own reason is the only honest answer.
func TestNetworkCoverageCarriesNeverAcquiredRunnerReason(t *testing.T) {
	now := time.Now().UTC()
	status := neverAcquiredStatus(now)
	vm := &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: "transport", NetworkPolicyID: "transport-public-web"}
	got, err := coverageFromNetworkStatus(status, vm, now)
	if err != nil {
		t.Fatalf("never-acquired runner status refused: %v", err)
	}
	if len(got) != 2 || got[0].ID != "flow" || got[1].ID != "denial" {
		t.Fatalf("collectors = %+v, want flow and one aggregated denial", got)
	}
	// The reason is the collectors' own words under the boundary join, nothing
	// added: zero counters name no loss, and there is no acquisition to describe.
	wantReason := map[string]string{
		"flow":   "namespace_gateway: network observer acquisition refused: privd said no",
		"denial": "namespace_gateway: network observer acquisition refused: privd said no; host_veth: network observer acquisition refused: privd said no",
	}
	for _, collector := range got {
		if collector.State != situation.CoverageUnavailable || collector.Reason != wantReason[collector.ID] {
			t.Errorf("%s = %+v, want unavailable with reason %q", collector.ID, collector, wantReason[collector.ID])
		}
		for _, scope := range collector.Scope {
			if !strings.HasPrefix(scope, "boundary=") {
				t.Errorf("%s scope %q names identity the runner never acquired", collector.ID, scope)
			}
		}
		if !slices.Contains(collector.Limitations, "no observer acquisition binds this status; traffic so far in this boot is unobserved") {
			t.Errorf("%s limitations = %q, want the unobserved traffic declared", collector.ID, collector.Limitations)
		}
	}
}

// Under an empty acquisition only the never-acquired shape is honest: a runner
// with no observers cannot have read, counted or identified anything. Status
// identity is refused for a second reason: with no acquisition to compare
// against, a profile named here never reaches the policy check that would
// otherwise catch a runner bound to another VM's policy.
func TestNetworkCoverageRefusesObservationWithoutAcquisition(t *testing.T) {
	now := time.Now().UTC()
	last := now.Add(-time.Second)
	for name, tc := range map[string]struct {
		change func(*runner.NetworkStatus)
		want   string
	}{
		"healthy collector": {func(s *runner.NetworkStatus) { s.Collectors[0].State = "healthy" }, "without an acquisition"},
		"source instance": {func(s *runner.NetworkStatus) {
			s.Collectors[1].SourceInstanceID = "00000000-0000-4000-8000-000000000012"
		}, "without an acquisition"},
		"non-zero counter": {func(s *runner.NetworkStatus) { s.Collectors[2].DroppedCount = "1" }, "without an acquisition"},
		"last success":     {func(s *runner.NetworkStatus) { s.Collectors[0].LastSuccessAt = &last }, "without an acquisition"},
		"status identity":  {func(s *runner.NetworkStatus) { s.Profile = "http_inspect" }, "without an acquisition"},
		"stale":            {func(s *runner.NetworkStatus) { s.UpdatedAt = now.Add(-10 * time.Second) }, "stale"},
	} {
		t.Run(name, func(t *testing.T) {
			status := neverAcquiredStatus(now)
			tc.change(&status)
			vm := &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: "transport", NetworkPolicyID: "transport-public-web"}
			_, err := coverageFromNetworkStatus(status, vm, now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want a refusal naming %q", err, tc.want)
			}
		})
	}
}

// Loss is named whatever state the aggregate lands in. A source still awaiting
// its baseline, or one that stopped, keeps the drops it measured; the reason
// has to say so rather than leave them to the counter alone.
func TestNetworkCoverageNamesObservedLossInEveryState(t *testing.T) {
	now := time.Now().UTC()
	last := now.Add(-time.Second)
	for name, tc := range map[string]struct {
		source    netobserve.SourceStatus
		wantState string
		wantWords string
	}{
		"starting": {
			netobserve.SourceStatus{ReadState: netobserve.ReadHealthy, Baseline: netobserve.BaselinePending, LastSuccess: last, QueueDrops: 37},
			situation.CoverageStarting, "awaiting conntrack baseline",
		},
		"stopped": {
			netobserve.SourceStatus{ReadState: netobserve.ReadStopped, Baseline: netobserve.BaselineReady, LastSuccess: last, QueueDrops: 4},
			situation.CoverageUnavailable, "runner stopped",
		},
	} {
		t.Run(name, func(t *testing.T) {
			status := validNetworkStatus(now)
			tc.source.ID = status.Collectors[0].SourceInstanceID
			status.Collectors[0], _ = runner.NetworkCollectorFromSource(status.Collectors[0], tc.source)
			got, err := coverageFromNetworkStatus(status, &store.VM{VMID: status.VMID, CurrentBootID: status.BootID, NetworkProfile: status.Profile, NetworkPolicyID: status.PolicyID}, now)
			if err != nil {
				t.Fatal(err)
			}
			flow := got[0]
			if flow.State != tc.wantState || !strings.Contains(flow.Reason, tc.wantWords) {
				t.Fatalf("flow = %+v, want %s with the source's own reason", flow, tc.wantState)
			}
			if *flow.ObservedDropped == "0" || !strings.Contains(flow.Reason, "observed loss") {
				t.Fatalf("flow = %+v, want the measured drops named in the reason", flow)
			}
		})
	}
}
