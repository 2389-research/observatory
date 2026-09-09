// ABOUTME: Exercises live network status and lossless host observation normalization.
// ABOUTME: Uses the production spool and control socket for durable and live evidence.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/netobserve"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/spool"
	"github.com/2389-research/observatory/internal/store"
)

func TestNetworkHealthKinds(t *testing.T) {
	for _, kind := range []string{"net.collector.health", "net.collector.loss"} {
		if info, ok := events.LookupKind(kind); !ok || info.Provenance != events.HostObserved {
			t.Fatalf("missing host kind %s", kind)
		}
	}
}

// net.collector.loss carries two payload shapes: a cumulative status snapshot and
// a single observation's loss classes. count_semantics tells them apart, so the
// registry has to name both shapes and the discriminator - otherwise a consumer
// has to learn the union by reading the two emit sites.
func TestNetworkLossKindDocumentsBothPayloadShapes(t *testing.T) {
	info, ok := events.LookupKind("net.collector.loss")
	if !ok {
		t.Fatal("net.collector.loss is not registered")
	}
	documented := info.Semantics + " " + strings.Join(info.Caveats, " ")
	for _, want := range []string{"count_semantics", "cumulative_for_source_acquisition", "single_observation"} {
		if !strings.Contains(documented, want) {
			t.Fatalf("registry does not name %q for net.collector.loss: %q", want, documented)
		}
	}
}

func TestNetworkNormalizationUint64(t *testing.T) {
	n := uint64(math.MaxUint64)
	data := networkFlowData(netobserve.FlowObservation{Flow: netobserve.Flow{Event: "snapshot", StartNanoseconds: &n, OriginalCounters: netobserve.Counters{Bytes: &n}}})
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"18446744073709551615"`) {
		t.Fatalf("precision lost: %s", raw)
	}
	if data["start_observed"] != false || data["policy_outcome"] != "unknown" {
		t.Fatalf("invented evidence: %v", data)
	}
}
func TestNetworkStatusUnavailableAndImmutable(t *testing.T) {
	r := &runner{cfg: Config{VMID: "vm", BootID: "boot", InstanceID: "runner"}}
	r.initNetworkStatus()
	a := r.networkStatus()
	if len(a.Collectors) != 3 || a.Collectors[0].State != "unavailable" {
		t.Fatalf("status: %+v", a)
	}
	a.Collectors[0].ScopeLimitations[0] = "changed"
	a.Collectors[0].State = "healthy"
	if b := r.networkStatus(); b.Collectors[0].State != "unavailable" || b.Collectors[0].ScopeLimitations[0] == "changed" {
		t.Fatal("mutable snapshot")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	dir, err := os.MkdirTemp("/tmp", "nw-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "ctl")
	srv, err := ListenCtl(ctx, sock, CtlHandlers{NetworkStatus: r.networkStatus})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	client, err := DialCtl(ctx, sock)
	if err != nil {
		t.Fatal(err)
	}
	deadline, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	reply, err := client.Do(deadline, CtlRequest{Cmd: "network-status"})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Network == nil || reply.Network.VMID != "vm" {
		t.Fatalf("reply %+v", reply)
	}
}
func TestNetworkMissingPrivdCancellation(t *testing.T) {
	r := &runner{cfg: Config{VMID: "vm", BootID: "boot", InstanceID: "runner"}}
	r.initNetworkStatus()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { r.networkLoop(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("network loop did not join")
	}
	if r.networkStatus().Collectors[0].State == "healthy" {
		t.Fatal("missing source healthy")
	}
}

// A runner that has permanently given up still answers. The coverage API refuses
// a status older than three seconds, so a frozen timestamp would replace the
// runner's own honest reason with a generic staleness verdict that cannot tell a
// refused acquisition from a hung runner. Staleness must mean exactly one thing:
// the runner stopped answering.
func TestNetworkStatusStaysLiveAfterPermanentGiveUp(t *testing.T) {
	r := &runner{cfg: Config{
		VMID: "vm", BootID: "boot", InstanceID: "runner",
		NetworkUnavailableReason: "network observer acquisition refused: privd has no gateway for this boot",
	}}
	r.initNetworkStatus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); r.networkLoop(ctx) }()

	// The give-up publishes once; everything after it is the keep-alive.
	published := waitForNetwork(t, r, func(s NetworkStatus) bool {
		return s.Collectors[0].State == "unavailable" && s.Collectors[0].Reason == r.cfg.NetworkUnavailableReason
	})
	// Three seconds is the coverage API's staleness bound, so an advance has to
	// arrive inside it or the published status is already unreadable.
	live := waitForNetwork(t, r, func(s NetworkStatus) bool { return s.UpdatedAt.After(published.UpdatedAt) })
	if got := live.Collectors[0]; got.State != "unavailable" || got.Reason != r.cfg.NetworkUnavailableReason {
		t.Fatalf("keep-alive changed the facts: %+v", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("keep-alive ignored cancellation")
	}
}

// waitForNetwork samples the published status until want holds, and fails inside
// the coverage API's three-second staleness bound if it never does.
func waitForNetwork(t *testing.T, r *runner, want func(NetworkStatus) bool) NetworkStatus {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		status := r.networkStatus()
		if want(status) {
			return status
		}
		if time.Now().After(deadline) {
			t.Fatalf("published network status never met the condition within the coverage staleness bound: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNetworkSpoolFailureVisible(t *testing.T) {
	r := &runner{cfg: Config{VMID: "vm", BootID: "boot", InstanceID: "runner"}}
	r.initNetworkStatus()
	sw, err := spool.OpenWriter(t.TempDir(), spool.WriterCfg{VMID: "vm", InstanceID: "runner", MaxSegmentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	r.sw = sw
	r.network.Collectors[0].SourceInstanceID = "source"
	r.persistNetwork("net.flow.observed", "source", map[string]uint64{}, networkFlowData(netobserve.FlowObservation{Flow: netobserve.Flow{Event: "new"}}), time.Now())
	if r.networkStatus().Collectors[0].LastEventAt == nil {
		t.Fatal("successful spool append not recorded")
	}
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	r.persistNetwork("net.flow.observed", "source", map[string]uint64{}, map[string]any{}, time.Now())
	if c := r.networkStatus().Collectors[0]; c.State != "degraded" || !strings.Contains(c.Reason, "spool") {
		t.Fatalf("failure hidden: %+v", c)
	}
}
func TestNetworkCtlBoundsAndDeadline(t *testing.T) {
	for _, large := range []bool{false, true} {
		t.Run(fmt.Sprint(large), func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			go func() {
				var req CtlRequest
				_ = json.NewDecoder(server).Decode(&req)
				if large {
					_ = json.NewEncoder(server).Encode(map[string]any{"ok": true, "padding": strings.Repeat("a", 40*1024)})
				}
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			if _, err := NewCtlClient(client).Do(ctx, CtlRequest{Cmd: "network-status"}); err == nil {
				t.Fatal("oversize or stalled response accepted")
			}
		})
	}
}
func TestNetworkWriterImportsExactEvidence(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "c28581fb-7b8b-499a-8671-8bf54d159830")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	sw, err := spool.OpenWriter(dir, spool.WriterCfg{VMID: "c28581fb-7b8b-499a-8671-8bf54d159830", InstanceID: "runner", MaxSegmentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{cfg: Config{VMID: "c28581fb-7b8b-499a-8671-8bf54d159830", BootID: "c28581fb-7b8b-499a-8671-8bf54d159831", InstanceID: "runner"}, sw: sw}
	r.initNetworkStatus()
	r.network.AcquisitionID = "acquisition"
	r.network.PolicyDigest = "digest"
	r.network.GatewayGeneration = "allocation"
	n := uint64(math.MaxUint64)
	obs := make(chan netobserve.Observation, 1)
	obs <- netobserve.Observation{SourceID: "c28581fb-7b8b-499a-8671-8bf54d159832", ObservedAt: time.Now(), Result: netobserve.Result{Scope: netobserve.Scope{Boundary: "namespace_gateway"}, Flows: []netobserve.FlowObservation{{Flow: netobserve.Flow{Event: "new", OriginalCounters: netobserve.Counters{Bytes: &n}}}}}}
	close(obs)
	r.networkWriter(obs, nil)
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	stats, err := spool.NewImporter(st, root, time.Second, nil).ImportOnce(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Appended != 1 {
		t.Fatalf("stats %+v", stats)
	}
	result, err := st.Query(t.Context(), store.Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	e := result.Events[0]
	if e.SourceInstanceID != "c28581fb-7b8b-499a-8671-8bf54d159832" || *e.BootID != "c28581fb-7b8b-499a-8671-8bf54d159831" || e.Provenance != events.HostObserved || e.Quality.Attribution != events.AttributionUnknown {
		t.Fatalf("identity %+v", e)
	}
	if e.Data["original_bytes"] != "18446744073709551615" || e.Data["policy_digest"] != "digest" || e.Data["gateway_generation"] != "allocation" {
		t.Fatalf("data %+v", e.Data)
	}
}
func TestNetworkReaderHealthStatesAndLoss(t *testing.T) {
	r := &runner{cfg: Config{VMID: "vm", BootID: "boot", InstanceID: "runner"}}
	r.initNetworkStatus()
	r.network.Collectors[0].SourceInstanceID = "source"
	status := netobserve.ReaderStatus{Sources: []netobserve.SourceStatus{{ID: "source", ReadState: "starting", Baseline: "pending"}}}
	if _, failed := r.refreshNetwork(status); failed || r.networkStatus().Collectors[0].State != "starting" {
		t.Fatal("baseline readiness invented")
	}
	status.Sources[0].ReadState = "healthy"
	status.Sources[0].Baseline = "ready"
	status.Sources[0].LastSuccess = time.Now()
	r.refreshNetwork(status)
	if c := r.networkStatus().Collectors[0]; c.State != "healthy" || c.LastSuccessAt == nil {
		t.Fatalf("readiness %+v", c)
	}
	status.Sources[0].QueueDrops = math.MaxUint64
	r.refreshNetwork(status)
	if c := r.networkStatus().Collectors[0]; c.State != "degraded" || c.DroppedCount != "18446744073709551615" {
		t.Fatalf("loss %+v", c)
	}
	status.Sources[0].ReadState = "failed"
	status.Sources[0].LastError = "malformed"
	reason, failed := r.refreshNetwork(status)
	if !failed {
		t.Fatal("failed reader not retried")
	}
	// Every production path that fails a read also bumps a loss counter in the
	// same critical section, so a generic loss wording here would erase the
	// kernel's own message on every real failure.
	if reason != "malformed" {
		t.Fatalf("retry reason = %q, want the kernel error the reader recorded", reason)
	}
	if c := r.networkStatus().Collectors[0]; c.Reason != "malformed" {
		t.Fatalf("failed reader reason = %q, want the kernel error the reader recorded", c.Reason)
	}
	r.networkSpoolError = true
	status.Sources[0].ReadState = "healthy"
	status.Sources[0].QueueDrops = 0
	r.refreshNetwork(status)
	if c := r.networkStatus().Collectors[0]; c.State != "degraded" || c.Reason != "network spool append failed" {
		t.Fatalf("spool failure cleared %+v", c)
	}
}

// net.collector.health has one durable shape everywhere: the network identity
// fields plus one collector object per record, with the reason inside it.
func TestNetworkUnavailablePersistsSameFacts(t *testing.T) {
	dir := t.TempDir()
	sw, err := spool.OpenWriter(dir, spool.WriterCfg{VMID: "vm", InstanceID: "runner", MaxSegmentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{cfg: Config{VMID: "vm", BootID: "boot", InstanceID: "runner"}, sw: sw}
	r.initNetworkStatus()
	r.networkUnavailable("network observer not acquired")
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	live := r.networkStatus()
	records := readSpoolRecords(t, dir)
	if len(records) != len(live.Collectors) {
		t.Fatalf("records = %d, want one per declared collector (%d)", len(records), len(live.Collectors))
	}
	for i, event := range records {
		if event.Kind != "net.collector.health" {
			t.Fatalf("kind = %q", event.Kind)
		}
		if _, ok := event.Data["status"]; ok {
			t.Fatalf("record %d still carries the whole-status shape: %+v", i, event.Data)
		}
		if _, ok := event.Data["reason"]; ok {
			t.Fatalf("record %d states a reason outside its collector: %+v", i, event.Data)
		}
		collector, ok := event.Data["collector"].(map[string]any)
		if !ok {
			t.Fatalf("record %d has no collector object: %+v", i, event.Data)
		}
		if collector["reason"] != live.Collectors[i].Reason || collector["state"] != "unavailable" {
			t.Fatalf("durable/live mismatch: %+v vs %+v", collector, live.Collectors[i])
		}
		if event.Data["boundary"] != live.Collectors[i].Boundary || event.Data["namespace_identity_role"] != "vm_gateway_ownership" {
			t.Fatalf("record %d lost the network identity fields: %+v", i, event.Data)
		}
	}
}

func readSpoolRecords(t *testing.T, dir string) []*events.Envelope {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.vmsp"))
	if err != nil {
		t.Fatal(err)
	}
	var out []*events.Envelope
	for _, p := range paths {
		it, err := spool.ReadSegment(p)
		if err != nil {
			t.Fatal(err)
		}
		for {
			event, err := it.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				it.Close()
				t.Fatal(err)
			}
			out = append(out, event)
		}
		it.Close()
	}
	return out
}
func TestNetworkLossSnapshotsDoNotInventAdditionalLoss(t *testing.T) {
	dir := t.TempDir()
	sw, err := spool.OpenWriter(dir, spool.WriterCfg{VMID: "vm", InstanceID: "runner", MaxSegmentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{cfg: Config{VMID: "vm", BootID: "boot", InstanceID: "runner"}, sw: sw}
	r.initNetworkStatus()
	status := r.networkStatus()
	status.Collectors = status.Collectors[:1]
	status.Collectors[0].SourceInstanceID = "source"
	status.Collectors[0].DroppedCount = "7"
	health := make(chan NetworkStatus, 2)
	health <- status
	changed := status
	changed.Collectors = append([]NetworkCollectorStatus(nil), status.Collectors...)
	changed.Collectors[0].State = "degraded"
	health <- changed
	close(health)
	r.networkWriter(nil, health)
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	paths, _ := filepath.Glob(filepath.Join(dir, "*.vmsp"))
	it, err := spool.ReadSegment(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	losses := 0
	for {
		e, err := it.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if e.Kind == "net.collector.loss" {
			losses++
			if e.Data["count_semantics"] != "cumulative_for_source_acquisition" {
				t.Fatal("ambiguous count semantics")
			}
		}
	}
	if losses != 1 {
		t.Fatalf("repeated unchanged loss: %d", losses)
	}
}
func TestNetworkNFLogUnknownIntervalsStayVisible(t *testing.T) {
	r := &runner{cfg: Config{VMID: "vm", BootID: "boot", InstanceID: "runner"}}
	r.initNetworkStatus()
	r.network.Collectors[1].SourceInstanceID = "nflog"
	source := netobserve.SourceStatus{ID: "nflog", ReadState: netobserve.ReadHealthy, Baseline: netobserve.BaselineNotApplicable, NFLogUnknownIntervals: 2, KernelUnknownIntervals: 3}
	r.refreshNetwork(netobserve.ReaderStatus{Sources: []netobserve.SourceStatus{source}})
	c := r.networkStatus().Collectors[1]
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if c.State != "degraded" || c.UnknownIntervals != "5" || !strings.Contains(string(raw), `"nflog_unknown_intervals":"2"`) {
		t.Fatalf("sequence uncertainty hidden: %s", raw)
	}
	source.LastSuccess = time.Now()
	r.refreshNetwork(netobserve.ReaderStatus{Sources: []netobserve.SourceStatus{source}})
	if c := r.networkStatus().Collectors[1]; c.State != "degraded" || c.UnknownIntervals != "5" {
		t.Fatalf("later success erased intervals: %+v", c)
	}
}

func TestNetworkNFLogUnknownIntervalAloneDegrades(t *testing.T) {
	r := &runner{}
	r.initNetworkStatus()
	r.network.Collectors[1].SourceInstanceID = "nflog"
	r.refreshNetwork(netobserve.ReaderStatus{Sources: []netobserve.SourceStatus{{ID: "nflog", ReadState: netobserve.ReadHealthy, Baseline: netobserve.BaselineNotApplicable, NFLogUnknownIntervals: 1}}})
	if c := r.networkStatus().Collectors[1]; c.State != "degraded" || c.UnknownIntervals != "1" || c.NFLogUnknownIntervals != "1" {
		t.Fatalf("sequence uncertainty hidden: %+v", c)
	}
}

func testObserverBundle() *privd.NetworkObserverBundle {
	return &privd.NetworkObserverBundle{
		Binding: privd.NetworkObserverBinding{
			VMID: "00000000-0000-4000-8000-000000000001", GuestBootID: "00000000-0000-4000-8000-000000000002",
			HostBootID: "00000000-0000-4000-8000-000000000005", AcquisitionID: "00000000-0000-4000-8000-000000000004",
			GatewayGeneration: strings.Repeat("a", 32), PolicyDigest: strings.Repeat("b", 64),
			NamespaceDevice: "4", NamespaceInode: "4026532000", PolicyID: "transport-public-web", Profile: "transport",
		},
		Sockets: []privd.ObserverSocket{
			{Kind: "conntrack", Boundary: "namespace_gateway", PortID: 11, SnapshotSequence: 7},
			{Kind: "nflog", Boundary: "namespace_gateway", PortID: 12, Group: 100},
			{Kind: "nflog", Boundary: "host_veth", PortID: 13, Group: 1024},
		},
	}
}

// A binding is validated against itself and nothing else. The runner labels its
// envelopes from --vm-id and --boot-id but scopes the reader from the binding, so
// a mismatched argv would produce records labelled one VM and scoped to another.
func TestParseFlagsRefusesObserverBindingForAnotherVMOrBoot(t *testing.T) {
	bundle := testObserverBundle()
	binding, err := privd.EncodeObserverBinding(bundle)
	if err != nil {
		t.Fatal(err)
	}
	args := func(vmID, bootID string) []string {
		return []string{
			"--vm-id", vmID, "--boot-id", bootID,
			"--instance-id", "00000000-0000-4000-8000-000000000003",
			"--uds", "/tmp/v.sock", "--token-file", "/tmp/token", "--spool-dir", "/tmp/spool",
			"--state-file", "/tmp/state.json", "--ctl-sock", "/tmp/runner.sock",
			"--vmm-pid", "123", "--vmm-starttime", "456",
			"--network-observers", string(binding),
		}
	}
	if _, err := ParseFlags("vmobs-runner", args(bundle.Binding.VMID, bundle.Binding.GuestBootID)); err != nil {
		t.Fatalf("the runner's own acquisition was refused: %v", err)
	}
	for _, mismatch := range []struct{ name, vmID, bootID string }{
		{"another VM", "00000000-0000-4000-8000-0000000000ff", bundle.Binding.GuestBootID},
		{"another boot", bundle.Binding.VMID, "00000000-0000-4000-8000-0000000000fe"},
	} {
		if _, err := ParseFlags("vmobs-runner", args(mismatch.vmID, mismatch.bootID)); err == nil {
			t.Fatalf("a binding for %s was accepted: its records would name one VM and observe another", mismatch.name)
		}
	}
}

// The interval before acquisition is not measured loss: it is a declared scope
// limit. A healthy reader that measured nothing must report zero unknown intervals.
func TestNetworkAcquisitionBoundaryIsDeclaredNotCounted(t *testing.T) {
	at := time.Date(2026, 9, 8, 1, 2, 3, 0, time.UTC)
	ids := []string{"00000000-0000-4000-8000-000000000011", "00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013"}
	status, err := NetworkStatusAtAcquisition(NewNetworkStatus("vm", "boot", "runner", "network observer not acquired", at), testObserverBundle(), ids, at)
	if err != nil {
		t.Fatal(err)
	}
	want := "observation began at " + at.Format(events.TimestampLayout) + "; earlier traffic unobserved"
	for i, c := range status.Collectors {
		if c.UnknownIntervals != "0" {
			t.Fatalf("collector %d claims %s unmeasured unknown intervals at acquisition", i, c.UnknownIntervals)
		}
		if !slices.Contains(c.ScopeLimitations, want) {
			t.Fatalf("collector %d does not declare its observation start: %v", i, c.ScopeLimitations)
		}
	}
	healthy, failed := NetworkCollectorFromSource(status.Collectors[0], netobserve.SourceStatus{ID: ids[0], ReadState: netobserve.ReadHealthy, Baseline: netobserve.BaselineReady, LastSuccess: at})
	if failed || healthy.State != "healthy" || healthy.UnknownIntervals != "0" || healthy.Reason != "reader ready" {
		t.Fatalf("healthy reader with no measured loss = %+v (failed=%v)", healthy, failed)
	}
}

// A clean stop is the end of observation, not a degraded capture with no reason.
// A stopping reader keeps every counter it measured, so the stop has to outrank
// the loss override rather than the other way round.
func TestNetworkStoppedReaderIsUnavailableWithReason(t *testing.T) {
	at := time.Now().UTC()
	ids := []string{"00000000-0000-4000-8000-000000000011", "00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013"}
	status, err := NetworkStatusAtAcquisition(NewNetworkStatus("vm", "boot", "runner", "network observer not acquired", at), testObserverBundle(), ids, at)
	if err != nil {
		t.Fatal(err)
	}
	stopped, _ := NetworkCollectorFromSource(status.Collectors[0], netobserve.SourceStatus{
		ID: ids[0], ReadState: netobserve.ReadStopped, Baseline: netobserve.BaselineReady,
		LastSuccess: at, QueueDrops: 4,
	})
	if stopped.State != "unavailable" || stopped.Reason != "runner stopped" {
		t.Fatalf("clean stop = %+v, want unavailable with a stated reason", stopped)
	}
	if stopped.DroppedCount != "4" {
		t.Fatalf("stopped collector = %+v, want the drops it measured still published", stopped)
	}
}

// Every reason a collector publishes is bounded, whatever length the kernel error
// had - and bounding it is the only thing that may happen to it. readError sets
// ReadFailed and bumps an unknown-interval count together, so this is the shape a
// real failed source has.
func TestNetworkReaderReasonIsBounded(t *testing.T) {
	at := time.Now().UTC()
	ids := []string{"00000000-0000-4000-8000-000000000011", "00000000-0000-4000-8000-000000000012", "00000000-0000-4000-8000-000000000013"}
	status, err := NetworkStatusAtAcquisition(NewNetworkStatus("vm", "boot", "runner", "network observer not acquired", at), testObserverBundle(), ids, at)
	if err != nil {
		t.Fatal(err)
	}
	failedSource := netobserve.SourceStatus{
		ID: ids[0], ReadState: netobserve.ReadFailed, Baseline: netobserve.BaselineReady,
		KernelUnknownIntervals: 1, LastError: strings.Repeat("x", 4096),
	}
	c, failed := NetworkCollectorFromSource(status.Collectors[0], failedSource)
	if !failed || len(c.Reason) > MaxNetworkReasonBytes {
		t.Fatalf("reason of %d bytes escaped the bound (failed=%v)", len(c.Reason), failed)
	}
	if c.Reason != strings.Repeat("x", MaxNetworkReasonBytes) {
		t.Fatalf("reason = %q, want the kernel error bounded, not replaced", c.Reason)
	}
	if c.State != "degraded" || c.UnknownIntervals != "1" {
		t.Fatalf("failed collector = %+v, want degraded carrying the interval it measured", c)
	}
}

// A reason is bounded in bytes but published as JSON: truncating inside a rune
// would hand json.Marshal invalid UTF-8, which it silently replaces with U+FFFD.
func TestNetworkReasonTruncatesAtRuneBoundary(t *testing.T) {
	// The last rune straddles the bound: one byte inside it, one byte past.
	reason := strings.Repeat("a", MaxNetworkReasonBytes-1) + "é"
	got := BoundNetworkReason(reason)
	if len(got) > MaxNetworkReasonBytes {
		t.Fatalf("bounded reason is %d bytes, want at most %d", len(got), MaxNetworkReasonBytes)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("bounded reason %q is not valid UTF-8: json.Marshal would replace the split rune", got)
	}
	if got != strings.Repeat("a", MaxNetworkReasonBytes-1) {
		t.Fatalf("bounded reason = %q, want the last whole rune at or below the bound", got)
	}
	if short := BoundNetworkReason("é"); short != "é" {
		t.Fatalf("reason inside the bound = %q, want it untouched", short)
	}
}

// The reader binds to the prefixes the gateway policy actually writes.
func TestNetworkDenialPrefixesMatchInstalledPolicy(t *testing.T) {
	if got := NetworkDenialPrefixes("conntrack", "namespace_gateway"); got != nil {
		t.Fatalf("conntrack source given denial prefixes: %v", got)
	}
	if got := NetworkDenialPrefixes("nflog", "namespace_gateway"); !slices.Contains(got, network.NamespaceDenialPrefix) || !slices.Contains(got, network.NamespaceIngressDenialPrefix) {
		t.Fatalf("namespace denial prefixes = %v", got)
	}
	if got := NetworkDenialPrefixes("nflog", "host_veth"); len(got) != 1 || got[0] != network.HostDenialPrefix {
		t.Fatalf("host denial prefixes = %v", got)
	}
}

// A flow the tracker cannot key, and a message outside the declared family scope,
// are limitations of what was correlated - never drops and never unknown intervals.
func TestNetworkUntrackedAndUnsupportedCountsAreTheirOwnLimitations(t *testing.T) {
	base := NewNetworkStatus("vm", "boot", "runner", "unacquired", time.Now())
	got, failed := NetworkCollectorFromSource(base.Collectors[0], netobserve.SourceStatus{
		ID: "source", ReadState: netobserve.ReadHealthy, Baseline: netobserve.BaselineReady,
		LastSuccess: time.Now(), FlowIdentityUntracked: 3, UnsupportedFamilyMessages: 2,
	})
	if failed || got.State != "healthy" {
		t.Fatalf("collector = %+v (failed=%v), want healthy: neither count is loss", got, failed)
	}
	if got.UntrackedFlowIdentities != "3" || got.UnsupportedFamilyMessages != "2" || got.DroppedCount != "0" || got.UnknownIntervals != "0" {
		t.Fatalf("collector = %+v, want the two limitation counts surfaced separately from loss", got)
	}
}

// Every loss class the tracker can report reaches durable evidence, including the
// ones no status counter carries.
func TestNetworkWriterPersistsObservationLosses(t *testing.T) {
	dir := t.TempDir()
	sw, err := spool.OpenWriter(dir, spool.WriterCfg{VMID: "vm", InstanceID: "runner", MaxSegmentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{cfg: Config{VMID: "vm", BootID: "boot", InstanceID: "runner"}, sw: sw}
	r.initNetworkStatus()
	obs := make(chan netobserve.Observation, 1)
	obs <- netobserve.Observation{SourceID: "source", ObservedAt: time.Now(), Result: netobserve.Result{
		Scope:  netobserve.Scope{Boundary: "namespace_gateway"},
		Flows:  []netobserve.FlowObservation{{Flow: netobserve.Flow{Event: "new"}}},
		Losses: []netobserve.Loss{{Reason: "flow_identity_untracked", Count: testPtrValue(uint64(1))}, {Reason: "invalid_flow_event"}},
	}}
	close(obs)
	r.networkWriter(obs, nil)
	if err := sw.Close(); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]map[string]any{}
	paths, err := filepath.Glob(filepath.Join(dir, "*.vmsp"))
	if err != nil {
		t.Fatal(err)
	}
	it, err := spool.ReadSegment(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	for {
		event, err := it.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		kinds[event.Kind] = event.Data
	}
	loss, ok := kinds["net.collector.loss"]
	if !ok {
		t.Fatalf("kinds = %v, want the observation's losses recorded", kinds)
	}
	if loss["count_semantics"] != "single_observation" || loss["boundary"] != "namespace_gateway" {
		t.Fatalf("loss record = %+v, want per-observation semantics at the observed boundary", loss)
	}
	encoded, err := json.Marshal(loss["losses"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "flow_identity_untracked") || !strings.Contains(string(encoded), "invalid_flow_event") {
		t.Fatalf("losses = %s, want every reported class", encoded)
	}
}

func testPtrValue[T any](v T) *T { return &v }

// A network failure this runner cannot repair must never end Run and must never
// move the runner's phase. The VMM is alive, every other collector keeps
// working, and only privd can replace an acquisition, so a runner that
// finalized here would publish a false statement about a live VM.
func TestNetworkFailureNeverEndsTheRunner(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "nw-run-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spoolDir := filepath.Join(dir, "spool")
	stateFile := filepath.Join(dir, "runner-state.json")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			VMID:         "vm",
			BootID:       "boot",
			InstanceID:   "runner",
			UDSPath:      filepath.Join(dir, "v.sock"),
			TokenFile:    filepath.Join(dir, "token"),
			SpoolDir:     spoolDir,
			StateFile:    stateFile,
			CtlSock:      filepath.Join(dir, "ctl"),
			VMMPID:       os.Getpid(),
			VMMStartTime: "1",
			PingInterval: 50 * time.Millisecond,
			PIDAlive:     func(int, string) bool { return true },
			// A binding this process cannot read from: the network side reports
			// the failure and has nothing left that a retry could repair.
			NetworkObservers: &privd.NetworkObserverBundle{},
		})
	}()

	// The failure is durable before anything else is asserted, so the assertions
	// below run against a runner whose network side has already given up.
	deadline := time.Now().Add(15 * time.Second)
	for unavailableHealthRecords(t, spoolDir) < 3 {
		select {
		case runErr := <-done:
			t.Fatalf("Run returned before the network failure was recorded: %v (phase %q, VMM alive)", runErr, runnerPhase(t, stateFile))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the network side never recorded its failure")
		}
		time.Sleep(25 * time.Millisecond)
	}

	// The runner is supervising a live VM: the network failure ends nothing.
	select {
	case runErr := <-done:
		t.Fatalf("a network failure ended the runner: %v (phase %q, VMM alive)", runErr, runnerPhase(t, stateFile))
	case <-time.After(500 * time.Millisecond):
	}
	if phase := runnerPhase(t, stateFile); phase != PhaseStarting && phase != PhaseDegraded {
		t.Fatalf("a network failure moved a live VM's runner to phase %q", phase)
	}

	cancel()
	select {
	case runErr := <-done:
		if !errors.Is(runErr, context.Canceled) {
			t.Fatalf("Run after cancellation = %v, want context.Canceled", runErr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// unavailableHealthRecords counts the durable unavailable collector records a
// live runner has written so far. Segments are read while the writer still owns
// them, so a torn tail ends this read instead of failing the test.
func unavailableHealthRecords(t *testing.T, dir string) int {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.vmsp"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, p := range paths {
		it, err := spool.ReadSegment(p)
		if err != nil {
			continue
		}
		for {
			event, err := it.Next()
			if err != nil {
				break
			}
			if event.Kind != "net.collector.health" {
				continue
			}
			collector, _ := event.Data["collector"].(map[string]any)
			if state, _ := collector["state"].(string); state == "unavailable" {
				count++
			}
		}
		it.Close()
	}
	return count
}

func runnerPhase(t *testing.T, stateFile string) string {
	t.Helper()
	raw, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	return state.Phase
}
