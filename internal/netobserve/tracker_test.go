// ABOUTME: Tests bounded collector state with real decoded netlink observations.
// ABOUTME: Pins restart, sequence-gap and eviction semantics without kernel substitutes.
package netobserve

import (
	"fmt"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testScope() Scope {
	return Scope{VMID: "vm-a", BootID: "guest-boot", HostBootID: "host-boot", Generation: "allocation-1", NamespaceID: "4026532500", Boundary: "tap0"}
}
func tracker(t *testing.T, maxFlows int) *Tracker {
	t.Helper()
	tr, err := NewTracker(testScope(), Limits{MaxFlows: maxFlows, MaxGroups: 1, IdleTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}
func decodedFlow(t *testing.T, id uint32, kind string) Flow {
	t.Helper()
	fs, err := ParseConntrack(flowMessage(0x600), false)
	if err != nil {
		t.Fatal(err)
	}
	f := fs[0]
	f.ID = &id
	f.Event = kind
	return f
}
func decodedDenial(t *testing.T, seq uint32, group uint16) Denial {
	t.Helper()
	ds, err := ParseNFLog(msg(0x400, 0, attr(12, be32(seq))))
	if err != nil {
		t.Fatal(err)
	}
	d := ds[0]
	d.Group = group
	return d
}
func TestTrackerScopeAndLimits(t *testing.T) {
	limit := Limits{MaxFlows: 1, MaxGroups: 1, IdleTimeout: time.Second}
	if _, err := NewTracker(Scope{}, limit); err == nil {
		t.Fatal("accepted unbound collector")
	}
	for _, bad := range []Limits{{}, {MaxFlows: 1, MaxGroups: 1}, {MaxFlows: -1, MaxGroups: 1, IdleTimeout: time.Second}, {MaxFlows: 1 << 30, MaxGroups: 1, IdleTimeout: time.Second}} {
		if _, err := NewTracker(testScope(), bad); err == nil {
			t.Fatalf("accepted limits %+v", bad)
		}
	}
	r := tracker(t, 1).ObserveFlow(decodedFlow(t, 1, "new"), time.Now())
	if r.Scope != testScope() {
		t.Fatalf("lost immutable source scope: %+v", r)
	}
}
func TestTrackerLifecycleAndSnapshot(t *testing.T) {
	tr := tracker(t, 2)
	now := time.Now()
	for _, phase := range []string{"new", "update", "destroy"} {
		r := tr.ObserveFlow(decodedFlow(t, 1, phase), now)
		if len(r.Flows) != 1 || !r.Flows[0].StartObserved || r.Flows[0].Flow.Event != phase {
			t.Fatalf("%s: %+v", phase, r)
		}
	}
	r := tr.ObserveFlow(decodedFlow(t, 1, "update"), now)
	if len(r.Flows) != 1 || r.Flows[0].StartObserved {
		t.Fatalf("destroyed flow history reused: %+v", r)
	}
	tr = tracker(t, 2)
	r = tr.ObserveFlow(decodedFlow(t, 1, "snapshot"), now)
	if len(r.Flows) != 1 || r.Flows[0].StartObserved || r.Flows[0].Flow.Event != "snapshot" {
		t.Fatalf("snapshot invented start: %+v", r)
	}
	r = tr.ObserveFlow(decodedFlow(t, 1, "destroy"), now)
	if len(r.Flows) != 1 || r.Flows[0].StartObserved {
		t.Fatal("snapshot became start")
	}
}
func TestTrackerEvictsWithoutInventingEnds(t *testing.T) {
	tr := tracker(t, 1)
	now := time.Now()
	tr.ObserveFlow(decodedFlow(t, 1, "new"), now)
	r := tr.ObserveFlow(decodedFlow(t, 2, "new"), now)
	if len(r.Flows) != 1 || len(r.Losses) != 1 || r.Losses[0].Reason != "flow_state_evicted" || *r.Losses[0].Count != 1 {
		t.Fatalf("eviction: %+v", r)
	}
	r = tr.ObserveFlow(decodedFlow(t, 1, "update"), now)
	if len(r.Flows) != 1 || r.Flows[0].StartObserved {
		t.Fatal("evicted flow kept start")
	}
	r = tr.Expire(now.Add(2 * time.Minute))
	if len(r.Flows) != 0 || len(r.Losses) != 1 || r.Losses[0].Reason != "flow_state_expired" {
		t.Fatalf("invented kernel timeout/end: %+v", r)
	}
}
func TestTrackerKeysCannotRelabelReusedTuples(t *testing.T) {
	tr := tracker(t, 3)
	now := time.Now()
	f := decodedFlow(t, 1, "new")
	tr.ObserveFlow(f, now)
	other := decodedFlow(t, 1, "update")
	p := uint16(4000)
	other.Original.SourcePort = &p
	if r := tr.ObserveFlow(other, now); len(r.Flows) != 1 || r.Flows[0].StartObserved {
		t.Fatal("ID reuse relabeled flow")
	}
	other = decodedFlow(t, 1, "update")
	z := uint16(8)
	other.Zone = &z
	if r := tr.ObserveFlow(other, now); len(r.Flows) != 1 || r.Flows[0].StartObserved {
		t.Fatal("zone crossed")
	}
	if r := tracker(t, 3).ObserveFlow(f, time.Now()); r.Scope != testScope() {
		t.Fatal("scope mutation")
	}
	// A new tracker has no evidence of starts before it acquired its source.
	if r := tracker(t, 3).ObserveFlow(decodedFlow(t, 1, "update"), now); len(r.Flows) != 1 || r.Flows[0].StartObserved {
		t.Fatal("restart invented past start")
	}
}
func TestNFLogSequencesAreBoundedAndWrap(t *testing.T) {
	tr := tracker(t, 1)
	for _, seq := range []uint32{^uint32(0) - 1, ^uint32(0), 0} {
		if r := tr.ObserveDenial(decodedDenial(t, seq, 1)); len(r.Losses) != 0 {
			t.Fatalf("wrap loss: %+v", r)
		}
	}
	r := tr.ObserveDenial(decodedDenial(t, 3, 1))
	if len(r.Denials) != 1 || len(r.Losses) != 1 || r.Losses[0].Reason != "nflog_sequence_gap" || *r.Losses[0].Count != 2 {
		t.Fatalf("gap: %+v", r)
	}
	r = tr.ObserveDenial(decodedDenial(t, 3, 1))
	if len(r.Losses) != 1 || r.Losses[0].Count != nil {
		t.Fatalf("duplicate falsely measured: %+v", r)
	}
	r = tr.ObserveDenial(decodedDenial(t, 1, 1))
	if len(r.Losses) != 1 || r.Losses[0].Count != nil {
		t.Fatalf("reset treated as billions lost: %+v", r)
	}
	r = tr.ObserveDenial(decodedDenial(t, 1, 2))
	if len(r.Losses) != 1 || r.Losses[0].Reason != "nflog_group_evicted" {
		t.Fatalf("unbounded groups: %+v", r)
	}
}
func TestReadErrorsDescribeUnknownLoss(t *testing.T) {
	tr := tracker(t, 1)
	for _, err := range []error{ErrOverrun, fmt.Errorf("receive: %w", syscall.ENOBUFS), ErrDumpInterrupted, ErrMalformed} {
		r := tr.ReadError(err)
		if len(r.Flows) != 0 || len(r.Denials) != 0 || len(r.Losses) != 1 || r.Losses[0].Count != nil {
			t.Fatalf("invented loss count: %+v", r)
		}
	}
	if r := tr.ReadError(nil); len(r.Losses) != 0 {
		t.Fatal("nil read error became loss")
	}
}
func TestTrackerUnkeyedAndInvalidFlow(t *testing.T) {
	tr := tracker(t, 1)
	r := tr.ObserveFlow(Flow{Event: "update"}, time.Now())
	if len(r.Flows) != 1 || len(r.Losses) != 1 || !strings.Contains(r.Losses[0].Reason, "identity") {
		t.Fatalf("unknown identity silently tracked: %+v", r)
	}
	r = tr.ObserveFlow(Flow{Event: "established"}, time.Now())
	if len(r.Flows) != 0 || len(r.Losses) != 1 {
		t.Fatalf("accepted invented lifecycle: %+v", r)
	}
}

func TestTrackerCannotKeyAmbiguousTupleWithoutID(t *testing.T) {
	f := decodedFlow(t, 1, "new")
	f.ID = nil
	f.Original.SourcePort = nil
	tr := tracker(t, 1)
	r := tr.ObserveFlow(f, time.Now())
	if len(r.Losses) != 1 || r.Losses[0].Reason != "flow_identity_untracked" {
		t.Fatalf("partial tuple became identity: %+v", r)
	}
	f.Event = "update"
	if r = tr.ObserveFlow(f, time.Now()); r.Flows[0].StartObserved {
		t.Fatal("ambiguous tuple correlated")
	}
}

func TestReadLossInvalidatesFlowCorrelation(t *testing.T) {
	tr := tracker(t, 1)
	now := time.Now()
	tr.ObserveFlow(decodedFlow(t, 1, "new"), now)
	tr.ReadError(ErrOverrun)
	r := tr.ObserveFlow(decodedFlow(t, 1, "update"), now)
	if len(r.Flows) != 1 || r.Flows[0].StartObserved {
		t.Fatal("gap can hide destroy/reuse; prior start must not relabel later identity")
	}
}
