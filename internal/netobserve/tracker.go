// ABOUTME: Bounds per-collector flow history and NFLOG sequence tracking.
// ABOUTME: Reports missing observation intervals without inventing packet events.
package netobserve

import (
	"container/list"
	"errors"
	"fmt"
	"strconv"
	"syscall"
	"time"
)

// Limits apply to one namespace acquisition. IdleTimeout discards local memory;
// expiration never claims the kernel flow ended or timed out.
type Limits struct {
	MaxFlows, MaxGroups int
	IdleTimeout         time.Duration
}

type flowState struct {
	key     string
	start   bool
	touched time.Time
}
type sequenceState struct {
	group uint16
	last  uint32
}

// Tracker is single-reader state: the caller serializes flow, denial and error
// observations. It retains only bounded keys and start/sequence facts, not packets.
type Tracker struct {
	scope      Scope
	limits     Limits
	flows      map[string]*list.Element
	flowOrder  list.List
	groups     map[uint16]*list.Element
	groupOrder list.List
}

func NewTracker(scope Scope, limits Limits) (*Tracker, error) {
	for _, v := range []string{scope.VMID, scope.BootID, scope.HostBootID, scope.Generation, scope.NamespaceID, scope.Boundary} {
		if len(v) == 0 || len(v) > 256 {
			return nil, fmt.Errorf("collector scope requires bounded, nonempty host identities")
		}
	}
	if limits.MaxFlows < 1 || limits.MaxFlows > 65536 || limits.MaxGroups < 1 || limits.MaxGroups > 65536 || limits.IdleTimeout <= 0 {
		return nil, fmt.Errorf("collector limits require 1..65536 flows/groups and a positive idle timeout")
	}
	return &Tracker{scope: scope, limits: limits, flows: make(map[string]*list.Element), groups: make(map[uint16]*list.Element)}, nil
}
func (t *Tracker) result() Result          { return Result{Scope: t.scope} }
func counted(reason string, n uint64) Loss { return Loss{Reason: reason, Count: &n} }
func value[T ~uint8 | ~uint16 | ~uint32 | ~uint64](p *T) string {
	if p == nil {
		return "?"
	}
	return strconv.FormatUint(uint64(*p), 10)
}
func flowKey(f Flow) (string, bool) {
	tuple := "?"
	if o := f.Original; o != nil {
		tuple = value(o.Zone) + "/" + o.Source.String() + "/" + o.Destination.String() + "/" + value(o.Protocol) + "/" + value(o.SourcePort) + "/" + value(o.DestinationPort) + "/" + value(o.ICMPID) + "/" + value(o.ICMPType) + "/" + value(o.ICMPCode)
	}
	if f.ID == nil {
		o := f.Original
		if o == nil || !o.Source.Is4() || !o.Destination.Is4() || o.Protocol == nil {
			return "", false
		}
		switch *o.Protocol {
		case 6, 17:
			if o.SourcePort == nil || o.DestinationPort == nil {
				return "", false
			}
		case 1:
			if o.ICMPID == nil || o.ICMPType == nil || o.ICMPCode == nil {
				return "", false
			}
		default:
			return "", false
		}
	}
	return value(f.ID) + "/" + value(f.Zone) + "/" + tuple, true
}

// ObserveFlow tracks whether this collector actually saw a NEW observation.
// It does not infer TCP establishment, policy acceptance or destroy cause.
func (t *Tracker) ObserveFlow(flow Flow, at time.Time) Result {
	out := t.result()
	switch flow.Event {
	case "new", "update", "destroy", "snapshot":
	default:
		out.Losses = append(out.Losses, Loss{Reason: "invalid_flow_event"})
		return out
	}
	obs := FlowObservation{Flow: flow, StartObserved: flow.Event == "new"}
	key, ok := flowKey(flow)
	if !ok {
		out.Losses = append(out.Losses, counted("flow_identity_untracked", 1))
		out.Flows = append(out.Flows, obs)
		return out
	}
	if item := t.flows[key]; item != nil {
		state := item.Value.(*flowState)
		state.start = state.start || flow.Event == "new"
		state.touched = at
		obs.StartObserved = state.start
		if flow.Event == "destroy" {
			delete(t.flows, key)
			t.flowOrder.Remove(item)
		} else {
			t.flowOrder.MoveToBack(item)
		}
	} else if flow.Event != "destroy" {
		if len(t.flows) == t.limits.MaxFlows {
			first := t.flowOrder.Front()
			delete(t.flows, first.Value.(*flowState).key)
			t.flowOrder.Remove(first)
			out.Losses = append(out.Losses, counted("flow_state_evicted", 1))
		}
		t.flows[key] = t.flowOrder.PushBack(&flowState{key: key, start: obs.StartObserved, touched: at})
	}
	out.Flows = append(out.Flows, obs)
	return out
}

// ObserveDenial measures only local NFLOG sequence gaps. Global sequence can
// include other groups, so it is evidence retained for callers, never a drop count.
func (t *Tracker) ObserveDenial(denial Denial) Result {
	out := t.result()
	out.Denials = append(out.Denials, denial)
	if denial.Sequence == nil {
		return out
	}
	seq := *denial.Sequence
	if item := t.groups[denial.Group]; item != nil {
		state := item.Value.(*sequenceState)
		delta := seq - state.last // uint32 wrap is part of the NFLOG sequence contract.
		switch {
		case delta == 1:
		case delta > 1 && delta < 1<<31:
			out.Losses = append(out.Losses, counted("nflog_sequence_gap", uint64(delta-1)))
		default:
			out.Losses = append(out.Losses, Loss{Reason: "nflog_sequence_discontinuity"})
		}
		state.last = seq
		t.groupOrder.MoveToBack(item)
	} else {
		if len(t.groups) == t.limits.MaxGroups {
			first := t.groupOrder.Front()
			delete(t.groups, first.Value.(*sequenceState).group)
			t.groupOrder.Remove(first)
			out.Losses = append(out.Losses, counted("nflog_group_evicted", 1))
		}
		t.groups[denial.Group] = t.groupOrder.PushBack(&sequenceState{group: denial.Group, last: seq})
	}
	return out
}

func (t *Tracker) Expire(at time.Time) Result {
	out := t.result()
	var count uint64
	for item := t.flowOrder.Front(); item != nil; {
		next := item.Next()
		state := item.Value.(*flowState)
		if at.Sub(state.touched) >= t.limits.IdleTimeout {
			delete(t.flows, state.key)
			t.flowOrder.Remove(item)
			count++
		}
		item = next
	}
	if count > 0 {
		out.Losses = append(out.Losses, counted("flow_state_expired", count))
	}
	return out
}

// ReadError reports an observation interval of unknown size. The caller must
// also pass receive MSG_TRUNC and kernel-sender validation failures here.
func (t *Tracker) ReadError(err error) Result {
	out := t.result()
	if err == nil {
		return out
	}
	// A missing interval can hide destroy and ID/tuple reuse. Reacquire local
	// correlation facts from subsequent observations rather than carry them over.
	clear(t.flows)
	t.flowOrder.Init()
	reason := "collector_read_error"
	switch {
	case errors.Is(err, ErrOverrun), errors.Is(err, syscall.ENOBUFS):
		reason = "kernel_buffer_overrun"
	case errors.Is(err, ErrDumpInterrupted):
		reason = "conntrack_dump_interrupted"
	case errors.Is(err, ErrMalformed):
		reason = "malformed_netlink"
	case errors.Is(err, ErrUnsupportedFamily):
		reason = "unsupported_network_family"
	}
	out.Losses = append(out.Losses, Loss{Reason: reason})
	return out
}
