// ABOUTME: Normalizes kernel network evidence into host-owned spool envelopes.
// ABOUTME: Preserves missing fields and full-width counters without packet retention.
package runner

import (
	"github.com/2389-research/observatory/internal/netobserve"
	"strconv"
)

func decimalPointer(v *uint64) any {
	if v == nil {
		return nil
	}
	return strconv.FormatUint(*v, 10)
}
func networkTuple(t *netobserve.Tuple) any {
	if t == nil {
		return nil
	}
	var source, destination any
	if t.Source.IsValid() {
		source = t.Source.String()
	}
	if t.Destination.IsValid() {
		destination = t.Destination.String()
	}
	return map[string]any{
		"source":           source,
		"destination":      destination,
		"protocol":         t.Protocol,
		"source_port":      t.SourcePort,
		"destination_port": t.DestinationPort,
		"zone":             t.Zone,
		"icmp_id":          t.ICMPID,
		"icmp_type":        t.ICMPType,
		"icmp_code":        t.ICMPCode,
	}
}

// networkFlowData keeps every absent kernel field absent. policy_outcome,
// direction, flow_lifetime_id and process_attribution are unknown to conntrack
// alone, so they are stated as unknown rather than guessed.
func networkFlowData(o netobserve.FlowObservation) map[string]any {
	f := o.Flow
	return map[string]any{
		"event":               f.Event,
		"start_observed":      o.StartObserved,
		"kernel_id":           f.ID,
		"original_tuple":      networkTuple(f.Original),
		"reply_tuple":         networkTuple(f.Reply),
		"zone":                f.Zone,
		"status":              f.Status,
		"mark":                f.Mark,
		"timeout_seconds":     f.TimeoutSeconds,
		"tcp_state":           f.TCPState,
		"original_packets":    decimalPointer(f.OriginalCounters.Packets),
		"original_bytes":      decimalPointer(f.OriginalCounters.Bytes),
		"reply_packets":       decimalPointer(f.ReplyCounters.Packets),
		"reply_bytes":         decimalPointer(f.ReplyCounters.Bytes),
		"start_nanoseconds":   decimalPointer(f.StartNanoseconds),
		"stop_nanoseconds":    decimalPointer(f.StopNanoseconds),
		"event_nanoseconds":   decimalPointer(f.EventNanoseconds),
		"policy_outcome":      "unknown",
		"direction":           "unknown",
		"flow_lifetime_id":    nil,
		"process_attribution": "unknown",
	}
}

// networkDenialData records the NFLOG header the kernel supplied. policy_outcome
// is denied because the record came from a denial chain; no packet is retained.
func networkDenialData(d netobserve.Denial) map[string]any {
	return map[string]any{
		"group":                  d.Group,
		"prefix":                 d.Prefix,
		"family":                 d.Family,
		"hardware_protocol":      d.HardwareProtocol,
		"hook":                   d.Hook,
		"in_interface":           d.InInterface,
		"out_interface":          d.OutInterface,
		"physical_in_interface":  d.PhysicalInInterface,
		"physical_out_interface": d.PhysicalOutInterface,
		"mark":                   d.Mark,
		"sequence":               d.Sequence,
		"global_sequence":        d.GlobalSequence,
		"timestamp_seconds":      decimalPointer(d.TimestampSeconds),
		"timestamp_microseconds": decimalPointer(d.TimestampMicroseconds),
		"tuple":                  networkTuple(d.Tuple),
		"original_length":        d.OriginalLength,
		"captured_length":        d.CapturedLength,
		"packet_truncated":       d.PacketTruncated,
		"packet_malformed":       d.PacketMalformed,
		"fragment_offset":        d.FragmentOffset,
		"scope_limitation":       d.ScopeLimitation,
		"policy_outcome":         "denied",
		"process_attribution":    "unknown",
	}
}
