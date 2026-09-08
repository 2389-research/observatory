// ABOUTME: Derives VM/boot-scoped collector coverage from live guest and host health.
// ABOUTME: Keeps channel liveness separate from evidence capture and declares every gap.
package situation

import (
	"context"
	"math"
	"slices"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/store"
)

const (
	CoverageUnavailable = "unavailable"
	CoverageUnsupported = "unsupported"
	CoverageDisabled    = "disabled"
	CoverageStarting    = "starting"
	CoverageHealthy     = "healthy"
	CoverageDegraded    = "degraded"
	maxSafeJSONInteger  = float64(1<<53 - 1)
)

var guestCollectorIDs = []string{"filesystem", "process"}
var hostCollectorIDs = []string{"flow", "dns", "denial", "request"}

type ChannelCoverage struct {
	State           string  `json:"state"`
	LastHeartbeatAt string  `json:"last_heartbeat_at,omitempty"`
	LastSuccessAt   string  `json:"last_success_at,omitempty"`
	ObservedDropped *string `json:"observed_dropped"`
	Reason          string  `json:"reason,omitempty"`
}

// CollectorCoverage describes one evidence collector without treating quiet as failure.
type CollectorCoverage struct {
	ID                   string   `json:"id"`
	VMID                 string   `json:"vm_id,omitempty"`
	BootID               string   `json:"boot_id,omitempty"`
	State                string   `json:"state"`
	Enabled              bool     `json:"enabled"`
	EventClasses         []string `json:"event_classes"`
	Scope                []string `json:"scope"`
	Exclusions           []string `json:"exclusions"`
	Limitations          []string `json:"limitations"`
	LastEventAt          string   `json:"last_event_at,omitempty"`
	LastSuccessAt        string   `json:"last_success_at,omitempty"`
	ObservedDropped      *string  `json:"observed_dropped"`
	UnknownLossIntervals *int     `json:"unknown_loss_intervals"`
	CaptureMode          string   `json:"capture_mode,omitempty"`
	Reason               string   `json:"reason,omitempty"`
	Source               string   `json:"source"`
	Provenance           string   `json:"provenance"`
}

type Coverage struct {
	VMID       string              `json:"vm_id"`
	BootID     string              `json:"boot_id,omitempty"`
	Channel    ChannelCoverage     `json:"channel"`
	Collectors []CollectorCoverage `json:"collectors"`
	Gaps       []string            `json:"gaps"`
}

type HostCoverageSource interface {
	Coverage(context.Context, *store.VM) ([]CollectorCoverage, error)
}

func (e *Engine) SetHostCoverageSource(source HostCoverageSource) {
	e.coverageMu.Lock()
	e.hostCoverage = source
	e.coverageMu.Unlock()
}

func (e *Engine) VMCoverage(ctx context.Context, vm *store.VM) (Coverage, error) {
	result := Coverage{VMID: vm.VMID, BootID: vm.CurrentBootID, Collectors: defaultCollectors(vm)}
	hb, err := e.currentHeartbeat(ctx, vm)
	if err != nil {
		return Coverage{}, err
	}
	result.Channel = e.channelCoverage(vm, hb)
	applyGuestSensors(result.Collectors, hb)

	e.coverageMu.RLock()
	source := e.hostCoverage
	e.coverageMu.RUnlock()
	if source != nil && vm.ObservedState == "running" && vm.CurrentBootID != "" {
		records, sourceErr := source.Coverage(ctx, vm)
		if sourceErr != nil {
			markHostFailure(result.Collectors, sourceErr)
		} else {
			applyHostCoverage(result.Collectors, records, vm)
		}
	}
	if result.Channel.State == TelemetryDegraded {
		degradeCollectorsForChannel(result.Collectors)
	}
	result.Gaps = coverageGaps(result.Channel, result.Collectors)
	return result, nil
}

func (e *Engine) currentHeartbeat(ctx context.Context, vm *store.VM) (*events.Envelope, error) {
	if vm.ObservedState != "running" || vm.CurrentBootID == "" {
		return nil, nil
	}
	return e.st.LatestForBoot(ctx, vm.VMID, vm.CurrentBootID, HeartbeatKind)
}

func (e *Engine) channelCoverage(vm *store.VM, hb *events.Envelope) ChannelCoverage {
	channel := ChannelCoverage{State: TelemetryUnavailable}
	if vm.ObservedState == "provisioning" || vm.ObservedState == "starting" {
		channel.State = TelemetryStarting
	} else if vm.ObservedState == "running" && vm.CurrentBootID != "" && hb != nil {
		channel.State = TelemetryHealthy
		if time.Since(hb.HostReceivedAt.Time) > stalenessIntervals*heartbeatInterval(hb.Data) {
			channel.State = TelemetryDegraded
			channel.Reason = "guest heartbeat is stale"
		}
		channel.LastHeartbeatAt = hb.HostReceivedAt.UTC().Format(events.TimestampLayout)
		channel.LastSuccessAt = channel.LastHeartbeatAt
		if ring, ok := hb.Data["ring"].(map[string]any); ok {
			if dropped, ok := ring["dropped"].(string); ok && events.DecimalString(dropped) {
				channel.ObservedDropped = &dropped
			}
		}
	}
	vmImport, allImport := e.ImporterStatus(vm.VMID), e.ImporterStatus("")
	if vm.ObservedState == "running" && (vmImport.State == "degraded" || allImport.State == "degraded") {
		channel.State = TelemetryDegraded
		channel.Reason = "durable import is degraded"
	}
	return channel
}

func defaultCollectors(vm *store.VM) []CollectorCoverage {
	ids := append(append([]string{}, guestCollectorIDs...), hostCollectorIDs...)
	out := make([]CollectorCoverage, 0, len(ids))
	for _, id := range ids {
		state, enabled, reason := CoverageUnavailable, true, "no current collector report available"
		if id == "request" && vm.NetworkProfile != "http_inspect" {
			state, enabled, reason = CoverageDisabled, false, "request capture requires the http_inspect network profile"
		}
		if vm.NetworkProfile == "offline" && (id == "flow" || id == "dns") {
			state, enabled, reason = CoverageDisabled, false, "collector is outside the offline network profile"
		}
		out = append(out, CollectorCoverage{
			ID: id, VMID: vm.VMID, BootID: vm.CurrentBootID, State: state, Enabled: enabled,
			EventClasses: []string{}, Scope: []string{}, Exclusions: []string{}, Limitations: []string{},
			Reason: reason, Source: sourceFor(id), Provenance: provenanceFor(id),
		})
	}
	return out
}

func sourceFor(id string) string {
	if slices.Contains(guestCollectorIDs, id) {
		return "guest"
	}
	return "host"
}

func provenanceFor(id string) string {
	if slices.Contains(guestCollectorIDs, id) {
		return string(events.GuestReported)
	}
	return string(events.HostObserved)
}

func applyGuestSensors(collectors []CollectorCoverage, hb *events.Envelope) {
	if hb == nil {
		return
	}
	list, ok := hb.Data["sensors"].([]any)
	if !ok {
		return
	}
	counts := make(map[string]int)
	for _, raw := range list {
		if entry, ok := raw.(map[string]any); ok {
			if id, ok := entry["id"].(string); ok {
				counts[id]++
			}
		}
	}
	for _, raw := range list {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		id, ok := entry["id"].(string)
		if !ok || !slices.Contains(guestCollectorIDs, id) {
			continue
		}
		for i := range collectors {
			if collectors[i].ID == id {
				if counts[id] > 1 {
					collectors[i].Reason = "duplicate sensor records in guest heartbeat"
					continue
				}
				collectors[i] = guestCoverage(entry, collectors[i])
			}
		}
	}
}

func guestCoverage(entry map[string]any, base CollectorCoverage) CollectorCoverage {
	state, _ := entry["state"].(string)
	if !validCoverageState(state) {
		return base
	}
	base.State, base.Enabled, base.Reason = state, state != CoverageDisabled, stringValue(entry, "reason")
	base.EventClasses, base.Scope = stringList(entry, "event_classes"), stringList(entry, "scope")
	base.Exclusions, base.Limitations = stringList(entry, "exclusions"), stringList(entry, "limitations")
	base.LastEventAt, base.LastSuccessAt = stringValue(entry, "last_event_at"), stringValue(entry, "last_success_at")
	base.CaptureMode = stringValue(entry, "capture_mode")
	if dropped, ok := entry["dropped"].(string); ok && events.DecimalString(dropped) {
		base.ObservedDropped = &dropped
	}
	if loss, ok := entry["unknown_loss_intervals"].(float64); ok && loss >= 0 && loss == math.Trunc(loss) && loss <= maxSafeJSONInteger {
		value := int(loss)
		base.UnknownLossIntervals = &value
	} else {
		base.State = CoverageDegraded
		base.Reason = "sensor reported an invalid unknown loss count"
	}
	return base
}

func applyHostCoverage(collectors []CollectorCoverage, records []CollectorCoverage, vm *store.VM) {
	for _, record := range records {
		if record.VMID != vm.VMID || record.BootID != vm.CurrentBootID ||
			!slices.Contains(hostCollectorIDs, record.ID) || !validCoverageState(record.State) {
			continue
		}
		for i := range collectors {
			if collectors[i].ID == record.ID {
				record.Enabled = record.State != CoverageDisabled
				record.Source, record.Provenance = "host", string(events.HostObserved)
				record.EventClasses, record.Scope = nonnil(record.EventClasses), nonnil(record.Scope)
				record.Exclusions, record.Limitations = nonnil(record.Exclusions), nonnil(record.Limitations)
				collectors[i] = record
			}
		}
	}
}

func markHostFailure(collectors []CollectorCoverage, _ error) {
	for i := range collectors {
		if slices.Contains(hostCollectorIDs, collectors[i].ID) && collectors[i].Enabled {
			collectors[i].State = CoverageUnavailable
			collectors[i].Reason = "host coverage source unavailable"
		}
	}
}

func degradeCollectorsForChannel(collectors []CollectorCoverage) {
	for i := range collectors {
		if slices.Contains(guestCollectorIDs, collectors[i].ID) && collectors[i].State == CoverageHealthy {
			collectors[i].State = CoverageDegraded
			collectors[i].Reason = "capture transport is degraded"
		}
	}
}

func coverageGaps(channel ChannelCoverage, collectors []CollectorCoverage) []string {
	gaps := make([]string, 0)
	if channel.ObservedDropped != nil && *channel.ObservedDropped != "0" {
		gaps = append(gaps, "channel:observed_loss")
	}
	for _, collector := range collectors {
		if collector.State != CoverageHealthy {
			gaps = append(gaps, collector.ID+":"+collector.State)
		}
		if (collector.ObservedDropped != nil && *collector.ObservedDropped != "0") ||
			(collector.UnknownLossIntervals != nil && *collector.UnknownLossIntervals != 0) {
			gaps = append(gaps, collector.ID+":observed_loss")
		}
	}
	return gaps
}

func validCoverageState(state string) bool {
	switch state {
	case CoverageUnavailable, CoverageUnsupported, CoverageDisabled, CoverageStarting, CoverageHealthy, CoverageDegraded:
		return true
	default:
		return false
	}
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func stringList(values map[string]any, key string) []string {
	raw, ok := values[key].([]any)
	if !ok {
		return []string{}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if value, ok := item.(string); ok {
			out = append(out, value)
		}
	}
	return out
}

func nonnil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
