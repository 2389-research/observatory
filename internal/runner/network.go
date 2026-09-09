// ABOUTME: Acquires VM-bound network sockets and joins their producers before spool close.
// ABOUTME: Refreshes live health independently of the bounded durable event consumer.
package runner

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"time"

	"github.com/2389-research/observatory/internal/events"
	"github.com/2389-research/observatory/internal/netobserve"
	"github.com/2389-research/observatory/internal/privd"
	"github.com/google/uuid"
)

// FirstObserverFD is where the jailer adapter places the first network observer
// descriptor in a launched runner: exec.Cmd's ExtraFiles begin at descriptor 3.
const FirstObserverFD = 3

// networkLoop owns the inherited descriptors for the runner's lifetime and gives
// each reader generation its own dups. It ends only with the runner: a failure
// here is one collector's failure, recorded durably and retried, never a reason
// to stop supervising a live VM.
func (r *runner) networkLoop(ctx context.Context) {
	if r.cfg.NetworkObservers == nil {
		r.networkUnavailable(r.cfg.NetworkUnavailableReason)
		r.keepNetworkStatusLive(ctx, 0)
		return
	}
	masters, err := adoptNetworkObservers(r.cfg.NetworkObservers)
	if err != nil {
		r.networkUnavailable("inherited observer descriptors are not the acquired sockets: " + err.Error())
		r.keepNetworkStatusLive(ctx, 0)
		return
	}
	defer masters.Close()
	backoff := time.Second
	for ctx.Err() == nil {
		reason := "observer read failed; unobserved retry interval"
		// Every failure re-baselines on the retained masters after the declared
		// interval: a reader generation owns only its own dups, so losing one
		// costs this runner nothing but the interval it declares.
		generation, dupErr := dupNetworkObservers(masters)
		if dupErr != nil {
			reason = "observer descriptors could not be duplicated; unobserved retry interval: " + dupErr.Error()
		} else if readErr := r.consumeNetwork(ctx, generation); readErr != nil {
			reason += ": " + readErr.Error()
		}
		if ctx.Err() != nil {
			return
		}
		r.networkUnavailable(reason)
		r.keepNetworkStatusLive(ctx, backoff)
		backoff = clampDouble(backoff, 30*time.Second)
	}
}

// networkStatusRefreshInterval re-stamps the published status well inside the
// coverage API's staleness bound.
const networkStatusRefreshInterval = time.Second

// keepNetworkStatusLive re-stamps the published status until d elapses, or for
// the rest of the runner's life when d is not positive. Only the timestamp
// moves: what each collector reports stays exactly as it was. The runner answers
// for its whole life, so a status the coverage API refuses as stale means one
// thing - the runner stopped answering.
func (r *runner) keepNetworkStatusLive(ctx context.Context, d time.Duration) {
	ticker := time.NewTicker(networkStatusRefreshInterval)
	defer ticker.Stop()
	var until <-chan time.Time
	if d > 0 {
		timer := time.NewTimer(d)
		defer timer.Stop()
		until = timer.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-until:
			return
		case <-ticker.C:
			r.networkMu.Lock()
			r.network.UpdatedAt = time.Now().UTC()
			r.networkMu.Unlock()
		}
	}
}

func (r *runner) consumeNetwork(ctx context.Context, bundle *privd.NetworkObserverBundle) error {
	defer bundle.Close()
	b := bundle.Binding
	cfg := netobserve.ReaderConfig{QueueCapacity: 128, BaselineTimeout: 10 * time.Second, TrackerLimits: netobserve.Limits{MaxFlows: 4096, MaxGroups: 1, IdleTimeout: 5 * time.Minute}}
	sourceIDs := make([]string, len(bundle.Sockets))
	for i, s := range bundle.Sockets {
		sourceIDs[i] = uuid.NewString()
		cfg.Sources = append(cfg.Sources, netobserve.SourceConfig{
			ID:   sourceIDs[i],
			File: bundle.Files[i],
			Scope: netobserve.Scope{
				VMID: b.VMID, BootID: b.GuestBootID, HostBootID: b.HostBootID,
				Generation:  b.AcquisitionID,
				NamespaceID: b.NamespaceDevice + ":" + b.NamespaceInode,
				Boundary:    s.Boundary,
			},
			Kind:             netobserve.SourceKind(s.Kind),
			PortID:           s.PortID,
			SnapshotSequence: s.SnapshotSequence,
			NFLogGroup:       s.Group,
			DenialPrefixes:   NetworkDenialPrefixes(s.Kind, s.Boundary),
		})
	}
	acquired, err := NetworkStatusAtAcquisition(NewNetworkStatus(r.cfg.VMID, r.cfg.BootID, r.cfg.InstanceID, "network observer not acquired", time.Now()), bundle, sourceIDs, time.Now())
	if err != nil {
		return err
	}
	r.networkMu.Lock()
	r.network = acquired
	r.networkMu.Unlock()
	reader, err := netobserve.NewReader(ctx, cfg)
	if err != nil {
		return err
	}
	bundle.Files = nil // Reader now owns the descriptors, including on cancellation.
	health := make(chan NetworkStatus, 1)
	writerDone := make(chan struct{})
	go func() { defer close(writerDone); r.networkWriter(reader.Observations(), health) }()
	// Closing the reader closes observations; writer joins before this acquisition returns.
	defer func() {
		_ = reader.Close()
		r.refreshNetwork(reader.Status())
		offerNetworkHealth(health, r.networkStatus())
		close(health)
		<-writerDone
	}()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		reason, failed := r.refreshNetwork(reader.Status())
		snapshot := r.networkStatus()
		offerNetworkHealth(health, snapshot)
		if failed {
			// The reason a failing source published is what the retry interval
			// must name; a constant here would hide the kernel's own message.
			return errors.New(reason)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// refreshNetwork republishes live collector health and returns the reason the
// first failing source gave, so the caller can name it without re-deriving it.
func (r *runner) refreshNetwork(status netobserve.ReaderStatus) (string, bool) {
	r.networkMu.Lock()
	defer r.networkMu.Unlock()
	r.network.UpdatedAt = time.Now().UTC()
	failed, reason := false, ""
	for _, s := range status.Sources {
		for i := range r.network.Collectors {
			c := &r.network.Collectors[i]
			if c.SourceInstanceID != s.ID {
				continue
			}
			mapped, sourceFailed := NetworkCollectorFromSource(*c, s)
			if sourceFailed && !failed {
				reason = mapped.Reason
			}
			failed = failed || sourceFailed
			if r.networkSpoolError {
				mapped.State = "degraded"
				mapped.Reason = "network spool append failed"
			}
			*c = mapped
		}
	}
	return reason, failed
}

func (r *runner) networkWriter(observations <-chan netobserve.Observation, health <-chan NetworkStatus) {
	sequences := map[string]uint64{}
	lastHealth := time.Time{}
	lastFacts := ""
	lastLoss := map[string]string{}
	for observations != nil || health != nil {
		select {
		case status, ok := <-health:
			if !ok {
				health = nil
				continue
			}
			facts := make([]NetworkCollectorStatus, len(status.Collectors))
			copy(facts, status.Collectors)
			for i := range facts {
				facts[i].LastEventAt = nil
				facts[i].LastSuccessAt = nil
			}
			encoded, _ := json.Marshal(facts)
			if string(encoded) == lastFacts && time.Since(lastHealth) < 5*time.Second {
				continue
			}
			lastHealth = time.Now()
			lastFacts = string(encoded)
			for _, c := range status.Collectors {
				data := networkHealthData(status, c)
				r.persistNetwork("net.collector.health", c.SourceInstanceID, sequences, data, time.Now())
				lossFacts := c.DroppedCount + ":" + c.UnknownIntervals
				if (c.DroppedCount != "0" || c.UnknownIntervals != "0") && lastLoss[c.SourceInstanceID] != lossFacts {
					lastLoss[c.SourceInstanceID] = lossFacts
					data["count_semantics"] = "cumulative_for_source_acquisition"
					r.persistNetwork("net.collector.loss", c.SourceInstanceID, sequences, data, time.Now())
				}
			}
		case o, ok := <-observations:
			if !ok {
				observations = nil
				continue
			}
			status := r.networkStatus()
			for _, f := range o.Result.Flows {
				data := networkFlowData(f)
				for k, v := range networkIdentity(status, o.Result.Scope.Boundary) {
					data[k] = v
				}
				r.persistNetwork("net.flow.observed", o.SourceID, sequences, data, o.ObservedAt)
			}
			for _, d := range o.Result.Denials {
				data := networkDenialData(d)
				for k, v := range networkIdentity(status, o.Result.Scope.Boundary) {
					data[k] = v
				}
				r.persistNetwork("policy.denial", o.SourceID, sequences, data, o.ObservedAt)
			}
			// Loss classes with no status counter still reach durable evidence.
			if len(o.Result.Losses) > 0 {
				data := networkIdentity(status, o.Result.Scope.Boundary)
				data["count_semantics"] = "single_observation"
				data["loss_class_count"] = strconv.Itoa(len(o.Result.Losses))
				data["losses"] = networkLosses(o.Result.Losses)
				r.persistNetwork("net.collector.loss", o.SourceID, sequences, data, o.ObservedAt)
			}
		}
	}
}

// networkHealthData is the only shape net.collector.health ever takes: the
// network identity fields plus exactly one collector, reason included.
func networkHealthData(status NetworkStatus, c NetworkCollectorStatus) map[string]any {
	data := networkIdentity(status, c.Boundary)
	data["collector"] = c
	return data
}

func networkIdentity(s NetworkStatus, boundary string) map[string]any {
	return map[string]any{
		"runner_instance_id":      s.InstanceID,
		"acquisition_id":          s.AcquisitionID,
		"gateway_generation":      s.GatewayGeneration,
		"host_boot_id":            s.HostBootID,
		"namespace_identity_role": "vm_gateway_ownership",
		"namespace_device":        s.NamespaceDevice,
		"namespace_inode":         s.NamespaceInode,
		"policy_id":               s.PolicyID,
		"policy_digest":           s.PolicyDigest,
		"profile":                 s.Profile,
		"boundary":                boundary,
	}
}
func (r *runner) persistNetwork(kind, source string, sequences map[string]uint64, data map[string]any, at time.Time) {
	sequences[source]++
	env := r.newEnvelope(kind, data)
	env.SourceInstanceID = source
	env.SourceSeq = strconv.FormatUint(sequences[source], 10)
	env.HostReceivedAt = events.Timestamp{Time: at.UTC()}
	env.Quality.Attribution = events.AttributionUnknown
	err := r.sw.Append(env)
	r.networkMu.Lock()
	defer r.networkMu.Unlock()
	if err != nil {
		r.networkSpoolError = true
		for i := range r.network.Collectors {
			r.network.Collectors[i].State = "degraded"
			r.network.Collectors[i].Reason = "network spool append failed"
		}
		return
	}
	if kind == "net.flow.observed" || kind == "policy.denial" {
		for i := range r.network.Collectors {
			if r.network.Collectors[i].SourceInstanceID == source {
				v := at.UTC()
				r.network.Collectors[i].LastEventAt = &v
			}
		}
	}
}

// maxNetworkLossClasses bounds one durable loss record. loss_class_count reports
// how many classes the observation carried, so truncation is never silent.
const maxNetworkLossClasses = 8

func networkLosses(losses []netobserve.Loss) []map[string]string {
	out := make([]map[string]string, 0, maxNetworkLossClasses)
	for _, loss := range losses {
		if len(out) == maxNetworkLossClasses {
			break
		}
		entry := map[string]string{"reason": loss.Reason, "count": "1"}
		if loss.Count != nil {
			entry["count"] = strconv.FormatUint(*loss.Count, 10)
		}
		out = append(out, entry)
	}
	return out
}

func networkCountSum(values ...uint64) string {
	var total, value big.Int
	for _, n := range values {
		value.SetUint64(n)
		total.Add(&total, &value)
	}
	return total.String()
}

// Replace a stale pending snapshot; health never competes for observation queue slots.
func offerNetworkHealth(ch chan NetworkStatus, status NetworkStatus) {
	select {
	case ch <- status:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- status:
	default:
	}
}
