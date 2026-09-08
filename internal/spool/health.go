// ABOUTME: Bounded import diagnostics and per-VM retry scheduling.
// ABOUTME: Reports each failure episode once through the service attention policy.
package spool

import (
	"context"
	"math"
	"strconv"
	"time"

	"github.com/2389-research/observatory/internal/events"
)

// ImportStatus is a fixed-size snapshot; counters use decimal strings on the wire.
// An empty LastSuccessAt means no successful cycle has been observed this process.
type ImportStatus struct {
	State               string `json:"state"`
	LastError           string `json:"last_error"`
	ConsecutiveFailures string `json:"consecutive_failures"`
	LastSuccessAt       string `json:"last_success_at"`
	NextRetryAt         string `json:"next_retry_at"`
}

type importHealth struct {
	ImportStatus
	failures uint64
	next     time.Time
	notified bool
}

// Status returns one VM's diagnostics, or root-directory diagnostics for an empty id.
// Health is process-local; restart reports unknown until a cycle actually runs.
func (imp *Importer) Status(vmID string) ImportStatus {
	imp.mu.RLock()
	defer imp.mu.RUnlock()
	h, ok := imp.health[vmID]
	if !ok {
		return ImportStatus{State: "unknown", ConsecutiveFailures: "0"}
	}
	return h.ImportStatus
}

func (imp *Importer) due(id string) bool {
	imp.mu.RLock()
	defer imp.mu.RUnlock()
	return !time.Now().Before(imp.health[id].next)
}

func (imp *Importer) record(ctx context.Context, id string, cause error) {
	if ctx.Err() != nil {
		return
	}
	now := time.Now().UTC()
	imp.mu.Lock()
	h := imp.health[id]
	if cause == nil {
		h = importHealth{ImportStatus: ImportStatus{State: "healthy", ConsecutiveFailures: "0", LastSuccessAt: now.Format(events.TimestampLayout)}}
	} else {
		if h.failures < math.MaxUint64 {
			h.failures++
		}
		h.State = "degraded"
		h.ConsecutiveFailures = strconv.FormatUint(h.failures, 10)
		h.LastError = string([]rune(cause.Error())[:min(len([]rune(cause.Error())), 512)])
		delay := min(imp.interval, time.Minute)
		for n := uint64(1); n < h.failures && delay < time.Minute; n++ {
			delay = min(delay*2, time.Minute)
		}
		h.next = now.Add(delay)
		h.NextRetryAt = h.next.Format(events.TimestampLayout)
	}
	imp.health[id] = h
	imp.mu.Unlock()
	if cause == nil || h.notified {
		return
	}
	if imp.reportFailure == nil {
		return
	}
	err := imp.reportFailure(ctx, id, h.ImportStatus)
	if err == nil {
		imp.mu.Lock()
		h = imp.health[id]
		h.notified = true
		imp.health[id] = h
		imp.mu.Unlock()
	}
}

// SetFailureReporter connects incident delivery to the service's attention policy.
// Returning nil marks this episode handled, including deliberately disabled or
// queue-refused attention. Failures are retried on the VM's next scheduled attempt.
func (imp *Importer) SetFailureReporter(report func(context.Context, string, ImportStatus) error) {
	imp.cycleMu.Lock()
	defer imp.cycleMu.Unlock()
	imp.reportFailure = report
}
