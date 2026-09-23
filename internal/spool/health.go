// ABOUTME: Bounded import diagnostics and per-VM retry scheduling.
// ABOUTME: Reports each failure episode once through the service attention policy.
package spool

import (
	"context"
	"math"
	"path/filepath"
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
	// Writer is the VM's spool writer health as its status file read at the
	// last cycle, or unknown before a cycle read it. The root status has none.
	Writer *WriterHealth `json:"writer,omitempty"`
}

type importHealth struct {
	ImportStatus
	failures uint64
	next     time.Time
	notified bool
}

// writerRead is the last writer status a cycle read for one VM, and the
// Since of the failing outage already reported for it, if any.
type writerRead struct {
	health   WriterHealth
	reported string
}

// UnobservedStatus is the diagnostic a VM (non-empty vmID) or the root
// directory (empty vmID) reports before any cycle has run: state unknown,
// zero consecutive failures, and for a VM a writer that is itself unknown
// because no cycle has read its status file yet. Both Importer.Status and
// situation.Engine.ImporterStatus start here, so a wired and an absent
// importer never disagree about a VM's unobserved shape.
func UnobservedStatus(vmID string) ImportStatus {
	s := ImportStatus{State: "unknown", ConsecutiveFailures: "0"}
	if vmID != "" {
		s.Writer = &WriterHealth{State: "unknown"}
	}
	return s
}

// Status returns one VM's diagnostics, or root-directory diagnostics for an empty id.
// Health is process-local; restart reports unknown until a cycle actually runs.
func (imp *Importer) Status(vmID string) ImportStatus {
	imp.mu.RLock()
	defer imp.mu.RUnlock()
	s := UnobservedStatus(vmID)
	if h, ok := imp.health[vmID]; ok {
		s = h.ImportStatus
	}
	if vmID != "" {
		w := WriterHealth{State: "unknown"}
		if r, ok := imp.writers[vmID]; ok {
			w = r.health
		}
		s.Writer = &w
	}
	return s
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
		h.LastError = boundRunes(cause.Error(), maxCauseRunes)
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

// observeWriter reads the VM's writer status for Status. A failing status
// whose Since has not been reported yet is reported, and a nil return marks
// that outage reported. A healthy read ends the outage; an unknown read
// changes nothing, because a missing or torn status is no evidence that the
// writer recovered.
func (imp *Importer) observeWriter(ctx context.Context, id string) {
	h := readStatus(filepath.Join(imp.root, id))
	imp.mu.Lock()
	r := imp.writers[id]
	r.health = h
	if h.State == "healthy" {
		r.reported = ""
	}
	imp.writers[id] = r
	imp.mu.Unlock()
	if h.State != "failing" || h.Since == r.reported || imp.reportWriterFailure == nil {
		return
	}
	if imp.reportWriterFailure(ctx, id, h) == nil {
		imp.mu.Lock()
		r = imp.writers[id]
		r.reported = h.Since
		imp.writers[id] = r
		imp.mu.Unlock()
	}
}

// SetWriterFailureReporter connects the report of a failing spool writer to
// the service's attention policy. The importer calls it once per outage,
// named by the outage's Since. Returning nil marks the outage handled; an
// error leaves it to be reported again on the next cycle.
func (imp *Importer) SetWriterFailureReporter(report func(context.Context, string, WriterHealth) error) {
	imp.cycleMu.Lock()
	defer imp.cycleMu.Unlock()
	imp.reportWriterFailure = report
}
