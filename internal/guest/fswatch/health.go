// ABOUTME: Preserves collector loss history across reopen attempts and bounds queued payloads.
// ABOUTME: Reports exact sensor-side oversize drops separately from unknown kernel loss.
package fswatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"syscall"

	"github.com/2389-research/observatory/internal/guest/telemetry"
)

var errPayloadLimit = errors.New("filesystem event exceeds 48 KiB telemetry budget")

func restoreHealth(r *telemetry.Reporter) telemetry.Sensor {
	h := telemetry.Sensor{ID: "filesystem", Dropped: "0"}
	for _, old := range r.Sensors().Snapshot() {
		if old.ID == h.ID {
			h.State = old.State
			h.Reason = old.Reason
			h.UnknownLossIntervals = old.UnknownLossIntervals
			h.Dropped = old.Dropped
			h.LastEventAt = old.LastEventAt
		}
	}
	return h
}
func push(r *telemetry.Reporter, h *telemetry.Sensor, kind string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > 48*1024 {
		if h.Dropped != "" {
			n, _ := strconv.ParseUint(h.Dropped, 10, 64)
			h.Dropped = strconv.FormatUint(n+1, 10)
		}
		h.State = telemetry.SensorDegraded
		h.Reason = errPayloadLimit.Error()
		r.Ring().Push("fs.loss", json.RawMessage(`{"sensor":"filesystem","reason":"payload_limit","lost_count":1,"count_quality":"measured"}`))
		return errPayloadLimit
	}
	r.Ring().Push(kind, b)
	return nil
}

func recordFailure(r *telemetry.Reporter, h *telemetry.Sensor, err error) {
	if unsupportedError(err) {
		h.State = telemetry.SensorUnsupported
		h.Reason = err.Error()
		r.Sensors().Set(*h)
		return
	}
	newInterval := h.State != telemetry.SensorUnavailable
	if newInterval {
		h.UnknownLossIntervals++
	}
	h.State = telemetry.SensorUnavailable
	h.Reason = err.Error()
	if !newInterval {
		r.Sensors().Set(*h)
		return
	}
	// Failure reasons are collector errors; names remain in mutation evidence.
	loss := map[string]any{"sensor": "filesystem", "reason": "collector_failure", "detail": coverageLabel(err.Error()), "lost_count": nil, "count_quality": "unknown"}
	b, _ := json.Marshal(loss)
	r.Ring().Push("fs.loss", b)
	r.Sensors().Set(*h)
}

func unsupportedError(err error) bool {
	return errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EOPNOTSUPP)
}

func normalizeInitError(err error) error {
	if errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("kernel does not support required fanotify report flags: %w", syscall.EOPNOTSUPP)
	}
	return err
}

func markHealthy(h *telemetry.Sensor) {
	h.State = telemetry.SensorHealthy
	h.Reason = ""
}

func coverageFingerprint(h telemetry.Sensor) string {
	current := struct {
		State                string
		Dropped              string
		UnknownLossIntervals int
		CaptureMode          string
		EventClasses         []string
		Scope                []string
		Exclusions           []string
		Limitations          []string
		Reason               string
	}{h.State, h.Dropped, h.UnknownLossIntervals, h.CaptureMode, h.EventClasses, h.Scope, h.Exclusions, h.Limitations, h.Reason}
	b, _ := json.Marshal(current)
	return string(b)
}
