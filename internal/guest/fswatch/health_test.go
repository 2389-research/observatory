// ABOUTME: Verifies collector restarts preserve recorded gaps and bounded payload loss.
// ABOUTME: Uses the real telemetry registry and ring without mocked kernel behavior.
package fswatch

import (
	"errors"
	"github.com/2389-research/observatory/internal/guest/telemetry"
	"strings"
	"syscall"
	"testing"
)

func TestRestoreHealthRetainsLossHistory(t *testing.T) {
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 8})
	r.Sensors().Set(telemetry.Sensor{ID: "filesystem", UnknownLossIntervals: 3, Dropped: "", LastEventAt: "previous"})
	h := restoreHealth(r)
	if h.UnknownLossIntervals != 3 || h.Dropped != "" || h.LastEventAt != "previous" {
		t.Fatalf("forgot loss: %+v", h)
	}
}
func TestPayloadLimitEmitsMeasuredLoss(t *testing.T) {
	r := telemetry.NewReporter(telemetry.ReporterConfig{})
	h := telemetry.Sensor{ID: "filesystem", Dropped: "0"}
	if err := push(r, &h, "fs.create", map[string]string{"path": strings.Repeat("x", 64*1024)}); !errors.Is(err, errPayloadLimit) {
		t.Fatalf("oversize: %v", err)
	}
	item, ok := r.Ring().Next()
	if !ok || item.Kind != "fs.loss" || h.Dropped != "1" {
		t.Fatalf("missing measured loss: %+v %+v", item, h)
	}
}

func TestFailureIsDurableEvenBeforeNextHeartbeat(t *testing.T) {
	r := telemetry.NewReporter(telemetry.ReporterConfig{})
	h := telemetry.Sensor{ID: "filesystem", Dropped: "5"}
	recordFailure(r, &h, errors.New("read failed"))
	item, ok := r.Ring().Next()
	if !ok || item.Kind != "fs.loss" || h.UnknownLossIntervals != 1 || h.Dropped != "5" {
		t.Fatalf("failure missing: %+v %+v", item, h)
	}
}

func TestOneOutageCountsOnceUntilRecovery(t *testing.T) {
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 8})
	h := telemetry.Sensor{ID: "filesystem", State: telemetry.SensorStarting, Dropped: "0"}
	recordFailure(r, &h, errors.New("read failed"))
	recordFailure(r, &h, errors.New("read still failed"))
	if h.UnknownLossIntervals != 1 {
		t.Fatalf("one outage counted %d intervals", h.UnknownLossIntervals)
	}
	items := 0
	for {
		item, ok := r.Ring().Next()
		if !ok {
			break
		}
		items++
		r.Ring().AckThrough(item.Seq)
	}
	if items != 1 {
		t.Fatalf("one outage emitted %d loss records", items)
	}
	markHealthy(&h)
	recordFailure(r, &h, errors.New("failed after recovery"))
	if h.UnknownLossIntervals != 2 {
		t.Fatalf("second outage count = %d, want 2", h.UnknownLossIntervals)
	}
}

func TestRecoveryKeepsHistoryButRestoresCurrentHealth(t *testing.T) {
	h := telemetry.Sensor{ID: "filesystem", State: telemetry.SensorUnavailable, Dropped: "4", UnknownLossIntervals: 2, Reason: "old failure"}
	markHealthy(&h)
	if h.State != telemetry.SensorHealthy || h.Reason != "" || h.Dropped != "4" || h.UnknownLossIntervals != 2 {
		t.Fatalf("recovery conflated history and current state: %+v", h)
	}
}

func TestUnsupportedCapabilityIsNotInventedLoss(t *testing.T) {
	r := telemetry.NewReporter(telemetry.ReporterConfig{})
	h := telemetry.Sensor{ID: "filesystem", State: telemetry.SensorStarting, Dropped: "0"}
	recordFailure(r, &h, syscall.ENOSYS)
	if h.State != telemetry.SensorUnsupported || h.UnknownLossIntervals != 0 {
		t.Fatalf("unsupported capability = %+v", h)
	}
}

func TestUnsupportedFanotifyInitFlagsAreClassifiedAtTheCallSite(t *testing.T) {
	if err := normalizeInitError(syscall.EINVAL); !unsupportedError(err) {
		t.Fatalf("EINVAL from fixed fanotify flags = %v, want unsupported", err)
	}
	if err := normalizeInitError(syscall.EPERM); unsupportedError(err) {
		t.Fatalf("EPERM = %v, want unavailable host capability", err)
	}
}

func TestCoverageFingerprintTracksStateButNotRefreshTime(t *testing.T) {
	h := telemetry.Sensor{ID: "filesystem", State: telemetry.SensorDegraded, Scope: []string{"/workspace"}, LastSuccessAt: "first"}
	first := coverageFingerprint(h)
	h.LastSuccessAt = "second"
	if got := coverageFingerprint(h); got != first {
		t.Fatalf("refresh timestamp changed coverage fingerprint: %q != %q", got, first)
	}
	h.State = telemetry.SensorHealthy
	if got := coverageFingerprint(h); got == first {
		t.Fatal("recovery did not change coverage fingerprint")
	}
}
