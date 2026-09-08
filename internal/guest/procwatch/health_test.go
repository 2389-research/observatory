// ABOUTME: Verifies process capture loss remains measurable and distinct across collector failures.
// ABOUTME: Uses the real shared reporter and queue without network or syscall mocks.
package procwatch

import (
	"errors"
	"github.com/2389-research/observatory/internal/guest/telemetry"
	"testing"
)

func TestLossPreservesMeasuredCountAcrossRestart(t *testing.T) {
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 32})
	h := newHealth(r)
	reportLoss(r, &h, 5, "kernel_output_failure")
	h = newHealth(r)
	if h.Dropped != "5" || h.State != telemetry.SensorDegraded {
		t.Fatalf("lost history %+v", h)
	}
}
func TestRepeatedFailureDoesNotInventKnownDropCount(t *testing.T) {
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 32})
	h := newHealth(r)
	reportLoss(r, &h, 5, "output")
	reportFailure(r, &h, errors.New("read failed"))
	reportFailure(r, &h, errors.New("read failed"))
	if h.Dropped != "5" || h.UnknownLossIntervals != 1 || h.State != telemetry.SensorUnavailable {
		t.Fatalf("failure health: %+v", h)
	}
}
