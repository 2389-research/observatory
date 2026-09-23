// ABOUTME: Outage describes an interval in which the spool writer refused records,
// ABOUTME: and renders it as the payload of the telemetry.loss that records it.
package spool

import (
	"strconv"
	"time"

	"github.com/2389-research/observatory/internal/events"
)

// maxCauseRunes bounds an error text kept for an operator: an outage's cause
// and the importer's last error.
const maxCauseRunes = 512

// Outage describes an interval in which the writer refused records.
type Outage struct {
	Since, Until         time.Time
	Cause                string // the first refusal's error, bounded to 512 runes
	RunnerRecordsRefused uint64 // refused envelopes whose Provenance is not guest_reported
	GuestPushesRefused   uint64 // refused envelopes whose Provenance is guest_reported
}

// Data returns the telemetry.loss payload. Every value is a string, because
// the counts can pass JavaScript's safe integers. guest_events_lost is
// "unknown" once any guest push was refused: the guest's bounded ring may
// have overwritten events while the runner refused them, and SPEC §12.5
// forbids inventing a count.
func (o Outage) Data() map[string]any {
	lost := "0"
	if o.GuestPushesRefused > 0 {
		lost = "unknown"
	}
	return map[string]any{
		"cause":                  o.Cause,
		"interval_start":         o.Since.UTC().Format(events.TimestampLayout),
		"interval_end":           o.Until.UTC().Format(events.TimestampLayout),
		"runner_records_refused": strconv.FormatUint(o.RunnerRecordsRefused, 10),
		"guest_pushes_refused":   strconv.FormatUint(o.GuestPushesRefused, 10),
		"guest_events_lost":      lost,
	}
}

// boundRunes returns the first n runes of s.
func boundRunes(s string, n int) string {
	r := []rune(s)
	return string(r[:min(len(r), n)])
}
