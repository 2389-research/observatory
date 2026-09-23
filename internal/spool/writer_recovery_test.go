// ABOUTME: White-box tests for how the spool writer survives a failed append: it abandons the
// ABOUTME: damaged segment, not itself, and writes a telemetry.loss in front of the next record.
package spool

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/2389-research/observatory/internal/events"
)

// The spool these tests write: its VM, the stream its records belong to, and
// the stream its loss records are filed under.
const (
	recoveryVMID       = "3f6c1a2e-8d4b-4c7a-9e5f-1b2c3d4e5f60"
	recoveryInstanceID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
	recoveryLossStream = "0b1c2d3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e"
)

// recoveryLossSeq numbers the loss records these tests build, from 1.
var recoveryLossSeq atomic.Uint64

// recoveryLoss is the tests' WriterCfg.LossRecord: a host_observed
// telemetry.loss from the runner sensor that carries the outage's payload.
func recoveryLoss(o Outage) *events.Envelope {
	vmID := recoveryVMID
	return &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vmID,
		SourceInstanceID: recoveryLossStream,
		SourceSeq:        strconv.FormatUint(recoveryLossSeq.Add(1), 10),
		Kind:             "telemetry.loss",
		Provenance:       events.HostObserved,
		Sensor:           Sensor,
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: o.Data(),
	}
}

// recoveryRecord builds record seq with provenance p. The writer counts a
// refused guest_reported record as a guest push and any other as a runner
// record.
func recoveryRecord(p events.Provenance, seq int) *events.Envelope {
	vmID := recoveryVMID
	kind := "vm.vmm_exited"
	if p == events.GuestReported {
		kind = "guest.sensor_health"
	}
	return &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vmID,
		SourceInstanceID: recoveryInstanceID,
		SourceSeq:        strconv.Itoa(seq),
		Kind:             kind,
		Provenance:       p,
		Sensor:           "test",
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: map[string]any{"seq": seq},
	}
}

func guestPush(seq int) *events.Envelope    { return recoveryRecord(events.GuestReported, seq) }
func runnerRecord(seq int) *events.Envelope { return recoveryRecord(events.HostObserved, seq) }

// openRecoveryWriter opens a writer on dir with 4 MiB segments and the given
// quota; 0 means DefaultMaxSpoolBytes.
func openRecoveryWriter(t *testing.T, dir string, quota int64) *Writer {
	t.Helper()
	w, err := OpenWriter(dir, WriterCfg{
		VMID:            recoveryVMID,
		InstanceID:      recoveryInstanceID,
		MaxSegmentBytes: 4 << 20,
		MaxSpoolBytes:   quota,
		LossRecord:      recoveryLoss,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	return w
}

// segPath names segment idx in dir.
func segPath(dir string, idx uint64) string {
	return filepath.Join(dir, segmentName(idx))
}

// fillQuota creates a sparse ballast.vmsp as large as the quota. The writer
// counts every *.vmsp file toward the quota, so the spool is then full while
// the disk is not.
func fillQuota(t *testing.T, dir string, quota int64) string {
	t.Helper()
	ballast := filepath.Join(dir, "ballast.vmsp")
	f, err := os.Create(ballast)
	if err != nil {
		t.Fatalf("create ballast: %v", err)
	}
	if err := f.Truncate(quota); err != nil {
		t.Fatalf("size ballast: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close ballast: %v", err)
	}
	return ballast
}

// lockDir makes dir read-only, so creating a segment in it fails with a real
// EACCES, and makes it writable again when the test ends so TempDir can
// clean up. Root ignores the mode; callers skip as root.
func lockDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod 0500: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

// segmentFrames parses a segment strictly: its header line, then whole frames
// with good checksums, then nothing or the end marker as the last 4 bytes.
// Anything else fails the test, where ReadSegment would read a damaged tail
// as a clean end.
func segmentFrames(t *testing.T, name string) (envs []*events.Envelope, marker bool) {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read segment: %v", err)
	}
	base := filepath.Base(name)
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 {
		t.Fatalf("%s has no header line", base)
	}
	var hdr segmentHeader
	if err := json.Unmarshal(raw[:nl], &hdr); err != nil || hdr.Magic != segmentMagic {
		t.Fatalf("%s header %q: %v", base, raw[:nl], err)
	}
	rest := raw[nl+1:]
	for len(rest) > 0 {
		if len(rest) < 4 {
			t.Fatalf("%s ends in %d stray bytes", base, len(rest))
		}
		n := binary.BigEndian.Uint32(rest)
		if n == endMarker {
			if len(rest) != 4 {
				t.Fatalf("%s has %d bytes after its end marker", base, len(rest)-4)
			}
			return envs, true
		}
		end := 8 + int(n)
		if len(rest) < end {
			t.Fatalf("%s ends in a partial frame: %d of %d bytes", base, len(rest), end)
		}
		body := rest[8:end]
		if crc32.Checksum(body, crc32cTable) != binary.BigEndian.Uint32(rest[4:]) {
			t.Fatalf("%s frame %d fails its checksum", base, len(envs))
		}
		var env events.Envelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("%s frame %d: %v", base, len(envs), err)
		}
		envs = append(envs, &env)
		rest = rest[end:]
	}
	return envs, false
}

// label names an envelope by kind and source_seq for failure messages.
func label(e *events.Envelope) string {
	return e.Kind + "#" + e.SourceSeq
}

// describe lists envelopes by label for failure messages.
func describe(envs []*events.Envelope) string {
	labels := make([]string, len(envs))
	for i, e := range envs {
		labels[i] = label(e)
	}
	return "[" + strings.Join(labels, " ") + "]"
}

// lossThenRecord asserts envs is exactly a telemetry.loss followed by record
// seq, and returns the loss's payload.
func lossThenRecord(t *testing.T, envs []*events.Envelope, seq string) map[string]any {
	t.Helper()
	if len(envs) != 2 || envs[0].Kind != "telemetry.loss" ||
		envs[1].Kind == "telemetry.loss" || envs[1].SourceSeq != seq {
		t.Fatalf("segment holds %s, want [telemetry.loss, record %s]", describe(envs), seq)
	}
	return envs[0].Data
}

// checkLoss compares the named fields of a loss payload.
func checkLoss(t *testing.T, data map[string]any, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if data[k] != v {
			t.Errorf("loss %s = %v, want %q", k, data[k], v)
		}
	}
}

// checkInterval asserts the loss interval parses and does not run backwards.
func checkInterval(t *testing.T, data map[string]any) {
	t.Helper()
	start, err := time.Parse(events.TimestampLayout, fmt.Sprint(data["interval_start"]))
	if err != nil {
		t.Fatalf("interval_start: %v", err)
	}
	end, err := time.Parse(events.TimestampLayout, fmt.Sprint(data["interval_end"]))
	if err != nil {
		t.Fatalf("interval_end: %v", err)
	}
	if end.Before(start) {
		t.Errorf("interval_end %s is before interval_start %s", data["interval_end"], data["interval_start"])
	}
}

// A failed write damages the segment, not the writer: the next append moves
// to a new segment and puts a telemetry.loss in front of its record.
func TestWriteFailureMovesToNewSegment(t *testing.T) {
	dir := t.TempDir()
	w := openRecoveryWriter(t, dir, 0)
	for seq := 1; seq <= 2; seq++ {
		if err := w.Append(runnerRecord(seq)); err != nil {
			t.Fatalf("append record %d: %v", seq, err)
		}
	}
	// With its fd closed behind the writer's back, the next write fails
	// with a real error from the os package.
	if err := w.f.Close(); err != nil {
		t.Fatalf("close the segment's fd: %v", err)
	}
	if err := w.Append(guestPush(3)); err == nil {
		t.Fatal("append to a closed fd succeeded")
	}
	if w.outage == nil {
		t.Fatal("the failed append opened no outage")
	}
	if w.outage.GuestPushesRefused != 1 || w.outage.RunnerRecordsRefused != 0 {
		t.Fatalf("outage counts %d guest pushes and %d runner records, want 1 and 0",
			w.outage.GuestPushesRefused, w.outage.RunnerRecordsRefused)
	}

	if err := w.Append(runnerRecord(4)); err != nil {
		t.Fatalf("append after the failed write: %v", err)
	}
	envs, _ := segmentFrames(t, segPath(dir, 1))
	loss := lossThenRecord(t, envs, "4")
	checkLoss(t, loss, map[string]string{
		"guest_pushes_refused":   "1",
		"runner_records_refused": "0",
		"guest_events_lost":      "unknown",
	})
	if cause := fmt.Sprint(loss["cause"]); !strings.Contains(cause, "write record") {
		t.Errorf("loss cause %q does not name the failed write", cause)
	}
	checkInterval(t, loss)

	// The retire could not use the closed fd, so the old segment keeps its
	// records and reads as crashed.
	old, marker := segmentFrames(t, segPath(dir, 0))
	if len(old) != 2 || marker {
		t.Errorf("%s holds %s, end marker %v; want its 2 records and no marker",
			segmentName(0), describe(old), marker)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// A full quota refuses records without damaging the segment, so the loss and
// the next record land in the same segment once space returns.
func TestQuotaOutageRecoversInSameSegment(t *testing.T) {
	dir := t.TempDir()
	const quota = 64 << 10
	w := openRecoveryWriter(t, dir, quota)
	if err := w.Append(runnerRecord(1)); err != nil {
		t.Fatalf("append record 1: %v", err)
	}
	ballast := fillQuota(t, dir, quota)
	for _, env := range []*events.Envelope{guestPush(2), guestPush(3), runnerRecord(4)} {
		if err := w.Append(env); !errors.Is(err, ErrSpoolFull) {
			t.Fatalf("append %s over the quota: %v, want ErrSpoolFull", label(env), err)
		}
	}
	if err := os.Remove(ballast); err != nil {
		t.Fatalf("remove the ballast: %v", err)
	}
	if err := w.Append(runnerRecord(5)); err != nil {
		t.Fatalf("append once the quota has room: %v", err)
	}

	if _, err := os.Stat(segPath(dir, 1)); !os.IsNotExist(err) {
		t.Errorf("a quota refusal moved the writer on to %s (stat: %v)", segmentName(1), err)
	}
	envs, _ := segmentFrames(t, segPath(dir, 0))
	if len(envs) != 3 || envs[0].Kind == "telemetry.loss" || envs[0].SourceSeq != "1" {
		t.Fatalf("%s holds %s, want [record 1, telemetry.loss, record 5]", segmentName(0), describe(envs))
	}
	loss := lossThenRecord(t, envs[1:], "5")
	checkLoss(t, loss, map[string]string{
		"guest_pushes_refused":   "2",
		"runner_records_refused": "1",
		"guest_events_lost":      "unknown",
	})
	if cause := fmt.Sprint(loss["cause"]); !strings.Contains(cause, "spool full") {
		t.Errorf("loss cause %q, want the quota refusal", cause)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// Each failed advance burns its segment index, so no retry reuses a name a
// failed create may have left behind. Once the dir is writable again the
// writer lands in the next unused index, and the loss counts every refusal.
func TestFailedAdvancesBurnIndices(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root creates files in a read-only directory")
	}
	dir := t.TempDir()
	w := openRecoveryWriter(t, dir, 0)
	if err := w.Append(runnerRecord(1)); err != nil {
		t.Fatalf("append record 1: %v", err)
	}
	if err := w.f.Close(); err != nil {
		t.Fatalf("close the segment's fd: %v", err)
	}
	if err := w.Append(guestPush(2)); err == nil {
		t.Fatal("append to a closed fd succeeded")
	}
	lockDir(t, dir)
	for _, env := range []*events.Envelope{runnerRecord(3), guestPush(4)} {
		if err := w.Append(env); err == nil {
			t.Fatalf("append %s with a read-only spool dir succeeded", label(env))
		}
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod 0700: %v", err)
	}
	if err := w.Append(runnerRecord(5)); err != nil {
		t.Fatalf("append once the dir is writable: %v", err)
	}

	for _, idx := range []uint64{1, 2} {
		if _, err := os.Stat(segPath(dir, idx)); !os.IsNotExist(err) {
			t.Errorf("%s exists although its create failed (stat: %v)", segmentName(idx), err)
		}
	}
	envs, _ := segmentFrames(t, segPath(dir, 3))
	loss := lossThenRecord(t, envs, "5")
	checkLoss(t, loss, map[string]string{
		"guest_pushes_refused":   "2",
		"runner_records_refused": "1",
		"guest_events_lost":      "unknown",
	})
	cause := fmt.Sprint(loss["cause"])
	if !strings.Contains(cause, "write record") || strings.Contains(cause, "create segment") {
		t.Errorf("loss cause %q, want the first refusal's failed write, not a later failed create", cause)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// Close writes an open outage's loss frame, which the quota does not count,
// and then the end marker.
func TestCloseRecordsAnOpenOutage(t *testing.T) {
	dir := t.TempDir()
	const quota = 64 << 10
	w := openRecoveryWriter(t, dir, quota)
	fillQuota(t, dir, quota)
	if err := w.Append(guestPush(1)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("append over the quota: %v, want ErrSpoolFull", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	envs, marker := segmentFrames(t, segPath(dir, 0))
	if len(envs) != 1 || envs[0].Kind != "telemetry.loss" || !marker {
		t.Fatalf("%s holds %s, end marker %v; want [telemetry.loss] and the marker",
			segmentName(0), describe(envs), marker)
	}
	checkLoss(t, envs[0].Data, map[string]string{
		"guest_pushes_refused":   "1",
		"runner_records_refused": "0",
		"guest_events_lost":      "unknown",
	})
}

// When Close cannot record the loss either, its error says so, with the
// counts and the failure that stopped the record, so the runner's log keeps
// what the spool could not.
func TestCloseReportsALossItCouldNotRecord(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root creates files in a read-only directory")
	}
	dir := t.TempDir()
	w := openRecoveryWriter(t, dir, 0)
	if err := w.f.Close(); err != nil {
		t.Fatalf("close the segment's fd: %v", err)
	}
	lockDir(t, dir)
	if err := w.Append(guestPush(1)); err == nil {
		t.Fatal("append to a closed fd succeeded")
	}
	err := w.Close()
	if err == nil || !strings.Contains(err.Error(), "not recorded") ||
		!strings.Contains(err.Error(), "0 runner records and 1 guest pushes refused") {
		t.Fatalf("Close: %v; want an error saying the loss of 1 guest push was not recorded", err)
	}
	// The damaged segment sends the loss record to a new segment, and the
	// read-only dir refuses its create.
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("Close: %v; want it to carry the refused segment create that stopped the loss record (errors.Is os.ErrPermission)", err)
	}
}

// A record rejected for its own content says nothing about the spool, so it
// opens no outage and the next record needs no loss in front of it.
func TestRejectedRecordOpensNoOutage(t *testing.T) {
	dir := t.TempDir()
	w := openRecoveryWriter(t, dir, 0)
	oversize := runnerRecord(1)
	oversize.Data = map[string]any{"pad": strings.Repeat("B", maxRecordBytes+1)}
	if err := w.Append(oversize); err == nil || !strings.Contains(err.Error(), "exceeds 256 KiB frame limit") {
		t.Fatalf("append an oversize record: %v, want the frame limit error", err)
	}
	unmarshalable := runnerRecord(2)
	unmarshalable.Data = map[string]any{"ch": make(chan int)}
	if err := w.Append(unmarshalable); err == nil || !strings.Contains(err.Error(), "marshal envelope") {
		t.Fatalf("append a record that cannot marshal: %v, want the marshal error", err)
	}
	if w.outage != nil {
		t.Fatalf("a rejected record opened an outage: %+v", *w.outage)
	}
	if err := w.Append(runnerRecord(3)); err != nil {
		t.Fatalf("append record 3: %v", err)
	}
	envs, _ := segmentFrames(t, segPath(dir, 0))
	if len(envs) != 1 || envs[0].Kind == "telemetry.loss" || envs[0].SourceSeq != "3" {
		t.Fatalf("%s holds %s, want only record 3", segmentName(0), describe(envs))
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// The refusal counts stop at the largest uint64 rather than wrap to zero,
// and refuse hands back the error it was given.
func TestRefusalCountsSaturate(t *testing.T) {
	w := &Writer{outage: &Outage{
		Cause:                "first",
		RunnerRecordsRefused: math.MaxUint64 - 1,
		GuestPushesRefused:   math.MaxUint64 - 1,
	}}
	later := errors.New("later")
	for seq := 1; seq <= 2; seq++ {
		for _, env := range []*events.Envelope{guestPush(seq), runnerRecord(seq)} {
			if err := w.refuse(env, later); err != later {
				t.Fatalf("refuse returned %v, want its argument unchanged", err)
			}
		}
	}
	if w.outage.GuestPushesRefused != math.MaxUint64 || w.outage.RunnerRecordsRefused != math.MaxUint64 {
		t.Errorf("counts after saturating: %d guest pushes, %d runner records; want %d for both",
			w.outage.GuestPushesRefused, w.outage.RunnerRecordsRefused, uint64(math.MaxUint64))
	}
	if w.outage.Cause != "first" {
		t.Errorf("cause %q, want the first refusal's %q", w.outage.Cause, "first")
	}
}

// refuse keeps the first 512 runes of the first cause, and cuts between
// runes, never inside one.
func TestRefuseBoundsTheCause(t *testing.T) {
	w := &Writer{}
	_ = w.refuse(guestPush(1), errors.New(strings.Repeat("é", 600)))
	if w.outage == nil {
		t.Fatal("refuse opened no outage")
	}
	if want := strings.Repeat("é", 512); w.outage.Cause != want {
		t.Errorf("cause holds %d runes (valid UTF-8: %v), want the first 512",
			utf8.RuneCountInString(w.outage.Cause), utf8.ValidString(w.outage.Cause))
	}
}

// Data renders every value as a string: times in UTC in the event timestamp
// layout, counts in decimal, and "unknown" events lost once a guest push was
// refused.
func TestOutageData(t *testing.T) {
	since := time.Date(2026, 9, 20, 2, 8, 0, 123456789, time.FixedZone("UTC-5", -5*60*60))
	o := Outage{
		Since:                since,
		Until:                since.Add(3*time.Hour + 18*time.Minute),
		Cause:                "spool: write record: no space left on device",
		RunnerRecordsRefused: 7,
	}
	want := map[string]any{
		"cause":                  "spool: write record: no space left on device",
		"interval_start":         "2026-09-20T07:08:00.123456Z",
		"interval_end":           "2026-09-20T10:26:00.123456Z",
		"runner_records_refused": "7",
		"guest_pushes_refused":   "0",
		"guest_events_lost":      "0",
	}
	if got := o.Data(); !reflect.DeepEqual(got, want) {
		t.Errorf("Data() with no guest push refused:\n got %v\nwant %v", got, want)
	}

	o.GuestPushesRefused = math.MaxUint64
	want["guest_pushes_refused"] = "18446744073709551615"
	want["guest_events_lost"] = "unknown"
	if got := o.Data(); !reflect.DeepEqual(got, want) {
		t.Errorf("Data() with guest pushes refused:\n got %v\nwant %v", got, want)
	}
}

// OpenWriter refuses a config without a LossRecord before it touches the dir.
func TestOpenWriterRequiresLossRecord(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWriter(dir, WriterCfg{
		VMID:            recoveryVMID,
		InstanceID:      recoveryInstanceID,
		MaxSegmentBytes: 4 << 20,
	})
	if err == nil {
		_ = w.Close()
		t.Fatal("OpenWriter without a LossRecord succeeded")
	}
	if !strings.Contains(err.Error(), "spool: WriterCfg.LossRecord is required") {
		t.Errorf("OpenWriter: %v, want the missing LossRecord named", err)
	}
	names, err := filepath.Glob(filepath.Join(dir, "*.vmsp"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("OpenWriter created %v before it refused", names)
	}
}

// An append after Close fails without counting as a refusal: the writer is
// finished, not in an outage.
func TestAppendAfterCloseOpensNoOutage(t *testing.T) {
	w := openRecoveryWriter(t, t.TempDir(), 0)
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.Append(guestPush(1)); err == nil || !strings.Contains(err.Error(), "spool: append after close") {
		t.Fatalf("append after Close: %v, want %q", err, "spool: append after close")
	}
	if w.outage != nil {
		t.Errorf("an append after Close opened an outage: %+v", *w.outage)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// Rotation retires the full segment with its end marker, so every segment but
// the newest reads as cleanly closed, and the records keep their order.
func TestRotationRetiresTheFullSegment(t *testing.T) {
	dir := t.TempDir()
	w, err := OpenWriter(dir, WriterCfg{
		VMID:            recoveryVMID,
		InstanceID:      recoveryInstanceID,
		MaxSegmentBytes: 1024,
		LossRecord:      recoveryLoss,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	for seq := 1; seq <= 4; seq++ {
		if err := w.Append(runnerRecord(seq)); err != nil {
			t.Fatalf("append record %d: %v", seq, err)
		}
	}
	names, err := filepath.Glob(filepath.Join(dir, "seg-*.vmsp"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(names) < 2 {
		t.Fatalf("4 records in 1024-byte segments made %d segment, want a rotation", len(names))
	}
	var seqs []string
	for i, name := range names {
		envs, marker := segmentFrames(t, name)
		if i < len(names)-1 && (len(envs) == 0 || !marker) {
			t.Errorf("%s holds %s, end marker %v; a rotated segment needs its records and the marker",
				filepath.Base(name), describe(envs), marker)
		}
		for _, e := range envs {
			seqs = append(seqs, e.SourceSeq)
		}
	}
	if got := strings.Join(seqs, " "); got != "1 2 3 4" {
		t.Errorf("records across segments: %q, want %q", got, "1 2 3 4")
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// retireSegment cuts whatever follows the last durable record before it
// writes the end marker, so a damaged tail cannot sit behind the marker.
func TestRetireSegmentTrimsJunk(t *testing.T) {
	name := segPath(t.TempDir(), 0)
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create segment: %v", err)
	}
	hdr, err := json.Marshal(segmentHeader{
		Magic:      segmentMagic,
		Version:    segmentVersion,
		VMID:       recoveryVMID,
		InstanceID: recoveryInstanceID,
	})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	body, err := json.Marshal(runnerRecord(1))
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	durable := append(hdr, '\n')
	durable = binary.BigEndian.AppendUint32(durable, uint32(len(body)))
	durable = binary.BigEndian.AppendUint32(durable, crc32.Checksum(body, crc32cTable))
	durable = append(durable, body...)
	// A frame that promises 256 bytes of body and holds 3 of them.
	junk := []byte{0, 0, 1, 0, 0xde, 0xad, 0xbe, 0xef, 'x', 'y', 'z'}
	if _, err := f.Write(append(durable, junk...)); err != nil {
		t.Fatalf("write segment: %v", err)
	}
	size := int64(len(durable))

	if err := retireSegment(f, size); err != nil {
		t.Fatalf("retireSegment: %v", err)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != size+4 {
		t.Errorf("retired segment is %d bytes, want %d: the durable %d and a 4-byte end marker",
			info.Size(), size+4, size)
	}
	it, err := ReadSegment(name)
	if err != nil {
		t.Fatalf("ReadSegment: %v", err)
	}
	defer it.Close()
	env, err := it.Next()
	if err != nil || env.SourceSeq != "1" {
		t.Fatalf("first Next: %v, %v; want record 1", env, err)
	}
	if env, err := it.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("second Next: %v, %v; want io.EOF", env, err)
	}
	// Neither the size nor ReadSegment tells the end marker from 4 other
	// bytes; the strict parse checks the marker's value.
	envs, marker := segmentFrames(t, name)
	if len(envs) != 1 || envs[0].SourceSeq != "1" || !marker {
		t.Errorf("%s holds %s, end marker %v; want record 1 and the marker",
			filepath.Base(name), describe(envs), marker)
	}
}
