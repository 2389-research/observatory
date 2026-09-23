// ABOUTME: Tests for writer.status, the fixed-size file that carries the spool writer's health
// ABOUTME: to the importer, and for the writer keeping it current through an outage and a close.
package spool

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/2389-research/observatory/internal/events"
)

// statusPath names dir's status file.
func statusPath(dir string) string {
	return filepath.Join(dir, statusFileName)
}

// writeStatusFile frames h the way the writer does and writes it as dir's
// status file.
func writeStatusFile(t *testing.T, dir string, h WriterHealth) {
	t.Helper()
	frame, ok := encodeStatus(h)
	if !ok {
		t.Fatalf("encodeStatus found no frame for a %s status", h.State)
	}
	if err := os.WriteFile(statusPath(dir), frame, 0o600); err != nil {
		t.Fatalf("write the status file: %v", err)
	}
}

// checkStatusFile fails the test unless dir's status file is exactly
// statusFileBytes long and has blocks allocated for all of them, so an
// update never needs a new block.
func checkStatusFile(t *testing.T, dir, when string) {
	t.Helper()
	info, err := os.Stat(statusPath(dir))
	if err != nil {
		t.Fatalf("%s: stat the status file: %v", when, err)
	}
	if info.Size() != statusFileBytes {
		t.Errorf("%s: the status file is %d bytes, want %d", when, info.Size(), statusFileBytes)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok {
		t.Errorf("%s: no block count in %T", when, info.Sys())
	} else if st.Blocks*512 < statusFileBytes {
		t.Errorf("%s: the status file has %d bytes of blocks allocated, want all %d", when, st.Blocks*512, statusFileBytes)
	}
}

// parseStatusTime parses a status timestamp and fails the test unless it is
// a UTC time in the event layout.
func parseStatusTime(t *testing.T, field, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(events.TimestampLayout, s)
	if err != nil || !strings.HasSuffix(s, "Z") {
		t.Fatalf("%s %q is not a UTC time in the event layout (%v)", field, s, err)
	}
	return ts
}

// currentStatus reads dir's status. For a healthy or failing status it
// checks that UpdatedAt is a UTC time in the event layout and blanks it, so
// the caller can compare the rest exactly.
func currentStatus(t *testing.T, dir string) WriterHealth {
	t.Helper()
	h := readStatus(dir)
	if h.State == "healthy" || h.State == "failing" {
		parseStatusTime(t, "updated_at", h.UpdatedAt)
		h.UpdatedAt = ""
	}
	return h
}

// checkStatusClosed fails the test unless the writer's status file is closed.
func checkStatusClosed(t *testing.T, w *Writer) {
	t.Helper()
	if _, err := w.status.WriteAt(make([]byte, statusFileBytes), 0); !errors.Is(err, os.ErrClosed) {
		t.Errorf("write to the status file after Close: %v, want os.ErrClosed", err)
	}
}

// Healthy and failing values come back from the file exactly as written.
func TestStatusRoundTrips(t *testing.T) {
	for _, h := range []WriterHealth{
		{
			State:                "healthy",
			Since:                "2026-09-20T02:08:00.123456Z",
			RunnerRecordsRefused: "0",
			GuestPushesRefused:   "0",
			UpdatedAt:            "2026-09-20T02:08:05.000001Z",
			InstanceID:           recoveryInstanceID,
		},
		{
			State:                "failing",
			Since:                "2026-09-20T02:08:00.123456Z",
			Cause:                "spool: write record: write seg-0000000000000003.vmsp: no space left on device",
			LastError:            "spool: spool full",
			RunnerRecordsRefused: "18446744073709551615",
			GuestPushesRefused:   "7",
			UpdatedAt:            "2026-09-20T05:26:00.000000Z",
			InstanceID:           recoveryInstanceID,
		},
	} {
		dir := t.TempDir()
		writeStatusFile(t, dir, h)
		if got := readStatus(dir); got != h {
			t.Errorf("read back %+v\nwant %+v", got, h)
		}
	}
}

// Anything but a whole, intact frame reads as unknown with every other field
// empty, so a read torn by the writer's overwrite never gives a wrong answer.
func TestStatusReadsUnknown(t *testing.T) {
	frame, ok := encodeStatus(WriterHealth{
		State:                "healthy",
		Since:                "2026-09-20T02:08:00.123456Z",
		RunnerRecordsRefused: "0",
		GuestPushesRefused:   "0",
		UpdatedAt:            "2026-09-20T02:08:05.000001Z",
		InstanceID:           recoveryInstanceID,
	})
	if !ok {
		t.Fatal("encodeStatus found no frame for a healthy status")
	}
	// framed pads a body the writer never writes into a whole file.
	framed := func(body string) []byte {
		b := make([]byte, statusFileBytes)
		copy(b, encodeFrame([]byte(body)))
		return b
	}
	flipped := bytes.Clone(frame)
	flipped[4] ^= 0x01
	tooLong := bytes.Clone(frame)
	binary.BigEndian.PutUint32(tooLong[0:4], maxStatusBody+1)
	for _, c := range []struct {
		name    string
		content []byte // nil: no file at all
	}{
		{"missing", nil},
		{"short", frame[:statusFileBytes-1]},
		{"zeroed", make([]byte, statusFileBytes)},
		{"flipped checksum byte", flipped},
		{"impossible length", tooLong},
		{"bad JSON", framed(`{"state":"healthy"`)},
		{"a state the writer never writes", framed(`{"state":"unknown","since":"2026-09-20T02:08:00.123456Z"}`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if c.content != nil {
				if err := os.WriteFile(statusPath(dir), c.content, 0o600); err != nil {
					t.Fatalf("write the status file: %v", err)
				}
			}
			if got := readStatus(dir); got != (WriterHealth{State: "unknown"}) {
				t.Errorf("read %+v, want state unknown and every other field empty", got)
			}
		})
	}
}

// A cause and last error too long for the frame are halved, by rune count,
// until the body fits, and what fits reads back whole.
func TestStatusHalvesAnOverlongCause(t *testing.T) {
	long := strings.Repeat("é", 4000)
	h := WriterHealth{
		State:                "failing",
		Since:                "2026-09-20T02:08:00.123456Z",
		Cause:                long,
		LastError:            long,
		RunnerRecordsRefused: "3",
		GuestPushesRefused:   "4",
		UpdatedAt:            "2026-09-20T02:09:00.000000Z",
		InstanceID:           recoveryInstanceID,
	}
	dir := t.TempDir()
	writeStatusFile(t, dir, h)
	got := readStatus(dir)
	// 4000 runes halve to 2000, 1000 and then 500. At 1000 runes the two
	// fields' 4000 bytes of é leave the other fields too little of the 4088.
	want := h
	want.Cause = strings.Repeat("é", 500)
	want.LastError = want.Cause
	if got != want {
		shown := got
		shown.Cause = fmt.Sprintf("<%d runes>", utf8.RuneCountInString(got.Cause))
		shown.LastError = fmt.Sprintf("<%d runes>", utf8.RuneCountInString(got.LastError))
		t.Errorf("read back %+v; want 500 runes of é in the cause and last error and the rest as written", shown)
	}
}

// When the body cannot fit even with the cause and last error gone, the
// halving stops and there is no frame. A writer then leaves the file as it
// was: the zeros it prepared, which read as unknown.
func TestStatusWithNoRoomHasNoFrame(t *testing.T) {
	huge := strings.Repeat("i", maxStatusBody)
	if frame, ok := encodeStatus(WriterHealth{State: "failing", Cause: "c", LastError: "e", InstanceID: huge}); ok {
		t.Errorf("encodeStatus gave a %d-byte frame for a body that cannot fit", len(frame))
	}
	dir := t.TempDir()
	w, err := OpenWriter(dir, WriterCfg{
		VMID:            recoveryVMID,
		InstanceID:      huge,
		MaxSegmentBytes: 4 << 20,
		LossRecord:      recoveryLoss,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	checkStatusFile(t, dir, "after open")
	if got := readStatus(dir); got != (WriterHealth{State: "unknown"}) {
		t.Errorf("a writer whose status cannot fit left %+v, want unknown", got)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// The writer keeps its status current: healthy from its open, failing on
// every refusal with the outage's counts, first cause and latest error, and
// healthy again, from a new Since, once the loss record lands.
func TestWriterStatusFollowsAnOutage(t *testing.T) {
	dir := t.TempDir()
	const quota = 64 << 10
	opening := time.Now()
	w := openRecoveryWriter(t, dir, quota)
	checkStatusFile(t, dir, "after open")
	got := currentStatus(t, dir)
	if since := parseStatusTime(t, "since", got.Since); since.Before(opening.Truncate(time.Microsecond)) || since.After(time.Now()) {
		t.Errorf("healthy since %s, want the writer's open", got.Since)
	}
	want := WriterHealth{State: "healthy", Since: got.Since, RunnerRecordsRefused: "0", GuestPushesRefused: "0", InstanceID: recoveryInstanceID}
	if got != want {
		t.Errorf("after open the status is %+v\nwant %+v", got, want)
	}

	// The first refusal, a write to a closed fd, names the cause.
	if err := w.f.Close(); err != nil {
		t.Fatalf("close the segment's fd: %v", err)
	}
	if err := w.Append(guestPush(1)); err == nil {
		t.Fatal("append to a closed fd succeeded")
	}
	cause := w.outage.Cause
	since := w.outage.Since.UTC().Format(events.TimestampLayout)
	want = WriterHealth{State: "failing", Since: since, Cause: cause, LastError: cause, RunnerRecordsRefused: "0", GuestPushesRefused: "1", InstanceID: recoveryInstanceID}
	if got := currentStatus(t, dir); got != want {
		t.Errorf("after the first refusal the status is %+v\nwant %+v", got, want)
	}
	if !strings.Contains(cause, "file already closed") {
		t.Errorf("cause %q, want the closed fd's write error", cause)
	}

	// The next refusal, the quota, is the latest error; the cause stays.
	ballast := fillQuota(t, dir, quota)
	if err := w.Append(runnerRecord(2)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("append over the quota: %v, want ErrSpoolFull", err)
	}
	checkStatusFile(t, dir, "after a refusal")
	want = WriterHealth{State: "failing", Since: since, Cause: cause, LastError: ErrSpoolFull.Error(), RunnerRecordsRefused: "1", GuestPushesRefused: "1", InstanceID: recoveryInstanceID}
	if got := currentStatus(t, dir); got != want {
		t.Errorf("after the second refusal the status is %+v\nwant %+v", got, want)
	}

	if err := os.Remove(ballast); err != nil {
		t.Fatalf("remove the ballast: %v", err)
	}
	landing := time.Now()
	if err := w.Append(runnerRecord(3)); err != nil {
		t.Fatalf("append after the quota freed: %v", err)
	}
	checkStatusFile(t, dir, "after the loss landed")
	got = currentStatus(t, dir)
	if recovered := parseStatusTime(t, "since", got.Since); recovered.Before(landing.Truncate(time.Microsecond)) {
		t.Errorf("healthy since %s, want the loss record's landing, after the outage's %s", got.Since, since)
	}
	want = WriterHealth{State: "healthy", Since: got.Since, RunnerRecordsRefused: "0", GuestPushesRefused: "0", InstanceID: recoveryInstanceID}
	if got != want {
		t.Errorf("after the loss landed the status is %+v\nwant %+v", got, want)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	checkStatusFile(t, dir, "after Close")
}

// Close leaves the status the writer ends with and closes the file: healthy
// once it records the open outage's loss, failing when it cannot.
func TestCloseWritesTheFinalStatus(t *testing.T) {
	t.Run("loss recorded", func(t *testing.T) {
		dir := t.TempDir()
		const quota = 64 << 10
		w := openRecoveryWriter(t, dir, quota)
		fillQuota(t, dir, quota)
		if err := w.Append(guestPush(1)); !errors.Is(err, ErrSpoolFull) {
			t.Fatalf("append over the quota: %v, want ErrSpoolFull", err)
		}
		closing := time.Now()
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got := currentStatus(t, dir)
		if since := parseStatusTime(t, "since", got.Since); since.Before(closing.Truncate(time.Microsecond)) {
			t.Errorf("healthy since %s, want the loss record's landing in Close", got.Since)
		}
		want := WriterHealth{State: "healthy", Since: got.Since, RunnerRecordsRefused: "0", GuestPushesRefused: "0", InstanceID: recoveryInstanceID}
		if got != want {
			t.Errorf("after Close the status is %+v\nwant %+v", got, want)
		}
		checkStatusClosed(t, w)
	})
	t.Run("loss not recorded", func(t *testing.T) {
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
		want := WriterHealth{
			State:                "failing",
			Since:                w.outage.Since.UTC().Format(events.TimestampLayout),
			Cause:                w.outage.Cause,
			LastError:            w.outage.Cause,
			RunnerRecordsRefused: "0",
			GuestPushesRefused:   "1",
			InstanceID:           recoveryInstanceID,
		}
		if err := w.Close(); err == nil || !strings.Contains(err.Error(), "not recorded") {
			t.Fatalf("Close: %v, want the loss it could not record", err)
		}
		if got := currentStatus(t, dir); got != want {
			t.Errorf("after Close the status is %+v\nwant %+v", got, want)
		}
		checkStatusClosed(t, w)
	})
}

// A new writer resets the status to healthy under its own instance id,
// whatever the last one left: here, a writer that died in an outage.
func TestNewWriterResetsTheStatus(t *testing.T) {
	dir := t.TempDir()
	const quota = 64 << 10
	old := openRecoveryWriter(t, dir, quota)
	fillQuota(t, dir, quota)
	if err := old.Append(guestPush(1)); !errors.Is(err, ErrSpoolFull) {
		t.Fatalf("append over the quota: %v, want ErrSpoolFull", err)
	}
	if got := readStatus(dir); got.State != "failing" {
		t.Fatalf("the old writer left %+v, want failing", got)
	}
	// The old writer's process dies: its descriptors close, and it writes
	// nothing more.
	_ = old.f.Close()
	_ = old.status.Close()

	const newInstance = "7c6d5e4f-3a2b-4c1d-9e8f-7a6b5c4d3e2f"
	w, err := OpenWriter(dir, WriterCfg{
		VMID:            recoveryVMID,
		InstanceID:      newInstance,
		MaxSegmentBytes: 4 << 20,
		MaxSpoolBytes:   quota,
		LossRecord:      recoveryLoss,
	})
	if err != nil {
		t.Fatalf("OpenWriter: %v", err)
	}
	got := currentStatus(t, dir)
	want := WriterHealth{State: "healthy", Since: got.Since, RunnerRecordsRefused: "0", GuestPushesRefused: "0", InstanceID: newInstance}
	if got != want {
		t.Errorf("the new writer's status is %+v\nwant %+v", got, want)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// OpenWriter zeroes the status before it creates its first segment and
// writes healthy only once that segment exists, so a writer whose first
// create fails leaves a status that reads unknown, not the last writer's.
func TestFailedOpenLeavesTheStatusUnknown(t *testing.T) {
	dir := t.TempDir()
	if err := openRecoveryWriter(t, dir, 0).Close(); err != nil {
		t.Fatalf("close the first writer: %v", err)
	}
	if got := readStatus(dir); got.State != "healthy" {
		t.Fatalf("the first writer left %+v, want healthy", got)
	}
	// The index scan skips a directory, so the next writer's first create
	// meets this one and fails.
	if err := os.Mkdir(segPath(dir, 1), 0o700); err != nil {
		t.Fatalf("make a directory at the next segment's name: %v", err)
	}
	_, err := OpenWriter(dir, WriterCfg{
		VMID:            recoveryVMID,
		InstanceID:      recoveryInstanceID,
		MaxSegmentBytes: 4 << 20,
		LossRecord:      recoveryLoss,
	})
	if err == nil || !strings.Contains(err.Error(), "create segment") {
		t.Fatalf("OpenWriter over a directory at its first segment's name: %v, want the failed create", err)
	}
	if got := readStatus(dir); got != (WriterHealth{State: "unknown"}) {
		t.Errorf("after the failed open the status reads %+v, want unknown", got)
	}
	checkStatusFile(t, dir, "after the failed open")
}

// A status file OpenWriter cannot prepare fails the open before any segment
// exists.
func TestUnpreparableStatusFailsOpenWriter(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(statusPath(dir), 0o700); err != nil {
		t.Fatalf("make a directory at the status file's name: %v", err)
	}
	_, err := OpenWriter(dir, WriterCfg{
		VMID:            recoveryVMID,
		InstanceID:      recoveryInstanceID,
		MaxSegmentBytes: 4 << 20,
		LossRecord:      recoveryLoss,
	})
	if err == nil || !strings.HasPrefix(err.Error(), "spool: prepare writer status: ") {
		t.Fatalf("OpenWriter: %v, want it to fail preparing the writer status", err)
	}
	if _, err := os.Stat(segPath(dir, 0)); !os.IsNotExist(err) {
		t.Errorf("stat %s after the failed prepare: %v, want no such file", segmentName(0), err)
	}
}
