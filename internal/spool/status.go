// ABOUTME: The runner spool writer's health file, writer.status: a fixed 4096-byte frame
// ABOUTME: the writer overwrites in place and vmobsd's importer reads each cycle.
package spool

import (
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/2389-research/observatory/internal/events"
)

// statusFileName is the writer's health file in its spool dir. Recovery and
// the quota see only segment names, so they never touch it.
const statusFileName = "writer.status"

// statusFileBytes is the status file's exact size. The writer overwrites the
// whole file at offset 0 and never changes its length, so an update needs no
// new block and a reader never sees a file of any other size.
const statusFileBytes = 4096

// maxStatusBody is the longest JSON body a status frame can hold.
const maxStatusBody = statusFileBytes - 8

// WriterHealth is the spool writer's health as its status file reports it.
//
// A healthy writer refuses nothing: Since is when it opened or last recorded
// a loss, both counts are "0", and Cause and LastError are empty. A failing
// writer has an outage open: Since, Cause and the counts are the outage's,
// and LastError is the latest refusal's error. Unknown means the file is
// missing or holds no intact frame, and every other field is empty. Times
// are UTC in events.TimestampLayout, and the counts are decimal strings.
type WriterHealth struct {
	State                string `json:"state"` // healthy | failing | unknown
	Since                string `json:"since"`
	Cause                string `json:"cause"`
	LastError            string `json:"last_error"`
	RunnerRecordsRefused string `json:"runner_records_refused"`
	GuestPushesRefused   string `json:"guest_pushes_refused"`
	UpdatedAt            string `json:"updated_at"`
	InstanceID           string `json:"instance_id"`
}

// encodeStatus lays h out as a whole status file: [len uint32 BE][crc32c
// uint32 BE][JSON body], then zeros to statusFileBytes. A body too long for
// the frame has its cause and last error halved, by rune count, until it
// fits. When it cannot fit even with both empty, there is no frame.
func encodeStatus(h WriterHealth) ([]byte, bool) {
	for {
		body, err := json.Marshal(h)
		if err != nil {
			return nil, false
		}
		if len(body) <= maxStatusBody {
			frame := make([]byte, statusFileBytes)
			copy(frame, encodeFrame(body))
			return frame, true
		}
		if h.Cause == "" && h.LastError == "" {
			return nil, false
		}
		h.Cause = boundRunes(h.Cause, utf8.RuneCountInString(h.Cause)/2)
		h.LastError = boundRunes(h.LastError, utf8.RuneCountInString(h.LastError)/2)
	}
}

// prepareStatus opens dir's status file for a new writer and fills it with
// statusFileBytes of zeros, fsynced, so its blocks are allocated before the
// first update and it reads unknown until the writer writes a frame.
func prepareStatus(dir string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(dir, statusFileName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteAt(make([]byte, statusFileBytes), 0); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// writeStatus overwrites the status file with the writer's health: failing
// while an outage is open, healthy otherwise. A zero Writer has no status
// file and writes nothing.
func (w *Writer) writeStatus() {
	if w.status == nil {
		return
	}
	h := WriterHealth{
		State:                "healthy",
		Since:                w.healthySince.UTC().Format(events.TimestampLayout),
		RunnerRecordsRefused: "0",
		GuestPushesRefused:   "0",
		UpdatedAt:            time.Now().UTC().Format(events.TimestampLayout),
		InstanceID:           w.cfg.InstanceID,
	}
	if o := w.outage; o != nil {
		h.State = "failing"
		h.Since = o.Since.UTC().Format(events.TimestampLayout)
		h.Cause = o.Cause
		h.LastError = w.lastRefusal
		h.RunnerRecordsRefused = strconv.FormatUint(o.RunnerRecordsRefused, 10)
		h.GuestPushesRefused = strconv.FormatUint(o.GuestPushesRefused, 10)
	}
	frame, ok := encodeStatus(h)
	if !ok {
		return
	}
	// The status is advisory and the loss record is the durable evidence, so
	// a failed overwrite is ignored and the file is never fsynced: a status
	// the writer cannot update must never refuse a record or fail a Close.
	_, _ = w.status.WriteAt(frame, 0)
}

// readStatus reads the status file in dir. A missing or short file, a zero
// or impossible length, a bad checksum, bad JSON or a state the writer never
// writes reads as unknown, so a read that races the writer's overwrite
// reports unknown rather than a mix of two updates.
func readStatus(dir string) WriterHealth {
	unknown := WriterHealth{State: "unknown"}
	f, err := os.Open(filepath.Join(dir, statusFileName))
	if err != nil {
		return unknown
	}
	defer f.Close()
	buf := make([]byte, statusFileBytes)
	if _, err := io.ReadFull(f, buf); err != nil {
		return unknown
	}
	n := binary.BigEndian.Uint32(buf[0:4])
	if n == 0 || n > maxStatusBody {
		return unknown
	}
	body := buf[8 : 8+n]
	if crc32.Checksum(body, crc32cTable) != binary.BigEndian.Uint32(buf[4:8]) {
		return unknown
	}
	var h WriterHealth
	if err := json.Unmarshal(body, &h); err != nil || (h.State != "healthy" && h.State != "failing") {
		return unknown
	}
	return h
}
