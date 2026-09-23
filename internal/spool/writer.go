// ABOUTME: Writer opens and manages spool segment files for durable appending.
// ABOUTME: Each Append is an ack barrier: write + fsync before returning.
package spool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/2389-research/observatory/internal/events"
)

// crc32cTable is the Castagnoli polynomial table used for all CRC32C operations.
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// WriterCfg configures a spool Writer.
type WriterCfg struct {
	// VMID identifies the VM whose events this spool carries.
	VMID string
	// InstanceID identifies the runner instance (written to each segment header).
	InstanceID string
	// MaxSegmentBytes is the maximum number of bytes a single segment file may
	// grow to before the writer rotates to a new segment. Must be > 0.
	MaxSegmentBytes int64
	// MaxSpoolBytes is the maximum total bytes across all segments in the spool
	// directory. When 0, DefaultMaxSpoolBytes applies.
	MaxSpoolBytes int64
	// LossRecord builds the telemetry.loss envelope for an outage. The writer
	// calls it while holding its lock, so it must not call the Writer.
	LossRecord func(Outage) *events.Envelope
}

// segmentHeader is the JSON object written as the first line of every segment.
type segmentHeader struct {
	Magic      string `json:"magic"`
	Version    int    `json:"version"`
	VMID       string `json:"vm_id"`
	InstanceID string `json:"instance_id"`
}

// Writer appends event envelopes to durable spool segments.
// A Writer is safe for concurrent use. More than one producer appends to a
// VM's spool — the supervision loop and the telemetry loop, at least — and a
// record is a length, a checksum and a body that must reach the file as one
// piece, so the writer serialises its own writes rather than asking every
// caller to remember to.
type Writer struct {
	mu       sync.Mutex
	dir      string
	cfg      WriterCfg
	maxSpool int64 // resolved MaxSpoolBytes (never zero)
	segIdx   uint64
	f        *os.File
	segBytes int64 // durable bytes in the current segment (header + records)
	// damaged means the current segment may hold bytes that failed to become
	// durable, and nothing more will be written to it. After a failed fsync
	// the kernel may drop dirty pages and clear the error, so a later fsync on
	// the same file can succeed although earlier bytes never reached disk.
	// That condemns the file, not the writer: the next Append moves to a new
	// segment, which has no such history. damaged implies an open outage.
	damaged bool
	// outage is open while refused appends are unrecorded. The next Append
	// that succeeds writes its telemetry.loss ahead of its own record.
	outage *Outage
	closed bool
	// status is the writer.status file the writer keeps its health in (see
	// writeStatus). healthySince is when the writer opened or last recorded
	// a loss, and lastRefusal is the latest refused Append's error, bounded.
	status       *os.File
	healthySince time.Time
	lastRefusal  string
}

// OpenWriter opens (or creates) a spool writer in dir with the given configuration.
// It returns an error when MaxSegmentBytes <= 0 or LossRecord is nil.
//
// The writer keeps its health in dir's writer.status (see WriterHealth).
// OpenWriter zeroes that file before it creates the first segment and writes
// healthy, under this writer's instance id, only once the segment exists: a
// writer that cannot create its first segment leaves a status that reads
// unknown.
func OpenWriter(dir string, cfg WriterCfg) (*Writer, error) {
	if cfg.MaxSegmentBytes <= 0 {
		return nil, fmt.Errorf("spool: MaxSegmentBytes must be > 0")
	}
	if cfg.LossRecord == nil {
		return nil, fmt.Errorf("spool: WriterCfg.LossRecord is required")
	}
	maxSpool := cfg.MaxSpoolBytes
	if maxSpool == 0 {
		maxSpool = DefaultMaxSpoolBytes
	}

	// Determine the next segment index from existing files.
	idx, err := nextSegmentIndex(dir)
	if err != nil {
		return nil, fmt.Errorf("spool: scan dir for next segment index: %w", err)
	}

	status, err := prepareStatus(dir)
	if err != nil {
		return nil, fmt.Errorf("spool: prepare writer status: %w", err)
	}

	w := &Writer{
		dir:      dir,
		cfg:      cfg,
		maxSpool: maxSpool,
		segIdx:   idx,
		status:   status,
	}
	if err := w.createSegment(); err != nil {
		_ = status.Close()
		return nil, err
	}
	w.healthySince = time.Now()
	w.writeStatus()
	return w, nil
}

// Append marshals env as JSON and appends it as a record to the current segment.
// It fsyncs the segment file before returning (ack barrier, SPEC §12.4).
//
// An Append the spool cannot make durable is refused. It returns ErrSpoolFull
// when the record would exceed MaxSpoolBytes, or else the error that stopped
// it: measuring the spool's size, building the outage's loss record, creating
// a segment, or a write or fsync. The writer counts each refusal in an open
// outage and tries again on the next Append. A failed write, fsync or segment
// create abandons the current segment, so the next Append moves to a new one.
// The first Append that succeeds after refusals writes the outage's
// telemetry.loss ahead of its own record.
//
// A record that cannot marshal or exceeds the frame limit is rejected for its
// own content. That is not a refusal: the spool is fine.
func (w *Writer) Append(env *events.Envelope) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("spool: append after close")
	}

	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("spool: marshal envelope: %w", err)
	}
	if len(body) > maxRecordBytes {
		return fmt.Errorf("spool: record body %d bytes exceeds 256 KiB frame limit", len(body))
	}
	rec := encodeFrame(body)

	// Spool total-bytes guard (SPEC §12.5). It counts the record's frame
	// only: the loss frame is exempt, so a full spool can still record its
	// own loss.
	totalNow, err := w.spoolTotalBytes()
	if err != nil {
		return w.refuse(env, fmt.Errorf("spool: measure spool size: %w", err))
	}
	if totalNow+int64(len(rec)) > w.maxSpool {
		return w.refuse(env, ErrSpoolFull)
	}

	var loss []byte
	if w.outage != nil {
		if loss, err = w.lossFrame(); err != nil {
			return w.refuse(env, err)
		}
	}
	if w.damaged || w.segBytes+int64(len(loss)+len(rec)) > w.cfg.MaxSegmentBytes {
		if err := w.advance(); err != nil {
			return w.refuse(env, err)
		}
	}
	if loss != nil {
		if err := w.writeFrame(loss, "loss record"); err != nil {
			return w.refuse(env, err)
		}
		w.lossRecorded()
	}
	if err := w.writeFrame(rec, "record"); err != nil {
		return w.refuse(env, err)
	}
	return nil
}

// Close records an open outage when it can, then retires the current segment
// with its end marker. When the loss cannot be recorded, the error says so,
// carries the counts, and wraps the failure that stopped the record, so the
// caller's log keeps what the spool could not. Close leaves the writer's
// final status, healthy or still failing, and closes the status file. A
// second Close returns nil.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	var recordErr error
	if w.outage != nil {
		recordErr = w.recordOutage()
	}
	// After a failed advance this is still the damaged segment, and the
	// retire trims it back to its last durable record.
	retireErr := retireSegment(w.f, w.segBytes)
	w.f = nil
	w.writeStatus()
	// The status is advisory; its close error is not the caller's concern.
	_ = w.status.Close()
	if o := w.outage; o != nil {
		lost := fmt.Errorf("spool: loss since %s not recorded: %d runner records and %d guest pushes refused; first cause: %s; recording it failed: %w",
			o.Since.UTC().Format(events.TimestampLayout), o.RunnerRecordsRefused, o.GuestPushesRefused, o.Cause, recordErr)
		return errors.Join(lost, retireErr)
	}
	return retireErr
}

// recordOutage writes the open outage's loss frame on its own, moving to a
// new segment first when the current one is damaged or has no room. It
// clears the outage only once the frame is durable, and otherwise returns
// the error that stopped it.
func (w *Writer) recordOutage() error {
	loss, err := w.lossFrame()
	if err != nil {
		return err
	}
	if w.damaged || w.segBytes+int64(len(loss)) > w.cfg.MaxSegmentBytes {
		if err := w.advance(); err != nil {
			return err
		}
	}
	if err := w.writeFrame(loss, "loss record"); err != nil {
		return err
	}
	w.lossRecorded()
	return nil
}

// lossRecorded closes the outage once its loss record is durable: the
// writer is healthy again from now, and its status says so.
func (w *Writer) lossRecorded() {
	w.outage = nil
	w.healthySince = time.Now()
	w.writeStatus()
}

// refuse counts a failed Append in the open outage, opening one when none is
// open, writes the failing status, and returns err unchanged, so errors.Is
// still finds ErrSpoolFull or the errno beneath a failed write. Each failed
// Append calls it exactly once.
func (w *Writer) refuse(env *events.Envelope, err error) error {
	msg := boundRunes(err.Error(), maxCauseRunes)
	if w.outage == nil {
		w.outage = &Outage{Since: time.Now(), Cause: msg}
	}
	if env != nil && env.Provenance == events.GuestReported {
		if w.outage.GuestPushesRefused < math.MaxUint64 {
			w.outage.GuestPushesRefused++
		}
	} else {
		if w.outage.RunnerRecordsRefused < math.MaxUint64 {
			w.outage.RunnerRecordsRefused++
		}
	}
	w.lastRefusal = msg
	w.writeStatus()
	return err
}

// lossFrame frames the telemetry.loss envelope for the open outage, with
// Until set to now.
func (w *Writer) lossFrame() ([]byte, error) {
	o := *w.outage
	o.Until = time.Now()
	env := w.cfg.LossRecord(o)
	if env == nil {
		return nil, fmt.Errorf("spool: LossRecord returned nil")
	}
	body, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("spool: marshal loss record: %w", err)
	}
	if len(body) > maxRecordBytes {
		return nil, fmt.Errorf("spool: loss record body %d bytes exceeds 256 KiB frame limit", len(body))
	}
	return encodeFrame(body), nil
}

// encodeFrame lays out one record: [len uint32 BE][crc32c uint32 BE][body].
func encodeFrame(body []byte) []byte {
	rec := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(rec[0:4], uint32(len(body)))
	binary.BigEndian.PutUint32(rec[4:8], crc32.Checksum(body, crc32cTable))
	copy(rec[8:], body)
	return rec
}

// writeFrame appends one frame to the current segment and fsyncs it. what
// names the frame in the error. On failure the segment is damaged: the frame
// may be partly written, or written and not durable.
func (w *Writer) writeFrame(frame []byte, what string) error {
	if _, err := w.f.Write(frame); err != nil {
		w.damage()
		return fmt.Errorf("spool: write %s: %w", what, err)
	}
	if err := w.f.Sync(); err != nil {
		w.damage()
		return fmt.Errorf("spool: fsync after %s: %w", what, err)
	}
	w.segBytes += int64(len(frame))
	return nil
}

// damage abandons the current segment: it may hold bytes that never became
// durable, so nothing more is written to it. The trim back to the last
// durable record and the fsync are best effort, and retireSegment trims the
// segment again.
func (w *Writer) damage() {
	w.damaged = true
	_ = w.f.Truncate(w.segBytes)
	_ = w.f.Sync()
}

// advance moves the writer to a new segment and retires the current one. It
// burns the index before the create, so a failed attempt never retries a
// name it may have left on disk. A failed advance damages the current
// segment, so the writer never again writes to a segment that the failed
// create may have left a higher-numbered file beside: only the newest
// segment grows.
func (w *Writer) advance() error {
	w.segIdx++
	old, oldSize := w.f, w.segBytes
	if err := w.createSegment(); err != nil {
		w.damage()
		return err
	}
	w.damaged = false
	// The old segment's records are already durable. A retire that fails
	// leaves it without an end marker, which only makes recovery read it as
	// crashed.
	_ = retireSegment(old, oldSize)
	return nil
}

// createSegment creates the segment file at segIdx, writes its header and
// fsyncs the file and the directory (SPEC §12.4 directory-entry durability).
// It becomes the current segment only on success; a failure after the create
// closes and removes the file.
func (w *Writer) createSegment() error {
	if w.segIdx > maxSegmentIndex {
		return fmt.Errorf("spool: segment index %d exceeds the 16-digit name space", w.segIdx)
	}
	name := segmentName(w.segIdx)
	path := filepath.Join(w.dir, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("spool: create segment %s: %w", name, err)
	}
	discard := func(err error) error {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}

	hdr := segmentHeader{
		Magic:      segmentMagic,
		Version:    segmentVersion,
		VMID:       w.cfg.VMID,
		InstanceID: w.cfg.InstanceID,
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		return discard(fmt.Errorf("spool: marshal segment header: %w", err))
	}
	hdrLine := append(hdrJSON, '\n')

	if _, err := f.Write(hdrLine); err != nil {
		return discard(fmt.Errorf("spool: write segment header: %w", err))
	}
	// fsync the file itself.
	if err := f.Sync(); err != nil {
		return discard(fmt.Errorf("spool: fsync new segment: %w", err))
	}
	// fsync the directory so the new dentry is durable (SPEC §12.4).
	if err := fSyncDir(w.dir); err != nil {
		return discard(fmt.Errorf("spool: fsync spool dir: %w", err))
	}

	w.f = f
	w.segBytes = int64(len(hdrLine))
	return nil
}

// retireSegment ends the segment in f at size: it trims anything past size,
// writes the end marker there, and fsyncs. The trim matters for a damaged
// segment, which may hold a partial or unsynced frame past size; the marker
// must follow the last durable record. It stops at the first failure, always
// closes f, and returns the first error, or else the Close error.
func retireSegment(f *os.File, size int64) error {
	var marker [4]byte
	binary.BigEndian.PutUint32(marker[:], endMarker)
	var err error
	if terr := f.Truncate(size); terr != nil {
		err = fmt.Errorf("spool: trim segment before end marker: %w", terr)
	} else if _, werr := f.WriteAt(marker[:], size); werr != nil {
		err = fmt.Errorf("spool: write end marker: %w", werr)
	} else if serr := f.Sync(); serr != nil {
		err = fmt.Errorf("spool: fsync end marker: %w", serr)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// spoolTotalBytes sums the sizes of all *.vmsp files in the spool directory.
func (w *Writer) spoolTotalBytes() (int64, error) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".vmsp" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			if os.IsNotExist(err) {
				continue // file vanished between ReadDir and Info — skip
			}
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

// nextSegmentIndex scans dir for existing *.vmsp files and returns the next
// monotonic index to use. The cursor is consulted too: a boot that starts
// after the importer has pruned every segment on disk must not reissue a
// name the cursor already points at, or the importer treats fresh records as
// already committed (CURRENT) or already seen (PAST).
//
// The directory listing is read before the cursor on purpose: the importer
// commits a record, then writes the cursor, then prunes the segment. A
// segment holding committed records was pruned only after the cursor was
// written to name it, so a cursor read afterwards still names it and the
// maximum still reflects it. Reading in the other order — cursor first, then
// listing — risks a prune landing between the two reads, which would hide
// the segment from both and let its index be reused.
//
// A closed segment with no records (header and end marker only) is pruned as
// FUTURE without the cursor ever being written to name it, so its name is
// missing from both reads and can come back in the very next writer. That
// reuse is safe: the name is still ahead of the cursor, so the importer
// reads the reissued segment from its first record instead of skipping it as
// already seen.
func nextSegmentIndex(dir string) (uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}

	found := false
	var maxIdx uint64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		idx, ok := parseSegmentName(e.Name())
		if !ok {
			continue
		}
		if !found || idx > maxIdx {
			maxIdx = idx
			found = true
		}
	}

	c, err := readCursor(dir)
	if err != nil {
		return 0, fmt.Errorf("read import cursor: %w", err)
	}
	if c.Segment != "" {
		idx, ok := parseSegmentName(c.Segment)
		if !ok {
			return 0, fmt.Errorf("import cursor names %q, which is not a segment name", c.Segment)
		}
		if !found || idx > maxIdx {
			maxIdx = idx
			found = true
		}
	}

	if !found {
		return 0, nil
	}
	return maxIdx + 1, nil
}

// segmentNameLen is the exact byte length of a segment file name:
// "seg-" (4) + 16 decimal digits + ".vmsp" (5).
const segmentNameLen = 4 + 16 + 5

// maxSegmentIndex is the highest index expressible in the fixed 16-digit
// name space. A 17-digit name would sort lexicographically before every
// 16-digit name, so the importer's string-order cursor comparison would
// misclassify it as PAST and prune it unread (see createSegment).
const maxSegmentIndex = 9999999999999999

// parseSegmentName reports whether name is exactly "seg-" + 16 ASCII decimal
// digits + ".vmsp", returning the encoded index when it is. fmt.Sscanf is
// deliberately not used here: it accepts a leading sign and leading spaces
// inside a %d verb, which would let a malformed name parse successfully.
func parseSegmentName(name string) (uint64, bool) {
	if len(name) != segmentNameLen {
		return 0, false
	}
	if name[:4] != "seg-" {
		return 0, false
	}
	if name[20:] != ".vmsp" {
		return 0, false
	}
	digits := name[4:20]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	idx, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return idx, true
}

// segmentName formats idx as a segment file name.
func segmentName(idx uint64) string {
	return fmt.Sprintf("seg-%016d.vmsp", idx)
}

// fSyncDir opens dir and calls fsync on the directory file descriptor.
// On macOS, fsync on a directory may return ENOTTY or EINVAL — both are
// tolerated because the kernel still updates directory caches; the real
// durability concern is Linux ext4/xfs.
func fSyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil && isDirSyncIgnorable(syncErr) {
		syncErr = nil
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// isDirSyncIgnorable returns true for errno values that some filesystems
// (notably HFS+ on macOS) return when fsync is called on a directory fd.
func isDirSyncIgnorable(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ENOTTY || errno == syscall.EINVAL
	}
	return false
}
