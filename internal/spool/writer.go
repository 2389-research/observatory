// ABOUTME: Writer opens and manages spool segment files for durable appending.
// ABOUTME: Each Append is an ack barrier: write + fsync before returning.
package spool

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

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
	segBytes int64 // bytes written to current segment (header + records)
	// poison is set on the first write or fsync failure that touches record
	// bytes. Once set, every subsequent Append returns it immediately.
	// Rationale: after a failed fsync the kernel may drop dirty pages and
	// clear the error flag, so a later fsync can succeed while earlier bytes
	// were lost — retrying turns a loud failure into silent evidence loss.
	// ErrSpoolFull and oversize-record errors do NOT poison: they reject the
	// record before any bytes reach the file.
	poison error
}

// OpenWriter opens (or creates) a spool writer in dir with the given configuration.
// It returns an error when MaxSegmentBytes <= 0.
func OpenWriter(dir string, cfg WriterCfg) (*Writer, error) {
	if cfg.MaxSegmentBytes <= 0 {
		return nil, fmt.Errorf("spool: MaxSegmentBytes must be > 0")
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

	w := &Writer{
		dir:      dir,
		cfg:      cfg,
		maxSpool: maxSpool,
		segIdx:   idx,
	}
	if err := w.openSegment(); err != nil {
		return nil, err
	}
	return w, nil
}

// Append marshals env as JSON and appends it as a record to the current segment.
// It returns ErrSpoolFull if the record would exceed MaxSpoolBytes.
// It fsyncs the segment file before returning (ack barrier, SPEC §12.4).
// If a previous Append poisoned the writer (see Writer.poison), it returns
// the poison error immediately without attempting any write.
func (w *Writer) Append(env *events.Envelope) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Poison check: return the sticky error immediately, no write attempt.
	if w.poison != nil {
		return w.poison
	}

	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("spool: marshal envelope: %w", err)
	}
	// Reject oversized records before any bytes reach the file — does NOT poison.
	if len(body) > maxRecordBytes {
		return fmt.Errorf("spool: record body %d bytes exceeds 256 KiB frame limit", len(body))
	}

	// Spool total-bytes guard (SPEC §12.5) — does NOT poison; no bytes written yet.
	totalNow, err := w.spoolTotalBytes()
	if err != nil {
		return fmt.Errorf("spool: measure spool size: %w", err)
	}
	// Record overhead: 4-byte len + 4-byte CRC = 8 bytes per record.
	needed := int64(8 + len(body))
	if totalNow+needed > w.maxSpool {
		return ErrSpoolFull
	}

	// Rotate if the current segment is already at or near capacity.
	if w.segBytes+needed > w.cfg.MaxSegmentBytes {
		if err := w.rotate(); err != nil {
			return err
		}
	}

	// Build the record: [len uint32 BE][crc32c uint32 BE][body].
	rec := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(rec[0:4], uint32(len(body)))
	checksum := crc32.Checksum(body, crc32cTable)
	binary.BigEndian.PutUint32(rec[4:8], checksum)
	copy(rec[8:], body)

	// Bytes are about to hit the file. Any failure from here poisons the writer.
	if _, err := w.f.Write(rec); err != nil {
		w.poison = fmt.Errorf("spool: write record: %w", err)
		return w.poison
	}
	if err := w.f.Sync(); err != nil {
		w.poison = fmt.Errorf("spool: fsync after record: %w", err)
		return w.poison
	}
	// segBytes is updated only after successful Sync. With poisoning, a stale
	// segBytes after a failed sync is unreachable (writer never appends again).
	w.segBytes += needed
	return nil
}

// Close writes the end marker, fsyncs, and closes the current segment.
// If the writer is poisoned, Close skips the end marker and just closes the fd,
// returning the poison error (or the close error if the fd is already closed).
// The end marker means "cleanly closed, tail trustworthy" — a poisoned segment
// is neither, so omitting it lets recovery treat it as crashed and verify it.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closeLocked()
}

// closeLocked is Close's body. rotate calls it while already holding the lock;
// Close takes the lock and calls it.
func (w *Writer) closeLocked() error {
	if w.f == nil {
		return nil
	}
	if w.poison != nil {
		// Poisoned: skip end marker. Just close the fd (may already be closed).
		_ = w.f.Close()
		w.f = nil
		return w.poison
	}
	// Write end marker: len == 0xFFFFFFFF.
	var marker [4]byte
	binary.BigEndian.PutUint32(marker[:], endMarker)
	if _, err := w.f.Write(marker[:]); err != nil {
		_ = w.f.Close()
		w.f = nil
		return fmt.Errorf("spool: write end marker: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		_ = w.f.Close()
		w.f = nil
		return fmt.Errorf("spool: fsync end marker: %w", err)
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// openSegment creates a new segment file at the current segIdx and writes its header.
// It fsyncs the file and the directory (SPEC §12.4 directory-entry durability).
func (w *Writer) openSegment() error {
	if w.segIdx > maxSegmentIndex {
		return fmt.Errorf("spool: segment index %d exceeds the 16-digit name space", w.segIdx)
	}
	name := segmentName(w.segIdx)
	path := filepath.Join(w.dir, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("spool: create segment %s: %w", name, err)
	}

	hdr := segmentHeader{
		Magic:      segmentMagic,
		Version:    segmentVersion,
		VMID:       w.cfg.VMID,
		InstanceID: w.cfg.InstanceID,
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("spool: marshal segment header: %w", err)
	}
	hdrLine := append(hdrJSON, '\n')

	if _, err := f.Write(hdrLine); err != nil {
		_ = f.Close()
		return fmt.Errorf("spool: write segment header: %w", err)
	}
	// fsync the file itself.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("spool: fsync new segment: %w", err)
	}
	// fsync the directory so the new dentry is durable (SPEC §12.4).
	if err := fSyncDir(w.dir); err != nil {
		_ = f.Close()
		return fmt.Errorf("spool: fsync spool dir: %w", err)
	}

	w.f = f
	w.segBytes = int64(len(hdrLine))
	return nil
}

// rotate closes the current segment cleanly and opens the next one.
func (w *Writer) rotate() error {
	if err := w.closeLocked(); err != nil {
		return fmt.Errorf("spool: rotate close: %w", err)
	}
	w.segIdx++
	return w.openSegment()
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
// segment missing from an earlier listing was pruned only after the cursor
// was written to name it, so a cursor read afterwards still names it and the
// maximum still reflects it. Reading in the other order — cursor first, then
// listing — risks a prune landing between the two reads, which would hide
// the segment from both and let its index be reused.
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
// misclassify it as PAST and prune it unread (see openSegment).
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
