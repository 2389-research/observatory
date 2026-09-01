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
	"sort"
	"syscall"

	"github.com/2389-research/observatory-v2/internal/events"
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
type Writer struct {
	dir      string
	cfg      WriterCfg
	maxSpool int64 // resolved MaxSpoolBytes (never zero)
	segIdx   uint64
	f        *os.File
	segBytes int64 // bytes written to current segment (header + records)
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
func (w *Writer) Append(env *events.Envelope) error {
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("spool: marshal envelope: %w", err)
	}
	if len(body) > maxRecordBytes {
		return fmt.Errorf("spool: record body %d bytes exceeds 256 KiB frame limit", len(body))
	}

	// Spool total-bytes guard (SPEC §12.5).
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

	if _, err := w.f.Write(rec); err != nil {
		return fmt.Errorf("spool: write record: %w", err)
	}
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("spool: fsync after record: %w", err)
	}
	w.segBytes += needed
	return nil
}

// Close writes the end marker, fsyncs, and closes the current segment.
func (w *Writer) Close() error {
	if w.f == nil {
		return nil
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
	name := fmt.Sprintf("seg-%016d.vmsp", w.segIdx)
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
	if err := w.Close(); err != nil {
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
// monotonic index to use.
func nextSegmentIndex(dir string) (uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".vmsp" {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return 0, nil
	}
	sort.Strings(names)
	last := names[len(names)-1]

	var idx uint64
	_, err = fmt.Sscanf(last, "seg-%016d.vmsp", &idx)
	if err != nil {
		// Unrecognized name — start fresh.
		return 0, nil
	}
	return idx + 1, nil
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
