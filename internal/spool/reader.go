// ABOUTME: Reader iterates records from a spool segment file, with truncated-tail tolerance.
// ABOUTME: Interior CRC mismatches return ErrCorruptRecord; truncated tails are silently skipped.
package spool

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
)

// SegmentIter iterates event envelopes from a single spool segment file.
type SegmentIter struct {
	f    *os.File
	r    io.Reader
	done bool // set when EOF or end-marker reached
}

// ReadSegment opens the segment at path and returns an iterator.
// It reads and validates the header; an invalid header is a hard error.
func ReadSegment(path string) (*SegmentIter, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("spool: open segment %s: %w", path, err)
	}

	br := bufio.NewReader(f)

	// The header is a JSON line terminated by \n.
	hdrLine, err := br.ReadString('\n')
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("spool: read segment header from %s: %w", path, err)
	}

	var hdr segmentHeader
	if err := json.Unmarshal([]byte(strings.TrimSuffix(hdrLine, "\n")), &hdr); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("spool: parse segment header in %s: %w", path, err)
	}
	if hdr.Magic != segmentMagic {
		_ = f.Close()
		return nil, fmt.Errorf("spool: segment %s has wrong magic %q (want %q)", path, hdr.Magic, segmentMagic)
	}
	if hdr.Version != segmentVersion {
		_ = f.Close()
		return nil, fmt.Errorf("spool: segment %s has unsupported version %d (want %d)", path, hdr.Version, segmentVersion)
	}

	return &SegmentIter{f: f, r: br}, nil
}

// Close releases the file descriptor held by the iterator. Callers should
// call Close when they are done reading, including after an io.EOF or
// ErrCorruptRecord return from Next.
func (it *SegmentIter) Close() error {
	if it.f == nil {
		return nil
	}
	err := it.f.Close()
	it.f = nil
	return err
}

// Next returns the next envelope in the segment.
// Returns io.EOF when all records have been read (including after a clean end marker).
// Returns ErrCorruptRecord for a CRC mismatch or oversize record — the caller should
// stop reading this segment after a corrupt interior record.
// A truncated trailing record (incomplete len or body) is treated as EOF: the caller
// sees clean termination after all complete records.
func (it *SegmentIter) Next() (*events.Envelope, error) {
	if it.done {
		return nil, io.EOF
	}

	// Read 4-byte length field.
	var lenBuf [4]byte
	if _, err := io.ReadFull(it.r, lenBuf[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// Truncated tail before the length field — treat as EOF (recovery rule).
			it.done = true
			return nil, io.EOF
		}
		return nil, fmt.Errorf("spool: read record length: %w", err)
	}
	recLen := binary.BigEndian.Uint32(lenBuf[:])

	// End marker.
	if recLen == endMarker {
		it.done = true
		return nil, io.EOF
	}

	// Reject records that exceed the frame limit — this is interior corruption,
	// not a truncated tail.
	if int(recLen) > maxRecordBytes {
		return nil, ErrCorruptRecord
	}

	// Read 4-byte CRC.
	var crcBuf [4]byte
	if _, err := io.ReadFull(it.r, crcBuf[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// Truncated tail inside the CRC — treat as EOF.
			it.done = true
			return nil, io.EOF
		}
		return nil, fmt.Errorf("spool: read record crc: %w", err)
	}
	storedCRC := binary.BigEndian.Uint32(crcBuf[:])

	// Read record body.
	body := make([]byte, recLen)
	if _, err := io.ReadFull(it.r, body); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// Truncated tail — the record body is incomplete.
			it.done = true
			return nil, io.EOF
		}
		return nil, fmt.Errorf("spool: read record body: %w", err)
	}

	// Verify CRC32C.
	computed := crc32.Checksum(body, crc32cTable)
	if computed != storedCRC {
		return nil, ErrCorruptRecord
	}

	// Unmarshal the envelope.
	var env events.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		// JSON parse failure after a good CRC is unusual but counts as interior corruption.
		return nil, ErrCorruptRecord
	}
	return &env, nil
}

// RecoverReport describes the result of a Recover call.
type RecoverReport struct {
	// Segments lists the segment file paths that were inspected (and repaired where needed).
	Segments []string
	// TruncatedTail is true when at least one segment had a truncated trailing record
	// that was removed by truncation.
	TruncatedTail bool
	// GapEmitted is non-nil when records were skipped due to corruption. It is a
	// synthetic envelope with kind "spool.recovery_gap" carrying gap metadata.
	// Registration of this kind is Task 7's responsibility (per controller ruling).
	GapEmitted *events.Envelope
}

// Recover inspects all *.vmsp segment files in dir and repairs any truncated tails.
// It returns a RecoverReport describing what it found and fixed.
// An empty dir returns a zero report without error.
func Recover(dir string) (RecoverReport, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return RecoverReport{}, fmt.Errorf("spool: recover readdir %s: %w", dir, err)
	}

	var paths []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".vmsp" {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	if len(paths) == 0 {
		return RecoverReport{}, nil
	}
	sort.Strings(paths)

	var report RecoverReport
	report.Segments = paths

	var totalCorrupt int
	var corruptPaths []string

	for _, path := range paths {
		truncated, corrupt, err := recoverSegment(path)
		if err != nil {
			return RecoverReport{}, fmt.Errorf("spool: recover segment %s: %w", path, err)
		}
		if truncated {
			report.TruncatedTail = true
		}
		if corrupt > 0 {
			totalCorrupt += corrupt
			corruptPaths = append(corruptPaths, filepath.Base(path))
		}
	}

	if totalCorrupt > 0 {
		report.GapEmitted = buildGapEnvelope(totalCorrupt, corruptPaths)
	}

	return report, nil
}

// recoverSegment reads through a single segment file.
// If the file ends with a truncated (incomplete) record it truncates the file
// to the last good byte position and returns (truncated=true, ...).
// If interior corrupt records exist it counts them and returns the count.
// It does NOT truncate interior corruption — the caller (importer, Task 7)
// must handle that; recovery only fixes the tail.
func recoverSegment(path string) (truncated bool, corruptCount int, err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return false, 0, err
	}
	defer f.Close()

	// Measure the header to know where records start.
	br := bufio.NewReader(f)
	hdrLine, err := br.ReadString('\n')
	if err != nil {
		// Malformed header — not a recoverable tail issue.
		return false, 0, fmt.Errorf("read header: %w", err)
	}

	var hdr segmentHeader
	if err := json.Unmarshal([]byte(strings.TrimSuffix(hdrLine, "\n")), &hdr); err != nil {
		return false, 0, fmt.Errorf("parse header: %w", err)
	}
	if hdr.Magic != segmentMagic {
		return false, 0, fmt.Errorf("wrong magic %q", hdr.Magic)
	}

	// Walk through all records, tracking positions so we can truncate.
	// filePos is the current read position in the underlying file.
	// Because we're using bufio.Reader, we track logical byte offsets manually.
	headerBytes := int64(len(hdrLine))
	pos := headerBytes
	lastGoodPos := headerBytes // position after the last complete record

	for {
		// Read length (4 bytes).
		var lenBuf [4]byte
		n, readErr := io.ReadFull(br, lenBuf[:])
		pos += int64(n)
		if readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				// Truncated before length — truncate file to lastGoodPos.
				// Sync after truncation: recovery emits a gap record for what it
				// removed; if the truncation itself isn't durable, a crash can
				// resurrect the garbage tail and a second recovery re-emits the gap.
				if pos > lastGoodPos {
					if terr := f.Truncate(lastGoodPos); terr != nil {
						return false, corruptCount, terr
					}
					if serr := f.Sync(); serr != nil {
						return false, corruptCount, serr
					}
					return true, corruptCount, nil
				}
				return false, corruptCount, nil
			}
			return false, corruptCount, readErr
		}
		recLen := binary.BigEndian.Uint32(lenBuf[:])

		if recLen == endMarker {
			// Clean end marker — nothing to repair.
			return false, corruptCount, nil
		}

		if int(recLen) > maxRecordBytes {
			// Interior corruption — oversize length. We do not try to repair
			// interior corruption; just count it and continue scanning (with
			// the knowledge we'll likely lose sync). For recovery purposes,
			// we count the corrupt record.
			corruptCount++
			// Can't safely skip; stop here.
			break
		}

		// Read CRC (4 bytes).
		var crcBuf [4]byte
		n, readErr = io.ReadFull(br, crcBuf[:])
		pos += int64(n)
		if readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				if err := f.Truncate(lastGoodPos); err != nil {
					return false, corruptCount, err
				}
				if err := f.Sync(); err != nil {
					return false, corruptCount, err
				}
				return true, corruptCount, nil
			}
			return false, corruptCount, readErr
		}
		storedCRC := binary.BigEndian.Uint32(crcBuf[:])

		// Read body (recLen bytes).
		body := make([]byte, recLen)
		n, readErr = io.ReadFull(br, body)
		pos += int64(n)
		if readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				if err := f.Truncate(lastGoodPos); err != nil {
					return false, corruptCount, err
				}
				if err := f.Sync(); err != nil {
					return false, corruptCount, err
				}
				return true, corruptCount, nil
			}
			return false, corruptCount, readErr
		}

		// Verify CRC.
		computed := crc32.Checksum(body, crc32cTable)
		if computed != storedCRC {
			// Interior corruption — count it, stop scanning.
			corruptCount++
			break
		}

		// Record is good; advance lastGoodPos.
		lastGoodPos = pos
	}

	return false, corruptCount, nil
}

// buildGapEnvelope constructs a synthetic recovery gap envelope.
// Kind is "spool.recovery_gap" (registration is Task 7's job per controller ruling).
func buildGapEnvelope(corruptCount int, paths []string) *events.Envelope {
	return &events.Envelope{
		SchemaVersion:    1,
		SourceInstanceID: "spool.recovery",
		SourceSeq:        "0",
		Kind:             "spool.recovery_gap",
		Provenance:       events.HostObserved,
		Sensor:           "spool.recovery",
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
			Notes:          []string{"synthetic gap record emitted by spool recovery"},
		},
		Data: map[string]any{
			"corrupt_record_count": corruptCount,
			"affected_segments":    paths,
		},
	}
}
