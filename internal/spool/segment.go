// ABOUTME: Spool segment format constants, types, and on-disk layout documentation.
// ABOUTME: The wire format and recovery rules defined here govern both writer and reader.

// Package spool implements the durable event spool: a directory of append-only
// segment files used by the guest runner (Task 8) to durably buffer event
// envelopes before the host importer (Task 7) reads them into SQLite.
//
// # Segment file layout
//
// File name: seg-%016d.vmsp (monotonic index, zero-padded to 16 decimal digits).
//
// Byte layout:
//
//	Header (JSON line): {"magic":"vmsp","version":1,"vm_id":"...","instance_id":"..."}\n
//	Zero or more records, each:
//	  [len uint32 BE][crc32c uint32 BE][len bytes — JSON-encoded events.Envelope]
//	End marker (clean close only):
//	  [0xFFFFFFFF uint32 BE]
//
// # Constraints
//
// Max record body size: 256 KiB (SPEC §6.2 event frame limit).
// A segment without an end marker is "open or crashed" — the reader applies
// truncated-tail tolerance per the recovery rules below.
//
// # Recovery rules (SPEC §12.4)
//
// Tolerate an unacknowledged truncated trailing record (truncate it away).
// Reject corrupt interior records — stop reading the segment at the first
// corruption and report it. A gap envelope (kind spool.recovery_gap) is
// emitted for the omitted span.
//
// # Durability (SPEC §12.4)
//
// On segment create: fsync the file AND its directory (directory-entry durability).
// On Append: write record, fsync file, then return — the fsync is the ack barrier.
package spool

import "errors"

// DefaultMaxSpoolBytes is the fallback when WriterCfg.MaxSpoolBytes == 0.
// 512 MiB matches the spec target (observation.max_runner_spool_bytes).
const DefaultMaxSpoolBytes = 512 << 20

// maxRecordBytes is the §6.2 event frame limit.
const maxRecordBytes = 256 * 1024

// segmentMagic is the JSON "magic" value in the segment header.
const segmentMagic = "vmsp"

// segmentVersion is the "version" field in the segment header.
const segmentVersion = 1

// endMarker is the uint32 big-endian value that signals a clean close.
const endMarker uint32 = 0xFFFFFFFF

// ErrCorruptRecord is returned by SegmentIter.Next when a record's CRC32C
// does not match its body, or when a record claims a length exceeding the
// 256 KiB frame limit.
var ErrCorruptRecord = errors.New("spool: corrupt record")

// ErrSpoolFull is returned by Writer.Append when adding the record would
// cause the total bytes across all segments in the spool directory to exceed
// WriterCfg.MaxSpoolBytes. The caller must stop acking the guest and emit
// the overflow health record; the record is never dropped silently (SPEC §12.5).
var ErrSpoolFull = errors.New("spool: spool full")
