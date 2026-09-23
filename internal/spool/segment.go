// ABOUTME: Spool segment format constants, types, and on-disk layout documentation.
// ABOUTME: The wire format and recovery rules defined here govern both writer and reader.

// Package spool implements the durable event spool: a directory of append-only
// segment files used by the guest runner to durably buffer event envelopes
// before the host importer reads them into SQLite.
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
// Only names of the form seg-%016d.vmsp are segments; every other name is
// never opened, truncated, or removed by recovery. Segments are ordered by
// that index, and the newest (highest) is never truncated: its writer may
// still be appending to it, so reading it simply stops at the torn tail. A
// torn tail on any other segment is truncated away, since no writer will
// return to finish it.
//
// A segment whose header has no trailing newline yet is a creation still in
// progress: left alone when it is the newest, removed when it is not, for
// the same reason — no writer will come back to finish it. Corrupt interior
// records (a bad CRC or an oversize length) are never repaired on any
// segment — reading stops at the first one and a gap envelope (kind
// spool.recovery_gap) reports the omitted span.
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
// WriterCfg.MaxSpoolBytes. The writer counts the refusal and records it in a
// telemetry.loss once an append succeeds, so the caller's only duty is to
// withhold the ack (SPEC §12.5).
var ErrSpoolFull = errors.New("spool: spool full")
