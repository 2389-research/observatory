// ABOUTME: Wire-frame encode/decode for the guest channel protocol.
// ABOUTME: 5-byte header [type:1][len:4 big-endian]; length validated before allocation.
package proto

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame type bytes.
const (
	FrameControl  byte = 0x01
	FramePTY      byte = 0x02
	FrameArtifact byte = 0x03
)

// Per-type maximum payload sizes.
const (
	MaxControlFrame = 1 << 20   // 1 MiB
	MaxBinaryFrame  = 256 << 10 // 256 KiB
)

// maxLen returns the per-type payload maximum for the given frame type.
// Returns 0 for unknown types.
func maxLen(typ byte) uint32 {
	switch typ {
	case FrameControl:
		return MaxControlFrame
	case FramePTY, FrameArtifact:
		return MaxBinaryFrame
	default:
		return 0
	}
}

// WriteFrame writes a single frame to w. It validates the payload size before
// writing and returns a "frame length" error if the payload exceeds the per-type
// maximum.
func WriteFrame(w io.Writer, typ byte, payload []byte) error {
	max := maxLen(typ)
	if max == 0 {
		return fmt.Errorf("unknown frame type 0x%02X", typ)
	}
	if uint32(len(payload)) > max {
		return fmt.Errorf("frame length %d exceeds maximum %d for type 0x%02X", len(payload), max, typ)
	}
	hdr := [5]byte{}
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return fmt.Errorf("write frame payload: %w", err)
		}
	}
	return nil
}

// ReadFrame reads a single frame from r. It validates the type and frame length
// BEFORE allocating a buffer for the payload; a hostile large length field will
// not cause a large allocation.
func ReadFrame(r io.Reader) (typ byte, payload []byte, err error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("read frame header: %w", err)
	}
	typ = hdr[0]
	max := maxLen(typ)
	if max == 0 {
		return 0, nil, fmt.Errorf("unknown frame type 0x%02X", typ)
	}
	length := binary.BigEndian.Uint32(hdr[1:])
	if length > max {
		return 0, nil, fmt.Errorf("frame length %d exceeds maximum %d for type 0x%02X", length, max, typ)
	}
	if length == 0 {
		return typ, []byte{}, nil
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("read frame payload: %w", err)
	}
	return typ, payload, nil
}
