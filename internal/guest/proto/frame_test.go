// ABOUTME: Tests for wire-frame encode/decode: round-trips, oversize rejection, unknown type, truncation.
// ABOUTME: Uses real net.Pipe — no test doubles.
package proto

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		typ     byte
		payload []byte
	}{
		{"control empty", FrameControl, []byte{}},
		{"control small", FrameControl, []byte("hello")},
		{"pty data", FramePTY, []byte{0x01, 0x02, 0x03}},
		{"artifact data", FrameArtifact, make([]byte, 1024)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()

			done := make(chan error, 1)
			go func() {
				done <- WriteFrame(c1, tc.typ, tc.payload)
				c1.Close()
			}()

			typ, payload, err := ReadFrame(c2)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if typ != tc.typ {
				t.Errorf("type: got %d, want %d", typ, tc.typ)
			}
			if len(payload) != len(tc.payload) {
				t.Errorf("payload len: got %d, want %d", len(payload), len(tc.payload))
			}
			for i := range tc.payload {
				if payload[i] != tc.payload[i] {
					t.Errorf("payload[%d]: got %d, want %d", i, payload[i], tc.payload[i])
				}
			}
			if err := <-done; err != nil {
				t.Errorf("WriteFrame: %v", err)
			}
		})
	}
}

func TestReadFrameRejectsOversizeBeforeAllocation(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		hdr := []byte{FrameControl, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(hdr[1:], 100<<20)
		_, _ = c1.Write(hdr) // no body ever sent; error irrelevant — we test the reader
	}()
	_, _, err := ReadFrame(c2)
	if err == nil || !strings.Contains(err.Error(), "frame length") {
		t.Fatalf("want frame length error, got %v", err)
	}
}

func TestReadFrameRejectsPTYOversize(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		hdr := []byte{FramePTY, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(hdr[1:], MaxBinaryFrame+1)
		_, _ = c1.Write(hdr)
	}()
	_, _, err := ReadFrame(c2)
	if err == nil || !strings.Contains(err.Error(), "frame length") {
		t.Fatalf("want frame length error, got %v", err)
	}
}

func TestReadFrameRejectsUnknownType(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		hdr := []byte{0x7F, 0, 0, 0, 3}
		_, _ = c1.Write(hdr)
		_, _ = c1.Write([]byte{1, 2, 3})
		c1.Close()
	}()
	_, _, err := ReadFrame(c2)
	if err == nil || !strings.Contains(err.Error(), "unknown frame type") {
		t.Fatalf("want unknown frame type error, got %v", err)
	}
}

func TestReadFrameRejectsTruncatedHeader(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		// Only 3 bytes of a 5-byte header.
		_, _ = c1.Write([]byte{FrameControl, 0, 0})
		c1.Close()
	}()
	_, _, err := ReadFrame(c2)
	if err == nil {
		t.Fatal("want error on truncated header, got nil")
	}
}

func TestReadFrameRejectsTruncatedBody(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		hdr := []byte{FrameControl, 0, 0, 0, 10}
		_, _ = c1.Write(hdr)
		// Only write 3 bytes of claimed 10.
		_, _ = c1.Write([]byte{1, 2, 3})
		c1.Close()
	}()
	_, _, err := ReadFrame(c2)
	if err == nil {
		t.Fatal("want error on truncated body, got nil")
	}
}

func TestWriteFrameRejectsOversizeControl(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	err := WriteFrame(c1, FrameControl, make([]byte, MaxControlFrame+1))
	if err == nil || !strings.Contains(err.Error(), "frame length") {
		t.Fatalf("want frame length error, got %v", err)
	}
}
