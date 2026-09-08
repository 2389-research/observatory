// ABOUTME: Exercises kernel event decoding without losing hostile filename bytes.
// ABOUTME: Rejects corrupt record boundaries and separates notifications from content evidence.
package fswatch

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func fixture(mask uint64, name []byte) []byte {
	size := 24 + 20 + 4 + len(name) + 1
	b := make([]byte, size)
	binary.NativeEndian.PutUint32(b, uint32(size))
	b[4] = 3
	binary.NativeEndian.PutUint16(b[6:], 24)
	binary.NativeEndian.PutUint64(b[8:], mask)
	binary.NativeEndian.PutUint32(b[16:], ^uint32(0))
	binary.NativeEndian.PutUint32(b[20:], 42)
	b[24] = 2
	binary.NativeEndian.PutUint16(b[26:], uint16(size-24))
	binary.NativeEndian.PutUint32(b[28:], 123)
	binary.NativeEndian.PutUint32(b[36:], 4)
	binary.NativeEndian.PutUint32(b[40:], 1)
	copy(b[44:], []byte{1, 2, 3, 4})
	copy(b[48:], name)
	return b
}
func TestDecodeRetainsRawNameAndNotificationSemantics(t *testing.T) {
	raw := []byte{'x', 0xff, '\n'}
	events, err := decode(fixture(0x100|0x8, raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(events[0].Identities) != 1 {
		t.Fatalf("events: %+v", events)
	}
	id := events[0].Identities[0]
	if id.NameBase64 != base64.StdEncoding.EncodeToString(raw) || id.NameDisplay != `"x\xff\n"` {
		t.Fatalf("name lost: %+v", id)
	}
	if events[0].PathStatus != "unresolved" || events[0].ProcessIdentity != "unknown" {
		t.Fatalf("fabricated attribution: %+v", events[0])
	}
	kinds := events[0].kinds()
	if len(kinds) != 2 || kinds[0] != "fs.create" || kinds[1] != "fs.close_write" {
		t.Fatalf("kinds: %v", kinds)
	}
}
func TestDecodeRejectsCorruptBoundaries(t *testing.T) {
	good := fixture(0x100, []byte("file"))
	for n := 0; n < len(good); n++ {
		if _, err := decode(good[:n]); err == nil && n != 0 {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	bad := append([]byte(nil), good...)
	bad[4] = 99
	if _, err := decode(bad); err == nil {
		t.Fatal("accepted unknown version")
	}
	bad = append([]byte(nil), good...)
	binary.NativeEndian.PutUint32(bad[36:], 0xffffffff)
	if _, err := decode(bad); err == nil {
		t.Fatal("accepted oversized handle")
	}
}

func TestRenameKeepsBothParentsAndFileIdentity(t *testing.T) {
	old := fixture(0x10000000, []byte("old"))
	old[24] = 10
	next := fixture(0x10000000, []byte("new"))
	next[24] = 12
	b := append(old, next[24:]...)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	events, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(events[0].Identities) != 2 || events[0].Identities[0].Role != "old_parent" || events[0].Identities[1].Role != "new_parent" {
		t.Fatalf("lost rename: %+v", events)
	}
}
func TestDecodeOverflowIsNotAMutation(t *testing.T) {
	b := fixture(0x4000, []byte("x"))[:24]
	binary.NativeEndian.PutUint32(b, 24)
	e, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(e) != 1 || e[0].Mask != 0x4000 || len(e[0].kinds()) != 0 {
		t.Fatalf("overflow: %+v", e)
	}
}
