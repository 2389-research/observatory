// ABOUTME: Verifies BTF field validation and the generated lifecycle BPF instruction stream.
// ABOUTME: Real load/attach and short-lived process evidence are checked separately in a Linux guest.
package procwatch

import (
	"bytes"
	"encoding/binary"
	"github.com/cilium/ebpf/btf"
	"runtime"
	"testing"
)

func TestFieldOffsetRejectsWrongWidthAndBitfields(t *testing.T) {
	u := &btf.Int{Name: "u64", Size: 8}
	typ := &btf.Struct{Name: "task_struct", Size: 32, Members: []btf.Member{{Name: "start_time", Type: u, Offset: 64}}}
	got, err := memberOffset(typ, "start_time", 8)
	if err != nil || got != 8 {
		t.Fatalf("offset=%d err=%v", got, err)
	}
	if _, err = memberOffset(typ, "start_time", 4); err == nil {
		t.Fatal("accepted wrong width")
	}
	typ.Members[0].BitfieldSize = 1
	if _, err = memberOffset(typ, "start_time", 8); err == nil {
		t.Fatal("accepted bitfield")
	}
}
func TestLifecycleProgramsMarshal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("BPF helper relocation requires Linux")
	}
	for _, kind := range []int32{1, 2, 3} {
		p := lifecycleProgram(kind, offsets{}, 10, 11, 12)
		var b bytes.Buffer
		if err := p.Marshal(&b, binary.LittleEndian); err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
		if b.Len() == 0 || len(p) > 256 {
			t.Fatalf("unbounded program kind %d: %d", kind, len(p))
		}
	}
}

func TestSyscallProgramsMarshal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("BPF helper relocation requires Linux")
	}
	for _, enter := range []bool{true, false} {
		p := syscallProgram(enter, offsets{}, syscallOffsets{}, 10, 11, 12)
		var b bytes.Buffer
		if err := p.Marshal(&b, binary.LittleEndian); err != nil {
			t.Fatalf("enter=%v: %v", enter, err)
		}
		if b.Len() == 0 || len(p) > 512 {
			t.Fatalf("unbounded syscall program enter=%v length=%d", enter, len(p))
		}
	}
}
