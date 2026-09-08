// ABOUTME: Builds bounded raw-tracepoint programs using offsets checked against live kernel BTF.
// ABOUTME: Every task-memory read is checked and failures join measured ring output loss.
package procwatch

import (
	"fmt"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func memberOffset(s *btf.Struct, name string, size int) (int32, error) {
	for _, m := range s.Members {
		if m.Name == name {
			n, err := btf.Sizeof(m.Type)
			if err != nil || n != size || m.BitfieldSize != 0 || uint32(m.Offset)%8 != 0 || uint32(m.Offset)/8+uint32(size) > s.Size {
				return 0, fmt.Errorf("unsupported BTF field %s.%s", s.Name, name)
			}
			return int32(m.Offset / 8), nil
		}
	}
	return 0, fmt.Errorf("missing BTF field %s.%s", s.Name, name)
}

type offsets struct{ pid, tgid, start, exec, leader, parent, comm, exit int32 }

// Stack [-104,0) is the complete wire record; [-120,-104) holds temporary pointers.
func lifecycleProgram(kind int32, o offsets, eventsFD, lossFD, tokensFD int) asm.Instructions {
	p := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.Mov.Imm(asm.R0, 0)}
	for i := int16(-104); i < 0; i += 8 {
		p = append(p, asm.StoreMem(asm.RFP, i, asm.R0, asm.DWord))
	}
	p = append(p, asm.StoreImm(asm.RFP, -104, int64(kind), asm.Word), asm.FnKtimeGetNs.Call(), asm.StoreMem(asm.RFP, -96, asm.R0, asm.DWord))
	taskArg := int16(0)
	if kind == 1 {
		taskArg = 8
	}
	p = append(p, asm.LoadMem(asm.R7, asm.R6, taskArg, asm.DWord))
	if kind == 2 || kind == 3 {
		p = append(p, asm.StoreMem(asm.RFP, -128, asm.R7, asm.DWord))
		if kind == 2 {
			p = append(p, asm.LoadMapPtr(asm.R1, tokensFD), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -128), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "delete_token"), asm.LoadMem(asm.R0, asm.R0, 0, asm.DWord), asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord))
		}
		p = append(p, asm.LoadMapPtr(asm.R1, tokensFD).WithSymbol("delete_token"), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -128), asm.FnMapDeleteElem.Call())
	}
	read := func(base asm.Register, off int32, dest int16, size int32) {
		p = append(p, asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, int32(dest)), asm.Mov.Imm(asm.R2, size), asm.Mov.Reg(asm.R3, base), asm.Add.Imm(asm.R3, off), asm.FnProbeReadKernel.Call(), asm.JNE.Imm(asm.R0, 0, "loss"))
	}
	read(asm.R7, o.pid, -88, 4)
	read(asm.R7, o.tgid, -84, 4)
	read(asm.R7, o.start, -16, 8)
	read(asm.R7, o.leader, -112, 8)
	p = append(p, asm.LoadMem(asm.R8, asm.RFP, -112, asm.DWord))
	read(asm.R8, o.start, -80, 8)
	read(asm.R8, o.exec, -72, 8)
	read(asm.R7, o.comm, -40, 16)
	if kind == 3 {
		read(asm.R7, o.exit, -60, 4)
	}
	if kind == 2 {
		p = append(p, asm.LoadMem(asm.R0, asm.R6, 8, asm.Word), asm.StoreMem(asm.RFP, -24, asm.R0, asm.Word))
	}
	// For a fork the tracepoint's first task is the observed creator. For other
	// events real_parent is the kernel relationship at capture, not a later lookup.
	if kind == 1 {
		p = append(p, asm.LoadMem(asm.R9, asm.R6, 0, asm.DWord))
	} else {
		read(asm.R7, o.parent, -120, 8)
		p = append(p, asm.LoadMem(asm.R9, asm.RFP, -120, asm.DWord))
	}
	read(asm.R9, o.leader, -112, 8)
	p = append(p, asm.LoadMem(asm.R9, asm.RFP, -112, asm.DWord))
	read(asm.R9, o.tgid, -64, 4)
	read(asm.R9, o.start, -56, 8)
	read(asm.R9, o.exec, -48, 8)
	p = append(p,
		asm.LoadMapPtr(asm.R1, eventsFD), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -104), asm.Mov.Imm(asm.R3, recordSize), asm.Mov.Imm(asm.R4, 0), asm.FnRingbufOutput.Call(), asm.JEq.Imm(asm.R0, 0, "return"),
		asm.StoreImm(asm.RFP, -120, 0, asm.Word).WithSymbol("loss"), asm.LoadMapPtr(asm.R1, lossFD), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -120), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "return"), asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("return"), asm.Return())
	return p
}
