// ABOUTME: Captures native amd64 exec/connect syscall arguments and results with bounded BPF reads.
// ABOUTME: Uses live BTF offsets and keeps failed user-memory reads explicit in each record.
package procwatch

import (
	"github.com/cilium/ebpf/asm"
)

type syscallOffsets struct{ di, si, dx, origAX, cs, nsproxy, netns, inum int32 }

// Stack [-400,0) is the syscall record; lower slots hold checked temporary values.
func syscallProgram(enter bool, o offsets, x syscallOffsets, eventsFD, lossFD, tokensFD int) asm.Instructions {
	p := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R7, asm.R6, 0, asm.DWord)}
	read := func(base asm.Register, off int32, dest int16, size int32) {
		p = append(p, asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, int32(dest)), asm.Mov.Imm(asm.R2, size), asm.Mov.Reg(asm.R3, base), asm.Add.Imm(asm.R3, off), asm.FnProbeReadKernel.Call(), asm.JNE.Imm(asm.R0, 0, "loss"))
	}
	read(asm.R7, x.origAX, -408, 8)
	p = append(p, asm.LoadMem(asm.R0, asm.RFP, -408, asm.DWord), asm.JEq.Imm(asm.R0, 59, "selected"), asm.JEq.Imm(asm.R0, 322, "selected"), asm.JNE.Imm(asm.R0, 42, "return"))
	p = append(p, asm.Mov.Imm(asm.R0, 0).WithSymbol("selected"))
	for i := int16(-400); i < 0; i += 8 {
		p = append(p, asm.StoreMem(asm.RFP, i, asm.R0, asm.DWord))
	}
	// 0x33 is the native long-mode user code selector; compat tasks are excluded.
	read(asm.R7, x.cs, -416, 8)
	p = append(p, asm.LoadMem(asm.R0, asm.RFP, -416, asm.DWord), asm.JNE.Imm(asm.R0, 0x33, "return"), asm.LoadMem(asm.R0, asm.RFP, -408, asm.DWord), asm.StoreMem(asm.RFP, -312, asm.R0, asm.DWord))
	kind := int64(4)
	if !enter {
		kind = 5
	}
	p = append(p, asm.StoreImm(asm.RFP, -400, kind, asm.Word), asm.JNE.Imm(asm.R0, 42, "identity"), asm.StoreImm(asm.RFP, -400, kind+2, asm.Word), asm.FnKtimeGetNs.Call().WithSymbol("identity"), asm.StoreMem(asm.RFP, -392, asm.R0, asm.DWord), asm.FnGetCurrentTask.Call(), asm.Mov.Reg(asm.R8, asm.R0))
	// Task pointers remain map keys inside the guest kernel; only timestamps leave it.
	p = append(p, asm.LoadMem(asm.R0, asm.RFP, -312, asm.DWord), asm.JEq.Imm(asm.R0, 42, "task_identity"), asm.StoreMem(asm.RFP, -440, asm.R8, asm.DWord), asm.LoadMapPtr(asm.R1, tokensFD), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -440), asm.FnMapDeleteElem.Call())
	if enter {
		p = append(p, asm.LoadMapPtr(asm.R1, tokensFD), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -440), asm.Mov.Reg(asm.R3, asm.RFP), asm.Add.Imm(asm.R3, -392), asm.Mov.Imm(asm.R4, 0), asm.FnMapUpdateElem.Call(), asm.JNE.Imm(asm.R0, 0, "loss"), asm.LoadMem(asm.R0, asm.RFP, -392, asm.DWord), asm.StoreMem(asm.RFP, -352, asm.R0, asm.DWord))
	}
	p = append(p, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("task_identity"))
	read(asm.R8, o.pid, -384, 4)
	read(asm.R8, o.tgid, -380, 4)
	read(asm.R8, o.start, -360, 8)
	read(asm.R8, o.comm, -336, 16)
	read(asm.R8, o.leader, -416, 8)
	p = append(p, asm.LoadMem(asm.R9, asm.RFP, -416, asm.DWord))
	read(asm.R9, o.start, -376, 8)
	read(asm.R9, o.exec, -368, 8)
	if !enter {
		p = append(p, asm.LoadMem(asm.R0, asm.R6, 8, asm.DWord), asm.StoreMem(asm.RFP, -304, asm.R0, asm.DWord), asm.Ja.Label("output"))
	} else {
		p = append(p, asm.LoadMem(asm.R0, asm.RFP, -312, asm.DWord), asm.JEq.Imm(asm.R0, 42, "connect"), asm.JEq.Imm(asm.R0, 322, "execveat"))
		read(asm.R7, x.si, -416, 8)
		p = append(p, asm.Ja.Label("argv"))
		p = append(p, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("execveat"))
		read(asm.R7, x.dx, -416, 8)
		p = append(p, asm.LoadMem(asm.R9, asm.RFP, -416, asm.DWord).WithSymbol("argv"))
		for i := 0; i < 4; i++ {
			p = append(p, asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -424), asm.Mov.Imm(asm.R2, 8), asm.Mov.Reg(asm.R3, asm.R9), asm.Add.Imm(asm.R3, int32(i*8)), asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "argv_failure"), asm.LoadMem(asm.R3, asm.RFP, -424, asm.DWord), asm.JEq.Imm(asm.R3, 0, "output"), asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, int32(-256+i*64)), asm.Mov.Imm(asm.R2, 64), asm.FnProbeReadUserStr.Call(), asm.JSLT.Imm(asm.R0, 1, "argv_failure"), asm.StoreMem(asm.RFP, int16(-288+i*4), asm.R0, asm.Word), asm.StoreImm(asm.RFP, -296, int64(i+1), asm.Word))
		}
		// The fifth pointer is read only to distinguish an exact four arguments from truncation.
		p = append(p, asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -424), asm.Mov.Imm(asm.R2, 8), asm.Mov.Reg(asm.R3, asm.R9), asm.Add.Imm(asm.R3, 32), asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "argv_failure"), asm.LoadMem(asm.R0, asm.RFP, -424, asm.DWord), asm.JEq.Imm(asm.R0, 0, "output"), asm.StoreImm(asm.RFP, -292, 1, asm.Word), asm.Ja.Label("output"), asm.StoreImm(asm.RFP, -292, 2, asm.Word).WithSymbol("argv_failure"), asm.Ja.Label("output"))
		p = append(p, asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("connect"))
		read(asm.R7, x.di, -272, 4)
		read(asm.R7, x.dx, -268, 4)
		read(asm.R7, x.si, -424, 8)
		read(asm.R8, x.nsproxy, -416, 8)
		p = append(p, asm.LoadMem(asm.R8, asm.RFP, -416, asm.DWord))
		read(asm.R8, x.netns, -416, 8)
		p = append(p, asm.LoadMem(asm.R8, asm.RFP, -416, asm.DWord))
		read(asm.R8, x.inum, -264, 4)
		// Read the family first, then exactly the supported sockaddr size.
		p = append(p, asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -256), asm.Mov.Imm(asm.R2, 2), asm.LoadMem(asm.R3, asm.RFP, -424, asm.DWord), asm.FnProbeReadUser.Call(), asm.JNE.Imm(asm.R0, 0, "address_failure"), asm.LoadMem(asm.R0, asm.RFP, -256, asm.Half), asm.JEq.Imm(asm.R0, 2, "ipv4"), asm.JNE.Imm(asm.R0, 10, "output"), asm.LoadMem(asm.R0, asm.RFP, -268, asm.Word), asm.JLT.Imm(asm.R0, 28, "address_failure"), asm.Mov.Imm(asm.R2, 28), asm.Ja.Label("address"), asm.LoadMem(asm.R0, asm.RFP, -268, asm.Word).WithSymbol("ipv4"), asm.JLT.Imm(asm.R0, 16, "address_failure"), asm.Mov.Imm(asm.R2, 16), asm.Mov.Reg(asm.R1, asm.RFP).WithSymbol("address"), asm.Add.Imm(asm.R1, -256), asm.LoadMem(asm.R3, asm.RFP, -424, asm.DWord), asm.FnProbeReadUser.Call(), asm.JEq.Imm(asm.R0, 0, "output"), asm.StoreImm(asm.RFP, -260, 1, asm.Word).WithSymbol("address_failure"))
	}
	p = append(p, asm.LoadMapPtr(asm.R1, eventsFD).WithSymbol("output"), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -400), asm.Mov.Imm(asm.R3, syscallRecordSize), asm.Mov.Imm(asm.R4, 0), asm.FnRingbufOutput.Call(), asm.JEq.Imm(asm.R0, 0, "return"), asm.StoreImm(asm.RFP, -432, 0, asm.Word).WithSymbol("loss"), asm.LoadMapPtr(asm.R1, lossFD), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -432), asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "return"), asm.Mov.Imm(asm.R1, 1), asm.StoreXAdd(asm.R0, asm.R1, asm.DWord), asm.Mov.Imm(asm.R0, 0).WithSymbol("return"), asm.Return())
	return p
}
