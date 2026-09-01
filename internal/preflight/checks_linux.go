// ABOUTME: Linux-only preflight checks: KVM open, API version, real-mode hlt guest.
// ABOUTME: diskFreeStatfs and kernelRelease use golang.org/x/sys/unix on Linux.
//go:build linux

package preflight

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// KVM ioctl constants from linux/kvm.h.
const (
	kvmGetAPIVersion   = 0xae00
	kvmCreateVM        = 0xae01
	kvmCreateVCPU      = 0xae41
	kvmRun             = 0xae80
	kvmGetVCPUMMapSize = 0xae04

	kvmSetUserMemoryRegion = 0x4020ae46
	kvmSetRegs             = 0x4090ae82
	kvmGetRegs             = 0x8090ae81
	kvmGetSregs            = 0x8138ae83
	kvmSetSregs            = 0x4138ae84

	kvmExitHLT = 5
)

// kvmUserMemoryRegion mirrors struct kvm_userspace_memory_region.
type kvmUserMemoryRegion struct {
	Slot          uint32
	Flags         uint32
	GuestPhysAddr uint64
	MemorySize    uint64
	UserspaceAddr uint64
}

// kvmRegs mirrors struct kvm_regs (x86_64 general purpose registers).
type kvmRegs struct {
	RAX, RBX, RCX, RDX uint64
	RSI, RDI, RSP, RBP uint64
	R8, R9, R10, R11   uint64
	R12, R13, R14, R15 uint64
	RIP, RFLAGS        uint64
}

// kvmSegment mirrors struct kvm_segment (one segment descriptor).
type kvmSegment struct {
	Base     uint64
	Limit    uint32
	Selector uint16
	Type     uint8
	Present  uint8
	DPL      uint8
	DB       uint8
	S        uint8
	L        uint8
	G        uint8
	AVL      uint8
	Unusable uint8
	Padding  uint8
}

// kvmDtable mirrors struct kvm_dtable (GDT/IDT descriptor).
type kvmDtable struct {
	Base    uint64
	Limit   uint16
	Padding [3]uint16
}

// kvmSregs mirrors struct kvm_sregs (x86_64 special/segment registers).
type kvmSregs struct {
	CS, DS, ES, FS, GS, SS  kvmSegment
	TR, LDT                 kvmSegment
	GDT, IDT                kvmDtable
	CR0, CR2, CR3, CR4, CR8 uint64
	EFER, ApicBase          uint64
	InterruptBitmap         [4]uint64
}

// checkArchKVM opens /dev/kvm, checks API version 12, creates a VM + vCPU,
// maps a page of guest RAM containing a real-mode `hlt` instruction, runs it,
// and asserts KVM_EXIT_HLT. On ENOENT or EACCES it fails with remediation.
func (r *Runner) checkArchKVM() Check {
	id := "arch_kvm"

	// Open /dev/kvm.
	kvmFd, err := unix.Open("/dev/kvm", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err == unix.ENOENT {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  "/dev/kvm not found",
			Evidence: []string{"open /dev/kvm: no such file or directory"},
			Remediation: &Remediation{
				Cause:  "kvm_absent",
				Action: "run scripts/aibox03/setup.sh to load the kvm module and ensure KVM is supported",
			},
		}
	}
	if err == unix.EACCES {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  "permission denied opening /dev/kvm",
			Evidence: []string{"open /dev/kvm: permission denied"},
			Remediation: &Remediation{
				Cause:  "kvm_permission",
				Action: "re-login for kvm group membership (sudo usermod -aG kvm $USER; log out and back in)",
			},
		}
	}
	if err != nil {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("cannot open /dev/kvm: %v", err),
			Evidence: []string{err.Error()},
		}
	}
	defer unix.Close(kvmFd)

	// KVM_GET_API_VERSION must be 12.
	apiVer, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(kvmFd), kvmGetAPIVersion, 0)
	if errno != 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM_GET_API_VERSION failed: %v", errno),
			Evidence: []string{fmt.Sprintf("ioctl KVM_GET_API_VERSION: %v", errno)},
		}
	}
	if int(apiVer) != 12 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM API version %d, want 12", apiVer),
			Evidence: []string{fmt.Sprintf("kvm_api_version: %d", apiVer)},
		}
	}

	evidence := []string{fmt.Sprintf("kvm_api_version: %d", apiVer)}

	// KVM_CREATE_VM.
	vmFd, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(kvmFd), kvmCreateVM, 0)
	if errno != 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM_CREATE_VM failed: %v", errno),
			Evidence: evidence,
		}
	}
	defer unix.Close(int(vmFd))

	// Allocate one 4 KiB page of guest RAM.
	const pageSize = 4096
	mem, err := unix.Mmap(-1, 0, pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_ANONYMOUS)
	if err != nil {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("mmap guest RAM: %v", err),
			Evidence: evidence,
		}
	}
	defer unix.Munmap(mem)

	// Write a real-mode `hlt` (0xF4) at offset 0.
	mem[0] = 0xF4

	// KVM_SET_USER_MEMORY_REGION — map the page at guest physical 0.
	region := kvmUserMemoryRegion{
		Slot:          0,
		Flags:         0,
		GuestPhysAddr: 0,
		MemorySize:    pageSize,
		UserspaceAddr: uint64(uintptr(unsafe.Pointer(&mem[0]))),
	}
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, vmFd, kvmSetUserMemoryRegion,
		uintptr(unsafe.Pointer(&region)))
	if errno != 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM_SET_USER_MEMORY_REGION failed: %v", errno),
			Evidence: evidence,
		}
	}

	// KVM_CREATE_VCPU.
	vcpuFd, _, errno := syscall.Syscall(syscall.SYS_IOCTL, vmFd, kvmCreateVCPU, 0)
	if errno != 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM_CREATE_VCPU failed: %v", errno),
			Evidence: evidence,
		}
	}
	defer unix.Close(int(vcpuFd))

	// mmap the kvm_run struct.
	mmapSize, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(kvmFd), kvmGetVCPUMMapSize, 0)
	if errno != 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM_GET_VCPU_MMAP_SIZE failed: %v", errno),
			Evidence: evidence,
		}
	}
	runMem, err := unix.Mmap(int(vcpuFd), 0, int(mmapSize),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("mmap kvm_run: %v", err),
			Evidence: evidence,
		}
	}
	defer unix.Munmap(runMem)

	// Set RIP=0 and RFLAGS=2 (reserved bit 1 always set).
	var regs kvmRegs
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, vcpuFd, kvmGetRegs,
		uintptr(unsafe.Pointer(&regs)))
	if errno != 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM_GET_REGS failed: %v", errno),
			Evidence: evidence,
		}
	}
	regs.RIP = 0
	regs.RFLAGS = 2
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, vcpuFd, kvmSetRegs,
		uintptr(unsafe.Pointer(&regs)))
	if errno != 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM_SET_REGS failed: %v", errno),
			Evidence: evidence,
		}
	}

	// Zero CS base and selector so the vCPU executes at physical address 0
	// (where we loaded hlt), not the reset-vector default 0xffff0000.
	var sregs kvmSregs
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, vcpuFd, kvmGetSregs,
		uintptr(unsafe.Pointer(&sregs)))
	if errno != 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM_GET_SREGS failed: %v", errno),
			Evidence: evidence,
		}
	}
	sregs.CS.Base = 0
	sregs.CS.Selector = 0
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, vcpuFd, kvmSetSregs,
		uintptr(unsafe.Pointer(&sregs)))
	if errno != 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("KVM_SET_SREGS failed: %v", errno),
			Evidence: evidence,
		}
	}

	// KVM_RUN: expect EINTR to be retried, exit when we see KVM_EXIT_HLT.
	for {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, vcpuFd, kvmRun, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return Check{
				ID:       id,
				Status:   StatusFail,
				Summary:  fmt.Sprintf("KVM_RUN failed: %v", errno),
				Evidence: evidence,
			}
		}
		break
	}

	// Read exit_reason from the kvm_run mmap (offset 8, uint32).
	exitReason := *(*uint32)(unsafe.Pointer(&runMem[8]))
	evidence = append(evidence, fmt.Sprintf("kvm_exit_reason: %d", exitReason))

	if exitReason != kvmExitHLT {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("expected KVM_EXIT_HLT (%d), got %d", kvmExitHLT, exitReason),
			Evidence: evidence,
		}
	}

	return Check{
		ID:       id,
		Status:   StatusPass,
		Summary:  "KVM open + real-mode hlt guest executed KVM_EXIT_HLT",
		Evidence: evidence,
	}
}

// kernelRelease returns the kernel release string from uname.
func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "uname failed"
	}
	// Utsname.Release is [65]int8 on linux/amd64.
	b := make([]byte, 0, 65)
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// diskFreeStatfs returns free disk in MiB using unix.Statfs.
func diskFreeStatfs(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	// Bavail is blocks free for non-root. Bsize may be signed on some platforms.
	freeMiB := int64(st.Bavail) * int64(st.Bsize) / (1024 * 1024)
	return freeMiB, nil
}
