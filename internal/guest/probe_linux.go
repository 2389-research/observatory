// ABOUTME: Linux capability probe: real syscalls for bpf_syscall, fanotify, fanotify_report_fid; path checks for the rest.
// ABOUTME: Each probe is self-contained: opens what it needs, closes it, records errno on failure.
//go:build linux

package guest

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/2389-research/observatory/internal/guest/proto"
)

func probeCapabilities() proto.CapabilityManifest {
	var release string
	var uts unix.Utsname
	if err := unix.Uname(&uts); err == nil {
		// Utsname.Release is [65]int8 on linux/amd64.
		for _, c := range uts.Release {
			if c == 0 {
				break
			}
			release += string(rune(c))
		}
	}

	features := []proto.Feature{
		probePath("btf", "/sys/kernel/btf/vmlinux"),
		probeBPFSyscall(),
		probeFanotify(),
		probeFanotifyReportFID(),
		probeProcFS("cgroup_v2", "/sys/fs/cgroup/cgroup.controllers"),
		probeProcFSLine("devpts", "devpts"),
		probeProcFSLine("ext4", "ext4"),
		probePath("vsock", "/dev/vsock"),
		probePath("virtio_net", "/sys/bus/virtio/drivers/virtio_net"),
		probePath("virtio_blk", "/sys/bus/virtio/drivers/virtio_blk"),
	}

	return proto.CapabilityManifest{
		Schema:        capabilitySchema,
		KernelRelease: release,
		Features:      features,
	}
}

// probePath checks whether path exists (stat succeeds).
func probePath(id, path string) proto.Feature {
	_, err := os.Stat(path)
	if err == nil {
		return proto.Feature{ID: id, Present: true, Evidence: path}
	}
	return proto.Feature{ID: id, Present: false, Evidence: errEvidence(err)}
}

// probeProcFS checks whether path is readable (open succeeds).
func probeProcFS(id, path string) proto.Feature {
	f, err := os.Open(path)
	if err == nil {
		f.Close()
		return proto.Feature{ID: id, Present: true, Evidence: path}
	}
	return proto.Feature{ID: id, Present: false, Evidence: errEvidence(err)}
}

// probeProcFSLine checks /proc/filesystems for a line containing fsType.
func probeProcFSLine(id, fsType string) proto.Feature {
	const procFilesystems = "/proc/filesystems"
	f, err := os.Open(procFilesystems)
	if err != nil {
		return proto.Feature{ID: id, Present: false, Evidence: errEvidence(err)}
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Lines are like "nodev\text4" or "\text4".
		fields := strings.Fields(line)
		for _, field := range fields {
			if field == fsType {
				return proto.Feature{ID: id, Present: true, Evidence: fmt.Sprintf("%s:%s", procFilesystems, fsType)}
			}
		}
	}
	return proto.Feature{ID: id, Present: false, Evidence: fmt.Sprintf("%s: %s not found", procFilesystems, fsType)}
}

// probeBPFSyscall attempts a benign BPF syscall (BPF_OBJ_GET with a zero fd)
// to detect kernel BPF support. The syscall is expected to fail with EBADF or
// EINVAL (not ENOSYS), indicating the kernel supports BPF.
func probeBPFSyscall() proto.Feature {
	const id = "bpf_syscall"
	// BPF_OBJ_GET = 7; pass a zeroed attr — kernel will reject with EBADF or EINVAL
	// if BPF is available, ENOSYS if not.
	_, _, errno := unix.Syscall(unix.SYS_BPF, 7 /* BPF_OBJ_GET */, 0, 0)
	if errno == unix.ENOSYS {
		return proto.Feature{ID: id, Present: false, Evidence: "ENOSYS"}
	}
	// Any other errno (EBADF, EINVAL, EPERM) means the kernel has the syscall.
	return proto.Feature{ID: id, Present: true, Evidence: "syscall reachable"}
}

// probeFanotify calls fanotify_init(FAN_CLASS_NOTIF, O_RDONLY) to test basic fanotify support.
func probeFanotify() proto.Feature {
	const id = "fanotify"
	const fanClassNotif = 0x0
	fd, err := unix.FanotifyInit(fanClassNotif, unix.O_RDONLY)
	if err != nil {
		return proto.Feature{ID: id, Present: false, Evidence: errEvidence(err)}
	}
	unix.Close(fd)
	return proto.Feature{ID: id, Present: true, Evidence: "fanotify_init ok"}
}

// probeFanotifyReportFID calls fanotify_init(FAN_CLASS_NOTIF|FAN_REPORT_FID, O_RDONLY).
func probeFanotifyReportFID() proto.Feature {
	const id = "fanotify_report_fid"
	const fanClassNotif = 0x0
	const fanReportFID = 0x200
	fd, err := unix.FanotifyInit(fanClassNotif|fanReportFID, unix.O_RDONLY)
	if err != nil {
		return proto.Feature{ID: id, Present: false, Evidence: errEvidence(err)}
	}
	unix.Close(fd)
	return proto.Feature{ID: id, Present: true, Evidence: "fanotify_init(FAN_REPORT_FID) ok"}
}

// errEvidence extracts a concise string from an error for use as Feature.Evidence.
func errEvidence(err error) string {
	if err != nil {
		return err.Error()
	}
	return "ok"
}
