// ABOUTME: Checks conntrack acquisition framing and actual namespace-local subscriptions.
// ABOUTME: Privileged tests run only in an explicitly selected disposable Linux container.
//go:build linux

package netobserve

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestConntrackSnapshotRequest(t *testing.T) {
	b := conntrackSnapshotRequest(17, 23)
	if len(b) != 20 || binary.NativeEndian.Uint32(b) != 20 || binary.NativeEndian.Uint16(b[4:]) != 0x101 || binary.NativeEndian.Uint16(b[6:]) != unix.NLM_F_REQUEST|unix.NLM_F_DUMP || binary.NativeEndian.Uint32(b[8:]) != 17 || binary.NativeEndian.Uint32(b[12:]) != 23 || b[16] != unix.AF_INET {
		t.Fatalf("invalid bounded IPv4 snapshot request: %x", b)
	}
}

func TestConntrackAcquisitionCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	file, _, err := OpenConntrack(ctx)
	if file != nil {
		_ = file.Close()
	}
	if err != context.Canceled || file != nil {
		t.Fatalf("canceled acquisition returned file=%v error=%v", file, err)
	}
}

func TestRealConntrackAcquisition(t *testing.T) {
	if os.Getenv("VMOBS_CONNTRACK_ACQUISITION_TEST") != "1" {
		t.Skip("explicit disposable Linux container required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged acquisition requires root inside disposable container")
	}
	if os.Getenv("VMOBS_CONNTRACK_ACQUISITION_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRealConntrackAcquisition$", "-test.v")
		cmd.Env = append(os.Environ(), "VMOBS_CONNTRACK_ACQUISITION_CHILD=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated acquisition: %v\n%s", err, out)
		}
		return
	}
	file, info, err := OpenConntrack(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	fd := int(file.Fd())
	address, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	nl, ok := address.(*unix.SockaddrNetlink)
	if !ok || nl.Groups != 7 || nl.Pid != info.PortID || info.SnapshotSequence != 1 {
		t.Fatalf("wrong collector binding: %+v %+v", address, info)
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("socket leaked across exec: flags=%d err=%v", flags, err)
	}
	buffer := make([]byte, 65536)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, flags, sender, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if flags&unix.MSG_TRUNC != 0 || sender.(*unix.SockaddrNetlink).Pid != 0 {
			t.Fatal("untrusted snapshot response")
		}
		if n < 16 || binary.NativeEndian.Uint32(buffer[8:]) != info.SnapshotSequence {
			t.Fatalf("wrong snapshot identity: %x", buffer[:n])
		}
		if _, err := ParseConntrack(buffer[:n], true); err != nil {
			t.Fatalf("incomplete snapshot: %v", err)
		}
		if binary.NativeEndian.Uint16(buffer[4:]) != unix.NLMSG_DONE {
			t.Fatalf("empty namespace snapshot failed: %x", buffer[:n])
		}
		return
	}
	t.Fatal("privileged snapshot did not complete")
}
