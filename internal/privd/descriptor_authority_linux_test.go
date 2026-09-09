// ABOUTME: Proves a real collector descriptor transfers observations without netlink mutation authority.
// ABOUTME: Uses a private network namespace and an unprivileged recipient over the production rights framing.
//go:build linux

package privd

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/netobserve"
	"golang.org/x/sys/unix"
)

func TestCollectorDescriptorDoesNotTransferMutationAuthority(t *testing.T) {
	if os.Getenv("VMOBS_DESCRIPTOR_AUTHORITY_TEST") != "1" {
		t.Skip("explicit disposable privileged Linux container required")
	}
	switch os.Getenv("VMOBS_DESCRIPTOR_AUTHORITY_ROLE") {
	case "recipient":
		testUnprivilegedCollectorRecipient(t)
		return
	case "namespace":
		// Continue in the private namespace made by the outer test process.
	default:
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCollectorDescriptorDoesNotTransferMutationAuthority$", "-test.v")
		cmd.Env = append(os.Environ(), "VMOBS_DESCRIPTOR_AUTHORITY_ROLE=namespace")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("private namespace authority check: %v\n%s", err, output)
		}
		t.Logf("private namespace: %s", output)
		return
	}

	selfNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parentNS, err := os.Readlink("/proc/" + strconv.Itoa(os.Getppid()) + "/ns/net")
	if err != nil || selfNS == parentNS {
		t.Fatalf("refusing mutation without a distinct child network namespace: %v", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatalf("refusing mutation in nonempty network namespace: interfaces=%+v err=%v", interfaces, err)
	}
	file, info, err := netobserve.OpenConntrack(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// A valid flush on this empty, disposable namespace is the positive control:
	// the same descriptor and request must work before privilege is dropped.
	if err := collectorRequestAck(file, collectorDeleteRequest(2, info.PortID), 2); err != nil {
		t.Fatalf("privileged positive control: %v", err)
	}
	// Queue a privileged baseline for the receiver. Reading this reply must not
	// require the privilege that sending a fresh request does.
	snapshot := collectorDeleteRequest(4, info.PortID)
	binary.NativeEndian.PutUint16(snapshot[4:], 0x101)
	binary.NativeEndian.PutUint16(snapshot[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	if err := unix.Sendto(int(file.Fd()), snapshot, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	parentFile := os.NewFile(uintptr(pair[0]), "authority-parent")
	childFile := os.NewFile(uintptr(pair[1]), "authority-child")
	defer childFile.Close()
	parent, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := parent.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCollectorDescriptorDoesNotTransferMutationAuthority$", "-test.v")
	cmd.Env = append(os.Environ(), "VMOBS_DESCRIPTOR_AUTHORITY_ROLE=recipient")
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
	if err := writeMsgFiles(parent.(*net.UnixConn), info, []*os.File{file}); err != nil {
		t.Fatal(err)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged recipient: %v\n%s", err, output)
	}
	t.Logf("unprivileged recipient: %s", output)
}

func testUnprivilegedCollectorRecipient(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 65534 {
		t.Fatalf("recipient uid=%d; expected unprivileged uid", os.Geteuid())
	}
	var caps [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&header, &caps[0]); err != nil {
		t.Fatal(err)
	}
	for _, cap := range caps {
		if cap.Effective != 0 || cap.Permitted != 0 {
			t.Fatalf("recipient retained capabilities: %+v", caps)
		}
	}
	socket := os.NewFile(3, "authority-child")
	conn, err := net.FileConn(socket)
	_ = socket.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var info netobserve.ConntrackSocketInfo
	files, err := readMsgFiles(conn.(*net.UnixConn), &info)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(files)
	if len(files) != 1 || info.PortID == 0 {
		t.Fatalf("unexpected collector handoff: files=%d info=%+v", len(files), info)
	}
	testReadCollectorBaseline(t, files[0])
	if err := collectorRequestAck(files[0], collectorDeleteRequest(3, info.PortID), 3); !errors.Is(err, unix.EPERM) {
		t.Fatalf("received collector socket allowed mutation or returned an unrelated error: %v", err)
	}
}

func testReadCollectorBaseline(t *testing.T, file *os.File) {
	t.Helper()
	buffer := make([]byte, 65536)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, flags, sender, err := unix.Recvmsg(int(file.Fd()), buffer, nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		address, ok := sender.(*unix.SockaddrNetlink)
		if !ok || address.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			t.Fatal("untrusted or truncated collector baseline")
		}
		if _, err := netobserve.ParseConntrack(buffer[:n], true); err != nil {
			t.Fatalf("collector baseline failed validation: %v", err)
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil || len(messages) != 1 || messages[0].Header.Seq != 4 || messages[0].Header.Type != unix.NLMSG_DONE {
			t.Fatalf("unexpected empty-namespace baseline: messages=%+v err=%v", messages, err)
		}
		return
	}
	t.Fatal("collector baseline timed out")
}

func collectorDeleteRequest(sequence, port uint32) []byte {
	request := make([]byte, 20)
	binary.NativeEndian.PutUint32(request, uint32(len(request)))
	// NFNL_SUBSYS_CTNETLINK=1, IPCTNL_MSG_CT_DELETE=2; no tuple flushes this namespace.
	binary.NativeEndian.PutUint16(request[4:], 0x102)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:], sequence)
	binary.NativeEndian.PutUint32(request[12:], port)
	request[16] = unix.AF_INET
	return request
}

func collectorRequestAck(file *os.File, request []byte, sequence uint32) error {
	fd := int(file.Fd())
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	deadline := time.Now().Add(2 * time.Second)
	buffer := make([]byte, 65536)
	for time.Now().Before(deadline) {
		n, _, flags, sender, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if err != nil {
			return err
		}
		address, ok := sender.(*unix.SockaddrNetlink)
		if !ok || address.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			return errors.New("untrusted or truncated kernel response")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return err
		}
		for _, message := range messages {
			if message.Header.Seq != sequence {
				continue
			}
			if message.Header.Type != unix.NLMSG_ERROR || len(message.Data) < 4 {
				return errors.New("missing kernel acknowledgement")
			}
			code := int32(binary.NativeEndian.Uint32(message.Data))
			if code != 0 {
				return syscall.Errno(-code)
			}
			return nil
		}
	}
	return errors.New("kernel acknowledgement timed out")
}
