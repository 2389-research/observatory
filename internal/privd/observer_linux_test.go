// ABOUTME: Exercises real privd observer acquisition and credential-dropped descriptor validation.
// ABOUTME: Isolates all kernel mutations in a disposable child network and mount namespace.
//go:build linux

package privd

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/netobserve"
	"github.com/2389-research/observatory/internal/network"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func TestObserverHandoffKernel(t *testing.T) {
	if os.Getenv("VMOBS_OBSERVER_HANDOFF_TEST") != "1" {
		t.Skip("requires explicit disposable Linux container: VMOBS_OBSERVER_HANDOFF_TEST=1")
	}
	switch os.Getenv("VMOBS_OBSERVER_ROLE") {
	case "recipient":
		observerRecipient(t)
		return
	case "namespace":
	default:
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestObserverHandoffKernel$", "-test.v", "-test.timeout=40s")
		cmd.Env = append(os.Environ(), "VMOBS_OBSERVER_ROLE=namespace")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET | unix.CLONE_NEWNS}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated observer component: %v\n%s", err, out)
		}
		t.Logf("%s", out)
		return
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Readlink("/proc/" + strconv.Itoa(os.Getppid()) + "/ns/net")
	if err != nil || self == parent {
		t.Fatal("refusing mutation outside distinct child namespace", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatalf("refusing nonempty network namespace: %+v %v", interfaces, err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "vmobs-observer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	policies := filepath.Join(dir, "policies")
	ledgerDir := filepath.Join(dir, "ledger")
	for _, p := range []string{policies, ledgerDir} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(policies, "offline.json"), []byte(`{"schema_version":1,"id":"offline","profile":"offline"}`), 0600); err != nil {
		t.Fatal(err)
	}
	ops := NewRealOps(RealOpsCfg{PolicyDirectory: policies})
	entry := VMEntry{VMID: "observer-real", NetCIDR: "10.209.0.0/30", NetworkHostNFLogGroup: 1024}
	req := AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "offline", PolicyID: "offline", GuestBootID: uuid.NewString()}
	if err := ops.PrepareNetworkEntry(t.Context(), &entry, req); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ops.ReleaseNetworkContext(ctx, entry); err != nil {
			t.Error("release:", err)
		}
	}()
	if err := ops.AllocateNetworkOwnedContext(t.Context(), &entry, req); err != nil {
		t.Fatal(err)
	}
	entry.NetworkComplete = true
	srv := NewServer(ServerCfg{AllowedUID: 65534, LedgerDir: ledgerDir, Ops: ops, FramingTimeout: time.Second})
	if err := srv.ledger.put(entry); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "privd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0666); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, listener) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	childBinary := observerChildExecutable(t)
	child := func(mode string) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), childBinary, "-test.run=^TestObserverHandoffKernel$", "-test.v", "-test.timeout=15s")
		cmd.Env = append(os.Environ(), "VMOBS_OBSERVER_ROLE=recipient", "VMOBS_OBSERVER_MODE="+mode, "VMOBS_OBSERVER_SOCKET="+socket, "VMOBS_OBSERVER_BOOT="+req.GuestBootID)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("recipient %s: %v\n%s", mode, err, out)
		}
		t.Logf("%s", out)
	}
	beforeFD := observerFDCount(t)
	child("success")
	settled := time.Now().Add(time.Second)
	for observerFDCount(t) != beforeFD && time.Now().Before(settled) {
		time.Sleep(time.Millisecond)
	}
	if count := observerFDCount(t); count != beforeFD {
		t.Fatalf("server handoff copies did not close: %d -> %d", beforeFD, count)
	}
	// A host-only collision happens after namespace descriptors are acquired.
	// Reacquisition after closing it proves partial setup did not leak group owners.
	hostReader, _, err := netobserve.OpenNFLog(t.Context(), entry.NetworkHostNFLogGroup)
	if err != nil {
		t.Fatal(err)
	}
	child("refused")
	if err := hostReader.Close(); err != nil {
		t.Fatal(err)
	}
	child("success")
	deadline := time.Now().Add(time.Second)
	for observerFDCount(t) != beforeFD && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if afterFD := observerFDCount(t); afterFD != beforeFD {
		t.Fatalf("server descriptor growth: %d -> %d", beforeFD, afterFD)
	}
	srv.mu.Lock()
	incomplete := entry
	incomplete.NetworkComplete = false
	err = srv.ledger.put(incomplete)
	srv.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	child("refused")
	srv.mu.Lock()
	err = srv.ledger.put(entry)
	srv.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Force an actual owned topology mismatch; probing must not repair it.
	cmd := exec.CommandContext(t.Context(), "ip", "netns", "exec", network.NamespaceName(entry.VMID), "ip", "address", "del", "172.31.255.1/30", "dev", "tap0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tamper fixture: %v %s", err, out)
	}
	child("refused")
}
func observerRecipient(t *testing.T) {
	if os.Geteuid() != 65534 {
		t.Fatalf("recipient UID %d", os.Geteuid())
	}
	var caps [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capget(&header, &caps[0]); err != nil {
		t.Fatal(err)
	}
	for _, c := range caps {
		if c.Effective != 0 || c.Permitted != 0 {
			t.Fatalf("recipient retained capability %+v", caps)
		}
	}
	client := &Client{SocketPath: os.Getenv("VMOBS_OBSERVER_SOCKET")}
	req := AcquireNetworkObserversReq{VMID: "observer-real", GuestBootID: os.Getenv("VMOBS_OBSERVER_BOOT")}
	startFD := observerFDCount(t)
	if os.Getenv("VMOBS_OBSERVER_MODE") == "refused" {
		for i := 0; i < 3; i++ {
			if b, err := client.AcquireNetworkObservers(t.Context(), req); err == nil {
				_ = b.Close()
				t.Fatal("invalid network acquired")
			}
		}
		if n := observerFDCount(t); n != startFD {
			t.Fatalf("failure leaked descriptors: %d -> %d", startFD, n)
		}
		return
	}
	bundle, err := client.AcquireNetworkObservers(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Close()
	if len(bundle.Files) != 3 || bundle.Binding.GuestBootID != req.GuestBootID || bundle.Binding.VMID != req.VMID {
		t.Fatalf("wrong scope %+v", bundle.Binding)
	}
	observerReadBaseline(t, bundle.Files[0], bundle.Sockets[0].SnapshotSequence)
	if err := collectorRequestAck(bundle.Files[0], collectorDeleteRequest(700, bundle.Sockets[0].PortID), 700); !errors.Is(err, unix.EPERM) {
		t.Fatalf("descriptor granted mutation or unrelated failure: %v", err)
	}
	for i := 0; i < 3; i++ {
		if second, err := client.AcquireNetworkObservers(t.Context(), req); err == nil {
			_ = second.Close()
			t.Fatal("duplicate NFLOG owner accepted")
		}
	}
	wrong := req
	wrong.GuestBootID = uuid.NewString()
	if b, err := client.AcquireNetworkObservers(t.Context(), wrong); err == nil {
		_ = b.Close()
		t.Fatal("wrong boot accepted")
	}
	wrong = req
	wrong.VMID = "missing"
	if b, err := client.AcquireNetworkObservers(t.Context(), wrong); err == nil {
		_ = b.Close()
		t.Fatal("missing VM accepted")
	}
	oldID := bundle.Binding.AcquisitionID
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		bundle, err = client.AcquireNetworkObservers(t.Context(), req)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("reacquire:", err)
	}
	if bundle.Binding.AcquisitionID == oldID {
		t.Fatal("acquisition identity reused")
	}
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	if n := observerFDCount(t); n != startFD {
		t.Fatalf("client leaked descriptors: %d -> %d", startFD, n)
	}
}
func observerFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}
func observerReadBaseline(t *testing.T, f *os.File, sequence uint32) {
	t.Helper()
	b := make([]byte, 65536)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		n, _, flags, sender, err := unix.Recvmsg(int(f.Fd()), b, nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN {
			time.Sleep(time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		address, ok := sender.(*unix.SockaddrNetlink)
		if !ok || address.Pid != 0 || flags&unix.MSG_TRUNC != 0 {
			t.Fatal("invalid kernel baseline sender")
		}
		messages, err := syscall.ParseNetlinkMessage(b[:n])
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range messages {
			if m.Header.Seq == sequence && m.Header.Type == unix.NLMSG_DONE {
				if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
					t.Fatal("interrupted baseline")
				}
				return
			}
		}
	}
	t.Fatal("missing matching baseline DONE")
}

func TestObserverSocketValidation(t *testing.T) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		t.Skipf("kernel netfilter socket unavailable: %v", err)
	}
	file := os.NewFile(uintptr(fd), "observer-validation")
	defer file.Close()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		t.Fatal(err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	info := ObserverSocket{Kind: "nflog", Boundary: "namespace_gateway", PortID: address.(*unix.SockaddrNetlink).Pid, Group: 100}
	if err := validateObserverFile(file, info); err != nil {
		t.Fatal(err)
	}
	wrong := info
	wrong.PortID++
	if err := validateObserverFile(file, wrong); err == nil {
		t.Fatal("wrong socket port accepted")
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	if err := validateObserverFile(file, info); err == nil {
		t.Fatal("blocking descriptor accepted")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	if err := validateObserverFile(file, info); err == nil {
		t.Fatal("inheritable descriptor accepted")
	}
	unix.CloseOnExec(fd)
	plain, err := os.CreateTemp(t.TempDir(), "wrong-kind")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if err := validateObserverFile(plain, info); err == nil {
		t.Fatal("ordinary file accepted")
	}
	wrongProtocol, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	route := os.NewFile(uintptr(wrongProtocol), "wrong-protocol")
	defer route.Close()
	if err := validateObserverFile(route, info); err == nil {
		t.Fatal("route socket accepted")
	}
	if err := validateObserverFiles(&NetworkObserverBundle{Files: []*os.File{file}}); err == nil {
		t.Fatal("descriptor count accepted")
	}
}
func TestObserverLockDeadline(t *testing.T) {
	srv := &Server{}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := srv.lockObservers(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("lock deadline ignored")
	}
}
func TestObserverRejectsNonRootPeer(t *testing.T) {
	if os.Getenv("VMOBS_OBSERVER_NONROOT_SERVER") == "1" {
		ln, err := net.Listen("unix", os.Getenv("VMOBS_OBSERVER_FAKE_SOCKET"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		if n, _ := conn.Read(b[:]); n != 0 {
			t.Fatal("client sent request to non-root server")
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("credential-dropping peer check requires root")
	}
	dir, err := os.MkdirTemp("/tmp", "observer-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, observerChildExecutable(t), "-test.run=^TestObserverRejectsNonRootPeer$", "-test.v")
	cmd.Env = append(os.Environ(), "VMOBS_OBSERVER_NONROOT_SERVER=1", "VMOBS_OBSERVER_FAKE_SOCKET="+socket)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			_ = cmd.Wait()
			t.Fatal("non-root server did not bind")
		}
		time.Sleep(time.Millisecond)
	}
	req, _ := validObserverMetadata()
	if b, err := (&Client{SocketPath: socket}).AcquireNetworkObservers(ctx, req); err == nil {
		_ = b.Close()
		t.Fatal("non-root observer peer accepted")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

// go test builds beneath a private ancestor. Copy only this executable into a
// root-owned traversable fixture; never relax permissions on the shared build tree.
func observerChildExecutable(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "observer-executable-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(dir, "observer.test")
	destination, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		t.Fatal(err)
	}
	return path
}
