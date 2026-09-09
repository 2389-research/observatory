// ABOUTME: Tests bounded live netlink classification, admission and lifecycle.
// ABOUTME: Privileged coverage reads real conntrack and NFLOG sockets after credential drop.
//go:build linux

package netobserve

import (
	"bytes"
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

	"golang.org/x/sys/unix"
)

func TestConntrackReaderClassifiesEachMessageBySnapshotIdentity(t *testing.T) {
	source := testReaderSource(t, SourceConntrack)
	snapshot := flowMessage(0)
	setNetlinkIdentity(snapshot, 41, 73)
	live := flowMessage(0x600)
	setNetlinkIdentity(live, 0, 0)
	done := netlinkDone(41, 73, 0)

	observations, err := source.consume(append(append(snapshot, live...), done...), kernelSender(), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 2 || observations[0].Result.Flows[0].Flow.Event != "snapshot" || observations[1].Result.Flows[0].Flow.Event != "new" {
		t.Fatalf("mixed datagram classification = %+v", observations)
	}
	if source.status.Baseline != BaselineReady {
		t.Fatalf("baseline = %q, want ready", source.status.Baseline)
	}
}

func TestConntrackReaderRejectsWrongIdentityAndInterruptedDone(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{name: "wrong sequence", data: withNetlinkIdentity(flowMessage(0), 40, 73), want: ErrMalformed},
		{name: "wrong port", data: withNetlinkIdentity(flowMessage(0), 41, 72), want: ErrMalformed},
		{name: "interrupted", data: interruptedDone(41, 73), want: ErrDumpInterrupted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := testReaderSource(t, SourceConntrack)
			if _, err := source.consume(tc.data, kernelSender(), 0, time.Now()); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if source.status.Baseline == BaselineReady {
				t.Fatal("invalid completion made baseline ready")
			}
		})
	}
}

func TestReaderRejectsUntrustedOrTruncatedDatagram(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sender *unix.SockaddrNetlink
		flags  int
	}{
		{name: "userspace sender", sender: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 9}},
		{name: "wrong family", sender: &unix.SockaddrNetlink{Family: unix.AF_UNIX}},
		{name: "unexpected multicast group", sender: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 8}},
		{name: "truncated", sender: kernelSender(), flags: unix.MSG_TRUNC},
		{name: "control truncated", sender: kernelSender(), flags: unix.MSG_CTRUNC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := testReaderSource(t, SourceConntrack)
			if _, err := source.consume(flowMessage(0), tc.sender, tc.flags, time.Now()); err == nil {
				t.Fatal("untrusted or incomplete datagram accepted")
			}
		})
	}
}

func TestConntrackReaderAcceptsKernelLiveMulticastGroups(t *testing.T) {
	for _, group := range []uint32{1, 2, 4} {
		source := testReaderSource(t, SourceConntrack)
		observations, err := source.consume(flowMessage(0x600), &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: group}, 0, time.Now())
		if err != nil || len(observations) != 1 || observations[0].Result.Flows[0].Flow.Event != "new" {
			t.Fatalf("group=%d observations=%+v error=%v", group, observations, err)
		}
	}

	source := testReaderSource(t, SourceConntrack)
	done := netlinkDone(41, 73, 0)
	if _, err := source.consume(done, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1}, 0, time.Now()); err == nil {
		t.Fatal("multicast sender completed unicast snapshot")
	}
}

func TestNFLogReaderBindsGroupAndExactPrefix(t *testing.T) {
	source := testReaderSource(t, SourceNFLog)
	valid := nflogReaderMessage(321, "vmobs-denied", 4, 0x86dd)
	observations, err := source.consume(valid, kernelSender(), 0, time.Now())
	if err != nil || len(observations) != 1 {
		t.Fatalf("observations=%+v error=%v", observations, err)
	}
	denial := observations[0].Result.Denials[0]
	if denial.ScopeLimitation != "unsupported_hardware_protocol" || denial.Tuple != nil {
		t.Fatalf("unsupported packet scope was lost: %+v", denial)
	}

	for name, data := range map[string][]byte{
		"group":  nflogReaderMessage(320, "vmobs-denied", 5, 0x0800),
		"prefix": nflogReaderMessage(321, "almost-vmobs-denied", 5, 0x0800),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := source.consume(data, kernelSender(), 0, time.Now()); err == nil {
				t.Fatal("unbound denial accepted")
			}
		})
	}
}

func TestReaderQueuePressureAndLossRemainVisible(t *testing.T) {
	r := &Reader{observations: make(chan Observation, 1), status: ReaderStatus{QueueCapacity: 1}}
	source := testReaderSource(t, SourceNFLog)
	r.sources = []*readerSource{source}
	r.publish(source, Observation{SourceID: source.config.ID})
	r.publish(source, Observation{SourceID: source.config.ID})
	if got := r.Status().Sources[0].QueueDrops; got != 1 {
		t.Fatalf("queue drops = %d, want 1", got)
	}

	if _, err := source.consume(nflogReaderMessage(321, "vmobs-denied", 7, 0x0800), kernelSender(), 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := source.consume(nflogReaderMessage(321, "vmobs-denied", 10, 0x0800), kernelSender(), 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if source.status.NFLogSequenceDrops != 2 {
		t.Fatalf("sequence drops = %d, want 2", source.status.NFLogSequenceDrops)
	}
}

func TestNFLogReaderSeparatesMeasuredAndUnknownSequenceLoss(t *testing.T) {
	wrapped := testReaderSource(t, SourceNFLog)
	if _, err := wrapped.consume(nflogReaderMessage(321, "vmobs-denied", ^uint32(0), 0x0800), kernelSender(), 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := wrapped.consume(nflogReaderMessage(321, "vmobs-denied", 0, 0x0800), kernelSender(), 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if wrapped.status.NFLogSequenceDrops != 0 || wrapped.status.NFLogUnknownIntervals != 0 {
		t.Fatalf("uint32 wrap became loss: %+v", wrapped.status)
	}

	duplicate := testReaderSource(t, SourceNFLog)
	for _, sequence := range []uint32{7, 7, 8} {
		if _, err := duplicate.consume(nflogReaderMessage(321, "vmobs-denied", sequence, 0x0800), kernelSender(), 0, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if duplicate.status.NFLogUnknownIntervals != 1 || duplicate.status.NFLogSequenceDrops != 0 {
		t.Fatalf("duplicate sequence loss was not retained: %+v", duplicate.status)
	}

	reset := testReaderSource(t, SourceNFLog)
	for _, sequence := range []uint32{100, 10} {
		if _, err := reset.consume(nflogReaderMessage(321, "vmobs-denied", sequence, 0x0800), kernelSender(), 0, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if reset.status.NFLogUnknownIntervals != 1 {
		t.Fatalf("sequence reset was not retained: %+v", reset.status)
	}

	missing := testReaderSource(t, SourceNFLog)
	data := msgFamily(0x400, 0, 5, packetHeader(0x0800), attr(10, []byte("vmobs-denied\x00")))
	binary.BigEndian.PutUint16(data[18:], 321)
	_, err := missing.consume(data, kernelSender(), 0, time.Now())
	if !errors.Is(err, errNFLogSequenceMissing) {
		t.Fatalf("missing local sequence error = %v", err)
	}
	missing.readError(err, time.Now())
	if missing.status.NFLogUnknownIntervals != 1 || missing.status.KernelUnknownIntervals != 0 {
		t.Fatalf("missing sequence loss classification = %+v", missing.status)
	}
}

func TestReaderConfigBounds(t *testing.T) {
	valid := ReaderConfig{Sources: []SourceConfig{{ID: "ct", File: os.Stdin, Scope: readerTestScope(), Kind: SourceConntrack, PortID: 1, SnapshotSequence: 1}}, TrackerLimits: Limits{MaxFlows: 1, MaxGroups: 1, IdleTimeout: time.Second}, QueueCapacity: 1, BaselineTimeout: time.Second, MaxDatagramBytes: 4096}
	for name, mutate := range map[string]func(*ReaderConfig){
		"no sources":       func(c *ReaderConfig) { c.Sources = nil },
		"too many sources": func(c *ReaderConfig) { c.Sources = append(c.Sources, c.Sources[0], c.Sources[0], c.Sources[0]) },
		"queue":            func(c *ReaderConfig) { c.QueueCapacity = 1025 },
		"baseline":         func(c *ReaderConfig) { c.BaselineTimeout = 31 * time.Second },
		"datagram":         func(c *ReaderConfig) { c.MaxDatagramBytes = MaxDatagramBytes + 1 },
		"prefix": func(c *ReaderConfig) {
			c.Sources[0].Kind = SourceNFLog
			c.Sources[0].NFLogGroup = 1
			c.Sources[0].DenialPrefixes = []string{""}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			config.Sources = append([]SourceConfig(nil), valid.Sources...)
			mutate(&config)
			if err := validateReaderConfig(&config); err == nil {
				t.Fatal("invalid reader config accepted")
			}
		})
	}
}

func TestReaderContextCancellationClosesOwnedDescriptor(t *testing.T) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "reader-cancel")
	ctx, cancel := context.WithCancel(t.Context())
	r, err := NewReader(ctx, ReaderConfig{
		Sources:       []SourceConfig{{ID: "log", File: file, Scope: readerTestScope(), Kind: SourceNFLog, PortID: address.(*unix.SockaddrNetlink).Pid, NFLogGroup: 321, DenialPrefixes: []string{"vmobs-denied"}}},
		TrackerLimits: Limits{MaxFlows: 4, MaxGroups: 1, IdleTimeout: time.Minute},
		QueueCapacity: 1, BaselineTimeout: time.Second, MaxDatagramBytes: 4096,
	})
	if err != nil {
		file.Close()
		t.Fatal(err)
	}
	if status := r.Status().Sources[0]; status.ReadState != ReadHealthy || status.LastSuccess.IsZero() {
		t.Fatalf("quiet validated NFLOG source is not ready: %+v", status)
	}
	cancel()
	select {
	case _, ok := <-r.Observations():
		if ok {
			t.Fatal("observation channel remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not join after cancellation")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
		t.Fatalf("owned descriptor still open: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReaderStopPreservesSourceFailure(t *testing.T) {
	source := testReaderSource(t, SourceNFLog)
	source.status.ReadState = ReadFailed
	source.status.LastError = "kernel buffer overrun"
	source.stop()
	if source.status.ReadState != ReadFailed || source.status.LastError != "kernel buffer overrun" {
		t.Fatalf("stop erased source failure: %+v", source.status)
	}
}

func TestRealCredentialDroppedNetlinkReader(t *testing.T) {
	if os.Getenv("VMOBS_NETLINK_READER_TEST") != "1" {
		t.Skip("explicit disposable privileged Linux container required")
	}
	if os.Getenv("VMOBS_NETLINK_READER_RECIPIENT") == "1" {
		testCredentialDroppedReader(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("privileged acquisition requires root inside disposable container")
	}
	if os.Getenv("VMOBS_NETLINK_READER_NAMESPACE") != "1" {
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRealCredentialDroppedNetlinkReader$", "-test.v")
		cmd.Env = append(os.Environ(), "VMOBS_NETLINK_READER_NAMESPACE=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated reader: %v\n%s", err, out)
		} else {
			t.Logf("%s", out)
		}
		return
	}

	assertFreshLoopbackNamespace(t)
	runNFLogCommand(t, "ip", "link", "set", "lo", "up")
	conntrack, conntrackInfo, err := OpenConntrack(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conntrack.Close()
	const group = uint16(321)
	logFile, logInfo, err := OpenNFLog(t.Context(), group)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	const deniedPort = 46321
	installNFLogDropRule(t, group, deniedPort)
	runNFLogCommand(t, "nft", "add", "rule", "ip", "vmobs_nflog_test", "output", "ct", "state", "new", "counter")
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()

	executable := readerChildExecutable(t)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestRealCredentialDroppedNetlinkReader$", "-test.v")
	cmd.Env = append(os.Environ(),
		"VMOBS_NETLINK_READER_RECIPIENT=1",
		"VMOBS_READER_CT_PORT="+strconv.FormatUint(uint64(conntrackInfo.PortID), 10),
		"VMOBS_READER_CT_SEQUENCE="+strconv.FormatUint(uint64(conntrackInfo.SnapshotSequence), 10),
		"VMOBS_READER_LOG_PORT="+strconv.FormatUint(uint64(logInfo.PortID), 10),
	)
	cmd.ExtraFiles = []*os.File{conntrack, logFile, readyWrite}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
	var childOutput bytes.Buffer
	cmd.Stdout = &childOutput
	cmd.Stderr = &childOutput
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := conntrack.Close(); err != nil {
		t.Fatal(err)
	}
	if err := logFile.Close(); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, 1)
	if _, err := readyRead.Read(ready); err != nil || ready[0] != 1 {
		t.Fatalf("credential-dropped reader did not reach baseline: byte=%v error=%v\n%s", ready, err, childOutput.Bytes())
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	connection, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	if _, err := connection.Write([]byte("conntrack reader proof")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if err := accepted.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := accepted.Read(buffer); err != nil {
		t.Fatal(err)
	}

	denied, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: deniedPort})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Write([]byte("nflog reader proof")); err != nil && !errors.Is(err, unix.EPERM) {
		t.Fatal(err)
	}
	denied.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("credential-dropped reader: %v\n%s", err, childOutput.Bytes())
	}
}

func testCredentialDroppedReader(t *testing.T) {
	if os.Geteuid() != 65534 {
		t.Fatalf("reader UID=%d want=65534", os.Geteuid())
	}
	ctPort := readerEnvUint32(t, "VMOBS_READER_CT_PORT")
	ctSequence := readerEnvUint32(t, "VMOBS_READER_CT_SEQUENCE")
	logPort := readerEnvUint32(t, "VMOBS_READER_LOG_PORT")
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	r, err := NewReader(ctx, ReaderConfig{
		Sources: []SourceConfig{
			{ID: "ct", File: os.NewFile(3, "conntrack"), Scope: readerTestScope(), Kind: SourceConntrack, PortID: ctPort, SnapshotSequence: ctSequence},
			{ID: "denial", File: os.NewFile(4, "nflog"), Scope: readerTestScope(), Kind: SourceNFLog, PortID: logPort, NFLogGroup: 321, DenialPrefixes: []string{"vmobs-denied"}},
		},
		TrackerLimits: Limits{MaxFlows: 64, MaxGroups: 2, IdleTimeout: time.Minute},
		QueueCapacity: 16, BaselineTimeout: 2 * time.Second, MaxDatagramBytes: 64 * 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for r.Status().Sources[0].Baseline != BaselineReady {
		select {
		case <-time.After(5 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("reader baseline timeout: %+v", r.Status())
		}
	}
	ready := os.NewFile(5, "baseline-ready")
	if _, err := ready.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := ready.Close(); err != nil {
		t.Fatal(err)
	}
	var sawFlow, sawDenial bool
	for !sawFlow || !sawDenial || r.Status().Sources[0].Baseline != BaselineReady {
		select {
		case observation, ok := <-r.Observations():
			if !ok {
				t.Fatal("reader stopped before evidence arrived")
			}
			sawFlow = sawFlow || len(observation.Result.Flows) == 1
			sawDenial = sawDenial || len(observation.Result.Denials) == 1
		case <-ctx.Done():
			t.Fatalf("reader evidence timeout: flow=%t denial=%t status=%+v", sawFlow, sawDenial, r.Status())
		}
	}
	status := r.Status()
	if status.Sources[0].ReadState != ReadHealthy || status.Sources[1].ReadState != ReadHealthy {
		t.Fatalf("reader sources are not healthy: %+v", status)
	}
}

func readerEnvUint32(t *testing.T, name string) uint32 {
	t.Helper()
	n, err := strconv.ParseUint(os.Getenv(name), 10, 32)
	if err != nil || n == 0 {
		t.Fatalf("invalid %s: %q", name, os.Getenv(name))
	}
	return uint32(n)
}

func readerChildExecutable(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "vmobs-reader-child-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	destination := directory + "/netobserve.test"
	input, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, input, 0o755); err != nil {
		t.Fatal(err)
	}
	return destination
}

func testReaderSource(t *testing.T, kind SourceKind) *readerSource {
	t.Helper()
	config := SourceConfig{ID: "source", Scope: readerTestScope(), Kind: kind, PortID: 73, SnapshotSequence: 41, NFLogGroup: 321, DenialPrefixes: []string{"vmobs-denied"}}
	tracker, err := NewTracker(config.Scope, Limits{MaxFlows: 4, MaxGroups: 4, IdleTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return newReaderSource(config, tracker, time.Now().Add(time.Second))
}

func readerTestScope() Scope {
	return Scope{VMID: "vm-1", BootID: "boot-1", HostBootID: "host-1", Generation: "generation-1", NamespaceID: "ns-1", Boundary: "namespace_gateway"}
}

func kernelSender() *unix.SockaddrNetlink { return &unix.SockaddrNetlink{Family: unix.AF_NETLINK} }

func setNetlinkIdentity(data []byte, sequence, port uint32) {
	binary.NativeEndian.PutUint32(data[8:], sequence)
	binary.NativeEndian.PutUint32(data[12:], port)
}

func withNetlinkIdentity(data []byte, sequence, port uint32) []byte {
	setNetlinkIdentity(data, sequence, port)
	return data
}

func netlinkDone(sequence, port uint32, code int32) []byte {
	b := make([]byte, 20)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint32(b[8:], sequence)
	binary.NativeEndian.PutUint32(b[12:], port)
	binary.NativeEndian.PutUint32(b[16:], uint32(code))
	return b
}

func interruptedDone(sequence, port uint32) []byte {
	b := netlinkDone(sequence, port, 0)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_DUMP_INTR)
	return b
}

func nflogReaderMessage(group uint16, prefix string, sequence uint32, protocol uint16) []byte {
	b := msgFamily(0x400, 0, 5, packetHeader(protocol), attr(10, append([]byte(prefix), 0)), attr(12, be32(sequence)))
	binary.BigEndian.PutUint16(b[18:], group)
	return b
}

// One unsupported address family is a counted limitation of that message, not a
// failure of the datagram: the supported messages still count and correlation
// state survives, the same rule NFLOG batches follow.
func TestConntrackReaderCountsUnsupportedFamilyWithoutFailingTheDatagram(t *testing.T) {
	source := testReaderSource(t, SourceConntrack)
	now := time.Now()
	if _, err := source.consume(withNetlinkIdentity(flowMessage(0x600), 0, 0), kernelSender(), 0, now); err != nil {
		t.Fatal(err)
	}
	v6 := withNetlinkIdentity(msgFamily(0x100, 0, 10, attr(12, be32(42))), 0, 0)
	update := withNetlinkIdentity(flowMessage(0), 0, 0)
	observations, err := source.consume(append(v6, update...), kernelSender(), 0, now)
	if err != nil {
		t.Fatalf("one unsupported-family message failed the whole datagram: %v", err)
	}
	if len(observations) != 1 || len(observations[0].Result.Flows) != 1 || !observations[0].Result.Flows[0].StartObserved {
		t.Fatalf("observations = %+v, want the supported message counted with its flow state kept", observations)
	}
	if source.status.UnsupportedFamilyMessages != 1 || source.status.KernelUnknownIntervals != 0 || source.status.ReadState != ReadHealthy {
		t.Fatalf("status = %+v, want one counted unsupported-family limitation and a healthy read", source.status)
	}
}

// A flow the tracker cannot key is still observed; it just cannot be correlated.
// That is its own limitation count, not a drop and not an unknown interval.
func TestConntrackReaderCountsUntrackableFlowIdentity(t *testing.T) {
	source := testReaderSource(t, SourceConntrack)
	gre := withNetlinkIdentity(msg(0x100, 0,
		attr(1|0x8000, attr(1|0x8000, attr(1, []byte{10, 0, 0, 2}), attr(2, []byte{93, 184, 216, 34})),
			attr(2|0x8000, attr(1, []byte{47})))), 0, 0)
	observations, err := source.consume(gre, kernelSender(), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || len(observations[0].Result.Flows) != 1 {
		t.Fatalf("observations = %+v, want the flow still observed", observations)
	}
	if source.status.FlowIdentityUntracked != 1 || source.status.QueueDrops != 0 || source.status.KernelUnknownIntervals != 0 {
		t.Fatalf("status = %+v, want one untracked identity and no drop or unknown interval", source.status)
	}
}
