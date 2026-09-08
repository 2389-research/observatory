// ABOUTME: Exercises actual BPF attach and short-lived exec/exit evidence inside a Linux guest.
// ABOUTME: Requires explicit integration opt-in and fails if advertised kernel support cannot capture.
//go:build linux

package procwatch

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/2389-research/observatory/internal/guest/telemetry"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestKernelLifecycle(t *testing.T) {
	if os.Getenv("VMOBS_PROCWATCH_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux guest and VMOBS_PROCWATCH_INTEGRATION=1")
	}
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 4096})
	s, err := Open(r, "kernel-test-boot")
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("verifier: %+v", verifier)
		}
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	cmd := exec.Command("/bin/sh", "-c", "exit 23")
	err = cmd.Run()
	if err == nil {
		t.Fatal("expected exit 23")
	}
	pid := uint32(cmd.Process.Pid)
	deadline := time.Now().Add(3 * time.Second)
	found := map[string]Event{}
	for time.Now().Before(deadline) {
		for {
			item, ok := r.Ring().Next()
			if !ok {
				break
			}
			r.Ring().Advance()
			var e Event
			if json.Unmarshal(item.Data, &e) == nil && e.PID == pid && (item.Kind == "proc.fork" || item.Kind == "proc.exec" || item.Kind == "proc.exit") {
				e.Kind = item.Kind
				found[item.Kind] = e
			}
		}
		if len(found) >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"proc.fork", "proc.exec", "proc.exit"} {
		if _, ok := found[kind]; !ok {
			t.Fatalf("missing %s for PID %d: %+v health=%+v", kind, pid, found, r.Health())
		}
	}
	fork, execution, exit := found["proc.fork"], found["proc.exec"], found["proc.exit"]
	if fork.Process.StartNS != execution.Process.StartNS || execution.Process.StartNS != exit.Process.StartNS {
		t.Fatalf("lifetime drift: %+v", found)
	}
	n, _ := strconv.ParseUint(fork.Process.ExecGeneration, 10, 64)
	m, _ := strconv.ParseUint(execution.Process.ExecGeneration, 10, 64)
	if m != n+1 || execution.Process.ExecGeneration != exit.Process.ExecGeneration {
		t.Fatalf("exec generation drift: %+v", found)
	}
	if exit.ExitWaitStatus == nil || *exit.ExitWaitStatus != 23<<8 {
		t.Fatalf("exit evidence: %+v", exit)
	}
}

func TestKernelRawTracepointCapability(t *testing.T) {
	if os.Getenv("VMOBS_PROCWATCH_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux guest")
	}
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "vmobs_probe", Type: ebpf.RawTracepoint, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("verifier: %+v", verifier)
		}
		t.Fatal(err)
	}
	defer p.Close()
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_fork", Program: p})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
}

func TestKernelExecArgumentsAndFailure(t *testing.T) {
	if os.Getenv("VMOBS_PROCWATCH_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux guest")
	}
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 4096})
	s, err := Open(r, "argv-test-boot")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	good := exec.Command("/bin/sh", "-c", "exit 0", "argv-marker")
	if err := good.Run(); err != nil {
		t.Fatal(err)
	}
	bad := exec.Command("/definitely-absent-vmobs-executable", "failed-marker")
	if err := bad.Run(); err == nil {
		t.Fatal("missing executable succeeded")
	}
	deadline := time.Now().Add(3 * time.Second)
	var success, failed bool
	for time.Now().Before(deadline) {
		for {
			item, ok := r.Ring().Next()
			if !ok {
				break
			}
			r.Ring().Advance()
			var fields struct {
				PID     uint32   `json:"pid"`
				Argv    []string `json:"argv_display"`
				Result  *int64   `json:"syscall_result"`
				Process Identity `json:"process"`
			}
			if json.Unmarshal(item.Data, &fields) != nil {
				continue
			}
			if item.Kind == "proc.exec" && fields.PID == uint32(good.Process.Pid) && len(fields.Argv) == 4 && fields.Argv[3] == "argv-marker" {
				success = true
			}
			if item.Kind == "proc.exec_failed" && len(fields.Argv) == 2 && fields.Argv[1] == "failed-marker" && fields.Result != nil && *fields.Result == -2 {
				failed = true
			}
		}
		if success && failed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("bounded argv success=%v failed exec=%v health=%+v", success, failed, r.Health())
}

func TestKernelConnectAttemptsAndResults(t *testing.T) {
	if os.Getenv("VMOBS_PROCWATCH_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux guest")
	}
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 4096})
	s, err := Open(r, "connect-test-boot")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address := listener.Addr().(*net.TCPAddr)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: address.Port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	var attempt, result bool
	for time.Now().Before(deadline) {
		for {
			item, ok := r.Ring().Next()
			if !ok {
				break
			}
			r.Ring().Advance()
			var e Event
			if json.Unmarshal(item.Data, &e) != nil || e.Process.TGID != uint32(os.Getpid()) || e.Socket == nil || e.Socket.FD != int32(fd) {
				continue
			}
			if e.Socket.Destination != "127.0.0.1" || e.Socket.Port != uint16(address.Port) || e.Socket.Namespace == "" || e.Socket.Namespace == "0" || e.Socket.LifetimeStatus != "unknown" || e.Socket.HostFlowAttribution != "unknown" {
				t.Fatalf("misleading connect: %+v", e.Socket)
			}
			if item.Kind == "socket.connect_attempt" {
				attempt = true
			}
			if item.Kind == "socket.connect_result" && e.SyscallResult != nil && *e.SyscallResult == 0 {
				result = true
			}
		}
		if attempt && result {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("connect attempt=%v result=%v health=%+v", attempt, result, r.Health())
}

func TestKernelSupervisorStartsAndStops(t *testing.T) {
	if os.Getenv("VMOBS_PROCWATCH_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux guest")
	}
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 4096})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { Run(ctx, r, "supervisor-test-boot"); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	healthy := false
	for time.Now().Before(deadline) {
		for _, sensor := range r.Sensors().Snapshot() {
			if sensor.ID == "process" && sensor.State == telemetry.SensorHealthy {
				healthy = true
			}
		}
		if healthy {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !healthy {
		t.Fatalf("supervisor did not start collector: %+v", r.Health())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("supervisor failed to stop")
	}
	for {
		_, ok := r.Ring().Next()
		if !ok {
			break
		}
		r.Ring().Advance()
	}
	if err := exec.Command("/bin/sh", "-c", "exit 0").Run(); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Ring().Next(); ok {
		t.Fatal("collector still emits after supervisor exits")
	}
}

func TestKernelCollectorFailureAndReopen(t *testing.T) {
	if os.Getenv("VMOBS_PROCWATCH_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux guest")
	}
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 4096})
	s, err := Open(r, "recovery-test-boot")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Run(context.Background()); err == nil {
		t.Fatal("closed kernel reader did not fail")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before := newHealth(r)
	if before.State != telemetry.SensorUnavailable || before.UnknownLossIntervals != 1 {
		t.Fatalf("missing failure coverage: %+v", before)
	}
	recovered, err := Open(r, "recovery-test-boot")
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if recovered.health.State != telemetry.SensorHealthy || recovered.health.UnknownLossIntervals != 1 {
		t.Fatalf("recovery lost gap history: %+v", recovered.health)
	}
}

func TestKernelNonleaderExecHelper(t *testing.T) {
	if os.Getenv("VMOBS_PROCWATCH_NONLEADER_HELPER") != "1" {
		return
	}
	runtime.LockOSThread()
	go func() {
		runtime.LockOSThread()
		if unix.Gettid() == os.Getpid() {
			os.Exit(98)
		}
		if err := unix.Exec("/bin/sh", []string{"/bin/sh", "-c", "exit 19", "nonleader-marker"}, os.Environ()); err != nil {
			os.Exit(99)
		}
	}()
	select {}
}
func TestKernelNonleaderExecArguments(t *testing.T) {
	if os.Getenv("VMOBS_PROCWATCH_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux guest")
	}
	r := telemetry.NewReporter(telemetry.ReporterConfig{RingCapacity: 4096})
	s, err := Open(r, "nonleader-test-boot")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestKernelNonleaderExecHelper$")
	cmd.Env = append(os.Environ(), "VMOBS_PROCWATCH_NONLEADER_HELPER=1")
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 19 {
		t.Fatalf("nonleader exec failed: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for {
			item, ok := r.Ring().Next()
			if !ok {
				break
			}
			r.Ring().Advance()
			var e Event
			if item.Kind == "proc.exec" && json.Unmarshal(item.Data, &e) == nil && e.PID == uint32(cmd.Process.Pid) && e.OldPID != nil && *e.OldPID != e.PID && len(e.ArgvDisplay) == 4 && e.ArgvDisplay[3] == "nonleader-marker" {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("missing argv for real nonleader exec PID %d", cmd.Process.Pid)
}
