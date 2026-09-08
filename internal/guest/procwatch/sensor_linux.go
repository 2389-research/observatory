// ABOUTME: Owns guest-only BPF lifecycle hooks and bounded telemetry output resources.
// ABOUTME: Tests exact load and attach operations before declaring process capture available.
//go:build linux

package procwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/2389-research/observatory/internal/guest/telemetry"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// Sensor owns a 256 KiB kernel ring, one loss counter and five tracepoint hooks.
// Call Close after Run returns. BootID is the configured VM boot identity.
type Sensor struct {
	reporter     *telemetry.Reporter
	bootID       string
	health       telemetry.Sensor
	events, loss *ebpf.Map
	tokens       *ebpf.Map
	reader       *ringbuf.Reader
	programs     []*ebpf.Program
	links        []link.Link
	lastLoss     uint64
	calls        correlator
}

func Open(r *telemetry.Reporter, bootID string) (sensor *Sensor, err error) {
	s := &Sensor{reporter: r, bootID: bootID, health: newHealth(r)}
	r.Sensors().Set(s.health)
	defer func() {
		if err != nil {
			reportFailure(r, &s.health, err)
			_ = s.Close()
		}
	}()
	if bootID == "" || len(bootID) > 128 {
		return nil, fmt.Errorf("process collector requires a bounded boot identity")
	}
	if runtime.GOARCH != "amd64" {
		return nil, fmt.Errorf("process collector has not verified architecture %s", runtime.GOARCH)
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load kernel BTF: %w", err)
	}
	offsets, err := taskOffsets(spec)
	if err != nil {
		return nil, err
	}
	s.events, err = ebpf.NewMap(&ebpf.MapSpec{Name: "vmobs_proc", Type: ebpf.RingBuf, MaxEntries: 256 * 1024})
	if err != nil {
		return nil, fmt.Errorf("create process ring: %w", err)
	}
	s.loss, err = ebpf.NewMap(&ebpf.MapSpec{Name: "vmobs_proc_loss", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return nil, fmt.Errorf("create process loss counter: %w", err)
	}
	s.tokens, err = ebpf.NewMap(&ebpf.MapSpec{Name: "vmobs_exec_token", Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: 1024})
	if err != nil {
		return nil, fmt.Errorf("create exec transition map: %w", err)
	}
	s.reader, err = ringbuf.NewReader(s.events)
	if err != nil {
		return nil, err
	}
	for i, name := range []string{"sched_process_fork", "sched_process_exec", "sched_process_exit"} {
		p, loadErr := ebpf.NewProgram(&ebpf.ProgramSpec{Name: fmt.Sprintf("vmobs_proc_%d", i), Type: ebpf.RawTracepoint, License: "GPL", Instructions: lifecycleProgram(int32(i+1), offsets, s.events.FD(), s.loss.FD(), s.tokens.FD())})
		if loadErr != nil {
			return nil, fmt.Errorf("load %s: %w", name, loadErr)
		}
		s.programs = append(s.programs, p)
		l, attachErr := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: p})
		if attachErr != nil {
			return nil, fmt.Errorf("attach %s: %w", name, attachErr)
		}
		s.links = append(s.links, l)
	}
	x, err := syscallBTFOffsets(spec)
	if err != nil {
		return nil, err
	}
	for _, enter := range []bool{true, false} {
		name := "sys_exit"
		if enter {
			name = "sys_enter"
		}
		p, loadErr := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "vmobs_" + name, Type: ebpf.RawTracepoint, License: "GPL", Instructions: syscallProgram(enter, offsets, x, s.events.FD(), s.loss.FD(), s.tokens.FD())})
		if loadErr != nil {
			return nil, fmt.Errorf("load %s: %w", name, loadErr)
		}
		s.programs = append(s.programs, p)
		l, attachErr := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: p})
		if attachErr != nil {
			return nil, fmt.Errorf("attach %s: %w", name, attachErr)
		}
		s.links = append(s.links, l)
	}
	s.health.State = telemetry.SensorHealthy
	s.health.Reason = ""
	s.health.LastSuccessAt = time.Now().UTC().Format(time.RFC3339Nano)
	r.Sensors().Set(s.health)
	return s, nil
}
func (s *Sensor) Close() error {
	var failures []error
	for _, l := range s.links {
		failures = append(failures, l.Close())
	}
	s.links = nil
	for _, p := range s.programs {
		failures = append(failures, p.Close())
	}
	s.programs = nil
	if s.reader != nil {
		failures = append(failures, s.reader.Close())
		s.reader = nil
	}
	if s.events != nil {
		failures = append(failures, s.events.Close())
		s.events = nil
	}
	if s.loss != nil {
		failures = append(failures, s.loss.Close())
		s.loss = nil
	}
	if s.tokens != nil {
		failures = append(failures, s.tokens.Close())
		s.tokens = nil
	}
	return errors.Join(failures...)
}
func (s *Sensor) readLoss() error {
	var current uint64
	if err := s.loss.Lookup(uint32(0), &current); err != nil {
		return fmt.Errorf("read process loss counter: %w", err)
	}
	if current != s.lastLoss {
		reportLoss(s.reporter, &s.health, current-s.lastLoss, "kernel_capture_failure")
		s.lastLoss = current
	}
	return nil
}
func (s *Sensor) Run(ctx context.Context) error {
	nextHealth := time.Now()
	for {
		if ctx.Err() != nil {
			return s.readLoss()
		}
		if !time.Now().Before(nextHealth) {
			if n := s.calls.expire(time.Now()); n != 0 {
				reportLoss(s.reporter, &s.health, n, "pending_syscall_correlation_expired")
			}
			if err := s.readLoss(); err != nil {
				reportFailure(s.reporter, &s.health, err)
				return err
			}
			s.health.LastSuccessAt = time.Now().UTC().Format(time.RFC3339Nano)
			s.reporter.Sensors().Set(s.health)
			nextHealth = time.Now().Add(time.Second)
		}
		s.reader.SetDeadline(time.Now().Add(250 * time.Millisecond))
		record, err := s.reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			reportFailure(s.reporter, &s.health, err)
			return err
		}
		event, err := decode(record.RawSample, s.bootID)
		if err != nil {
			reportLoss(s.reporter, &s.health, 1, "malformed_kernel_record")
			continue
		}
		events, lost := s.calls.consume(event, time.Now())
		if lost != 0 {
			reportLoss(s.reporter, &s.health, lost, "pending_syscall_correlation_discarded")
		}
		for _, event := range events {
			data, err := json.Marshal(event)
			if err != nil {
				reportLoss(s.reporter, &s.health, 1, "record_encoding_failure")
				continue
			}
			s.reporter.Ring().Push(event.Kind, data)
			s.health.LastEventAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}
}

func taskOffsets(spec *btf.Spec) (offsets, error) {
	var task *btf.Struct
	if err := spec.TypeByName("task_struct", &task); err != nil {
		return offsets{}, err
	}
	var o offsets
	for _, f := range []struct {
		name string
		size int
		out  *int32
	}{{"pid", 4, &o.pid}, {"tgid", 4, &o.tgid}, {"start_time", 8, &o.start}, {"self_exec_id", 8, &o.exec}, {"group_leader", 8, &o.leader}, {"real_parent", 8, &o.parent}, {"comm", 16, &o.comm}, {"exit_code", 4, &o.exit}} {
		n, err := memberOffset(task, f.name, f.size)
		if err != nil {
			return offsets{}, err
		}
		*f.out = n
	}
	return o, nil
}

func syscallBTFOffsets(spec *btf.Spec) (syscallOffsets, error) {
	var x syscallOffsets
	for _, f := range []struct {
		typ, name string
		size      int
		out       *int32
	}{
		{"pt_regs", "di", 8, &x.di}, {"pt_regs", "si", 8, &x.si}, {"pt_regs", "dx", 8, &x.dx}, {"pt_regs", "orig_ax", 8, &x.origAX}, {"pt_regs", "cs", 8, &x.cs},
		{"task_struct", "nsproxy", 8, &x.nsproxy}, {"nsproxy", "net_ns", 8, &x.netns}, {"ns_common", "inum", 4, &x.inum},
	} {
		var typ *btf.Struct
		if err := spec.TypeByName(f.typ, &typ); err != nil {
			return x, fmt.Errorf("syscall capture BTF %s: %w", f.typ, err)
		}
		value, err := memberOffset(typ, f.name, f.size)
		if err != nil {
			return x, err
		}
		*f.out = value
	}
	var net, ns *btf.Struct
	if err := spec.TypeByName("net", &net); err != nil {
		return x, err
	}
	if err := spec.TypeByName("ns_common", &ns); err != nil {
		return x, err
	}
	n, err := memberOffset(net, "ns", int(ns.Size))
	if err != nil {
		return x, err
	}
	x.inum += n
	return x, nil
}

// Run owns collector startup, retry and shutdown for the guest agent.
func Run(ctx context.Context, r *telemetry.Reporter, bootID string) {
	for ctx.Err() == nil {
		s, err := Open(r, bootID)
		if err == nil {
			runErr := s.Run(ctx)
			closeErr := s.Close()
			if err := errors.Join(runErr, closeErr); err != nil {
				reportFailure(r, &s.health, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}
