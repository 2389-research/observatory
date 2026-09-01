// ABOUTME: Per-VM runner: supervises the VMM by pid+starttime identity, manages
// ABOUTME: the authenticated vsock control channel, and records observations to spool.
package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/spool"
)

// maxSegmentBytes is the per-segment size cap (8 MiB).
// No command-line flag per brief controller resolution — documented here.
const maxSegmentBytes = 8 * 1024 * 1024

// vsockPort is the guest vsock control port.
const vsockPort = 10000

// vmmWatchInterval is the tick rate for the VMM identity check.
const vmmWatchInterval = 1 * time.Second

// dialMaxInterval caps exponential backoff when redialing guestd.
const dialMaxInterval = 30 * time.Second

// pingMissThreshold is the number of consecutive missed pings before
// the channel is declared lost and redial begins.
const pingMissThreshold = 3

// Config holds everything Run needs. Populated by ParseFlags in cmd/vmobs-runner.
type Config struct {
	VMID         string
	BootID       string
	InstanceID   string
	UDSPath      string        // path to the VM's vsock UDS (v.sock)
	TokenFile    string        // path to the capability token file (§15.3)
	SpoolDir     string        // directory for spool segments
	StateFile    string        // path to runner-state.json
	CtlSock      string        // path for the control unix socket
	VMMPID       int           // supervised VMM process PID
	VMMStartTime string        // expected /proc starttime (decimal ticks)
	PingInterval time.Duration // period between guest pings

	// PIDAlive is the VMM identity check function. Nil → PIDAliveFunc (package var).
	// Inject in non-linux tests to override the /proc stub.
	PIDAlive func(pid int, starttime string) bool
}

func (c Config) pidAlive(pid int, starttime string) bool {
	if c.PIDAlive != nil {
		return c.PIDAlive(pid, starttime)
	}
	return PIDAliveFunc(pid, starttime)
}

// shutdownRequest queues a shutdown_guest ctl command to the supervision loop.
type shutdownRequest struct {
	graceS int
	result chan error // exactly one send; closed by the loop when done
}

// runner holds live state for one Run invocation.
type runner struct {
	cfg   Config
	token string

	// state is the most-recently written runner state.
	state State

	// sw is the spool writer; opened once, closed on Run exit.
	sw *spool.Writer

	// seq is the monotonic per-instance event counter (1-based).
	seq atomic.Uint64

	// shutdownCh receives shutdown requests from the ctl handler.
	shutdownCh chan shutdownRequest

	// finalizeCh receives a single signal when a finalize ctl arrives.
	finalizeCh chan struct{}

	// shutdownRequested is set when a shutdown_guest ctl was accepted this boot.
	mu                sync.Mutex
	shutdownRequested bool
}

// Run is the main entry point. Returns nil on clean exit (vmm_exited→finalized
// or explicit finalize command). Returns ctx.Err() on context cancellation.
func Run(ctx context.Context, cfg Config) error {
	r := &runner{
		cfg:        cfg,
		shutdownCh: make(chan shutdownRequest, 1),
		finalizeCh: make(chan struct{}, 1),
	}
	return r.run(ctx)
}

func (r *runner) run(ctx context.Context) error {
	// §15.3: read token from file only — never from argv.
	tokenBytes, err := os.ReadFile(r.cfg.TokenFile)
	if err != nil {
		return fmt.Errorf("runner: read token file: %w", err)
	}
	r.token = strings.TrimRight(string(tokenBytes), "\n")

	// Open spool writer.
	if err := os.MkdirAll(r.cfg.SpoolDir, 0o700); err != nil {
		return fmt.Errorf("runner: mkdir spool: %w", err)
	}
	sw, err := spool.OpenWriter(r.cfg.SpoolDir, spool.WriterCfg{
		VMID:            r.cfg.VMID,
		InstanceID:      r.cfg.InstanceID,
		MaxSegmentBytes: maxSegmentBytes,
		// MaxSpoolBytes 0 → DefaultMaxSpoolBytes (512 MiB)
	})
	if err != nil {
		return fmt.Errorf("runner: open spool: %w", err)
	}
	r.sw = sw

	// Initialise state.
	r.state = State{
		VMID:         r.cfg.VMID,
		BootID:       r.cfg.BootID,
		InstanceID:   r.cfg.InstanceID,
		RunnerPID:    os.Getpid(),
		VMMPID:       r.cfg.VMMPID,
		VMMStartTime: r.cfg.VMMStartTime,
		Phase:        PhaseStarting,
	}
	if err := r.writeState(); err != nil {
		_ = sw.Close()
		return fmt.Errorf("runner: write initial state: %w", err)
	}

	// Start control socket.
	ctlSrv, err := ListenCtl(ctx, r.cfg.CtlSock, r.doShutdown, r.doFinalize)
	if err != nil {
		_ = sw.Close()
		return fmt.Errorf("runner: listen ctl: %w", err)
	}
	defer ctlSrv.Close()

	// VMM identity watch signals vmmGone when the VMM process is gone.
	vmmGone := make(chan struct{})
	go r.watchVMM(ctx, vmmGone)

	// Run the supervision loop.
	runErr := r.supervisionLoop(ctx, vmmGone)

	// Close spool cleanly (writes end marker).
	if closeErr := sw.Close(); closeErr != nil {
		fmt.Fprintf(os.Stderr, "runner: spool close: %v\n", closeErr)
	}

	return runErr
}

// supervisionLoop is the dial→handshake→ping→redial cycle.
// Returns nil on vmm_exited→finalized or finalize cmd.
// Returns ctx.Err() on context cancellation.
func (r *runner) supervisionLoop(ctx context.Context, vmmGone <-chan struct{}) error {
	dialBackoff := 1 * time.Second

	for {
		// Check termination before each dial attempt.
		select {
		case <-ctx.Done():
			return r.cleanExit(ctx.Err())
		case <-vmmGone:
			return r.onVMMGone()
		case <-r.finalizeCh:
			return r.onFinalize()
		default:
		}

		// Dial with a per-attempt timeout.
		dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := proto.DialHostVsock(dialCtx, r.cfg.UDSPath, vsockPort)
		dialCancel()
		if err != nil {
			select {
			case <-ctx.Done():
				return r.cleanExit(ctx.Err())
			case <-vmmGone:
				return r.onVMMGone()
			case <-r.finalizeCh:
				return r.onFinalize()
			case <-time.After(dialBackoff):
			}
			dialBackoff = clampDouble(dialBackoff, dialMaxInterval)
			continue
		}
		dialBackoff = 1 * time.Second

		// Handshake.
		if err := r.handshake(conn); err != nil {
			conn.Close()
			select {
			case <-ctx.Done():
				return r.cleanExit(ctx.Err())
			case <-vmmGone:
				return r.onVMMGone()
			case <-r.finalizeCh:
				return r.onFinalize()
			case <-time.After(dialBackoff):
			}
			dialBackoff = clampDouble(dialBackoff, dialMaxInterval)
			continue
		}

		// Transition to attached.
		r.state.Phase = PhaseAttached
		if err := r.writeState(); err != nil {
			fmt.Fprintf(os.Stderr, "runner: write state (attached): %v\n", err)
		}

		// Serve pings. Returns (lostReason, action) where action is one of
		// "redial", "vmm_gone", "finalize", "ctx_done".
		reason, action := r.pingLoop(ctx, conn, vmmGone)

		switch action {
		case "ctx_done":
			return r.cleanExit(ctx.Err())
		case "vmm_gone":
			return r.onVMMGone()
		case "finalize":
			return r.onFinalize()
		}

		// action == "redial": append channel_lost, degrade, redial.
		_ = r.appendChannelLost(reason)
		r.state.Phase = PhaseDegraded
		if err := r.writeState(); err != nil {
			fmt.Fprintf(os.Stderr, "runner: write state (degraded): %v\n", err)
		}
		select {
		case <-ctx.Done():
			return r.cleanExit(ctx.Err())
		case <-vmmGone:
			return r.onVMMGone()
		case <-r.finalizeCh:
			return r.onFinalize()
		case <-time.After(dialBackoff):
		}
		dialBackoff = clampDouble(dialBackoff, dialMaxInterval)
	}
}

// pingLoop runs the ping/pong cycle for one established connection.
// It returns (lostReason, action) where action is "redial", "vmm_gone",
// "finalize", or "ctx_done".
func (r *runner) pingLoop(ctx context.Context, conn net.Conn, vmmGone <-chan struct{}) (reason, action string) {
	// Read loop: pushes envelopes into readCh, errors into readErrCh.
	readCh := make(chan proto.Envelope, 16)
	readErrCh := make(chan error, 1)
	go func() {
		for {
			env, err := proto.ReadControl(conn)
			if err != nil {
				readErrCh <- err
				return
			}
			readCh <- env
		}
	}()

	// shutdownAckCh: set when a shutdown_guest ctl is in flight.
	var ackMu sync.Mutex
	var ackCh chan<- error

	setAck := func(ch chan<- error) {
		ackMu.Lock()
		ackCh = ch
		ackMu.Unlock()
	}
	routeAck := func(err error) {
		ackMu.Lock()
		ch := ackCh
		ackCh = nil
		ackMu.Unlock()
		if ch != nil {
			ch <- err
		}
	}

	defer func() {
		conn.Close()
		// If a shutdown handler is still waiting, unblock it.
		routeAck(fmt.Errorf("channel closed"))
	}()

	pingTicker := time.NewTicker(r.cfg.PingInterval)
	defer pingTicker.Stop()

	// pingsPending tracks pings sent with no pong received yet.
	// 3 consecutive pings without a pong = channel lost.
	pingsPending := 0

	for {
		select {
		case <-ctx.Done():
			return "", "ctx_done"

		case <-vmmGone:
			return "", "vmm_gone"

		case <-r.finalizeCh:
			return "", "finalize"

		case req := <-r.shutdownCh:
			// Send KindShutdown to the guest.
			shutdownMsg := proto.Shutdown{DeadlineS: req.graceS}
			if err := proto.WriteControl(conn, proto.KindShutdown, shutdownMsg); err != nil {
				req.result <- fmt.Errorf("write shutdown: %w", err)
				break
			}
			r.markShutdownRequested()

			// Wire up the ack channel and wait for the result.
			ackResult := make(chan error, 1)
			setAck(ackResult)
			deadline := time.Duration(req.graceS)*time.Second + 5*time.Second
			go func() {
				select {
				case err := <-ackResult:
					req.result <- err
				case <-time.After(deadline):
					setAck(nil)
					req.result <- fmt.Errorf("shutdown_ack timeout")
				}
			}()

		case <-pingTicker.C:
			pingsPending++
			if pingsPending > pingMissThreshold {
				return "ping window expired", "redial"
			}
			if err := proto.WriteControl(conn, proto.KindPing, struct{}{}); err != nil {
				return fmt.Sprintf("ping write: %v", err), "redial"
			}
			// Write state on each ping cycle.
			if err := r.writeState(); err != nil {
				fmt.Fprintf(os.Stderr, "runner: write state (ping): %v\n", err)
			}

		case env, ok := <-readCh:
			if !ok {
				return "read channel closed", "redial"
			}
			switch env.Kind {
			case proto.KindPong:
				pingsPending = 0
			case proto.KindShutdownAck:
				routeAck(nil)
			default:
				// Unknown kinds are silently ignored.
			}

		case err := <-readErrCh:
			msg := "connection closed"
			if err != nil {
				msg = fmt.Sprintf("read: %v", err)
			}
			return msg, "redial"
		}
	}
}

// handshake performs Hello → HelloAck → get_capabilities → capabilities.
// Appends channel_established on success.
func (r *runner) handshake(conn net.Conn) error {
	hello := proto.Hello{
		ProtocolVersion: proto.ProtocolVersion,
		VMID:            r.cfg.VMID,
		BootID:          r.cfg.BootID,
		SourceInstance:  r.cfg.InstanceID,
		ResumeCursor:    "0",
		AuthProof:       r.token,
	}
	if err := proto.WriteControl(conn, proto.KindHello, hello); err != nil {
		return fmt.Errorf("write hello: %w", err)
	}

	ackEnv, err := proto.ReadControl(conn)
	if err != nil {
		return fmt.Errorf("read hello_ack: %w", err)
	}
	if ackEnv.Kind != proto.KindHelloAck {
		return fmt.Errorf("expected hello_ack, got %q", ackEnv.Kind)
	}
	var ack proto.HelloAck
	if err := json.Unmarshal(ackEnv.Data, &ack); err != nil {
		return fmt.Errorf("unmarshal hello_ack: %w", err)
	}
	if !ack.Accepted {
		return fmt.Errorf("handshake rejected: %s", ack.Reason)
	}

	if err := proto.WriteControl(conn, proto.KindGetCapabilities, struct{}{}); err != nil {
		return fmt.Errorf("write get_capabilities: %w", err)
	}
	capEnv, err := proto.ReadControl(conn)
	if err != nil {
		return fmt.Errorf("read capabilities: %w", err)
	}
	if capEnv.Kind != proto.KindCapabilities {
		return fmt.Errorf("expected capabilities, got %q", capEnv.Kind)
	}
	var manifest proto.CapabilityManifest
	if err := json.Unmarshal(capEnv.Data, &manifest); err != nil {
		return fmt.Errorf("unmarshal capabilities: %w", err)
	}

	_ = r.appendChannelEstablished(len(manifest.Features))
	return nil
}

// watchVMM ticks every second and closes vmmGone when the VMM process is gone.
func (r *runner) watchVMM(ctx context.Context, vmmGone chan<- struct{}) {
	ticker := time.NewTicker(vmmWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !r.cfg.pidAlive(r.cfg.VMMPID, r.cfg.VMMStartTime) {
				close(vmmGone)
				return
			}
		}
	}
}

// onVMMGone emits vmm_exited and transitions to finalized; returns nil.
func (r *runner) onVMMGone() error {
	graceful := r.isShutdownRequested()
	_ = r.appendVMMExited(graceful)
	r.state.Phase = PhaseVMMExited
	_ = r.writeState()
	r.state.Phase = PhaseFinalized
	_ = r.writeState()
	return nil
}

// onFinalize transitions to finalized; returns nil.
func (r *runner) onFinalize() error {
	r.state.Phase = PhaseFinalized
	_ = r.writeState()
	return nil
}

// cleanExit transitions to finalized and returns the passed error.
func (r *runner) cleanExit(err error) error {
	r.state.Phase = PhaseFinalized
	_ = r.writeState()
	return err
}

// doShutdown is the ctl shutdown_guest handler; queues to the supervision loop.
func (r *runner) doShutdown(graceS int) error {
	result := make(chan error, 1)
	select {
	case r.shutdownCh <- shutdownRequest{graceS: graceS, result: result}:
	default:
		return fmt.Errorf("shutdown already in progress")
	}
	return <-result
}

// doFinalize is the ctl finalize handler.
func (r *runner) doFinalize() error {
	select {
	case r.finalizeCh <- struct{}{}:
	default:
	}
	return nil
}

// nextSeq returns the next monotonic source sequence (decimal string, starts at 1).
func (r *runner) nextSeq() string {
	return fmt.Sprintf("%d", r.seq.Add(1))
}

// newEnvelope builds a host_observed spool envelope for runner-emitted events.
func (r *runner) newEnvelope(kind string, data map[string]any) *events.Envelope {
	vmID := r.cfg.VMID
	bootID := r.cfg.BootID
	return &events.Envelope{
		SchemaVersion:    1,
		VMID:             &vmID,
		BootID:           &bootID,
		SourceInstanceID: r.cfg.InstanceID,
		SourceSeq:        r.nextSeq(),
		Kind:             kind,
		Provenance:       events.HostObserved,
		Sensor:           spool.Sensor,
		HostReceivedAt:   events.Timestamp{Time: time.Now().UTC()},
		Quality: events.Quality{
			PathResolution: events.PathNotApplicable,
			Attribution:    events.AttributionNotApplicable,
		},
		Data: data,
	}
}

// appendChannelEstablished appends a guest.channel_established envelope.
// On Append failure: logs one line to stderr and continues (spool is poisoned
// so later appends will fast-fail; identity watch outlives spooling). Limitation:
// no overflow-health-record path in this milestone.
func (r *runner) appendChannelEstablished(capsCount int) error {
	env := r.newEnvelope("guest.channel_established", map[string]any{
		"protocol_version":   1,
		"capabilities_count": capsCount,
	})
	if err := r.sw.Append(env); err != nil {
		fmt.Fprintf(os.Stderr, "runner: spool append (channel_established): %v\n", err)
		return err
	}
	return nil
}

// appendChannelLost appends a guest.channel_lost envelope.
func (r *runner) appendChannelLost(reason string) error {
	env := r.newEnvelope("guest.channel_lost", map[string]any{
		"reason": reason,
	})
	if err := r.sw.Append(env); err != nil {
		fmt.Fprintf(os.Stderr, "runner: spool append (channel_lost): %v\n", err)
		return err
	}
	return nil
}

// appendVMMExited appends a vm.vmm_exited envelope.
func (r *runner) appendVMMExited(graceful bool) error {
	env := r.newEnvelope("vm.vmm_exited", map[string]any{
		"graceful":         graceful,
		"exit_observed_by": "pidfile_stat",
	})
	if err := r.sw.Append(env); err != nil {
		fmt.Fprintf(os.Stderr, "runner: spool append (vmm_exited): %v\n", err)
		return err
	}
	return nil
}

// writeState persists r.state atomically.
func (r *runner) writeState() error {
	r.state.UpdatedAtUnix = time.Now().Unix()
	return WriteState(r.cfg.StateFile, r.state)
}

// markShutdownRequested records that a shutdown_guest was accepted this boot.
func (r *runner) markShutdownRequested() {
	r.mu.Lock()
	r.shutdownRequested = true
	r.mu.Unlock()
}

// isShutdownRequested returns whether a shutdown_guest ctl was accepted this boot.
func (r *runner) isShutdownRequested() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.shutdownRequested
}

// clampDouble doubles d and clamps to max.
func clampDouble(d, max time.Duration) time.Duration {
	d *= 2
	if d > max {
		return max
	}
	return d
}
