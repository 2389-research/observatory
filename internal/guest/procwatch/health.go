// ABOUTME: Publishes lifecycle capture availability and measured loss through the shared reporter.
// ABOUTME: Keeps kernel queue failure separate from the aggregate telemetry transport queue.
package procwatch

import (
	"encoding/json"
	"github.com/2389-research/observatory/internal/guest/telemetry"
	"strconv"
)

func newHealth(r *telemetry.Reporter) telemetry.Sensor {
	h := telemetry.Sensor{ID: "process", State: telemetry.SensorStarting, Dropped: "0", CaptureMode: "bpf_raw_sched_and_syscall_tracepoints", EventClasses: []string{"proc.fork", "proc.exec", "proc.exit", "proc.exec_attempt", "proc.exec_failed", "socket.connect_attempt", "socket.connect_result", "proc.loss"}, Scope: []string{"guest tasks; task PID and group-leader start identity captured in kernel"}, Limitations: []string{"native amd64 execve/execveat/connect only; compat syscalls excluded", "argv limited to 4 arguments and 63 bytes per argument; read failures and truncation explicit", "cwd, credentials and executable path not captured", "connect captures syscall arguments/results, not socket lifetime, transport protocol or host flow attribution", "unconnected UDP sends and socket close/state changes not captured", "shell builtins and in-process operations are not separate execs", "entry/result correlation bounded to 1024 pending calls and 30 seconds", "exit means task exit, not proof that all process threads exited", "comm is a bounded kernel task label, not executable path or command", "exec generation is kernel self_exec_id, inherited at fork; not a zero-based count", "shared telemetry ring loss is aggregate transport loss", "no file or socket attribution is inferred from PID alone"}}
	for _, v := range r.Sensors().Snapshot() {
		if v.ID == h.ID {
			h.Dropped = v.Dropped
			h.UnknownLossIntervals = v.UnknownLossIntervals
			h.LastEventAt = v.LastEventAt
			if v.State == telemetry.SensorDegraded || v.State == telemetry.SensorUnavailable {
				h.State = v.State
				h.Reason = v.Reason
			}
		}
	}
	return h
}
func reportLoss(r *telemetry.Reporter, h *telemetry.Sensor, n uint64, reason string) {
	previous, _ := strconv.ParseUint(h.Dropped, 10, 64)
	if ^uint64(0)-previous < n {
		h.Dropped = strconv.FormatUint(^uint64(0), 10)
	} else {
		h.Dropped = strconv.FormatUint(previous+n, 10)
	}
	h.State = telemetry.SensorDegraded
	h.Reason = reason
	b, _ := json.Marshal(map[string]any{"sensor": "process", "reason": reason, "lost_count": strconv.FormatUint(n, 10), "count_quality": "measured"})
	r.Ring().Push("proc.loss", b)
	r.Sensors().Set(*h)
}

func reportFailure(r *telemetry.Reporter, h *telemetry.Sensor, err error) {
	if h.State != telemetry.SensorUnavailable {
		h.UnknownLossIntervals++
		b, _ := json.Marshal(map[string]any{"sensor": "process", "reason": "collector_failure", "lost_count": nil, "count_quality": "unknown"})
		r.Ring().Push("proc.loss", b)
	}
	h.State = telemetry.SensorUnavailable
	h.Reason = err.Error()
	if len(h.Reason) > 512 {
		h.Reason = h.Reason[:512]
	}
	r.Sensors().Set(*h)
}
