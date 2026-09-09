// ABOUTME: vmobs-guestd: the in-guest control-channel agent. Mounts config device, probes kernel, serves vsock.
// ABOUTME: Linux-only binary; a stub for other platforms lives in main_other.go.
//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/2389-research/observatory/internal/guest"
	"github.com/2389-research/observatory/internal/guest/fswatch"
	"github.com/2389-research/observatory/internal/guest/procwatch"
	"github.com/2389-research/observatory/internal/guest/telemetry"
)

func main() {
	fs := flag.NewFlagSet("vmobs-guestd", flag.ExitOnError)
	configDev := fs.String("config-dev", "/dev/vdb", "block device holding the boot config ext4 image")
	configMount := fs.String("config-mount", "/run/vmobs/config", "mountpoint for the config device")
	controlPort := fs.Uint("control-port", 10000, "vsock port to listen on (§7.3)")
	streamPort := fs.Uint("stream-port", 10002, "vsock port carrying session byte streams (§7.3)")
	telemetryPort := fs.Uint("telemetry-port", 10001, "vsock port carrying guest telemetry (§7.3)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		log.Fatalf("parse flags: %v", err)
	}

	cfg, err := guest.LoadBootConfig(*configDev, *configMount)
	if err != nil {
		log.Fatalf("load boot config: %v", err)
	}

	manifest := guest.ProbeCapabilities()
	agent := guest.NewAgent(cfg, manifest)

	ln, err := vsock.Listen(uint32(*controlPort), nil)
	if err != nil {
		log.Fatalf("vsock listen port %d: %v", *controlPort, err)
	}
	defer ln.Close()

	// A stream port that will not bind costs terminals, not the VM. The control
	// channel is how the host stops this guest at all, so exiting here would
	// strand it; instead the failure is logged to the console and every terminal
	// verb fails at the host with a real error rather than hanging.
	streamLn, streamErr := vsock.Listen(uint32(*streamPort), nil)
	if streamErr != nil {
		fmt.Fprintf(os.Stderr, "vmobs-guestd: vsock listen port %d: %v; terminals unavailable\n",
			*streamPort, streamErr)
	} else {
		defer streamLn.Close()
	}

	// Telemetry degrades the same way a stream port does, and for the same
	// reason: losing sensing is worse than losing the VM only if you also lose
	// the ability to stop it. A host that never sees a heartbeat reports the
	// guest's telemetry unavailable, which is the honest answer.
	telemetryLn, telemetryErr := vsock.Listen(uint32(*telemetryPort), nil)
	if telemetryErr != nil {
		fmt.Fprintf(os.Stderr, "vmobs-guestd: vsock listen port %d: %v; telemetry unavailable\n",
			*telemetryPort, telemetryErr)
	} else {
		defer telemetryLn.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	fmt.Printf("vmobs-guestd: serving vsock control %d stream %d telemetry %d vm=%s boot=%s\n",
		*controlPort, *streamPort, *telemetryPort, cfg.VMID, cfg.BootID)

	done := serveGuest(ctx, agent, guestListeners{
		control:   ln,
		stream:    streamLn,
		telemetry: telemetryLn,
	}, func(networkCtx context.Context) error {
		return guest.ConfigureNetwork(networkCtx, cfg.Network)
	}, 5*time.Second)

	// The heartbeat runs whether or not the port bound: what piles up in the
	// ring while nobody reads is the evidence that nobody was reading. serveGuest
	// registers network configuration as pending before the first beat.
	go agent.RunHeartbeat(ctx, guest.HeartbeatInterval)
	go fswatch.Run(ctx, agent.Telemetry())
	go procwatch.Run(ctx, agent.Telemetry(), cfg.BootID)

	if err := <-done; err != nil {
		log.Fatalf("%v", err)
	}
}

type guestListeners struct {
	control   net.Listener
	stream    net.Listener
	telemetry net.Listener
}

// serveGuest starts every available management path before the one-shot
// network setup. A setup operation that fails to return cannot hold control or
// spawn retries; its late result is ignored after the deadline health verdict.
func serveGuest(
	ctx context.Context,
	agent *guest.Agent,
	listeners guestListeners,
	configure func(context.Context) error,
	networkTimeout time.Duration,
) <-chan error {
	recordNetworkPending(agent)
	done := make(chan error, 3)
	serve := func(name string, fn func(context.Context, net.Listener) error, listener net.Listener) {
		if listener == nil {
			return
		}
		go func() {
			if err := fn(ctx, listener); err != nil {
				done <- fmt.Errorf("%s: %w", name, err)
				return
			}
			done <- nil
		}()
	}
	serve("ServeControl", agent.ServeControl, listeners.control)
	serve("ServeStreams", agent.ServeStreams, listeners.stream)
	serve("ServeTelemetry", agent.ServeTelemetry, listeners.telemetry)

	networkCtx, cancelNetwork := context.WithTimeout(ctx, networkTimeout)
	result := make(chan error, 1)
	go func() {
		result <- configure(networkCtx)
	}()
	go func() {
		defer cancelNetwork()
		select {
		case err := <-result:
			if networkCtx.Err() != nil {
				err = networkCtx.Err()
			}
			recordNetworkHealth(agent, err)
			if err != nil {
				fmt.Fprintf(os.Stderr, "vmobs-guestd: guest network configuration failed: %v; management remains available\n", err)
			}
		case <-networkCtx.Done():
			err := fmt.Errorf("deadline reached before network setup returned: %w", networkCtx.Err())
			recordNetworkHealth(agent, err)
			fmt.Fprintf(os.Stderr, "vmobs-guestd: guest network configuration failed: %v; management remains available\n", err)
		}
	}()
	return done
}

func networkHealth(state, reason string) telemetry.Sensor {
	return telemetry.Sensor{
		ID:          "network_configuration",
		State:       state,
		Dropped:     "0",
		Scope:       []string{"eth0 static address", "default route", "managed DNS"},
		Limitations: []string{"configuration health does not report host flow or DNS query coverage"},
		Reason:      reason,
	}
}

func recordNetworkPending(agent *guest.Agent) {
	agent.Telemetry().Sensors().Set(networkHealth(telemetry.SensorStarting, "guest network configuration pending"))
}

func recordNetworkHealth(agent *guest.Agent, err error) {
	sensor := networkHealth(telemetry.SensorHealthy, "")
	if err != nil {
		sensor.State = telemetry.SensorDegraded
		sensor.Reason = "guest network configuration failed: " + err.Error()
	}
	agent.Telemetry().Sensors().Set(sensor)
}
