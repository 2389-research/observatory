// ABOUTME: Tests startup reporting for guest network configuration failures.
// ABOUTME: A failed link leaves the agent alive and publishes degraded health.
//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/guest"
	"github.com/2389-research/observatory/internal/guest/proto"
)

func TestStartupServesManagementWhileNetworkBlocks(t *testing.T) {
	cfg := &guest.BootConfig{VMID: "vm-test", BootID: "boot-test", CapabilityToken: "token"}
	agent := guest.NewAgent(cfg, guest.ProbeCapabilities())
	testDir := t.TempDir()
	stderr, err := os.Create(filepath.Join(testDir, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	os.Stderr = stderr
	defer func() {
		os.Stderr = originalStderr
		_ = stderr.Close()
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fifo := filepath.Join(testDir, "blocked-network")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	configureStarted := make(chan struct{})
	configureReturned := make(chan struct{})
	configure := func(context.Context) error {
		close(configureStarted)
		file, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err == nil {
			_ = file.Close()
		}
		close(configureReturned)
		return err
	}
	done := serveGuest(ctx, agent, guestListeners{control: ln}, configure, 150*time.Millisecond)
	pending := agent.Telemetry().Sensors().Snapshot()
	if len(pending) != 1 || pending[0].State != "starting" || !strings.Contains(pending[0].Reason, "pending") {
		t.Fatalf("network sensor before deadline = %+v, want pending", pending)
	}
	select {
	case <-configureStarted:
	case <-time.After(time.Second):
		t.Fatal("network configuration never started")
	}
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := proto.WriteControl(conn, proto.KindHello, proto.Hello{
		ProtocolVersion: proto.ProtocolVersion,
		VMID:            cfg.VMID,
		BootID:          cfg.BootID,
		SourceInstance:  "host-test",
		ResumeCursor:    "0",
		AuthProof:       cfg.CapabilityToken,
	}); err != nil {
		t.Fatal(err)
	}
	envelope, err := proto.ReadControl(conn)
	if err != nil {
		t.Fatal(err)
	}
	var ack proto.HelloAck
	if err := json.Unmarshal(envelope.Data, &ack); err != nil {
		t.Fatal(err)
	}
	if envelope.Kind != proto.KindHelloAck || !ack.Accepted {
		t.Fatalf("management hello after network failure = kind %q ack %+v", envelope.Kind, ack)
	}

	deadline := time.After(time.Second)
	for {
		sensors := agent.Telemetry().Sensors().Snapshot()
		if len(sensors) == 1 && sensors[0].State == "degraded" {
			if sensors[0].ID != "network_configuration" || !strings.Contains(sensors[0].Reason, "deadline") {
				t.Fatalf("network sensor = %+v", sensors)
			}
			if len(sensors[0].EventClasses) != 0 || len(sensors[0].Limitations) != 1 {
				t.Fatalf("network sensor claims capture coverage: %+v", sensors[0])
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("network sensor did not become degraded: %+v", sensors)
		case <-time.After(5 * time.Millisecond):
		}
	}

	wantLog := "vmobs-guestd: guest network configuration failed: deadline reached before network setup returned: context deadline exceeded; management remains available"
	logDeadline := time.After(time.Second)
	for {
		if err := stderr.Sync(); err != nil {
			t.Fatal(err)
		}
		logged, err := os.ReadFile(stderr.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(logged), wantLog) {
			break
		}
		select {
		case <-logDeadline:
			t.Fatalf("stderr = %q, want %q", logged, wantLog)
		case <-time.After(5 * time.Millisecond):
		}
	}

	reader, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	select {
	case <-configureReturned:
	case <-time.After(time.Second):
		t.Fatal("blocked filesystem operation did not release")
	}
	if got := agent.Telemetry().Sensors().Snapshot()[0].State; got != "degraded" {
		t.Fatalf("late network result changed terminal health to %q", got)
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("serveGuest: %v", err)
		}
	default:
	}
}
