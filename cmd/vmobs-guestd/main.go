// ABOUTME: vmobs-guestd: the in-guest control-channel agent. Mounts config device, probes kernel, serves vsock.
// ABOUTME: Linux-only binary; a stub for other platforms lives in main_other.go.
//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/mdlayher/vsock"

	"github.com/2389-research/observatory-v2/internal/guest"
)

func main() {
	fs := flag.NewFlagSet("vmobs-guestd", flag.ExitOnError)
	configDev := fs.String("config-dev", "/dev/vdb", "block device holding the boot config ext4 image")
	configMount := fs.String("config-mount", "/run/vmobs/config", "mountpoint for the config device")
	controlPort := fs.Uint("control-port", 10000, "vsock port to listen on (§7.3)")
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	fmt.Printf("vmobs-guestd: serving vsock port %d vm=%s boot=%s\n",
		*controlPort, cfg.VMID, cfg.BootID)

	if err := agent.ServeControl(ctx, ln); err != nil {
		log.Fatalf("ServeControl: %v", err)
	}
}
