// ABOUTME: vmobs-privd daemon entrypoint: parses flags, binds the unix socket, and serves.
// ABOUTME: Linux-only; a stub for other platforms lives in main_other.go.
//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/2389-research/observatory-v2/internal/privd"
)

const (
	// uidMin and uidMax mirror the root helper's uid policy ([10000,59999] inclusive,
	// i.e. [10000,60000) half-open). See scripts/aibox03/vmobs-root-helper line 21.
	uidMin = 10000
	uidMax = 60000
)

func main() {
	flags, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "vmobs-privd: %v\n", err)
		os.Exit(2)
	}

	// Remove a stale socket from a previous run so Listen doesn't fail with EADDRINUSE.
	_ = os.Remove(flags.socket)

	ln, err := net.Listen("unix", flags.socket)
	if err != nil {
		log.Fatalf("vmobs-privd: listen %s: %v", flags.socket, err)
	}

	// Restrict socket access: root owns it (uid 0), gid = allowedGID, perms 0660.
	// The peer-cred uid check in the server is the real boundary; this is defence in depth.
	if err := os.Chown(flags.socket, 0, flags.allowedGID); err != nil {
		log.Fatalf("vmobs-privd: chown socket: %v", err)
	}
	if err := os.Chmod(flags.socket, 0o660); err != nil {
		log.Fatalf("vmobs-privd: chmod socket: %v", err)
	}

	ops := privd.NewRealOps(privd.RealOpsCfg{
		JailBase:        flags.jailBase,
		StageRoot:       flags.stageRoot,
		FirecrackerPath: flags.firecracker,
		JailerPath:      flags.jailer,
	})

	srv := privd.NewServer(privd.ServerCfg{
		AllowedUID: flags.allowedUID,
		LedgerDir:  flags.ledgerDir,
		StageRoot:  flags.stageRoot,
		JailBase:   flags.jailBase,
		UIDMin:     uidMin,
		UIDMax:     uidMax,
		Ops:        ops,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	fmt.Printf("vmobs-privd: serving %s (allowed uid %d gid %d)\n",
		flags.socket, flags.allowedUID, flags.allowedGID)

	if err := srv.Serve(ctx, ln); err != nil {
		log.Fatalf("vmobs-privd: serve: %v", err)
	}

	// Clean up the socket on clean shutdown.
	_ = os.Remove(flags.socket)
}
