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

// applyProcessUmask sets vmobs-privd's process-wide umask to 0002 and returns the
// previous umask. Go has no per-child umask (syscall.SysProcAttr has no umask field),
// so this process-wide setting is the only way to reach the jailer: the jailer, and
// firecracker exec'd beneath it, inherit it across exec. Firecracker binds v.sock as
// uid 20000+slot, gid 36000, mode 0777 & ~umask; the daemon's own uid is a member of
// gid 36000 but never the owner, so v.sock must be group-writable or every connect()
// from the daemon fails with EACCES. This mirrors the M0 root helper's own
// `umask 0002` (scripts/aibox03/vmobs-root-helper:97).
func applyProcessUmask() int {
	return syscall.Umask(0o002)
}

func main() {
	// The probe child re-enters this binary inside its own mount and network
	// namespaces. Dispatched before flag parsing so its argv is never mistaken
	// for an operator's, and never the other way round.
	if dir, ok := privd.JailProbeChildArgs(os.Args[1:]); ok {
		os.Exit(privd.RunJailProbeChild(dir, os.Stdout, os.Stderr))
	}

	flags, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "vmobs-privd: %v\n", err)
		os.Exit(2)
	}

	applyProcessUmask()

	// Measure the privileged operations the jailer performs before agreeing to
	// serve. A container missing one flag would otherwise take a launch through
	// admission, network allocation and staging before failing inside the
	// jailer, and the operator would read that as a bug in vmobs.
	//
	// It probes under the jail base, not somewhere convenient, because that is
	// the path the AppArmor rules name; see ProbeJailSyscalls.
	if err := privd.ProbeJailSyscalls(flags.jailBase); err != nil {
		log.Fatalf("vmobs-privd: %v", err)
	}

	// Own the socket path and the ledger directory before touching either, and
	// clear the stale socket a previous run left only once that hold proves
	// nothing is listening on the name. A second privd fails here, naming the
	// holder, instead of unlinking a live one's socket and serving its clients.
	//
	// The kernel drops both holds when this process ends however it ends, so the
	// release below is the orderly path rather than the guarantee.
	single, err := acquireSingleton(flags)
	if err != nil {
		log.Fatalf("vmobs-privd: %v", err)
	}
	defer single.release()

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

	// The jail base is privd's to create and the unprivileged daemon's to walk
	// through, and it is settled here rather than at the first launch: teardown
	// reaches through it too, and a teardown creates nothing. See
	// privd.EnsureJailBase.
	if err := privd.EnsureJailBase(flags.jailBase); err != nil {
		log.Fatalf("vmobs-privd: %v", err)
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

	fmt.Printf("vmobs-privd: serving %s (allowed uid %d gid %d)\n",
		flags.socket, flags.allowedUID, flags.allowedGID)

	serveErr := srv.Serve(ctx, ln)
	stop()
	// The socket goes; the lock files stay. Removing a lock file while another
	// privd is between its open and its flock would leave the two holding
	// different inodes and both believing they own the host.
	_ = os.Remove(flags.socket)
	if serveErr != nil {
		log.Printf("vmobs-privd: serve: %v", serveErr)
		os.Exit(1)
	}
}
