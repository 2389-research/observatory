// ABOUTME: Privileged socket outcomes fence disk credit after a caller loses its reply.
// ABOUTME: Real backend cleanup removes images after controlled start and release delays.
//go:build linux

package jailer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/store"
)

type delayedDiskCleanup struct {
	*privd.RealOps
	entered chan struct{}
	finish  chan struct{}
}

func (b *delayedDiskCleanup) StartVMContext(context.Context, *privd.VMEntry, privd.StartVMReq) (privd.StartVMResp, error) {
	close(b.entered)
	<-b.finish
	return privd.StartVMResp{}, errors.New("injected pre-exec failure")
}

func (b *delayedDiskCleanup) ReleaseVM(entry privd.VMEntry) error {
	close(b.entered)
	<-b.finish
	return b.RealOps.ReleaseVM(entry)
}

func TestObserveDiskRetainsDebtAfterLostPrivilegedReply(t *testing.T) {
	for _, verb := range []string{"start", "release"} {
		t.Run(verb, func(t *testing.T) {
			root := t.TempDir()
			cfg := Config{StateDir: root, JailBase: filepath.Join(root, "jails"), StageRoot: filepath.Join(root, "stage")}
			jail := filepath.Join(cfg.JailBase, "firecracker", "owner", "root")
			stage := filepath.Join(cfg.StageRoot, "owner")
			ledger := filepath.Join(root, "ledger")
			for _, dir := range []string{jail, stage, ledger} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			disk := filepath.Join(jail, "rootfs.ext4")
			if err := os.WriteFile(disk, make([]byte, 2<<20), 0600); err != nil {
				t.Fatal(err)
			}
			entry, err := json.Marshal(privd.VMEntry{VMID: "owner", NetCIDR: "10.88.0.0/30"})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ledger, "owner.json"), entry, 0600); err != nil {
				t.Fatal(err)
			}
			backend := &delayedDiskCleanup{RealOps: privd.NewRealOps(privd.RealOpsCfg{JailBase: cfg.JailBase}), entered: make(chan struct{}), finish: make(chan struct{})}
			socket := filepath.Join(root, "p.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			server := privd.NewServer(privd.ServerCfg{AllowedUID: os.Getuid(), LedgerDir: ledger, StageRoot: cfg.StageRoot, JailBase: cfg.JailBase, UIDMin: os.Getuid(), UIDMax: os.Getuid() + 1, Ops: backend, Log: log.New(io.Discard, "", 0)})
			serving, stop := context.WithCancel(t.Context())
			defer stop()
			served := make(chan error, 1)
			go func() { served <- server.Serve(serving, listener) }()
			defer func() {
				stop()
				if err := <-served; err != nil {
					t.Error(err)
				}
			}()
			client := &privd.Client{SocketPath: socket}
			a := &Adapter{cfg: cfg, pc: client}
			reservations := []store.DiskReservation{{VMID: "owner", DiskMiB: 2}}
			settled, err := a.ObserveDisk(reservations)
			if err != nil || settled.MaterializedMiB != 2 {
				t.Fatalf("settled inventory: %+v %v", settled, err)
			}
			ctx, cancel := context.WithCancel(privd.WithOperationID(t.Context(), "disk-op"))
			defer cancel()
			result := make(chan error, 1)
			go func() {
				if verb == "start" {
					_, err := client.StartVM(ctx, privd.StartVMReq{VMID: "owner", UID: os.Getuid(), GID: os.Getgid(), CID: 3, StageDir: stage})
					result <- err
				} else {
					result <- client.ReleaseVM(ctx, privd.ReleaseVMReq{VMID: "owner"})
				}
			}()
			select {
			case <-backend.entered:
			case err := <-result:
				t.Fatalf("mutation did not reach backend: %v", err)
			case <-time.After(time.Second):
				t.Fatal("backend did not start")
			}
			cancel()
			var unknown *privd.UnknownOutcomeError
			if err := <-result; !errors.As(err, &unknown) {
				t.Fatalf("lost reply: %v", err)
			}
			// The caller is gone, but this privileged mutation still owns image deletion.
			observed, err := a.ObserveDisk(reservations)
			close(backend.finish)
			if err != nil || observed.MaterializedMiB != 0 {
				t.Errorf("pending %s credited mutable image: %+v %v", verb, observed, err)
			}
			deadline := time.Now().Add(time.Second)
			for {
				outcome, err := client.QueryOperation(t.Context(), "disk-op")
				if err != nil {
					t.Fatal(err)
				}
				if outcome.State == "succeeded" || outcome.State == "failed" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("mutation unsettled: %+v", outcome)
				}
				time.Sleep(time.Millisecond)
			}
			if _, err := os.Stat(disk); !os.IsNotExist(err) {
				t.Fatalf("late real cleanup did not remove disk: %v", err)
			}
			observed, err = a.ObserveDisk(reservations)
			if err != nil || observed.MaterializedMiB != 0 {
				t.Fatalf("reclaimed disk credit: %+v %v", observed, err)
			}
		})
	}
}
