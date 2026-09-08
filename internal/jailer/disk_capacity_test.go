// ABOUTME: Filesystem observations credit allocated guest disks without trusting manifests.
// ABOUTME: Sparse files and lifecycle serialization retain outstanding disk promises.
package jailer

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/store"
	"golang.org/x/sys/unix"
)

func TestObserveDiskCreditsOnlyGuestAllocation(t *testing.T) {
	root := t.TempDir()
	a := &Adapter{cfg: Config{StateDir: root, JailBase: filepath.Join(root, "jails"), StageRoot: filepath.Join(root, "stage")}}
	jail := filepath.Join(a.cfg.JailBase, "firecracker", "owner", "root")
	if err := os.MkdirAll(jail, 0750); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2*1024*1024)
	for i := range data {
		data[i] = byte(i % 251)
	}
	file := filepath.Join(jail, "rootfs.ext4")
	if err := os.WriteFile(file, data, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(jail, "workspace.ext4"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(64 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	_, dev, err := diskFilesystemAt(root)
	if err != nil {
		t.Fatal(err)
	}
	observe := func(reservations []store.DiskReservation) (runtime.DiskObservation, error) {
		return a.observeSettledDisk(reservations, map[uint64]*diskFilesystem{dev: {path: root}})
	}
	reservations := []store.DiskReservation{{VMID: "owner", DiskMiB: 66}, {VMID: "pending", DiskMiB: 66}}
	obs, err := observe(reservations)
	if err != nil {
		t.Fatal(err)
	}
	if obs.MaterializedMiB != 2 {
		t.Fatalf("sparse or pending disk credited: %+v", obs)
	}
	if obs.FreeMiB <= 0 {
		t.Fatalf("missing filesystem availability: %+v", obs)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	obs, err = observe(reservations)
	if err != nil {
		t.Fatal(err)
	}
	if obs.MaterializedMiB != 0 {
		t.Fatalf("reclaimed file remains credited: %+v", obs)
	}
	if err := os.Symlink(filepath.Join(root, "elsewhere"), file); err != nil {
		t.Fatal(err)
	}
	if _, err := observe(reservations); err == nil {
		t.Fatal("symlink observation accepted")
	}
}

func TestObserveDiskWithoutPrivilegedWitnessRetainsDebt(t *testing.T) {
	root := t.TempDir()
	a := &Adapter{cfg: Config{StateDir: root, JailBase: filepath.Join(root, "jails"), StageRoot: filepath.Join(root, "stage")}}
	jail := filepath.Join(a.cfg.JailBase, "firecracker", "owner", "root")
	if err := os.MkdirAll(jail, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jail, "rootfs.ext4"), make([]byte, 2<<20), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := a.ObserveDisk([]store.DiskReservation{{VMID: "owner", DiskMiB: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if got.MaterializedMiB != 0 {
		t.Fatalf("missing privileged witness credited mutable images: %+v", got)
	}
}

func TestObserveDiskPrivilegedInventoryTimeoutRetainsDebt(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "disk-inventory-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socket := filepath.Join(root, "p.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	stop := make(chan struct{})
	defer close(stop)
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- err
		if err == nil {
			defer conn.Close()
			<-stop
		}
	}()
	a := &Adapter{cfg: Config{StateDir: root, JailBase: filepath.Join(root, "jails"), StageRoot: filepath.Join(root, "stage")}, pc: &privd.Client{SocketPath: socket}}
	jail := filepath.Join(a.cfg.JailBase, "firecracker", "owner", "root")
	if err := os.MkdirAll(jail, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jail, "rootfs.ext4"), make([]byte, 2<<20), 0600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got, err := a.ObserveDisk([]store.DiskReservation{{VMID: "owner", DiskMiB: 2}})
	if err != nil || got.MaterializedMiB != 0 {
		t.Fatalf("unanswered inventory credited images: %+v %v", got, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("inventory held writer for %s", elapsed)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestObserveDiskBusyLifecycleReturnsConservativeCapacity(t *testing.T) {
	root := t.TempDir()
	a := &Adapter{cfg: Config{StateDir: root, JailBase: filepath.Join(root, "jails"), StageRoot: filepath.Join(root, "stage")}}
	a.launchMu.Lock()
	locked := true
	defer func() {
		if locked {
			a.launchMu.Unlock()
		}
	}()
	type result struct {
		credit int64
		free   int64
		err    error
	}
	observed := make(chan result, 1)
	go func() {
		observation, err := a.ObserveDisk([]store.DiskReservation{{VMID: "pending", DiskMiB: 64}})
		observed <- result{observation.MaterializedMiB, observation.FreeMiB, err}
	}()
	select {
	case got := <-observed:
		if got.err != nil || got.credit != 0 || got.free <= 0 {
			t.Fatalf("busy lifecycle observation must retain all disk debt: %+v", got)
		}
	case <-time.After(time.Second):
		a.launchMu.Unlock()
		locked = false
		<-observed
		t.Fatal("disk observation waited for the lifecycle lock")
	}
}

func TestObserveDiskSamplesSeparateRuntimeFilesystemBeforeImages(t *testing.T) {
	state := t.TempDir()
	var stateStat unix.Stat_t
	if err := unix.Stat(state, &stateStat); err != nil {
		t.Fatal(err)
	}
	other := ""
	for _, path := range []string{"/dev", "/proc", "/sys"} {
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err == nil && stat.Dev != stateStat.Dev {
			other = path
			break
		}
	}
	if other == "" {
		t.Skip("no second readable filesystem available")
	}
	for _, storage := range []string{"jail", "stage"} {
		for _, scenario := range []string{"empty", "pending", "busy"} {
			t.Run(storage+"/"+scenario, func(t *testing.T) {
				cfg := Config{StateDir: state, JailBase: filepath.Join(state, "jails"), StageRoot: filepath.Join(state, "stage")}
				// The pipeline normally creates these directories later. No files
				// are written to the second filesystem by this test.
				missing := filepath.Join(other, "vmobs-disk-layout-nonexistent", "runtime")
				if storage == "jail" {
					cfg.JailBase = missing
				} else {
					cfg.StageRoot = missing
				}
				a := &Adapter{cfg: cfg}
				var reservations []store.DiskReservation
				if scenario != "empty" {
					reservations = []store.DiskReservation{{VMID: "pending", DiskMiB: 64}}
				}
				if scenario == "busy" {
					a.launchMu.Lock()
					defer a.launchMu.Unlock()
				}
				got, err := a.ObserveDisk(reservations)
				if err != nil {
					t.Fatal(err)
				}
				var stateFS, otherFS unix.Statfs_t
				if err := unix.Statfs(state, &stateFS); err != nil {
					t.Fatal(err)
				}
				if err := unix.Statfs(other, &otherFS); err != nil {
					t.Fatal(err)
				}
				limit := min(int64(stateFS.Bavail)*int64(stateFS.Bsize), int64(otherFS.Bavail)*int64(otherFS.Bsize)) / (1024 * 1024)
				if got.MaterializedMiB != 0 || got.FreeMiB > limit+1 {
					t.Fatalf("unrelated filesystem authorized runtime capacity: got=%+v limit=%d", got, limit)
				}
			})
		}
	}
}

func TestManagerCapacityDuringBusyLifecycleAllowsUnrelatedWriter(t *testing.T) {
	root := t.TempDir()
	st, err := store.Open(filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := &Adapter{cfg: Config{StateDir: root, JailBase: filepath.Join(root, "runtime", "jails"), StageRoot: filepath.Join(root, "runtime", "stage")}}
	mgr, err := runtime.NewManager(st, a, runtime.ManagerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	a.launchMu.Lock()
	defer a.launchMu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	capacity := make(chan error, 1)
	go func() {
		_, err := mgr.Capacity(ctx)
		capacity <- err
	}()
	written := make(chan error, 1)
	go func() {
		_, err := st.CreateAnnotation(ctx, store.AnnotationInput{TargetRef: "host:local", Author: "disk-test", Text: "writer remains available during lifecycle work"})
		written <- err
	}()
	for _, result := range []<-chan error{capacity, written} {
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("capacity or unrelated writer waited for the lifecycle lock")
		}
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := mgr.Capacity(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled capacity request: %v", err)
	}
	if _, err := st.CreateAnnotation(ctx, store.AnnotationInput{TargetRef: "host:local", Author: "disk-test", Text: "canceled capacity did not retain writer"}); err != nil {
		t.Fatal(err)
	}
}
