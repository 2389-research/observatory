// ABOUTME: Refresh disk headroom under the same lock as image creation and reclamation.
// ABOUTME: Credit physical guest image blocks only against their SQLite reservation.
package jailer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/store"
	"golang.org/x/sys/unix"
)

// ObserveDisk is called with a live SQLite writer snapshot. No adapter method
// holding launchMu may acquire that writer. A busy lifecycle returns free space
// without materialization credit, retaining all reservation debt. Otherwise the
// lock prevents images disappearing between allocated-block and free-space
// samples; guest writes can only make that observation more conservative.
func (a *Adapter) ObserveDisk(reservations []store.DiskReservation) (runtime.DiskObservation, error) {
	var observation runtime.DiskObservation
	// Each configured filesystem must cover the outstanding promises. Credit
	// belongs only to the filesystem containing the reserved guest image.
	filesystems := map[uint64]*diskFilesystem{}
	for _, path := range []string{a.cfg.StateDir, a.cfg.JailBase, a.cfg.StageRoot, filepath.Join(a.cfg.JailBase, "firecracker")} {
		if path == "" {
			return observation, fmt.Errorf("disk runtime path is required")
		}
		dir, dev, err := diskFilesystemAt(path)
		if err != nil {
			return observation, err
		}
		filesystems[dev] = &diskFilesystem{path: dir}
	}
	if !a.launchMu.TryLock() {
		return observeDiskFilesystems(filesystems)
	}
	defer a.launchMu.Unlock()
	inventory, ok := a.pc.(interface {
		NetworkLeases(context.Context) (map[string]string, error)
	})
	if !ok {
		return observeDiskFilesystems(filesystems)
	}
	// The adapter lock cannot exclude work still executing inside privd after
	// a lost reply. Its inventory refuses every busy, pending or unknown
	// mutation. A settled response plus this lock excludes late host deletion
	// and new adapter mutations through the final free-space sample.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := inventory.NetworkLeases(ctx); err != nil {
		return observeDiskFilesystems(filesystems)
	}
	return a.observeSettledDisk(reservations, filesystems)
}

// observeSettledDisk requires lifecycle exclusion and settled privileged work.
// Physical accounting is separate so filesystem tests need no invented authority.
func (a *Adapter) observeSettledDisk(reservations []store.DiskReservation, filesystems map[uint64]*diskFilesystem) (runtime.DiskObservation, error) {
	var observation runtime.DiskObservation
	seen := map[[2]uint64]bool{}
	for _, reservation := range reservations {
		if reservation.VMID == "" || reservation.VMID == "." || reservation.VMID == ".." || strings.ContainsAny(reservation.VMID, "/\\") {
			return observation, fmt.Errorf("invalid disk reservation owner")
		}
		allocated := map[uint64]int64{}
		for _, name := range []string{"rootfs.ext4", "workspace.ext4"} {
			path := filepath.Join(a.cfg.JailBase, "firecracker", reservation.VMID, "root", name)
			// Every guest-controlled path component must be an ordinary directory or
			// file, never a symlink whose target could inflate materialization credit.
			for component := path; component != filepath.Clean(a.cfg.JailBase); component = filepath.Dir(component) {
				info, err := os.Lstat(component)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					return observation, fmt.Errorf("observe guest disk: %w", err)
				}
				if info.Mode()&os.ModeSymlink != 0 {
					return observation, fmt.Errorf("guest disk path contains symlink: %s", component)
				}
			}
			var stat unix.Stat_t
			if err := unix.Lstat(path, &stat); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return observation, fmt.Errorf("observe guest disk: %w", err)
			}
			if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
				return observation, fmt.Errorf("guest disk is not a private regular file: %s", path)
			}
			dev := uint64(stat.Dev)
			if filesystems[dev] == nil {
				return observation, fmt.Errorf("guest disk is on an unconfigured filesystem")
			}
			inode := [2]uint64{dev, uint64(stat.Ino)}
			if seen[inode] {
				continue
			}
			seen[inode] = true
			allocated[dev] += stat.Blocks * 512
		}
		for dev, bytes := range allocated {
			filesystems[dev].credit += min(bytes/(1024*1024), reservation.DiskMiB)
		}
	}
	// Sample free last. Writes after the block sample only reduce headroom.
	return observeDiskFilesystems(filesystems)
}

type diskFilesystem struct {
	path   string
	credit int64
}

func observeDiskFilesystems(filesystems map[uint64]*diskFilesystem) (runtime.DiskObservation, error) {
	var result runtime.DiskObservation
	first := true
	for _, disk := range filesystems {
		var fs unix.Statfs_t
		if err := unix.Statfs(disk.path, &fs); err != nil {
			return result, fmt.Errorf("observe free disk: %w", err)
		}
		free := int64(fs.Bavail) * int64(fs.Bsize) / (1024 * 1024)
		if first || free+disk.credit < result.FreeMiB+result.MaterializedMiB {
			result = runtime.DiskObservation{FreeMiB: free, MaterializedMiB: disk.credit}
			first = false
		}
	}
	return result, nil
}

// Missing runtime directories inherit their nearest existing parent's filesystem.
func diskFilesystemAt(path string) (string, uint64, error) {
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		var stat unix.Stat_t
		err := unix.Stat(dir, &stat)
		if err == nil {
			if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
				return "", 0, fmt.Errorf("disk runtime path %s is not a directory", dir)
			}
			return dir, uint64(stat.Dev), nil
		}
		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(dir) == dir {
			return "", 0, fmt.Errorf("observe runtime disk path %s: %w", path, err)
		}
	}
}
