// ABOUTME: LoadBootConfig: mounts the config device ext4 read-only then delegates to LoadBootConfigDir.
// ABOUTME: Linux-only; uses unix.Mount/Unmount from x/sys/unix.
//go:build linux

package guest

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// LoadBootConfig mounts the ext4 device at mountpoint read-only, loads the
// boot config from the mountpoint, then unmounts. The mount is best-effort
// on unmount failure (logged, not fatal) — the config has already been read.
func LoadBootConfig(device, mountpoint string) (*BootConfig, error) {
	if err := unix.Mount(device, mountpoint, "ext4", unix.MS_RDONLY, ""); err != nil {
		return nil, fmt.Errorf("mount %s at %s: %w", device, mountpoint, err)
	}
	cfg, loadErr := LoadBootConfigDir(mountpoint)
	// Unmount even on load error; ignore unmount failure (best-effort cleanup).
	_ = unix.Unmount(mountpoint, 0)
	if loadErr != nil {
		return nil, loadErr
	}
	return cfg, nil
}
