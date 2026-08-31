//go:build unix

// ABOUTME: disk-free probe using unix.Statfs; shared by darwin and linux.
package runtime

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func diskFreeMiB(path string) (int64, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", path, err)
	}
	freeBytes := int64(fs.Bavail) * int64(fs.Bsize)
	return freeBytes / (1024 * 1024), nil
}
