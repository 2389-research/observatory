// ABOUTME: darwin memory probe: hw.memsize via sysctl.
package runtime

import "golang.org/x/sys/unix"

func hostMemoryMiB() (int64, error) {
	bytes, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return 0, err
	}
	return int64(bytes) / (1024 * 1024), nil
}
