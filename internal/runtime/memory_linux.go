// ABOUTME: linux memory probe: MemTotal from /proc/meminfo.
package runtime

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func hostMemoryMiB() (int64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("open /proc/meminfo: %w", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		// "MemTotal:    16384000 kB"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("unexpected MemTotal format: %q", line)
		}
		kib, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse MemTotal %q: %w", fields[1], err)
		}
		return kib / 1024, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read /proc/meminfo: %w", err)
	}
	return 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
}
