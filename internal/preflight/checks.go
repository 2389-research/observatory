// ABOUTME: Portable preflight checks — all build tags, no KVM ioctls here.
// ABOUTME: Each function returns a single Check with evidence for the operator.
package preflight

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/2389-research/observatory/internal/lock"
)

// --- fc_binaries ---

// loadLock reads runtime.lock.json once per report, so every check that
// consults it describes the same file at the same moment. Three answers:
// (nil, nil) when no lock is configured or none is there, (nil, err) when one is
// there and unreadable, and the lock otherwise. A path with nothing behind it is
// the same operator answer as no lock at all — create one — and not the "this
// file is damaged" answer, which would send them looking for a tampered host.
func (r *Runner) loadLock() (*lock.Lock, error) {
	if r.cfg.LockPath == "" {
		return nil, nil
	}
	l, err := lock.Load(r.cfg.LockPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return l, nil
}

// checkFCBinaries verifies the installed firecracker and jailer against the
// digests pinned in runtime.lock.json, reading that file on every run. The
// pins and the binaries are read within microseconds of each other, so the
// verdict is about one host at one moment. Holding a lock parsed at daemon
// startup instead would report a mismatch for every legitimate re-pin —
// scripts/aibox03/setup.sh installs a release and re-pins in one step — and the
// jailer adapter turns any failing check into an UnavailableError, so the wrong
// answer refuses every VM creation until someone restarts the daemon.
func (r *Runner) checkFCBinaries(l *lock.Lock, loadErr error) Check {
	id := "fc_binaries"

	if loadErr != nil {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  "runtime lock load error",
			Evidence: []string{loadErr.Error()},
			Remediation: &Remediation{
				Cause:  "lock_load_error",
				Action: "re-run scripts/aibox03/setup.sh to install firecracker and re-pin runtime.lock.json",
			},
		}
	}
	if l == nil {
		evidence := "runtime.lock.json absent or not configured"
		if r.cfg.LockPath != "" {
			evidence = "runtime.lock.json absent: " + r.cfg.LockPath
		}
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  "no runtime lock",
			Evidence: []string{evidence},
			Remediation: &Remediation{
				Cause:  "lock_absent",
				Action: "run scripts/aibox03/setup.sh to install firecracker and create runtime.lock.json",
			},
		}
	}

	// Check only binary components (fc + jailer) for unpinned; artifact pinning
	// is a separate concern. lock.Unpinned() includes artifacts, so filter.
	allUnpinned := l.Unpinned()
	var binaryUnpinned []string
	for _, u := range allUnpinned {
		if u == "firecracker" || u == "jailer" {
			binaryUnpinned = append(binaryUnpinned, u)
		}
	}
	if len(binaryUnpinned) > 0 {
		return Check{
			ID:       id,
			Status:   StatusWarn,
			Summary:  fmt.Sprintf("unpinned binaries: %s", strings.Join(binaryUnpinned, ", ")),
			Evidence: []string{fmt.Sprintf("binaries without a sha256 pin: %s", strings.Join(binaryUnpinned, ", "))},
		}
	}

	mismatches := l.VerifyBinaries()
	if len(mismatches) > 0 {
		var evidence []string
		var subjects []string
		for _, m := range mismatches {
			evidence = append(evidence, m.Describe())
			subjects = append(subjects, m.Subject)
		}
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("binary mismatch: %s", strings.Join(subjects, ", ")),
			Evidence: evidence,
			Remediation: &Remediation{
				Cause:  "binary_mismatch",
				Action: "run scripts/aibox03/setup.sh to reinstall the pinned firecracker release",
			},
		}
	}

	return Check{
		ID:      id,
		Status:  StatusPass,
		Summary: "firecracker and jailer binaries verified",
		Evidence: []string{
			"firecracker: " + l.Firecracker.InstallPath,
			"jailer: " + l.Jailer.InstallPath,
			"pinned by: " + r.cfg.LockPath,
		},
	}
}

// --- kernel_tuple ---

func (r *Runner) checkKernelTuple(l *lock.Lock) Check {
	id := "kernel_tuple"
	release := kernelRelease()

	if l == nil {
		return Check{
			ID:       id,
			Status:   StatusWarn,
			Summary:  "no runtime lock; cannot verify kernel version",
			Evidence: []string{"kernel: " + release},
		}
	}

	minKernel := l.HostSupport.MinKernel
	if minKernel == "" {
		return Check{
			ID:       id,
			Status:   StatusWarn,
			Summary:  "min_kernel not set in runtime lock",
			Evidence: []string{"kernel: " + release},
		}
	}

	ok, err := kernelMeetsMin(release, minKernel)
	if err != nil {
		return Check{
			ID:       id,
			Status:   StatusWarn,
			Summary:  fmt.Sprintf("cannot parse kernel version: %v", err),
			Evidence: []string{"kernel: " + release, "min_kernel: " + minKernel},
		}
	}
	if !ok {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("kernel %s is below minimum %s", release, minKernel),
			Evidence: []string{"kernel: " + release, "min_kernel: " + minKernel},
			Remediation: &Remediation{
				Cause:  "kernel_too_old",
				Action: "upgrade the host kernel to at least " + minKernel,
			},
		}
	}

	return Check{
		ID:       id,
		Status:   StatusPass,
		Summary:  fmt.Sprintf("kernel %s meets minimum %s", release, minKernel),
		Evidence: []string{"kernel: " + release, "min_kernel: " + minKernel},
	}
}

// kernelMeetsMin compares major.minor numerically.
// It parses the first two dot-separated components of each string.
func kernelMeetsMin(release, minKernel string) (bool, error) {
	rMaj, rMin, err := parseMajorMinor(release)
	if err != nil {
		return false, fmt.Errorf("release %q: %w", release, err)
	}
	mMaj, mMin, err := parseMajorMinor(minKernel)
	if err != nil {
		return false, fmt.Errorf("min_kernel %q: %w", minKernel, err)
	}
	if rMaj != mMaj {
		return rMaj > mMaj, nil
	}
	return rMin >= mMin, nil
}

func parseMajorMinor(s string) (int, int, error) {
	// Strip leading v if present.
	s = strings.TrimPrefix(s, "v")
	parts := strings.SplitN(s, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("need at least major.minor in %q", s)
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("major %q: %w", parts[0], err)
	}
	// minor may have a trailing suffix like "0-134-generic"; take up to first non-digit.
	minStr := parts[1]
	for i, c := range minStr {
		if c < '0' || c > '9' {
			minStr = minStr[:i]
			break
		}
	}
	min, err := strconv.Atoi(minStr)
	if err != nil {
		return 0, 0, fmt.Errorf("minor %q: %w", parts[1], err)
	}
	return maj, min, nil
}

// --- cgroup_v2 ---

func (r *Runner) checkCgroupV2() Check {
	id := "cgroup_v2"
	path := "/sys/fs/cgroup/cgroup.controllers"
	data, err := os.ReadFile(path)
	if err != nil {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  "cgroup v2 not detected",
			Evidence: []string{fmt.Sprintf("read %s: %v", path, err)},
			Remediation: &Remediation{
				Cause:  "cgroup_v2_absent",
				Action: "boot with systemd.unified_cgroup_hierarchy=1 or upgrade to a cgroup v2 kernel",
			},
		}
	}
	controllers := strings.TrimSpace(string(data))
	return Check{
		ID:       id,
		Status:   StatusPass,
		Summary:  "cgroup v2 unified hierarchy present",
		Evidence: []string{fmt.Sprintf("controllers: %s", controllers)},
	}
}

// --- net_prereqs ---

func (r *Runner) checkNetPrereqs() Check {
	id := "net_prereqs"
	var evidence []string
	var missing []string

	for _, tool := range []string{"ip", "nft"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			missing = append(missing, tool)
			evidence = append(evidence, fmt.Sprintf("%s: not found", tool))
		} else {
			evidence = append(evidence, fmt.Sprintf("%s: %s", tool, p))
		}
	}

	if len(missing) > 0 {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("missing network tools: %s", strings.Join(missing, ", ")),
			Evidence: evidence,
			Remediation: &Remediation{
				Cause:  "network_tools_absent",
				Action: "install iproute2 and nftables (apt-get install iproute2 nftables)",
			},
		}
	}

	return Check{
		ID:       id,
		Status:   StatusPass,
		Summary:  "ip and nft available",
		Evidence: evidence,
	}
}

// --- resources ---

func (r *Runner) checkResources() Check {
	id := "resources"
	var evidence []string
	failing := false

	// Memory: read /proc/meminfo.
	memAvailKiB, err := readMemAvailable(r.cfg.ProcRoot)
	if err != nil {
		evidence = append(evidence, fmt.Sprintf("meminfo read error: %v", err))
		failing = true
	} else {
		memMiB := memAvailKiB / 1024
		evidence = append(evidence, fmt.Sprintf("mem_available_mib: %d", memMiB))
		if memMiB < 512 {
			failing = true
			evidence = append(evidence, "warning: less than 512 MiB available")
		}
	}

	// Disk: statfs on DataDir.
	diskFreeMiB, err := diskFreeStatfs(r.cfg.DataDir)
	if err != nil {
		evidence = append(evidence, fmt.Sprintf("statfs(%s) error: %v", r.cfg.DataDir, err))
		failing = true
	} else {
		evidence = append(evidence, fmt.Sprintf("disk_free_mib: %d (at %s)", diskFreeMiB, r.cfg.DataDir))
		if diskFreeMiB < 1024 {
			failing = true
			evidence = append(evidence, "warning: less than 1 GiB free on state disk")
		}
	}

	if failing {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  "resource check failed",
			Evidence: evidence,
			Remediation: &Remediation{
				Cause:  "insufficient_resources",
				Action: "free memory or disk space on the host",
			},
		}
	}

	return Check{
		ID:       id,
		Status:   StatusPass,
		Summary:  "memory and disk sufficient",
		Evidence: evidence,
	}
}

// readMemAvailable reads MemAvailable from the /proc/meminfo-format file.
func readMemAvailable(procRoot string) (int64, error) {
	path := procRoot + "/meminfo"
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		// "MemAvailable:    12345678 kB"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("unexpected MemAvailable line: %q", line)
		}
		v, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse MemAvailable %q: %w", fields[1], err)
		}
		return v, nil
	}
	return 0, fmt.Errorf("MemAvailable not found in %s", path)
}

// --- dir_permissions ---

func (r *Runner) checkDirPermissions() Check {
	id := "dir_permissions"

	info, err := os.Stat(r.cfg.DataDir)
	if err != nil {
		return Check{
			ID:       id,
			Status:   StatusFail,
			Summary:  fmt.Sprintf("data directory does not exist: %s", r.cfg.DataDir),
			Evidence: []string{err.Error()},
			Remediation: &Remediation{
				Cause:  "dir_absent",
				Action: "create the data directory and ensure the daemon user owns it",
			},
		}
	}

	mode := info.Mode().Perm()
	worldWritable := mode&0o002 != 0
	if worldWritable {
		return Check{
			ID:      id,
			Status:  StatusFail,
			Summary: "data directory is world-writable",
			Evidence: []string{
				fmt.Sprintf("path: %s", r.cfg.DataDir),
				fmt.Sprintf("mode: %o", mode),
			},
			Remediation: &Remediation{
				Cause:  "world_writable",
				Action: "chmod o-w " + r.cfg.DataDir,
			},
		}
	}

	return Check{
		ID:      id,
		Status:  StatusPass,
		Summary: "data directory exists and is not world-writable",
		Evidence: []string{
			fmt.Sprintf("path: %s", r.cfg.DataDir),
			fmt.Sprintf("mode: %04o", mode),
		},
	}
}

// --- api_binding ---

func (r *Runner) checkAPIBinding() Check {
	id := "api_binding"

	// The safe configurations, mirroring config.Validate:
	//   loopback_only + require_auth=false  → pass (host-ACL trust, dev)
	//   loopback_only + require_auth=true   → pass (unreachable off-host AND credentialed)
	//   https + require_auth=true           → pass
	// Anything else — an https binding that asks for no credential, or a mode
	// this daemon does not serve — is what the doctor reports.
	apiMode := r.cfg.APIMode
	requireAuth := r.cfg.RequireAuth

	switch {
	case apiMode == "loopback_only" && !requireAuth:
		return Check{
			ID:      id,
			Status:  StatusPass,
			Summary: "loopback-only mode with host-ACL trust (dev mode)",
			Evidence: []string{
				"mode: loopback_only",
				"require_authentication: false",
			},
		}
	case apiMode == "loopback_only" && requireAuth:
		return Check{
			ID:      id,
			Status:  StatusPass,
			Summary: "loopback-only mode with authentication required",
			Evidence: []string{
				"mode: loopback_only",
				"require_authentication: true",
			},
		}
	case apiMode == "https" && requireAuth:
		return Check{
			ID:      id,
			Status:  StatusPass,
			Summary: "HTTPS mode with authentication required",
			Evidence: []string{
				"mode: https",
				"require_authentication: true",
			},
		}
	default:
		return Check{
			ID:      id,
			Status:  StatusFail,
			Summary: fmt.Sprintf("unsafe API binding: mode=%s require_auth=%v", apiMode, requireAuth),
			Evidence: []string{
				fmt.Sprintf("mode: %s", apiMode),
				fmt.Sprintf("require_authentication: %v", requireAuth),
			},
			Remediation: &Remediation{
				Cause:  "insecure_binding",
				Action: "use loopback_only (dev) or https+authentication (production)",
			},
		}
	}
}

// --- guest_channel ---

// checkGuestChannel is the platform-dispatched guest_channel check.
// On Linux: dials the privd socket and stats the stage root (see checks_linux.go).
// On non-Linux: returns not_implemented honestly.
func (r *Runner) checkGuestChannel() Check {
	return guestChannelCheck(r.cfg)
}
