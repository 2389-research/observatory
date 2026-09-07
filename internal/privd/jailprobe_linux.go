// ABOUTME: Startup self-check: performs the jailer's privileged operations in a
// ABOUTME: throwaway namespace so a misconfigured container fails before allocation.

//go:build linux

package privd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// JailProbeChildArg is the first argument of the probe child's argv. The child
// half of the probe runs in its own mount and network namespaces, which is the
// only safe place to call pivot_root: done in this process it would move privd's
// own root.
const JailProbeChildArg = "probe-jail-child"

// JailProbeChildArgs reports whether args (os.Args[1:]) is the probe child's
// exact argv, and returns the scratch directory it was given. A privd started
// with an operator's ordinary flags must never fall into the child path, so the
// match is on the whole argv, not on a flag appearing anywhere in it.
func JailProbeChildArgs(args []string) (dir string, ok bool) {
	if len(args) != 2 || args[0] != JailProbeChildArg {
		return "", false
	}
	return args[1], true
}

// jailProbeStep is one privileged operation the jailer performs on the way to
// exec'ing firecracker. The set and their order are docs/design/container-boundary.md
// §5 turned into code: the kernel applies capabilities, then AppArmor, then
// seccomp, and each gate is invisible until the one before it is open.
type jailProbeStep struct {
	name  string
	needs string // the kernel facility, for the failure message
	run   func() error
}

// jailProbeSteps builds the probe against a scratch directory the caller owns.
// dir is pivoted into and never written back to; the child's mount namespace
// dies with the child, so nothing here needs undoing.
func jailProbeSteps(dir string) []jailProbeStep {
	return []jailProbeStep{
		{
			name:  "mount_propagation_slave",
			needs: "mount(2) with MS_SLAVE|MS_REC on /",
			run: func() error {
				return unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, "")
			},
		},
		{
			// What `ip netns add` does after unshare(CLONE_NEWNET): bind the
			// caller's net namespace onto a file so it has a name. privd runs
			// that verb for every VM. The bind target is inside the probe's own
			// scratch directory rather than /run/netns, so a probe that dies
			// mid-flight leaves no named namespace behind.
			name:  "netns_create",
			needs: "bind mount of /proc/self/ns/net",
			run: func() error {
				target := filepath.Join(dir, "netns")
				f, err := os.OpenFile(target, os.O_CREATE|os.O_RDONLY|os.O_EXCL, 0o600)
				if err != nil {
					return err
				}
				f.Close()
				return unix.Mount("/proc/self/ns/net", target, "", unix.MS_BIND, "")
			},
		},
		{
			// `ip tuntap add dev tap0 mode tap` in one ioctl. The child holds its
			// own network namespace, so the interface exists only for as long as
			// the probe does.
			name:  "tap_create",
			needs: "/dev/net/tun with TUNSETIFF",
			run: func() error {
				fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
				if err != nil {
					return err
				}
				defer unix.Close(fd)
				ifr, err := unix.NewIfreq("vmobsprobe0")
				if err != nil {
					return err
				}
				ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
				return unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
			},
		},
		{
			// The jailer's own sequence: bind the chroot onto itself so it is a
			// mount point, chdir into it, pivot_root(".", "."), then detach the
			// old root. Docker's default seccomp profile has pivot_root in no
			// allow group, so this is the step that fails with everything else
			// already open.
			name:  "pivot_root",
			needs: "pivot_root(2)",
			run: func() error {
				if err := unix.Mount(dir, dir, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
					return err
				}
				if err := unix.Chdir(dir); err != nil {
					return err
				}
				if err := unix.PivotRoot(".", "."); err != nil {
					return err
				}
				return unix.Unmount(".", unix.MNT_DETACH)
			},
		},
	}
}

// jailProbeRemedy turns a step and its errno into the one change an operator
// makes next. The errno is load-bearing: on a mount-family call EACCES is
// AppArmor refusing the operation and EPERM is the kernel refusing the caller,
// and those are different files to edit. Docker's default seccomp profile
// answers with EPERM (defaultAction SCMP_ACT_ERRNO, defaultErrnoRet 1), which is
// why pivot_root reads EPERM as seccomp rather than as a missing capability --
// by that step the capability has already been proven by the steps before it.
func jailProbeRemedy(step string, err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		errno = 0
	}
	const (
		// EACCES says an AppArmor profile refused this and nothing more; the
		// two profiles it could be need opposite fixes, and only the kernel's
		// denial line names which one is in force.
		apparmor = "an AppArmor profile refused this -- read which one: " +
			"journalctl -k | grep 'apparmor=\"DENIED\"'. " +
			"If it names docker-default, load ours and use it: " +
			"apparmor_parser -r -W deploy/apparmor/vmobs-jailer, then run the container with " +
			"--security-opt apparmor=vmobs-jailer. " +
			"If it names vmobs-jailer, that profile is missing a rule for the operation " +
			"the denial line reports"
		seccomp  = "run the container with --security-opt seccomp=deploy/seccomp/vmobs-jailer.json"
		sysadmin = "run the container with --cap-add SYS_ADMIN"
		netadmin = "run the container with --cap-add NET_ADMIN"
		tundev   = "run the container with --device /dev/net/tun"
	)
	switch {
	case errno == unix.EACCES:
		return apparmor
	case step == "pivot_root" && errno == unix.EPERM:
		return seccomp
	case step == "tap_create" && errno == unix.ENOENT:
		return tundev
	case step == "tap_create" && errno == unix.EPERM:
		return netadmin + " and --device /dev/net/tun"
	case errno == unix.EPERM:
		return sysadmin
	}
	return "compare this host against the prerequisites in deploy/README.md; " +
		"the operation is one docs/design/container-boundary.md §5 measures"
}

// RunJailProbeChild is the child half. It runs every step in order and prints one
// machine-readable line to stdout when a step fails, so the parent can classify
// the errno it never sees. Returns the process exit code.
func RunJailProbeChild(dir string, stdout, stderr *os.File) int {
	for _, step := range jailProbeSteps(dir) {
		err := step.run()
		if err == nil {
			continue
		}
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			errno = 0
		}
		fmt.Fprintf(stdout, "step=%s errno=%d\n", step.name, int(errno))
		fmt.Fprintf(stderr, "vmobs-privd: jail probe: %s (%s): %v\n", step.name, step.needs, err)
		return 1
	}
	return 0
}

// ProbeJailSyscalls runs the probe in a child process holding its own mount and
// network namespaces, and returns nil only if every step succeeded.
//
// privd calls this before it binds its socket. The jailer's privileged work
// happens several stages into a launch -- after admission, after the network is
// allocated, after the stage directory is filled -- so a container missing one
// flag would otherwise spend a VM's worth of resources to produce a failure deep
// in the runtime. Refusing to serve is the honest form of that answer.
func ProbeJailSyscalls() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jail probe: locate this binary: %w", err)
	}
	dir, err := os.MkdirTemp("", "vmobs-jailprobe-")
	if err != nil {
		return fmt.Errorf("jail probe: scratch directory: %w", err)
	}
	defer os.RemoveAll(dir)

	cmd := exec.Command(self, JailProbeChildArg, dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Unshareflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		// The child never ran. Go unshares the namespaces and marks / private
		// inside the child before exec (syscall/exec_linux.go), so a refusal here
		// is the same capability-or-AppArmor gate the first step measures, just
		// reached one syscall earlier.
		return fmt.Errorf("jail probe: could not enter a private mount namespace: %w; %s",
			err, jailProbeRemedy("mount_propagation_slave", err))
	}
	runErr := cmd.Wait()
	if runErr == nil {
		return nil
	}
	step, errno := parseJailProbeFailure(stdout.String())
	detail := strings.TrimSpace(stderr.String())
	if step == "" {
		return fmt.Errorf("jail probe: child failed without naming a step: %w; stderr: %s", runErr, detail)
	}
	return fmt.Errorf("jail probe: %s failed: %s; %s", step, detail, jailProbeRemedy(step, errno))
}

// parseJailProbeFailure reads the child's one machine line. An unparseable line
// yields an empty step, which the caller reports as such rather than guessing.
func parseJailProbeFailure(out string) (step string, err error) {
	for _, field := range strings.Fields(strings.TrimSpace(out)) {
		name, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch name {
		case "step":
			step = value
		case "errno":
			if n, convErr := strconv.Atoi(value); convErr == nil && n != 0 {
				err = syscall.Errno(n)
			}
		}
	}
	return step, err
}
