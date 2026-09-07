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
	// dependsOn names a step whose failure makes this one's result meaningless.
	// Such a step is reported inconclusive rather than run, because the error it
	// would raise describes the missing prerequisite and not the gate under test.
	dependsOn string
	run       func() error
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
			// The verb privd runs for every VM, run rather than reimplemented.
			// `ip netns add` makes more than the one bind of /proc/self/ns/net
			// that is obvious from outside -- it also prepares /run/netns as a
			// mount point -- and a reimplementation would measure this author's
			// model of the command instead of the command. The namespace it
			// leaves behind is what the next step enters; that step deletes it.
			name:  "netns_create",
			needs: "`ip netns add`: bind mount of /proc/self/ns/net under /run/netns",
			run: func() error {
				return runIP("add", probeNetnsName())
			},
		},
		{
			// The other half of the verb pair: privd runs every network setup
			// command as `ip netns exec <ns> ...`, and entering a namespace
			// that way replaces /sys with a sysfs instance that describes it.
			// That remount is mediated, and it is not reachable from `ip netns
			// add` -- which is why granting the add's three mounts still left
			// every launch failing at network allocation.
			name:      "netns_exec",
			needs:     "`ip netns exec`: sysfs remount of /sys inside the namespace",
			dependsOn: "netns_create",
			run: func() error {
				ns := probeNetnsName()
				defer func() { _ = runIP("delete", ns) }()
				out, err := exec.Command("ip", "netns", "exec", ns, "true").CombinedOutput() //nolint:gosec // fixed argv
				if err != nil {
					return fmt.Errorf("ip netns exec %s true: %w: %s", ns, err, bytes.TrimSpace(out))
				}
				return nil
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
			name:      "pivot_root",
			needs:     "pivot_root(2)",
			dependsOn: "mount_propagation_slave",
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

// probeNetnsName is the namespace the two netns steps share. The pid is in it
// because the probe runs before privd takes its singleton lock, so two starting
// daemons must not collide on the name, and a leftover says which left it.
func probeNetnsName() string {
	return fmt.Sprintf("vmobs-jailprobe-%d", os.Getpid())
}

// runIP runs one `ip netns` verb and folds its own diagnostics into the error.
// The exit status alone carries no errno, so what iproute2 wrote to stderr is
// the only thing that says which of its several mounts the kernel refused.
func runIP(verb, ns string) error {
	out, err := exec.Command("ip", "netns", verb, ns).CombinedOutput() //nolint:gosec // fixed argv
	if err != nil {
		return fmt.Errorf("ip netns %s %s: %w: %s", verb, ns, err, bytes.TrimSpace(out))
	}
	return nil
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
	// No errno to read: a step that runs a command gets an exit status, and the
	// AppArmor denial that most often causes one is written only to the kernel
	// log. Send the operator there first rather than to a prerequisites list
	// that says nothing about which operation was refused.
	return "read the kernel's own answer: journalctl -k | grep 'apparmor=\"DENIED\"'; " +
		"then compare this host against the prerequisites in deploy/README.md. " +
		"The operation is one docs/design/container-boundary.md §5 measures"
}

// RunJailProbeChild is the child half. It runs every step in order and prints one
// machine-readable line to stdout when a step fails, so the parent can classify
// the errno it never sees. Returns the process exit code.
func RunJailProbeChild(dir string, stdout, stderr *os.File) int {
	rc := 0
	failed := make(map[string]bool)
	for _, step := range jailProbeSteps(dir) {
		// pivot_root(2) after a failed mount_propagation_slave raises an EINVAL
		// that says nothing about pivot_root; `ip netns exec` on a namespace that
		// was never created reports only that it is missing. Neither answers the
		// question the step was asked, so neither is run.
		if step.dependsOn != "" && failed[step.dependsOn] {
			fmt.Fprintf(stderr, "vmobs-privd: jail probe: %s (%s): inconclusive, %s failed first\n",
				step.name, step.needs, step.dependsOn)
			continue
		}
		err := step.run()
		if err == nil {
			continue
		}
		failed[step.name] = true
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			errno = 0
		}
		fmt.Fprintf(stdout, "step=%s errno=%d\n", step.name, int(errno))
		fmt.Fprintf(stderr, "vmobs-privd: jail probe: %s (%s): %v\n", step.name, step.needs, err)
		rc = 1
	}
	return rc
}

// ProbeJailSyscalls runs the probe in a child process holding its own mount and
// network namespaces, and returns nil only if every step succeeded.
//
// privd calls this before it binds its socket. The jailer's privileged work
// happens several stages into a launch -- after admission, after the network is
// allocated, after the stage directory is filled -- so a container missing one
// flag would otherwise spend a VM's worth of resources to produce a failure deep
// in the runtime. Refusing to serve is the honest form of that answer.
func ProbeJailSyscalls(jailBase string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("jail probe: locate this binary: %w", err)
	}
	// The scratch directory sits where the jailer's chroots sit, at the same
	// depth, because the AppArmor rules that permit the jailer's self-bind and
	// its pivot_root name that path shape exactly. A probe run anywhere else
	// measures a grant no launch will ever use: it would pass on a host where
	// /srv/vmobs/jail was denied, and the operator would meet that denial one
	// launch later, from inside the jailer, with a VM's worth of work spent.
	if err := EnsureJailBase(jailBase); err != nil {
		return fmt.Errorf("jail probe: %w", err)
	}
	dir, err := os.MkdirTemp(filepath.Join(jailBase, "firecracker"), "jailprobe-")
	if err != nil {
		return fmt.Errorf("jail probe: scratch directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	// One level further down, because the pivot_root rule names <id>/root and
	// nothing shallower.
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		return fmt.Errorf("jail probe: scratch root: %w", err)
	}

	cmd := exec.Command(self, JailProbeChildArg, root)
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
	failures := parseJailProbeFailures(stdout.String())
	detail := strings.TrimSpace(stderr.String())
	if len(failures) == 0 {
		return fmt.Errorf("jail probe: child failed without naming a step: %w; stderr: %s", runErr, detail)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "jail probe: %d of %d steps failed", len(failures), len(jailProbeSteps("")))
	for _, f := range failures {
		fmt.Fprintf(&b, "\n  %s: %s", f.step, jailProbeRemedy(f.step, f.errno))
	}
	fmt.Fprintf(&b, "\n%s", detail)
	return errors.New(b.String())
}

// jailProbeFailure is one step the child could not complete.
type jailProbeFailure struct {
	step  string
	errno error
}

// parseJailProbeFailures reads the child's machine-readable output, one line per
// failed step. Lines are parsed separately because a host can be missing several
// things at once, and reading the whole output as one set of fields kept only the
// last step named -- an operator fixing that one, rebuilding, and meeting the next.
// A line that names no step is skipped; if none does, the caller says so rather
// than guessing.
func parseJailProbeFailures(out string) []jailProbeFailure {
	var failures []jailProbeFailure
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var f jailProbeFailure
		for _, field := range strings.Fields(line) {
			name, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			switch name {
			case "step":
				f.step = value
			case "errno":
				if n, convErr := strconv.Atoi(value); convErr == nil && n != 0 {
					f.errno = syscall.Errno(n)
				}
			}
		}
		if f.step != "" {
			failures = append(failures, f)
		}
	}
	return failures
}
