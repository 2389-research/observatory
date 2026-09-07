// ABOUTME: Checks the shipped container security profiles still say what
// ABOUTME: deploy/README.md claims: default-deny seccomp, no blanket AppArmor deny.
package deploy_test

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

const (
	seccompPath  = "../../deploy/seccomp/vmobs-jailer.json"
	apparmorPath = "../../deploy/apparmor/vmobs-jailer"
)

// seccompProfile is the subset of the OCI seccomp schema these checks read.
type seccompProfile struct {
	DefaultAction   string `json:"defaultAction"`
	DefaultErrnoRet *int   `json:"defaultErrnoRet"`
	Syscalls        []struct {
		Names    []string `json:"names"`
		Action   string   `json:"action"`
		Includes struct {
			Caps []string `json:"caps"`
		} `json:"includes"`
	} `json:"syscalls"`
}

func loadSeccomp(t *testing.T) seccompProfile {
	t.Helper()
	raw, err := os.ReadFile(seccompPath)
	if err != nil {
		t.Fatalf("read %s: %v", seccompPath, err)
	}
	var p seccompProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("parse %s: %v", seccompPath, err)
	}
	return p
}

// TestSeccompDeniesByDefault: the profile is a modification of Docker's default,
// not a permissive profile that happens to allow pivot_root. If the default
// action ever became ALLOW, every check below would still pass while the
// container ran with no syscall filtering at all.
func TestSeccompDeniesByDefault(t *testing.T) {
	p := loadSeccomp(t)
	if p.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("defaultAction = %q, want SCMP_ACT_ERRNO", p.DefaultAction)
	}
	// EPERM, and it is load-bearing: privd's startup probe reads the errno to
	// tell seccomp (EPERM) from AppArmor (EACCES) and name the right flag.
	if p.DefaultErrnoRet == nil || *p.DefaultErrnoRet != 1 {
		t.Errorf("defaultErrnoRet = %v, want 1 (EPERM); the probe's remedy advice reads this errno", p.DefaultErrnoRet)
	}
}

// TestPivotRootIsGatedOnSysAdmin: pivot_root is allowed in exactly one group,
// that group requires CAP_SYS_ADMIN, and it is the group Docker already ships
// for CAP_SYS_ADMIN holders -- proven by the company it keeps. Adding a fresh
// ungated ALLOW group would hand pivot_root to every container that used this
// profile regardless of its capabilities.
func TestPivotRootIsGatedOnSysAdmin(t *testing.T) {
	p := loadSeccomp(t)

	var groups []int
	for i, g := range p.Syscalls {
		if slices.Contains(g.Names, "pivot_root") {
			groups = append(groups, i)
		}
	}
	if len(groups) != 1 {
		t.Fatalf("pivot_root appears in %d syscall groups, want exactly 1", len(groups))
	}
	g := p.Syscalls[groups[0]]

	if g.Action != "SCMP_ACT_ALLOW" {
		t.Errorf("pivot_root group action = %q, want SCMP_ACT_ALLOW", g.Action)
	}
	if !slices.Contains(g.Includes.Caps, "CAP_SYS_ADMIN") {
		t.Errorf("pivot_root group includes.caps = %v, want it to require CAP_SYS_ADMIN", g.Includes.Caps)
	}
	// The jailer's other mount-family calls. Their presence identifies this as
	// the upstream CAP_SYS_ADMIN group rather than one added alongside it.
	for _, name := range []string{"mount", "umount2", "setns", "unshare", "move_mount"} {
		if !slices.Contains(g.Names, name) {
			t.Errorf("pivot_root group does not contain %q; this is not Docker's CAP_SYS_ADMIN group", name)
		}
	}
}

// TestAppArmorAllowsTheJailerAndNothingMore: the AppArmor half of the same
// story. docker-default carries a blanket `deny mount,`, and an AppArmor deny
// overrides every allow regardless of order -- so a profile that keeps the deny
// and adds mount rules grants nothing, silently.
func TestAppArmorAllowsTheJailerAndNothingMore(t *testing.T) {
	raw, err := os.ReadFile(apparmorPath)
	if err != nil {
		t.Fatalf("read %s: %v", apparmorPath, err)
	}

	var rules []string
	for _, line := range strings.Split(string(raw), "\n") {
		if code, _, _ := strings.Cut(line, "#"); strings.TrimSpace(code) != "" {
			rules = append(rules, strings.TrimSpace(code))
		}
	}

	for _, rule := range rules {
		if strings.HasPrefix(rule, "deny mount") {
			t.Errorf("profile carries %q; an AppArmor deny is absolute and would block the jailer whatever else is allowed", rule)
		}
		if rule == "mount," {
			t.Errorf("profile carries a blanket %q; the three measured rules are the whole grant", rule)
		}
	}

	// The three operations docs/design/container-boundary.md measures.
	for _, want := range []string{
		"mount options=(rw, rslave) -> /,",
		"mount options=(rw, rbind) /srv/vmobs/jail/** -> /srv/vmobs/jail/**,",
		"pivot_root /srv/vmobs/jail/firecracker/*/root/,",
	} {
		if !slices.Contains(rules, want) {
			t.Errorf("profile is missing the rule %q", want)
		}
	}
}

// TestAppArmorAllowsTheProbeChildsPrivateRoot: privd's jail probe runs its child
// with SysProcAttr.Unshareflags CLONE_NEWNS, and Go's own exec does
// mount("", "/", "", MS_REC|MS_PRIVATE) in that child before execve
// (syscall/exec_linux.go). That mount is privd's, not the jailer's, so the trace
// that produced the rules above never saw it.
//
// Measured 2026-09-06 on aibox03 with the profile loaded and only rslave allowed:
//
//	apparmor="DENIED" operation="mount" info="failed flags match" error=-13
//	profile="vmobs-jailer" name="/" comm="vmobs-privd" flags="rw, rprivate"
//
// error=-13 is EACCES, raised in the forked child, so Go reported it as
// "fork/exec /usr/local/sbin/vmobs-privd: permission denied" -- an exec failure
// naming no mount. privd refused to bind its socket and the API never came up.
//
// rprivate is the stricter of the two: rslave still lets host mount events into
// the container, rprivate lets nothing propagate either way. Neither can reach
// the host, which is what the rule is defending.
func TestAppArmorAllowsTheProbeChildsPrivateRoot(t *testing.T) {
	raw, err := os.ReadFile(apparmorPath)
	if err != nil {
		t.Fatalf("read %s: %v", apparmorPath, err)
	}
	const want = "mount options=(rw, rprivate) -> /,"
	if !strings.Contains(string(raw), want) {
		t.Errorf("profile is missing %q; privd cannot exec its jail probe child without it", want)
	}
}

// TestAppArmorAllowsTheNetnsBind: `ip netns add` names a network namespace by
// bind-mounting /proc/self/ns/net onto a file, and privd runs that verb for
// every VM. Its startup probe makes the same mount against its own scratch
// directory rather than /run/netns, so a probe that dies mid-flight leaves no
// named namespace behind. The jailer makes neither mount, which is why the trace
// that produced the rules above never saw them.
//
// Measured 2026-09-06 on aibox03 with the profile loaded and neither rule
// present:
//
//	apparmor="DENIED" operation="mount" class="mount" info="failed mntpnt match"
//	error=-13 profile="vmobs-jailer" name="/tmp/vmobs-jailprobe-1810112568/netns"
//	comm="vmobs-privd" srcname="/" flags="rw, bind"
//
// The probe reported netns_create as a permission error and privd refused to
// bind its socket, so the appliance came up with no API at all.
func TestAppArmorAllowsTheNetnsBind(t *testing.T) {
	raw, err := os.ReadFile(apparmorPath)
	if err != nil {
		t.Fatalf("read %s: %v", apparmorPath, err)
	}
	const want = "mount options=(rw, bind) -> /run/netns/*,"
	if !strings.Contains(string(raw), want) {
		t.Errorf("profile is missing %q; privd cannot name a network namespace without it", want)
	}
}
