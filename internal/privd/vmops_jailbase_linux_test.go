// ABOUTME: The jail base is created by root and traversed by the unprivileged daemon;
// ABOUTME: this proves privd leaves it reachable instead of root-only.

//go:build linux

package privd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestJailBaseIsTraversableByTheDaemon: privd creates <jail-base>/firecracker as
// root, and the daemon that reaches into it -- to dial v.sock, to stat the
// chroot at teardown -- is not root and is not in root's group. A base only
// root can traverse breaks both, and breaks them silently: the runner's dial
// gets EACCES and retries until the sixty-second attach deadline, so the launch
// reports "timeout waiting for runner to attach" and never names the mode.
//
// The mode is checked here rather than left to the process umask because the
// requirement is not a preference: a umask that clears the traverse bits
// produces a host where no VM can boot.
func TestJailBaseIsTraversableByTheDaemon(t *testing.T) {
	jailBase := t.TempDir()
	ops := NewRealOps(RealOpsCfg{JailBase: jailBase})

	rootfd, err := ops.jailRoot("vm-jailbase", true)
	if err != nil {
		t.Fatalf("jailRoot: %v", err)
	}
	defer func() { _ = rootfd.Close() }()

	base := filepath.Join(jailBase, "firecracker")
	fi, err := os.Stat(base)
	if err != nil {
		t.Fatalf("stat jail base: %v", err)
	}
	mode := fi.Mode().Perm()
	if mode&0o005 != 0o005 {
		t.Errorf("jail base mode is %04o; a daemon that is neither the owner nor in its group cannot read or traverse it", mode)
	}
}

// TestJailBaseModeSurvivesATightUmask: the same requirement, held against the
// one thing that quietly removes it. os.MkdirAll applies the umask, so a privd
// started from a shell with 0027 would create a base its own daemon cannot
// enter -- the failure would depend on how privd was launched, not on anything
// an operator configured.
func TestJailBaseModeSurvivesATightUmask(t *testing.T) {
	old := syscall.Umask(0o027)
	defer syscall.Umask(old)

	jailBase := t.TempDir()
	ops := NewRealOps(RealOpsCfg{JailBase: jailBase})

	rootfd, err := ops.jailRoot("vm-jailbase-umask", true)
	if err != nil {
		t.Fatalf("jailRoot: %v", err)
	}
	defer func() { _ = rootfd.Close() }()

	fi, err := os.Stat(filepath.Join(jailBase, "firecracker"))
	if err != nil {
		t.Fatalf("stat jail base: %v", err)
	}
	if mode := fi.Mode().Perm(); mode&0o005 != 0o005 {
		t.Errorf("jail base mode is %04o under umask 0027; the traverse bits must not depend on how privd was started", mode)
	}
}

// TestEnsureJailBaseRepairsAnInheritedBase: the mode has to be fixed on the way
// up, not on the way into a launch. An install carrying a 0750 base from an
// earlier privd cannot delete the VMs it inherited -- teardown stats the chroot
// through that base and gets EACCES -- and it cannot launch its way out either,
// because the reservations those undeleted VMs hold are what refuse the launch.
// Measured on aibox03 against a persistent runtime volume: three VMs parked in
// deleting, every DELETE 500, and POST /vms refused for capacity they held.
//
// os.MkdirAll leaves an existing directory's mode alone, so creating the base
// is not the same act as making it traversable.
func TestEnsureJailBaseRepairsAnInheritedBase(t *testing.T) {
	jailBase := t.TempDir()
	base := filepath.Join(jailBase, "firecracker")
	if err := os.Mkdir(base, 0o750); err != nil {
		t.Fatalf("seed an inherited base: %v", err)
	}

	if err := EnsureJailBase(jailBase); err != nil {
		t.Fatalf("EnsureJailBase: %v", err)
	}

	fi, err := os.Stat(base)
	if err != nil {
		t.Fatalf("stat jail base: %v", err)
	}
	if mode := fi.Mode().Perm(); mode&0o005 != 0o005 {
		t.Errorf("jail base mode is %04o; privd inherited a base its own daemon cannot traverse and left it that way", mode)
	}
}

// TestEnsureJailBaseCreatesAMissingBase: the fresh-install half of the same
// call. privd runs it before it serves, so the first launch on a new host finds
// the base already there and already traversable.
func TestEnsureJailBaseCreatesAMissingBase(t *testing.T) {
	jailBase := t.TempDir()

	if err := EnsureJailBase(jailBase); err != nil {
		t.Fatalf("EnsureJailBase: %v", err)
	}

	fi, err := os.Stat(filepath.Join(jailBase, "firecracker"))
	if err != nil {
		t.Fatalf("stat jail base: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("jail base is not a directory")
	}
	if mode := fi.Mode().Perm(); mode&0o005 != 0o005 {
		t.Errorf("jail base mode is %04o on a fresh install", mode)
	}
}
