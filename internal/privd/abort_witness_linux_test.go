// ABOUTME: A stale pidfile cannot prove the exit of a process started by the jailer.
// ABOUTME: Uses real live and zombie subprocesses to test failed-start ownership.
//go:build linux

package privd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAbortAttemptedStartRetainsUntrustedDeadPID(t *testing.T) {
	live := exec.Command("/bin/sleep", "60")
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Process.Kill(); _ = live.Wait() }()
	dead := exec.Command("/bin/true")
	if err := dead.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dead.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(ProcStatPath(dead.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), ") Z ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not become a zombie")
		}
		time.Sleep(time.Millisecond)
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "firecracker", "vm-witness", "root")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "firecracker.pid"), []byte(strconv.Itoa(dead.Process.Pid)), 0600); err != nil {
		t.Fatal(err)
	}
	ops := NewRealOps(RealOpsCfg{JailBase: dir})
	if err := ops.AbortStartVM(VMEntry{VMID: "vm-witness", StartAttempted: true}); err == nil {
		t.Error("untrusted dead PID authorized attempted-start cleanup")
	}
	if _, err := os.Stat(root); err != nil {
		t.Errorf("unproven jail removed: %v", err)
	}
	if err := unix.Kill(live.Process.Pid, 0); err != nil {
		t.Errorf("live process no longer present: %v", err)
	}
}
