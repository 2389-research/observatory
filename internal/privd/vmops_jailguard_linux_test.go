// ABOUTME: Tests the VM-identity guard on AbortStartVM's kill: a stale pid file can name
// ABOUTME: another VM's firecracker, and SIGKILLing a healthy neighbour is worse than a leak.

//go:build linux

package privd

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeFirecracker is a live process the kernel records as "firecracker",
// carrying an argv this test chose. exited is closed once the process has been
// reaped, so every reader sees it.
type fakeFirecracker struct {
	pid    int
	cmd    *exec.Cmd
	exited chan struct{}
}

// startFakeFirecracker execs a stand-in whose comm reads "firecracker" and whose
// argv ends in args.
//
// comm comes from the basename of the path handed to execve, so a symlink of
// that name over a stock binary is enough. The binary is a shell blocked on a
// read from a pipe this test holds open: it stays alive without a timer and,
// unlike a sleep, it does not care what its remaining arguments say — which is
// the whole point, because the guard under test identifies the process by them.
//
// Nothing here reaps the child: one test needs it to stay a zombie.
func startFakeFirecracker(t *testing.T, args ...string) *fakeFirecracker {
	t.Helper()
	shBin, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("no sh binary to stand in for firecracker: %v", err)
	}
	link := filepath.Join(t.TempDir(), "firecracker")
	if err := os.Symlink(shBin, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, shBin, err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe for the stand-in's stdin: %v", err)
	}
	argv := append([]string{link, "-c", "read line"}, args...)
	/* #nosec G204 — link is a temp-dir symlink this test just created. */
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec
	cmd.Stdin = r
	if err := cmd.Start(); err != nil {
		t.Fatalf("start fake firecracker: %v", err)
	}
	_ = r.Close()
	t.Cleanup(func() { _ = w.Close() })
	f := &fakeFirecracker{pid: cmd.Process.Pid, cmd: cmd, exited: make(chan struct{})}

	// The premises. Without comm reading "firecracker" the guard short-circuits
	// before the check under test, and without this argv in /proc the check under
	// test is reading something other than what this test staged; either way every
	// assertion below would prove nothing.
	statData, err := os.ReadFile(ProcStatPath(f.pid))
	if err != nil {
		t.Fatalf("read %s: %v", ProcStatPath(f.pid), err)
	}
	if comm := ParseComm(string(statData)); comm != "firecracker" {
		t.Fatalf("comm of the stand-in process = %q, want \"firecracker\": the kernel takes comm from "+
			"the basename of the execve path, and without it this test never reaches the argv check", comm)
	}
	gotArgv, err := procCmdline(f.pid)
	if err != nil {
		t.Fatalf("read the stand-in's argv: %v", err)
	}
	if !reflect.DeepEqual(gotArgv, argv) {
		t.Fatalf("argv of the stand-in process = %q, want %q", gotArgv, argv)
	}
	return f
}

// spawnFakeFirecracker starts a stand-in and reaps it in the background, so
// exited closes when the process is really gone.
func spawnFakeFirecracker(t *testing.T, args ...string) *fakeFirecracker {
	t.Helper()
	f := startFakeFirecracker(t, args...)
	go func() {
		_ = f.cmd.Wait()
		close(f.exited)
	}()
	t.Cleanup(func() {
		_ = f.cmd.Process.Kill()
		select {
		case <-f.exited:
		case <-time.After(5 * time.Second):
			t.Errorf("fake firecracker pid %d did not exit after the cleanup kill", f.pid)
		}
	})
	return f
}

// alive reports whether the process is still running. Presence in /proc is not
// enough: a SIGKILLed child stays there as a zombie until it is reaped, with its
// start time unchanged, so PIDAlive would call it alive.
func (f *fakeFirecracker) alive(t *testing.T) bool {
	t.Helper()
	select {
	case <-f.exited:
		return false
	case <-time.After(500 * time.Millisecond):
		return true
	}
}

// waitForZombie blocks until pid has died but not yet been reaped: /proc/<pid>
// is still there, and the state field of its stat line reads Z.
func waitForZombie(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(ProcStatPath(pid))
		if err != nil {
			t.Fatalf("read %s while waiting for a zombie: %v", ProcStatPath(pid), err)
		}
		// State is the first field after the comm, which the last ')' ends.
		stat := string(data)
		rest := strings.TrimSpace(stat[strings.LastIndex(stat, ")")+1:])
		if strings.HasPrefix(rest, "Z") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d never became a zombie; stat = %q", pid, stat)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// guardOps builds a RealOps over a temp jail base with its log captured.
func guardOps(t *testing.T) (*RealOps, string, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	jailBase := filepath.Join(dir, "jail")
	if err := os.MkdirAll(jailBase, 0o750); err != nil {
		t.Fatalf("mkdir jail base: %v", err)
	}
	ops := NewRealOps(RealOpsCfg{JailBase: jailBase, StageRoot: filepath.Join(dir, "stage")})
	var buf bytes.Buffer
	ops.log = log.New(&buf, "", 0)
	return ops, jailBase, &buf
}

// writeJailedPID builds the jail tree a failed start leaves behind and writes pid
// into its firecracker.pid — the only thing in that tree that names a process.
func writeJailedPID(t *testing.T, jailBase, vmID string, pid int) string {
	t.Helper()
	jailDir := filepath.Join(jailBase, "firecracker", vmID)
	root := filepath.Join(jailDir, "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir jail root: %v", err)
	}
	pidFile := filepath.Join(root, "firecracker.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
	return jailDir
}

// TestAbortStartVMSparesAnotherVMsFirecracker is the finding. StartVM's MkdirAll
// does not clear the tree, so a failed start's firecracker.pid survives into the
// next attempt; pids recycle; and on a host whose whole job is running
// firecrackers, the process that inherits the pid is often another VM's VMM. comm
// cannot tell them apart. This one's argv names a different VM, so it must live.
func TestAbortStartVMSparesAnotherVMsFirecracker(t *testing.T) {
	ops, jailBase, logBuf := guardOps(t)
	fc := spawnFakeFirecracker(t, "--id", "vm-neighbour")
	writeJailedPID(t, jailBase, "vm-recycled", fc.pid)

	if err := ops.AbortStartVM(VMEntry{VMID: "vm-recycled"}); err != nil {
		t.Fatalf("AbortStartVM: %v", err)
	}
	if !fc.alive(t) {
		t.Fatalf("the rollback SIGKILLed pid %d, a live firecracker serving vm-neighbour; "+
			"killing a healthy neighbour is worse than the leak this rollback exists to prevent (log: %q)",
			fc.pid, logBuf.String())
	}
	if !strings.Contains(logBuf.String(), strconv.Itoa(fc.pid)) {
		t.Errorf("log = %q; a withheld kill has to name the pid it left running", logBuf.String())
	}
}

// TestAbortStartVMKillsTheFirecrackerServingThisVM: the guard must still let the
// kill through for the process it exists to reap. A firecracker started by a
// start_vm that then failed is recorded nowhere — the ledger keeps PID 0 and the
// manifest is written only after start_vm returns — so if this rollback does not
// kill it, nothing ever will.
func TestAbortStartVMKillsTheFirecrackerServingThisVM(t *testing.T) {
	ops, jailBase, logBuf := guardOps(t)
	fc := spawnFakeFirecracker(t, "--id", "vm-own")
	writeJailedPID(t, jailBase, "vm-own", fc.pid)

	if err := ops.AbortStartVM(VMEntry{VMID: "vm-own"}); err != nil {
		t.Fatalf("AbortStartVM: %v", err)
	}
	if fc.alive(t) {
		t.Errorf("pid %d carries --id vm-own in its argv and survived the rollback (log: %q)",
			fc.pid, logBuf.String())
	}
}

// TestAbortStartVMWithholdsTheKillWhenTheArgvIsGone: a process that dies between
// the stat read and the cmdline read leaves a zombie — comm intact, argv
// released with the rest of its memory. That proves nothing about identity, so
// it withholds the kill like every other unproven case, and says so. Nothing is
// lost: a zombie needs no killing.
func TestAbortStartVMWithholdsTheKillWhenTheArgvIsGone(t *testing.T) {
	ops, jailBase, logBuf := guardOps(t)
	fc := startFakeFirecracker(t, "--id", "vm-zombie")
	writeJailedPID(t, jailBase, "vm-zombie", fc.pid)

	if err := fc.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill the stand-in: %v", err)
	}
	t.Cleanup(func() { _ = fc.cmd.Wait() })
	waitForZombie(t, fc.pid)

	// The premises again, for the state this test actually needs: the guard must
	// still get past comm, and the argv must really be gone.
	statData, err := os.ReadFile(ProcStatPath(fc.pid))
	if err != nil {
		t.Fatalf("read %s: %v", ProcStatPath(fc.pid), err)
	}
	if comm := ParseComm(string(statData)); comm != "firecracker" {
		t.Fatalf("comm of the zombie = %q, want \"firecracker\": with any other comm the guard "+
			"stops before the argv check and this test proves nothing", comm)
	}
	argv, err := procCmdline(fc.pid)
	if err != nil || len(argv) != 0 {
		t.Fatalf("argv of the zombie = %q (err %v), want none: the kernel releases it with the "+
			"process's memory, and that emptiness is the case under test", argv, err)
	}

	if err := ops.AbortStartVM(VMEntry{VMID: "vm-zombie"}); err != nil {
		t.Fatalf("AbortStartVM: %v", err)
	}
	logged := logBuf.String()
	if !strings.Contains(logged, strconv.Itoa(fc.pid)) {
		t.Errorf("log = %q; a withheld kill has to name the pid it left alone", logged)
	}
	if strings.Contains(logged, "killed firecracker") {
		t.Errorf("log = %q; an empty argv proves nothing about identity and must withhold the kill", logged)
	}
}

// TestArgvServesVM pins the predicate to element equality. Every jail path is
// keyed by the VM id, so a substring search over the joined command line would
// match a process that merely mentions this VM — and this predicate gates a
// SIGKILL.
func TestArgvServesVM(t *testing.T) {
	const vmID = "ce4cbe5e-4622-4bfc-a789-cd7a7dbca048"
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{
			// The shape observed on the host: jailer v1.16.1 execs firecracker with
			// --id and the VM id as two separate argv elements.
			name: "the jailed firecracker serving this VM",
			argv: []string{"/firecracker", "--id", vmID, "--start-time-us", "183182266695",
				"--start-time-cpu-us", "106", "--parent-cpu-time-us", "2626",
				"--config-file", "fc-config.json", "--api-sock", "api.sock"},
			want: true,
		},
		{
			name: "another VM's firecracker",
			argv: []string{"/firecracker", "--id", "9c1f0f3e-0000-4000-8000-000000000002"},
			want: false,
		},
		{
			name: "the id only inside a path",
			argv: []string{"/usr/local/bin/vmobs-runner", "--vm-id", vmID,
				"--uds", "/srv/vmobs/jail/firecracker/" + vmID + "/root/v.sock"},
			want: false,
		},
		{
			name: "an id this one is a prefix of",
			argv: []string{"/firecracker", "--id", vmID + "-2"},
			want: false,
		},
		{
			name: "--id with nothing after it",
			argv: []string{"/firecracker", "--id"},
			want: false,
		},
		{
			name: "no argv at all",
			argv: nil,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := argvServesVM(tc.argv, vmID); got != tc.want {
				t.Errorf("argvServesVM(%q, %q) = %v, want %v", tc.argv, vmID, got, tc.want)
			}
		})
	}
}
