// ABOUTME: Recovery retains trusted process ownership across privileged-server restarts.
// ABOUTME: Real child processes and on-disk ledgers prove boot and namespace checks precede cleanup.

//go:build linux

package privd

import (
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recoveryEntry(t *testing.T, pid int, boot, namespace string) VMEntry {
	t.Helper()
	stat, err := os.ReadFile(ProcStatPath(pid))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]any{"vm_id": "vm-recovery", "pid": pid, "start_time": ParseStartTime(string(stat)), "boot_id": boot, "pid_namespace": namespace, "uid": 30001, "gid": 30001, "cid": 10, "net_cidr": "10.201.0.0/30"})
	if err != nil {
		t.Fatal(err)
	}
	var e VMEntry
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func recoveryHost(t *testing.T) (string, string) {
	t.Helper()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	ns, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(boot)), ns
}

func TestRecoveryBootAndNamespaceSignalGuard(t *testing.T) {
	for _, kind := range []string{"previous_boot", "unknown_boot", "other_namespace"} {
		t.Run(kind, func(t *testing.T) {
			ops, _, _ := guardOps(t)
			f := spawnFakeFirecracker(t, "--id", "vm-recovery")
			boot, ns := recoveryHost(t)
			switch kind {
			case "previous_boot":
				boot = "11111111-1111-4111-8111-111111111111"
			case "unknown_boot", "unknown_boot_dead":
				boot = ""
			case "other_namespace", "other_namespace_dead":
				ns = "pid:[1]"
			}
			e := recoveryEntry(t, f.pid, boot, ns)
			if err := ops.SignalVM(e, "kill"); err == nil {
				t.Error("signal accepted ambiguous or stale ownership")
			}
			if !f.alive(t) {
				t.Error("unrelated current-boot process was killed")
			}
		})
	}
}

func TestRecoveryReleaseAfterServerRestart(t *testing.T) {
	for _, kind := range []string{"live", "previous_boot", "unknown_boot", "other_namespace", "dead", "unknown_boot_dead", "other_namespace_dead"} {
		t.Run(kind, func(t *testing.T) {
			ops, jail, _ := guardOps(t)
			dir := t.TempDir()
			cfg := ServerCfg{LedgerDir: dir, JailBase: jail, Ops: ops}
			first := NewServer(cfg)
			f := spawnFakeFirecracker(t, "--id", "vm-recovery")
			boot, ns := recoveryHost(t)
			switch kind {
			case "previous_boot":
				boot = "11111111-1111-4111-8111-111111111111"
			case "unknown_boot", "unknown_boot_dead":
				boot = ""
			case "other_namespace", "other_namespace_dead":
				ns = "pid:[1]"
			}
			e := recoveryEntry(t, f.pid, boot, ns)
			if err := first.ledger.put(e); err != nil {
				t.Fatal(err)
			}
			tree := filepath.Join(jail, "firecracker", e.VMID, "root")
			if err := os.MkdirAll(tree, 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "dead" || strings.HasSuffix(kind, "_dead") {
				if err := f.cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				<-f.exited
			}
			restarted := NewServer(cfg)
			payload, _ := json.Marshal(ReleaseVMReq{VMID: e.VMID})
			resp := restarted.handleReleaseVM(payload)
			wantRelease := kind == "previous_boot" || kind == "dead"
			if resp.OK != wantRelease {
				t.Fatalf("release OK=%v want %v (%s)", resp.OK, wantRelease, resp.Message)
			}
			_, err := os.Stat(tree)
			if wantRelease && !os.IsNotExist(err) {
				t.Fatalf("released jail survives: %v", err)
			}
			if !wantRelease && err != nil {
				t.Fatalf("refused release removed jail: %v", err)
			}
			stored, err := restarted.ledger.get(e.VMID)
			if err != nil {
				t.Fatal(err)
			}
			if wantRelease && (stored.PID != 0 || stored.UID != 0 || stored.CID != 0) {
				t.Fatalf("released identities still reserved: %+v", stored)
			}
			if !wantRelease && stored.PID != e.PID {
				t.Fatal("refused cleanup changed ownership")
			}
			if kind != "dead" && !strings.HasSuffix(kind, "_dead") && !f.alive(t) {
				t.Fatal("cleanup killed unrelated process")
			}
		})
	}
}

// TestStartVMAllowsIdentitiesAReleasedVMGaveUp: the refusal has to be a lease,
// not a tombstone. release_vm zeroes the uid and CID, and the slot allocator
// will hand the same ones out again on the next launch -- if privd kept
// refusing them the host would run out of slots one VM at a time.
func TestStartVMAllowsIdentitiesAReleasedVMGaveUp(t *testing.T) {
	s, _, stageFor := identityFixture(t)

	mustOK(t, "allocate first", allocateCIDR(t, s, "vm-first", "10.201.0.0/30"))
	mustOK(t, "start first", startWithIdentity(t, s, "vm-first", stageFor("vm-first"), 30001, 10))

	// Preserve a real kernel process identity in the persisted first lease.
	// Reap it before release, then prove the second VM can claim its UID/CID.
	child := spawnFakeFirecracker(t, "--id", "vm-first")
	boot, ns := recoveryHost(t)
	entry := recoveryEntry(t, child.pid, boot, ns)
	entry.VMID = "vm-first"
	allocated, err := s.ledger.get(entry.VMID)
	if err != nil {
		t.Fatal(err)
	}
	entry.NetworkHostNFLogGroup = allocated.NetworkHostNFLogGroup
	if err := s.ledger.put(entry); err != nil {
		t.Fatal(err)
	}
	if err := child.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-child.exited
	payload, err := json.Marshal(ReleaseVMReq{VMID: "vm-first"})
	if err != nil {
		t.Fatalf("marshal release: %v", err)
	}
	mustOK(t, "release first", s.dispatch(Request{V: ProtoVersion, OpID: uuid.NewString(), Verb: "release_vm", Payload: payload}))

	mustOK(t, "allocate second", allocateCIDR(t, s, "vm-second", "10.201.0.4/30"))
	mustOK(t, "start second", startWithIdentity(t, s, "vm-second", stageFor("vm-second"), 30001, 10))
}
