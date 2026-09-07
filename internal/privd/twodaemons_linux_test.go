// ABOUTME: Drives the kata-4fap scenario end to end: two vmobsd daemons, one privd, colliding slots.
// ABOUTME: Real unix sockets, a fresh one per request, so the refusal is tested where it is served.

//go:build linux

package privd_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/privd"
)

// twoDaemonFixture starts one privd over a real socket and returns its path plus
// a function that makes a stage directory for one VM.
//
// privd serves one request per connection, so nothing on the wire says which
// daemon a claim came from -- and that is the defect in one sentence. A vmobsd's
// slot allocator sees only its own state directory, so two of them derive the
// same jail uid, guest CID and subnet, and the ledger is the only place those
// claims meet.
func twoDaemonFixture(t *testing.T) (sockPath string, stageFor func(string) string) {
	t.Helper()
	dir := t.TempDir()
	sockPath = filepath.Join(dir, "privd.sock")
	stageRoot := filepath.Join(dir, "stage")
	ledgerDir := filepath.Join(dir, "ledger")
	for _, d := range []string{stageRoot, ledgerDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	pid, starttime := spawnShortProcess(t)
	startServer(t, sockPath, privd.ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  stageRoot,
		JailBase:   filepath.Join(dir, "jail"),
		UIDMin:     os.Getuid(),
		UIDMax:     os.Getuid() + 100,
		Ops:        &recordingBackend{startResp: privd.StartVMResp{PID: pid, StartTime: starttime}},
	})
	stageFor = func(vmID string) string {
		d := filepath.Join(stageRoot, vmID)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
		return d
	}
	return sockPath, stageFor
}

// TestTwoDaemonsCollideLoudly: the second daemon's launch is refused at the verb
// that would have made the collision, with a message naming the VM that holds
// what it asked for.
//
// Before this, both claims succeeded. The observed result was a VM that failed
// several stages later with "runner exited before attaching: exit status 1" and
// nothing connecting that to a slot the other daemon had already spent.
func TestTwoDaemonsCollideLoudly(t *testing.T) {
	sockPath, stageFor := twoDaemonFixture(t)

	// call dials a fresh connection, which is what a vmobsd does for every verb.
	call := func(verb string, payload any) privd.Response {
		t.Helper()
		return sendRecv(t, dialPrivd(t, sockPath), makeReq(t, verb, payload))
	}

	// Daemon one launches its first VM: slot 0, so uid base + 0 and cid base + 0.
	const firstID = "vm-daemon-one"
	uid, cid := os.Getuid(), uint32(3)

	resp := call("allocate_network", privd.AllocateNetworkReq{VMID: firstID, CIDR: "10.202.0.0/30"})
	if !resp.OK {
		t.Fatalf("daemon one allocate_network: cause=%q message=%q", resp.Cause, resp.Message)
	}
	resp = call("start_vm", privd.StartVMReq{
		VMID: firstID, UID: uid, GID: uid, CID: cid, StageDir: stageFor(firstID),
	})
	if !resp.OK {
		t.Fatalf("daemon one start_vm: cause=%q message=%q", resp.Cause, resp.Message)
	}

	// Daemon two has its own state directory, so its allocator also returns slot
	// 0 and it derives the identical uid, cid and subnet.
	const secondID = "vm-daemon-two"

	resp = call("allocate_network", privd.AllocateNetworkReq{VMID: secondID, CIDR: "10.202.0.0/30"})
	assertRefusedNaming(t, "daemon two allocate_network", resp, firstID, "10.202.0.0/30")

	// Give it a subnet of its own so the launch reaches the next claim, which is
	// where the uid and CID are spent.
	resp = call("allocate_network", privd.AllocateNetworkReq{VMID: secondID, CIDR: "10.202.0.4/30"})
	if !resp.OK {
		t.Fatalf("daemon two allocate_network on a free subnet: cause=%q message=%q", resp.Cause, resp.Message)
	}
	resp = call("start_vm", privd.StartVMReq{
		VMID: secondID, UID: uid, GID: uid, CID: cid, StageDir: stageFor(secondID),
	})
	assertRefusedNaming(t, "daemon two start_vm", resp, firstID, "uid")

	// A third daemon configured with its own jail_uid_base but the default
	// cid_base -- the shape an operator produces by separating the uid ranges and
	// believing that is enough. The uid claim now succeeds and the CID is the only
	// thing left standing between two VMs on one vsock address.
	const thirdID = "vm-daemon-three"

	resp = call("allocate_network", privd.AllocateNetworkReq{VMID: thirdID, CIDR: "10.202.0.8/30"})
	if !resp.OK {
		t.Fatalf("daemon three allocate_network: cause=%q message=%q", resp.Cause, resp.Message)
	}
	resp = call("start_vm", privd.StartVMReq{
		VMID: thirdID, UID: uid + 1, GID: uid + 1, CID: cid, StageDir: stageFor(thirdID),
	})
	assertRefusedNaming(t, "daemon three start_vm", resp, firstID, "cid")
}

// assertRefusedNaming fails unless resp is an invalid_state refusal whose message
// names both the holder and the thing that was refused. A refusal that says only
// "already in use" leaves the operator where the silent collision did.
func assertRefusedNaming(t *testing.T, what string, resp privd.Response, holder, subject string) {
	t.Helper()
	if resp.OK {
		t.Fatalf("%s: succeeded, but %s holds what it asked for", what, holder)
	}
	if resp.Cause != "invalid_state" {
		t.Errorf("%s: cause = %q, want invalid_state", what, resp.Cause)
	}
	if !strings.Contains(resp.Message, holder) {
		t.Errorf("%s: message %q does not name the holder %s", what, resp.Message, holder)
	}
	if !strings.Contains(resp.Message, subject) {
		t.Errorf("%s: message %q does not name what it refused (%s)", what, resp.Message, subject)
	}
}
