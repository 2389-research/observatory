// ABOUTME: Tests that privd refuses a host identity another live VM already holds.
// ABOUTME: Portable — driven at the Ops seam, so no socket, peer creds or root.
package privd

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// identityFixture builds a real Server over a real ledger with stubOps behind
// it, and returns the server, that backend, and a function that makes a stage
// directory for one VM. Two daemons on one host is what this file is about, so
// every test needs at least two VMs and the shared fixture cannot own a single
// stage dir.
func identityFixture(t *testing.T) (*Server, *stubOps, func(string) string) {
	t.Helper()
	dir := t.TempDir()
	ledgerDir := filepath.Join(dir, "ledger")
	stageRoot := filepath.Join(dir, "stage")
	jailBase := filepath.Join(dir, "jail")
	for _, d := range []string{ledgerDir, stageRoot, jailBase} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	ops := &stubOps{jailBase: jailBase}
	s := NewServer(ServerCfg{
		AllowedUID: os.Getuid(),
		LedgerDir:  ledgerDir,
		StageRoot:  stageRoot,
		JailBase:   jailBase,
		UIDMin:     30000,
		UIDMax:     31000,
		Ops:        ops,
		Log:        log.New(io.Discard, "", 0),
	})
	stageFor := func(vmID string) string {
		d := filepath.Join(stageRoot, vmID)
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
		return d
	}
	return s, ops, stageFor
}

// allocateCIDR runs allocate_network for one VM on one subnet.
func allocateCIDR(t *testing.T, s *Server, vmID, cidr string) Response {
	t.Helper()
	payload, err := json.Marshal(AllocateNetworkReq{VMID: vmID, CIDR: cidr})
	if err != nil {
		t.Fatalf("marshal allocate: %v", err)
	}
	return s.dispatch(Request{V: ProtoVersion, Verb: "allocate_network", Payload: payload})
}

// startWithIdentity runs start_vm for one VM under one uid and CID.
func startWithIdentity(t *testing.T, s *Server, vmID, stageDir string, uid int, cid uint32) Response {
	t.Helper()
	payload, err := json.Marshal(StartVMReq{
		VMID:     vmID,
		UID:      uid,
		GID:      uid,
		CID:      cid,
		StageDir: stageDir,
	})
	if err != nil {
		t.Fatalf("marshal start: %v", err)
	}
	return s.dispatch(Request{V: ProtoVersion, Verb: "start_vm", Payload: payload})
}

// mustOK fails the test unless the verb succeeded.
func mustOK(t *testing.T, what string, resp Response) {
	t.Helper()
	if !resp.OK {
		t.Fatalf("%s: cause=%q message=%q", what, resp.Cause, resp.Message)
	}
}

// refusalNames fails unless the response is a refusal whose message names the
// holder. Naming it is the point: the failure this file exists for was silent at
// the allocator and surfaced four stages later as "runner exited before
// attaching", with nothing to connect the two.
func refusalNames(t *testing.T, what string, resp Response, holder string) {
	t.Helper()
	if resp.OK {
		t.Fatalf("%s: succeeded, but the identity it asked for is already held by %s", what, holder)
	}
	if resp.Cause != "invalid_state" {
		t.Errorf("%s: cause = %q, want invalid_state", what, resp.Cause)
	}
	if !strings.Contains(resp.Message, holder) {
		t.Errorf("%s: message %q does not name the holder %s", what, resp.Message, holder)
	}
}

// TestStartVMRefusesAUIDAnotherVMHolds: the jail uid is a host-global identity.
// Two vmobsd processes with separate state dirs both allocate slot 0 and both
// derive JailUIDBase+0, so the second VM would run as the first one's user --
// able to signal its firecracker and read whatever its jail modes allow.
func TestStartVMRefusesAUIDAnotherVMHolds(t *testing.T) {
	s, _, stageFor := identityFixture(t)

	mustOK(t, "allocate first", allocateCIDR(t, s, "vm-first", "10.201.0.0/30"))
	mustOK(t, "start first", startWithIdentity(t, s, "vm-first", stageFor("vm-first"), 30001, 10))

	mustOK(t, "allocate second", allocateCIDR(t, s, "vm-second", "10.201.0.4/30"))
	resp := startWithIdentity(t, s, "vm-second", stageFor("vm-second"), 30001, 11)
	refusalNames(t, "start second", resp, "vm-first")
}

// TestStartVMRefusesACIDAnotherVMHolds: the guest CID is the other identity
// derived from the slot. Two VMs on one CID means the host's vsock connections
// reach whichever bound it first -- so a controller's runner can attach to a VM
// it did not launch.
func TestStartVMRefusesACIDAnotherVMHolds(t *testing.T) {
	s, _, stageFor := identityFixture(t)

	mustOK(t, "allocate first", allocateCIDR(t, s, "vm-first", "10.201.0.0/30"))
	mustOK(t, "start first", startWithIdentity(t, s, "vm-first", stageFor("vm-first"), 30001, 10))

	mustOK(t, "allocate second", allocateCIDR(t, s, "vm-second", "10.201.0.4/30"))
	resp := startWithIdentity(t, s, "vm-second", stageFor("vm-second"), 30002, 10)
	refusalNames(t, "start second", resp, "vm-first")
}

// TestAllocateNetworkRefusesASubnetAnotherVMHolds: the CIDR comes from a
// per-daemon allocator, so it collides for the same reason the slot does. It is
// claimed one stage earlier than the uid and CID, which makes it the first place
// a second daemon can be told what it has walked into.
func TestAllocateNetworkRefusesASubnetAnotherVMHolds(t *testing.T) {
	s, _, _ := identityFixture(t)

	mustOK(t, "allocate first", allocateCIDR(t, s, "vm-first", "10.201.0.0/30"))
	resp := allocateCIDR(t, s, "vm-second", "10.201.0.0/30")
	refusalNames(t, "allocate second", resp, "vm-first")
}

// TestStartVMRetriesAfterItsOwnFailedStart: the scan reads every entry in the
// ledger, including the requesting VM's own. That is only safe because a start
// that fails records nothing -- handleStartVM writes the ledger after StartVM
// returns a pid, so the uid and CID a failed attempt asked for never land. Write
// them any earlier and a VM's own dead attempt would refuse its retry, and the
// only way back would be deleting the VM.
func TestStartVMRetriesAfterItsOwnFailedStart(t *testing.T) {
	s, ops, stageFor := identityFixture(t)
	stageDir := stageFor("vm-retry")

	mustOK(t, "allocate", allocateCIDR(t, s, "vm-retry", "10.201.0.0/30"))
	ops.startErr = errors.New("firecracker refused to boot")
	if resp := startWithIdentity(t, s, "vm-retry", stageDir, 30001, 10); resp.OK {
		t.Fatal("start_vm succeeded while the backend was failing")
	}

	ops.startErr = nil
	mustOK(t, "retry", startWithIdentity(t, s, "vm-retry", stageDir, 30001, 10))
}

// TestStartVMRefusesAReservedCID: identityHolder reads a zero CID in the ledger
// as an identity a released VM gave back. A live VM must never carry one, or the
// refusal this file exists for silently stops firing -- and config accepts
// cid_base: 0, which would give slot 0 exactly that. The vsock spec reserves
// 0-2 and firecracker refuses them anyway, so the request is the right place to
// stop it.
func TestStartVMRefusesAReservedCID(t *testing.T) {
	s, _, stageFor := identityFixture(t)

	mustOK(t, "allocate", allocateCIDR(t, s, "vm-reserved", "10.201.0.0/30"))
	for _, cid := range []uint32{0, 1, 2} {
		resp := startWithIdentity(t, s, "vm-reserved", stageFor("vm-reserved"), 30001, cid)
		if resp.OK {
			t.Errorf("start_vm with cid %d succeeded; the vsock spec reserves it", cid)
			continue
		}
		if resp.Cause != "bad_request" {
			t.Errorf("cid %d: cause = %q, want bad_request", cid, resp.Cause)
		}
	}

	mustOK(t, "start on the first usable cid", startWithIdentity(t, s, "vm-reserved", stageFor("vm-reserved"), 30001, 3))
}

// TestAllocateNetworkRefusesWhenAnotherEntryCannotBeRead: an entry that will not
// parse held a subnet, a uid and a CID, and which ones is now unknown. Unknown
// is not free -- the same ruling allocateSlot makes about an unreadable manifest
// (internal/jailer/manifest.go).
func TestAllocateNetworkRefusesWhenAnotherEntryCannotBeRead(t *testing.T) {
	s, _, _ := identityFixture(t)

	mustOK(t, "allocate first", allocateCIDR(t, s, "vm-first", "10.201.0.0/30"))
	if err := os.WriteFile(filepath.Join(s.ledger.dir, "vm-corrupt.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("plant corrupt entry: %v", err)
	}

	resp := allocateCIDR(t, s, "vm-second", "10.201.0.8/30")
	if resp.OK {
		t.Fatal("allocate_network succeeded while an unreadable entry held unknown identities")
	}
	if !strings.Contains(resp.Message, "vm-corrupt") {
		t.Errorf("message %q does not name the entry it could not read", resp.Message)
	}
}

// TestAllocateNetworkIgnoresDebrisInTheLedgerDirectory: durable.WriteFile
// publishes through a temporary file in this directory, so a crash between its
// create and its rename leaves one behind. The scan meets it where get() never
// did, and a claim must not be refused by a file that is not a VM record.
func TestAllocateNetworkIgnoresDebrisInTheLedgerDirectory(t *testing.T) {
	s, _, _ := identityFixture(t)

	mustOK(t, "allocate first", allocateCIDR(t, s, "vm-first", "10.201.0.0/30"))
	// Two of these are load-bearing rather than illustrative. LedgerLockName is
	// privd's own singleton lock, which lives in this directory and must never
	// read as a VM record -- ValidVMID drops it on the leading dot. And
	// "vm-no-extension" is a valid VM id with no suffix: the .json check is the
	// only thing standing between it and a get() for a file that is not there,
	// which would fail the scan and refuse every claim on the host.
	for _, name := range []string{".publish-12345.tmp", "notes.txt", ".hidden.json", LedgerLockName, "vm-no-extension"} {
		if err := os.WriteFile(filepath.Join(s.ledger.dir, name), []byte("{not json"), 0o600); err != nil {
			t.Fatalf("plant %s: %v", name, err)
		}
	}

	mustOK(t, "allocate second", allocateCIDR(t, s, "vm-second", "10.201.0.4/30"))
}
