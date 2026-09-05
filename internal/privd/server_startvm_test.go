// ABOUTME: Portable tests for handleStartVM's rollback of a partial start, driven at the Ops seam.
// ABOUTME: package privd (internal) so dispatch runs without a socket, peer creds or root.
package privd

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

// stubOps is an OpsBackend whose StartVM builds the jail tree before it fails —
// the shape every real StartVM failure has, since RealOps creates
// <JailBase>/firecracker/<id>/root and copies the boot artifacts into it before
// reaching any step that can report an error.
type stubOps struct {
	jailBase string
	startErr error
	abortErr error

	startCalls []string
	abortCalls []string
}

func (o *stubOps) AllocateNetwork(VMEntry, AllocateNetworkReq) error { return nil }
func (o *stubOps) ReleaseNetwork(VMEntry) error                      { return nil }

func (o *stubOps) StartVM(_ *VMEntry, req StartVMReq) (StartVMResp, error) {
	o.startCalls = append(o.startCalls, req.VMID)
	root := filepath.Join(o.jailBase, "firecracker", req.VMID, "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		return StartVMResp{}, err
	}
	if err := os.WriteFile(filepath.Join(root, "rootfs.ext4"), []byte("boot artifact"), 0o600); err != nil {
		return StartVMResp{}, err
	}
	if o.startErr != nil {
		return StartVMResp{}, o.startErr
	}
	return StartVMResp{PID: 4242, StartTime: "907199254"}, nil
}

func (o *stubOps) AbortStartVM(entry VMEntry) error {
	o.abortCalls = append(o.abortCalls, entry.VMID)
	if o.abortErr != nil {
		return o.abortErr
	}
	return os.RemoveAll(filepath.Join(o.jailBase, "firecracker", entry.VMID))
}

func (o *stubOps) SignalVM(VMEntry, string) error { return nil }

func (o *stubOps) ReleaseVM(entry VMEntry) error {
	return os.RemoveAll(filepath.Join(o.jailBase, "firecracker", entry.VMID))
}

// startVMFixture builds a real Server over a real on-disk ledger with stubOps
// behind it, and returns the server, the backend and the stage dir to send.
func startVMFixture(t *testing.T) (*Server, *stubOps, string) {
	t.Helper()
	dir := t.TempDir()
	ledgerDir := filepath.Join(dir, "ledger")
	stageRoot := filepath.Join(dir, "stage")
	stageDir := filepath.Join(stageRoot, "vm-rollback")
	jailBase := filepath.Join(dir, "jail")
	for _, d := range []string{ledgerDir, stageDir, jailBase} {
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
	return s, ops, stageDir
}

// allocate runs the allocate_network verb so the VM has the ledger entry
// start_vm requires.
func allocate(t *testing.T, s *Server, vmID string) {
	t.Helper()
	payload, err := json.Marshal(AllocateNetworkReq{VMID: vmID, CIDR: "10.201.0.0/30"})
	if err != nil {
		t.Fatalf("marshal allocate: %v", err)
	}
	resp := s.dispatch(Request{V: ProtoVersion, Verb: "allocate_network", Payload: payload})
	if !resp.OK {
		t.Fatalf("allocate_network: cause=%q message=%q", resp.Cause, resp.Message)
	}
}

// startVM runs the start_vm verb for vmID.
func startVM(t *testing.T, s *Server, vmID, stageDir string) Response {
	t.Helper()
	payload, err := json.Marshal(StartVMReq{
		VMID:     vmID,
		UID:      30001,
		GID:      30001,
		CID:      10,
		StageDir: stageDir,
	})
	if err != nil {
		t.Fatalf("marshal start: %v", err)
	}
	return s.dispatch(Request{V: ProtoVersion, Verb: "start_vm", Payload: payload})
}

// TestStartVMFailureRollsBackPartialStart: a StartVM that fails after building
// the jail tree must not leave it behind. A later release_vm could reclaim the
// tree — the entry allocate_network wrote is still in the ledger with PID 0 —
// but a firecracker the same failure left running could not be: the ledger write
// never runs, so its pid is recorded nowhere. Rolling back here is the only
// chance either survivor gets while anything still knows they exist.
func TestStartVMFailureRollsBackPartialStart(t *testing.T) {
	s, ops, stageDir := startVMFixture(t)
	const vmID = "vm-rollback"
	allocate(t, s, vmID)

	ops.startErr = errors.New("injected: read firecracker.pid")
	resp := startVM(t, s, vmID, stageDir)

	if resp.OK {
		t.Fatal("start_vm reported OK after the backend failed")
	}
	if len(ops.abortCalls) != 1 || ops.abortCalls[0] != vmID {
		t.Errorf("abort calls = %v; want exactly [%s]", ops.abortCalls, vmID)
	}
	jailDir := filepath.Join(ops.jailBase, "firecracker", vmID)
	if _, err := os.Stat(jailDir); !os.IsNotExist(err) {
		t.Errorf("jail tree %s survived the failed start (stat err: %v)", jailDir, err)
	}

	// The ledger keeps the network half and records no process identity.
	entry, err := s.ledger.get(vmID)
	if err != nil {
		t.Fatalf("ledger get: %v", err)
	}
	if entry.PID != 0 {
		t.Errorf("ledger recorded pid %d for a start that failed", entry.PID)
	}
	if entry.NetCIDR == "" {
		t.Error("rollback dropped the network allocation; release_network owns that half")
	}
}

// TestStartVMFailureKeepsTheOriginalCause: the undo must not overwrite the
// reason the start failed. A digest mismatch has to reach the caller as
// digest_mismatch, not as whatever the rollback did next.
func TestStartVMFailureKeepsTheOriginalCause(t *testing.T) {
	s, ops, stageDir := startVMFixture(t)
	const vmID = "vm-rollback"
	allocate(t, s, vmID)

	ops.startErr = &BackendError{Cause: "digest_mismatch", Message: "rootfs.ext4 digest mismatch"}
	ops.abortErr = errors.New("injected: rollback could not remove the tree")
	resp := startVM(t, s, vmID, stageDir)

	if resp.OK {
		t.Fatal("start_vm reported OK after the backend failed")
	}
	if resp.Cause != "digest_mismatch" {
		t.Errorf("cause = %q; want digest_mismatch", resp.Cause)
	}
	if resp.Message != "rootfs.ext4 digest mismatch" {
		t.Errorf("message = %q; want the original backend message", resp.Message)
	}
}

// TestStartVMSuccessDoesNotRollBack: the undo fires only on failure.
func TestStartVMSuccessDoesNotRollBack(t *testing.T) {
	s, ops, stageDir := startVMFixture(t)
	const vmID = "vm-rollback"
	allocate(t, s, vmID)

	resp := startVM(t, s, vmID, stageDir)
	if !resp.OK {
		t.Fatalf("start_vm: cause=%q message=%q", resp.Cause, resp.Message)
	}
	if len(ops.abortCalls) != 0 {
		t.Errorf("abort calls = %v; want none on the success path", ops.abortCalls)
	}
	entry, err := s.ledger.get(vmID)
	if err != nil {
		t.Fatalf("ledger get: %v", err)
	}
	if entry.PID != 4242 {
		t.Errorf("ledger pid = %d; want 4242", entry.PID)
	}
}

// startVMWithFiles runs start_vm carrying a file list, which the helper above
// omits because the rollback tests drive the backend at its seam.
func startVMWithFiles(t *testing.T, s *Server, vmID, stageDir string, files []StagedFile) Response {
	t.Helper()
	payload, err := json.Marshal(StartVMReq{
		VMID:     vmID,
		UID:      30001,
		GID:      30001,
		CID:      10,
		StageDir: stageDir,
		Files:    files,
	})
	if err != nil {
		t.Fatalf("marshal start: %v", err)
	}
	return s.dispatch(Request{V: ProtoVersion, Verb: "start_vm", Payload: payload})
}

// TestStartVMRefusesAStagedNameThatIsNotOneOfOurs: the handler validates the
// file list the way it validates vm_id and the uid range -- before the backend
// runs, so nothing is created and no fd is opened on the caller's behalf.
//
// The backend is where the name would do its damage, so the assertion that
// matters is that StartVM was never called at all. A refusal the backend has to
// make for itself is a second chance, not a gate.
func TestStartVMRefusesAStagedNameThatIsNotOneOfOurs(t *testing.T) {
	hostile := []string{
		"../../victim/owned.txt",
		"sub/vmlinux",
		"/etc/cron.d/pwn",
		"..",
		"",
		"initrd",
	}
	for _, name := range hostile {
		t.Run(name, func(t *testing.T) {
			s, ops, stageDir := startVMFixture(t)
			const vmID = "vm-rollback"
			allocate(t, s, vmID)

			// A legal name alongside it: the refusal must be about the list, not
			// about the first element.
			files := []StagedFile{
				{Name: "vmlinux", SHA256: "00"},
				{Name: name, SHA256: "00"},
			}
			resp := startVMWithFiles(t, s, vmID, stageDir, files)

			if resp.OK {
				t.Fatalf("start_vm accepted staged name %q", name)
			}
			if resp.Cause != "bad_request" {
				t.Errorf("cause = %q, want bad_request (message %q)", resp.Cause, resp.Message)
			}
			if len(ops.startCalls) != 0 {
				t.Errorf("backend StartVM ran %v for a request the handler should have refused", ops.startCalls)
			}
		})
	}
}

// TestStartVMTakesTheFileListALaunchSends: the refusal above must not be bought
// by refusing every list. The names computeStagedFiles builds still reach the
// backend.
func TestStartVMTakesTheFileListALaunchSends(t *testing.T) {
	s, ops, stageDir := startVMFixture(t)
	const vmID = "vm-rollback"
	allocate(t, s, vmID)

	files := make([]StagedFile, 0, len(StagedFileNames))
	for _, name := range StagedFileNames {
		files = append(files, StagedFile{Name: name, SHA256: "00"})
	}
	resp := startVMWithFiles(t, s, vmID, stageDir, files)

	if !resp.OK {
		t.Fatalf("start_vm refused the list every launch sends: cause=%q message=%q", resp.Cause, resp.Message)
	}
	if len(ops.startCalls) != 1 {
		t.Errorf("backend StartVM ran %v; want exactly one call", ops.startCalls)
	}
}
