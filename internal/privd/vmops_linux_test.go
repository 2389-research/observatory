// ABOUTME: Linux tests for privd VM operations: digest verification, jailer argv, signal identity.
// ABOUTME: Non-root: all tests run unprivileged; actual jailer exec is tested in Task 5 smoke.

//go:build linux

package privd_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/network"
	"github.com/2389-research/observatory-v2/internal/privd"
)

// ----- TestStagedFileVerification -----

// TestStagedFileVerification checks the fd-pinned digest verification helper:
//   - Correct digest → success (no error).
//   - Wrong digest → BackendError with cause "digest_mismatch" naming the file.
//   - Symlink in place of the file → error (O_NOFOLLOW).
func TestStagedFileVerification(t *testing.T) {
	dir := t.TempDir()

	content := []byte("hello vm image data")
	fname := "rootfs.ext4"
	fpath := filepath.Join(dir, fname)
	if err := os.WriteFile(fpath, content, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	h := sha256.Sum256(content)
	correctDigest := hex.EncodeToString(h[:])
	wrongDigest := strings.Repeat("a", 64)

	t.Run("correct_digest", func(t *testing.T) {
		staged := privd.StagedFile{Name: fname, SHA256: correctDigest}
		fd, err := privd.VerifyStagedFile(dir, staged)
		if err != nil {
			t.Errorf("correct digest: unexpected error: %v", err)
		}
		if fd == nil {
			t.Fatal("correct digest: expected non-nil fd on success (pinned fd is the copy contract)")
		}
		fd.Close()
	})

	t.Run("wrong_digest", func(t *testing.T) {
		staged := privd.StagedFile{Name: fname, SHA256: wrongDigest}
		fd, err := privd.VerifyStagedFile(dir, staged)
		if fd != nil {
			fd.Close()
			t.Error("wrong digest: expected nil fd, got non-nil (fd leak)")
		}
		if err == nil {
			t.Fatal("wrong digest: expected error, got nil")
		}
		var be *privd.BackendError
		if !privd.AsBackendError(err, &be) {
			t.Fatalf("wrong digest: expected BackendError, got %T: %v", err, err)
		}
		if be.Cause != "digest_mismatch" {
			t.Errorf("wrong digest: cause = %q, want digest_mismatch", be.Cause)
		}
		if !strings.Contains(be.Message, fname) {
			t.Errorf("wrong digest: message %q does not name the file %q", be.Message, fname)
		}
		// §15.3: no secret material (contents) in the message.
		if strings.Contains(be.Message, string(content)) {
			t.Errorf("wrong digest: message must not contain file contents")
		}
	})

	t.Run("symlink_rejected", func(t *testing.T) {
		linkName := "symlink.ext4"
		linkPath := filepath.Join(dir, linkName)
		if err := os.Symlink(fpath, linkPath); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		staged := privd.StagedFile{Name: linkName, SHA256: correctDigest}
		fd, err := privd.VerifyStagedFile(dir, staged)
		if fd != nil {
			fd.Close()
			t.Error("symlink: expected nil fd, got non-nil (fd leak)")
		}
		if err == nil {
			t.Fatal("symlink: expected error from O_NOFOLLOW, got nil")
		}
	})
}

// ----- TestJailerArgv -----

// TestJailerArgv verifies that JailerArgv builds the exact argv the brief specifies:
//
//	jailer --id <id> --exec-file <fc> --uid <uid> --gid <gid>
//	       --chroot-base-dir <JailBase> --netns /var/run/netns/vmobs-<id>
//	       --cgroup-version 2 --daemonize
//	       -- --config-file fc-config.json --api-sock api.sock
func TestJailerArgv(t *testing.T) {
	cfg := privd.RealOpsCfg{
		JailerPath:      "/usr/local/bin/jailer",
		FirecrackerPath: "/usr/local/bin/firecracker",
		JailBase:        "/srv/vmobs/jail",
	}
	entry := privd.VMEntry{
		VMID: "vm-test-001",
		UID:  20000,
		GID:  20001,
	}

	argv := privd.JailerArgv(cfg, entry)

	ns := network.NamespaceName(entry.VMID)
	netnsPath := "/var/run/netns/" + ns

	want := []string{
		"/usr/local/bin/jailer",
		"--id", "vm-test-001",
		"--exec-file", "/usr/local/bin/firecracker",
		"--uid", "20000",
		"--gid", "20001",
		"--chroot-base-dir", "/srv/vmobs/jail",
		"--netns", netnsPath,
		"--cgroup-version", "2",
		"--daemonize",
		"--",
		"--config-file", "fc-config.json",
		"--api-sock", "api.sock",
	}

	if len(argv) != len(want) {
		t.Fatalf("argv len = %d, want %d\n  got:  %v\n  want: %v", len(argv), len(want), argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}

	// Netns path must use network.NamespaceName, not a hand-built string.
	// Verified above: /var/run/netns/ + network.NamespaceName(id).
	if !strings.HasPrefix(argv[12], "/var/run/netns/") {
		t.Errorf("netns arg must start with /var/run/netns/; got %q", argv[12])
	}
	if !strings.Contains(argv[12], ns) {
		t.Errorf("netns arg %q must contain the namespace name %q", argv[12], ns)
	}
}

// ----- TestSignalIdentityGate -----

// TestSignalIdentityGate verifies the host-level PID identity check:
//   - Reading our own process starttime succeeds and matches ProcStatPath output.
//   - The identity gate refuses to signal when the ledger starttime differs from /proc.
func TestSignalIdentityGate(t *testing.T) {
	selfPID := os.Getpid()

	// Read our own starttime via the exported helper.
	data, err := os.ReadFile(privd.ProcStatPath(selfPID))
	if err != nil {
		t.Fatalf("read /proc/%d/stat: %v", selfPID, err)
	}
	selfStartTime := privd.ParseStartTime(string(data))
	if selfStartTime == "" {
		t.Fatalf("could not parse starttime from own /proc stat")
	}

	t.Run("matching_starttime_is_alive", func(t *testing.T) {
		// PIDAlive with the correct starttime must return true for our own PID.
		if !privd.PIDAlive(selfPID, selfStartTime) {
			t.Error("PIDAlive(selfPID, correct starttime) = false, want true")
		}
	})

	t.Run("wrong_starttime_not_alive", func(t *testing.T) {
		// PIDAlive with a deliberately wrong starttime must return false.
		wrongTime := "99999999"
		if privd.PIDAlive(selfPID, wrongTime) {
			t.Error("PIDAlive(selfPID, wrong starttime) = true, want false")
		}
	})

	t.Run("identity_gate_refuses_on_mismatch", func(t *testing.T) {
		// CheckSignalIdentity with a wrong ledger starttime must return BackendError
		// with cause "invalid_state" and message containing "pid recycled".
		ledgerEntry := privd.VMEntry{
			VMID:      "vm-ident-001",
			PID:       selfPID,
			StartTime: "99999999", // deliberate mismatch
		}
		err := privd.CheckSignalIdentity(ledgerEntry)
		if err == nil {
			t.Fatal("expected error for mismatched identity, got nil")
		}
		var be *privd.BackendError
		if !privd.AsBackendError(err, &be) {
			t.Fatalf("expected BackendError, got %T: %v", err, err)
		}
		if be.Cause != "invalid_state" {
			t.Errorf("cause = %q, want invalid_state", be.Cause)
		}
		if !strings.Contains(be.Message, "pid recycled") {
			t.Errorf("message %q must contain 'pid recycled'", be.Message)
		}
	})

	t.Run("identity_gate_passes_on_match", func(t *testing.T) {
		// CheckSignalIdentity with the correct starttime must return nil.
		ledgerEntry := privd.VMEntry{
			VMID:      "vm-ident-002",
			PID:       selfPID,
			StartTime: selfStartTime,
		}
		err := privd.CheckSignalIdentity(ledgerEntry)
		if err != nil {
			t.Errorf("CheckSignalIdentity with correct starttime: unexpected error: %v", err)
		}
	})
}

// ----- TestVerifyAndCopyFromPinnedFd -----

// TestVerifyAndCopyFromPinnedFd is the RED/GREEN test for the fd-reuse fix.
//
// Protocol:
//  1. Write a known file to a stage dir and compute its digest.
//  2. Call VerifyStagedFile — it must return a non-nil *os.File (the pinned fd).
//  3. Swap the stage path with different content (simulating a TOCTOU attacker).
//  4. Seek the pinned fd to 0 and copy via CopyFromPinnedFd into a destination.
//  5. Assert the destination contains the ORIGINAL content, not the swapped content.
//
// Under the old two-open code, CopyFromPinnedFd did not exist (or reopened by path),
// so this test either fails to compile or copies the swapped content.
func TestVerifyAndCopyFromPinnedFd(t *testing.T) {
	dir := t.TempDir()

	original := []byte("original verified image data")
	swapped := []byte("ATTACKER CONTENT — should never land in jail")
	fname := "rootfs.ext4"
	fpath := filepath.Join(dir, fname)
	if err := os.WriteFile(fpath, original, 0o644); err != nil {
		t.Fatalf("write original: %v", err)
	}

	h := sha256.Sum256(original)
	digest := hex.EncodeToString(h[:])

	staged := privd.StagedFile{Name: fname, SHA256: digest}

	// VerifyStagedFile must now return the open fd on success.
	fd, err := privd.VerifyStagedFile(dir, staged)
	if err != nil {
		t.Fatalf("VerifyStagedFile: %v", err)
	}
	if fd == nil {
		t.Fatal("VerifyStagedFile returned nil fd on success")
	}
	defer fd.Close()

	// TOCTOU attacker replaces the file at the path: remove the original inode
	// and create a new file. os.WriteFile rewrites in-place (same inode, same fd);
	// the real attack is a rename/create that plants a new inode at the path.
	if err := os.Remove(fpath); err != nil {
		t.Fatalf("remove original: %v", err)
	}
	if err := os.WriteFile(fpath, swapped, 0o644); err != nil {
		t.Fatalf("write swapped: %v", err)
	}

	// Copy from the pinned fd — must ignore the swapped path content.
	// Use current uid/gid; chowning to root requires privileges we don't have here.
	dstDir := t.TempDir()
	if err := privd.CopyFromPinnedFd(fd, dstDir, staged, os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("CopyFromPinnedFd: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dstDir, fname))
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("destination contains %q, want original %q", got, original)
	}
	if string(got) == string(swapped) {
		t.Error("destination contains swapped (attacker) content — fd reuse is BROKEN")
	}
}

// TestVerifyStagedFileReturnsNilFdOnMismatch checks that VerifyStagedFile returns
// nil fd (not a leaked fd) when digest verification fails.
func TestVerifyStagedFileReturnsNilFdOnMismatch(t *testing.T) {
	dir := t.TempDir()
	content := []byte("some data")
	fname := "kernel"
	if err := os.WriteFile(filepath.Join(dir, fname), content, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	staged := privd.StagedFile{Name: fname, SHA256: strings.Repeat("a", 64)}
	fd, err := privd.VerifyStagedFile(dir, staged)
	if err == nil {
		t.Fatal("expected digest_mismatch error, got nil")
	}
	if fd != nil {
		fd.Close()
		t.Error("VerifyStagedFile returned non-nil fd on mismatch — fd leak")
	}
}

// ----- TestWireBackendErrorCause -----

// TestWireBackendErrorCause checks that typed BackendErrors from the backend surface
// as the correct wire cause in the server response (not blanket "exec_failed").
func TestWireBackendErrorCause(t *testing.T) {
	tests := []struct {
		name      string
		backendFn func(b *recordingBackend)
		verb      string
		payload   any
		wantCause string
	}{
		{
			name: "start_vm_digest_mismatch",
			backendFn: func(b *recordingBackend) {
				b.startErr = &privd.BackendError{Cause: "digest_mismatch", Message: "file rootfs.ext4: digest mismatch"}
			},
			verb: "start_vm",
			// payload wired below in the test loop
			wantCause: "digest_mismatch",
		},
		{
			name: "signal_vm_invalid_state",
			backendFn: func(b *recordingBackend) {
				b.signalErr = &privd.BackendError{Cause: "invalid_state", Message: "pid recycled"}
			},
			verb:      "signal_vm",
			wantCause: "invalid_state",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sockPath := filepath.Join(dir, "privd.sock")
			stageRoot := filepath.Join(dir, "stage")
			if err := os.MkdirAll(stageRoot, 0o755); err != nil {
				t.Fatalf("mkdir stageroot: %v", err)
			}
			stageDir := filepath.Join(stageRoot, "vm-wire-001")
			if err := os.MkdirAll(stageDir, 0o755); err != nil {
				t.Fatalf("mkdir stagedir: %v", err)
			}
			ledgerDir := filepath.Join(dir, "ledger")
			if err := os.MkdirAll(ledgerDir, 0o755); err != nil {
				t.Fatalf("mkdir ledger: %v", err)
			}

			backend := &recordingBackend{}
			tc.backendFn(backend)

			pid, starttime := spawnShortProcess(t)
			backend.startResp = privd.StartVMResp{PID: pid, StartTime: starttime}

			cfg := privd.ServerCfg{
				AllowedUID: os.Getuid(),
				LedgerDir:  ledgerDir,
				StageRoot:  stageRoot,
				JailBase:   filepath.Join(dir, "jail"),
				UIDMin:     os.Getuid(),
				UIDMax:     os.Getuid() + 100,
				Ops:        backend,
			}
			startServer(t, sockPath, cfg)

			vmID := "vm-wire-001"
			cidr := "10.50.0.0/30"

			// allocate_network first.
			conn := dialPrivd(t, sockPath)
			resp := sendRecv(t, conn, makeReq(t, "allocate_network", privd.AllocateNetworkReq{VMID: vmID, CIDR: cidr}))
			conn.Close()
			if !resp.OK {
				t.Fatalf("allocate_network: %+v", resp)
			}

			var payload any
			switch tc.verb {
			case "start_vm":
				payload = privd.StartVMReq{
					VMID:     vmID,
					UID:      os.Getuid(),
					GID:      os.Getgid(),
					CID:      7,
					StageDir: stageDir,
				}
			case "signal_vm":
				// Need to start_vm with a different (non-error) backend first so the
				// ledger has the entry; then the signal call can hit the signalErr.
				// The start backend has no error set here; only signalErr is set.
				conn2 := dialPrivd(t, sockPath)
				resp2 := sendRecv(t, conn2, makeReq(t, "start_vm", privd.StartVMReq{
					VMID:     vmID,
					UID:      os.Getuid(),
					GID:      os.Getgid(),
					CID:      7,
					StageDir: stageDir,
				}))
				conn2.Close()
				if !resp2.OK {
					t.Fatalf("start_vm (setup for signal): %+v", resp2)
				}
				payload = privd.SignalVMReq{VMID: vmID, Kind: "term"}
			}

			conn3 := dialPrivd(t, sockPath)
			resp3 := sendRecv(t, conn3, makeReq(t, tc.verb, payload))
			conn3.Close()

			if resp3.OK {
				t.Fatalf("%s: expected failure with cause %q, got OK", tc.verb, tc.wantCause)
			}
			if resp3.Cause != tc.wantCause {
				t.Errorf("%s: cause = %q, want %q", tc.verb, resp3.Cause, tc.wantCause)
			}
		})
	}
}

// ----- AbortStartVM -----

// TestParseComm pins the comm extraction AbortStartVM's kill guard depends on.
// The comm field is parenthesised and the kernel lets it contain spaces and
// parens, so the bounds have to be the first '(' and the LAST ')'.
func TestParseComm(t *testing.T) {
	cases := []struct {
		name string
		stat string
		want string
	}{
		{"plain", "4242 (firecracker) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 907199254", "firecracker"},
		{"spaces and parens", "17 (a (weird) name) S 1 17 17 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 5", "a (weird) name"},
		{"no parens", "4242 firecracker S 1", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := privd.ParseComm(tc.stat); got != tc.want {
				t.Errorf("ParseComm = %q, want %q", got, tc.want)
			}
		})
	}
}

// abortOps builds a RealOps over a temp jail base and returns it with that base.
func abortOps(t *testing.T) (*privd.RealOps, string) {
	t.Helper()
	dir := t.TempDir()
	jailBase := filepath.Join(dir, "jail")
	if err := os.MkdirAll(jailBase, 0o750); err != nil {
		t.Fatalf("mkdir jail base: %v", err)
	}
	return privd.NewRealOps(privd.RealOpsCfg{
		JailBase:  jailBase,
		StageRoot: filepath.Join(dir, "stage"),
	}), jailBase
}

// writeJailTree creates <jailBase>/firecracker/<vmID>/root with one stand-in
// boot artifact, and returns the jail dir. This is what StartVM leaves behind
// when it fails after step 2.
func writeJailTree(t *testing.T, jailBase, vmID string) string {
	t.Helper()
	jailDir := filepath.Join(jailBase, "firecracker", vmID)
	root := filepath.Join(jailDir, "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir jail root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "rootfs.ext4"), []byte("boot artifact"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	return jailDir
}

// TestAbortStartVMRemovesJailTree: the partial tree a failed start leaves is
// gone afterwards. Nothing else reclaims it — the ledger entry keeps PID 0, so
// release_vm never runs for this VM.
func TestAbortStartVMRemovesJailTree(t *testing.T) {
	ops, jailBase := abortOps(t)
	jailDir := writeJailTree(t, jailBase, "vm-abort")

	if err := ops.AbortStartVM(privd.VMEntry{VMID: "vm-abort"}); err != nil {
		t.Fatalf("AbortStartVM: %v", err)
	}
	if _, err := os.Stat(jailDir); !os.IsNotExist(err) {
		t.Errorf("jail tree survived the abort (stat err: %v)", err)
	}
}

// TestAbortStartVMIsIdempotent: an abort with no tree to remove is not an error.
// privd can be asked to undo a start that failed before it created anything.
func TestAbortStartVMIsIdempotent(t *testing.T) {
	ops, _ := abortOps(t)
	if err := ops.AbortStartVM(privd.VMEntry{VMID: "vm-never-started"}); err != nil {
		t.Errorf("AbortStartVM on a missing tree = %v, want nil", err)
	}
}

// TestAbortStartVMSparesAForeignPID: the pid file inside a stale jail tree can
// name a recycled pid, so the kill is gated on the process really being a
// firecracker. The pid written here is this test binary's own: if the guard ever
// stops biting, the abort SIGKILLs the test run itself and the failure is
// impossible to miss.
func TestAbortStartVMSparesAForeignPID(t *testing.T) {
	ops, jailBase := abortOps(t)
	jailDir := writeJailTree(t, jailBase, "vm-foreign")
	pidFile := filepath.Join(jailDir, "root", "firecracker.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	if err := ops.AbortStartVM(privd.VMEntry{VMID: "vm-foreign"}); err != nil {
		t.Fatalf("AbortStartVM: %v", err)
	}
	// Reaching this line at all is the assertion: a SIGKILL to our own pid ends
	// the process. The tree still has to be gone.
	if _, err := os.Stat(jailDir); !os.IsNotExist(err) {
		t.Errorf("jail tree survived the abort (stat err: %v)", err)
	}
}

// TestAbortStartVMToleratesAGarbagePIDFile: a truncated or half-written pid file
// must not stop the tree removal, which is the part that always applies.
func TestAbortStartVMToleratesAGarbagePIDFile(t *testing.T) {
	ops, jailBase := abortOps(t)
	jailDir := writeJailTree(t, jailBase, "vm-garbage")
	if err := os.WriteFile(filepath.Join(jailDir, "root", "firecracker.pid"), []byte("not-a-pid"), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}

	if err := ops.AbortStartVM(privd.VMEntry{VMID: "vm-garbage"}); err != nil {
		t.Fatalf("AbortStartVM: %v", err)
	}
	if _, err := os.Stat(jailDir); !os.IsNotExist(err) {
		t.Errorf("jail tree survived the abort (stat err: %v)", err)
	}
}
