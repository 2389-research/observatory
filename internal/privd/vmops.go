// ABOUTME: RealOps VM half: StartVM (fd-pinned digest-verified staging + jailer exec),
// ABOUTME: SignalVM (identity-gated), ReleaseVM (jail dir removal). Linux only.

//go:build linux

package privd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/2389-research/observatory-v2/internal/network"
	"golang.org/x/sys/unix"
)

// VerifyStagedFile opens the named file in stageDir using O_NOFOLLOW (refuses symlinks),
// streams its SHA-256 from the open fd, and returns the open *os.File on success.
// On any error (including digest mismatch) the fd is closed and nil is returned.
// Callers must close the returned *os.File. This is the TOCTOU-safe entry point:
// the same fd is used for the subsequent copy (via CopyFromPinnedFd) so the path
// is never reopened after verification.
//
// §15.3: error messages name the file, never dump its contents.
func VerifyStagedFile(stageDir string, f StagedFile) (*os.File, error) {
	// The name is joined onto stageDir here and onto the jail root by
	// CopyFromPinnedFd. Both joins are only as safe as the name, and this
	// function is exported: the server's check is the gate, and this one is what
	// makes the gate's absence in some future caller a refusal instead of a
	// traversal.
	if !ValidStagedName(f.Name) {
		return nil, &BackendError{
			Cause:   "bad_request",
			Message: fmt.Sprintf("%q is not a staged file name", truncateName(f.Name)),
		}
	}
	fpath := filepath.Join(stageDir, f.Name)

	// O_NOFOLLOW: if the path is a symlink the open fails (ELOOP on Linux).
	fd, err := unix.Open(fpath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("privd: open staged file %q: %w", f.Name, err)
	}
	file := os.NewFile(uintptr(fd), fpath)

	// fstat: confirm regular file.
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		file.Close()
		return nil, fmt.Errorf("privd: fstat staged file %q: %w", f.Name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		file.Close()
		return nil, fmt.Errorf("privd: staged file %q is not a regular file", f.Name)
	}

	// Stream SHA-256 from the open fd.
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		file.Close()
		return nil, fmt.Errorf("privd: hash staged file %q: %w", f.Name, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != f.SHA256 {
		file.Close()
		return nil, &BackendError{
			Cause:   "digest_mismatch",
			Message: fmt.Sprintf("file %s: digest mismatch (got %s, want %s)", f.Name, got, f.SHA256),
		}
	}
	// fd position is after the last byte — caller must Seek(0, io.SeekStart) before copying.
	return file, nil
}

// CopyFromPinnedFd copies from the already-verified *os.File (seeks to 0 first) into
// dstDir/<f.Name>. This is the second half of the single-open staging pipeline: the fd
// was opened and digest-verified by VerifyStagedFile; we never reopen the path.
// Mode: 0644 for most files, 0640 for fc-config.json. Chowns to uid:gid.
func CopyFromPinnedFd(src *os.File, dstDir string, f StagedFile, uid, gid int) error {
	// Seek the verified fd back to the start — same open, never a new path open.
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("privd: seek staged file %q: %w", f.Name, err)
	}

	mode := os.FileMode(0o644)
	if f.Name == "fc-config.json" {
		mode = 0o640
	}

	dstPath := filepath.Join(dstDir, f.Name)
	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("privd: create dst %q: %w", f.Name, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("privd: copy %q: %w", f.Name, err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("privd: close dst %q: %w", f.Name, err)
	}

	// chown to uid:gid.
	if err := os.Lchown(dstPath, uid, gid); err != nil {
		return fmt.Errorf("privd: chown %q: %w", f.Name, err)
	}
	return nil
}

// JailerArgv builds the jailer command argv from cfg and entry.
// Pure function — no filesystem access; safe to call in portable tests.
//
// Produces:
//
//	jailer --id <id> --exec-file <fc> --uid <uid> --gid <gid>
//	       --chroot-base-dir <JailBase> --netns /var/run/netns/vmobs-<id>
//	       --cgroup-version 2 --daemonize
//	       -- --config-file fc-config.json --api-sock api.sock
func JailerArgv(cfg RealOpsCfg, entry VMEntry) []string {
	nsName := network.NamespaceName(entry.VMID)
	netnsPath := "/var/run/netns/" + nsName
	return []string{
		cfg.JailerPath,
		"--id", entry.VMID,
		"--exec-file", cfg.FirecrackerPath,
		"--uid", strconv.Itoa(entry.UID),
		"--gid", strconv.Itoa(entry.GID),
		"--chroot-base-dir", cfg.JailBase,
		"--netns", netnsPath,
		"--cgroup-version", "2",
		"--daemonize",
		"--",
		"--config-file", "fc-config.json",
		"--api-sock", "api.sock",
	}
}

// openProcess takes a descriptor on pid before anything is checked about it.
//
// os.FindProcess calls pidfd_open on Linux, and the Signal that follows goes
// through pidfd_send_signal rather than kill(2). That is the whole point: a pid
// is a number the host reissues, so between reading /proc to decide a process is
// ours and signalling it there is a window in which the number can come to mean
// a different process -- and privd signals as root, on behalf of a caller that
// is not.
//
// Opening first is what closes that window, and it closes it either way round.
// A pid already recycled when this runs is refused by the starttime compare that
// follows. A pid recycled after this runs cannot redirect the signal, because
// the descriptor still names the process that was opened; the signal reaches a
// process that is gone and returns ESRCH. Neither case rests on the kernel
// keeping the pid number reserved for as long as the descriptor is held.
//
// os.FindProcess reports no error for a process that is gone -- it hands back a
// value whose every operation fails -- so the zero signal is what asks. Callers
// must Release the returned process.
func openProcess(pid int) (*os.Process, error) {
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil, err
	}
	if err := p.Signal(syscall.Signal(0)); err != nil {
		_ = p.Release()
		return nil, err
	}
	return p, nil
}

// CheckSignalIdentity re-reads /proc/<pid>/stat and returns a BackendError with
// cause "invalid_state" and message "pid recycled" if the starttime does not match
// the ledger entry. If the pid has no /proc entry, it is also treated as mismatch.
//
// This is a host check done at signal time — the server's in-memory ledger may be stale.
func CheckSignalIdentity(entry VMEntry) error {
	data, err := os.ReadFile(ProcStatPath(entry.PID))
	if err != nil {
		// Process gone — starttime cannot match.
		return &BackendError{
			Cause:   "invalid_state",
			Message: "pid recycled",
		}
	}
	cur := ParseStartTime(string(data))
	if cur == "" || cur != entry.StartTime {
		return &BackendError{
			Cause:   "invalid_state",
			Message: "pid recycled",
		}
	}
	return nil
}

// StartVM implements OpsBackend.StartVM.
//
// Steps:
//  1. Verify each StagedFile: O_NOFOLLOW open, fstat, SHA-256 from fd.
//  2. Copy each verified fd into <JailBase>/firecracker/<id>/root/ (dirs 0750),
//     chown uid:gid, mode 0644 (fc-config.json gets 0640).
//  3. Exec jailer (via RunCmd hook if set, otherwise exec.CommandContext).
//     Wait up to 10s for <root>/v.sock, then chmod root 0750.
//  4. Read <root>/firecracker.pid, read /proc/<pid>/stat field 22, return both.
func (r *RealOps) StartVM(entry *VMEntry, req StartVMReq) (StartVMResp, error) {
	stageDir := req.StageDir

	// Step 1: verify all staged files, keeping each fd open (single-open pipeline).
	// All files are verified before any jail dir is touched; on any mismatch we
	// close all open fds and abort.
	fds := make([]*os.File, len(req.Files))
	for i, f := range req.Files {
		pinned, err := VerifyStagedFile(stageDir, f)
		if err != nil {
			// Close fds opened so far.
			for _, open := range fds[:i] {
				open.Close()
			}
			return StartVMResp{}, err
		}
		fds[i] = pinned
	}

	// Step 2: create jail dirs and copy each file from its pinned fd.
	// The path is never reopened — CopyFromPinnedFd seeks to 0 and reads the
	// same fd that was digest-verified above, closing the TOCTOU window entirely.
	root := filepath.Join(r.cfg.JailBase, "firecracker", req.VMID, "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		for _, f := range fds {
			f.Close()
		}
		return StartVMResp{}, fmt.Errorf("privd: mkdir jail root %q: %w", root, err)
	}

	for i, f := range req.Files {
		err := CopyFromPinnedFd(fds[i], root, f, req.UID, req.GID)
		fds[i].Close() // close immediately after copy, regardless of outcome
		if err != nil {
			// Close remaining open fds.
			for _, open := range fds[i+1:] {
				open.Close()
			}
			return StartVMResp{}, err
		}
	}

	// chown the whole jail tree to uid:gid (matching the helper's `chown -R`).
	jailDir := filepath.Join(r.cfg.JailBase, "firecracker", req.VMID)
	if err := chownTree(jailDir, req.UID, req.GID); err != nil {
		return StartVMResp{}, fmt.Errorf("privd: chown jail: %w", err)
	}

	// Step 3: exec jailer.
	argv := JailerArgv(r.cfg, *entry)
	if r.hooks.RunCmd != nil {
		if err := r.hooks.RunCmd(argv); err != nil {
			return StartVMResp{}, fmt.Errorf("privd: jailer exec: %w", err)
		}
	} else {
		ctx := context.Background()
		/* #nosec G204 — argv is built from JailerArgv, literal path constants only. */
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return StartVMResp{}, fmt.Errorf("privd: jailer: %w: %s", err, truncateStderr(stderr.Bytes()))
		}

		// Wait for v.sock (100 × 100ms = 10s), then fix the chmod race.
		// Jailer tightens the chroot root to 0700 mid-startup; we reopen to 0750
		// strictly after firecracker binds v.sock (which follows jailer's chroot prep).
		sockPath := filepath.Join(root, "v.sock")
		sockFound := false
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(sockPath); err == nil {
				sockFound = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !sockFound {
			r.log.Printf("v.sock not found after 10s at %s — proceeding with chmod anyway", sockPath)
		}
		if err := os.Chmod(root, 0o750); err != nil {
			r.log.Printf("chmod jail root 0750: %v (non-fatal)", err)
		}
	}

	// Step 4: read firecracker.pid and derive starttime.
	pidFile := filepath.Join(root, "firecracker.pid")
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		return StartVMResp{}, fmt.Errorf("privd: read firecracker.pid: %w", err)
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(pidData)))
	if err != nil {
		return StartVMResp{}, fmt.Errorf("privd: parse firecracker.pid %q: %w", string(pidData), err)
	}

	statData, err := os.ReadFile(ProcStatPath(pid))
	if err != nil {
		return StartVMResp{}, fmt.Errorf("privd: read /proc/%d/stat: %w", pid, err)
	}
	startTime := ParseStartTime(string(statData))
	if startTime == "" {
		return StartVMResp{}, fmt.Errorf("privd: could not parse starttime from /proc/%d/stat", pid)
	}

	return StartVMResp{PID: pid, StartTime: startTime}, nil
}

// AbortStartVM implements OpsBackend.AbortStartVM: undo a start that failed
// partway through.
//
// Two things survive such a failure. The jail tree is the certain one — StartVM
// creates <JailBase>/firecracker/<id>/root and copies the boot artifacts into it
// before it reaches any step that can report an error, so a failure at step 3 or
// 4 leaves gigabytes behind. The other is a live firecracker: the jailer exec
// can succeed and the pid read that follows can fail, and then the VMM runs with
// its pid recorded nowhere — not in the ledger, which the server writes only on
// success, and not in the jailer's manifest, which is written only after
// start_vm returns. Nothing would ever find it again.
//
// So kill first, then remove: an unlinked chroot would leave a running VMM with
// no pid file for anyone to find it by. Returning an error here is advisory —
// the server surfaces the original start failure, not this one — which is why
// every step that does not happen is logged instead.
func (r *RealOps) AbortStartVM(entry VMEntry) error {
	jailDir := filepath.Join(r.cfg.JailBase, "firecracker", entry.VMID)
	r.killJailedVMM(jailDir, entry.VMID)
	if err := os.RemoveAll(jailDir); err != nil {
		return fmt.Errorf("privd: abort start %s: remove jail dir %q: %w", entry.VMID, jailDir, err)
	}
	return nil
}

// procCmdline reads /proc/<pid>/cmdline and splits it into argv elements. The
// file holds the arguments the process was execed with, NUL-terminated, and it
// reads the same from every mount namespace — which is why the identity check
// below asks it and not /proc/<pid>/root.
//
// A process with no argv left to report — a kernel thread, or a zombie whose
// memory the kernel has already released — reads as zero bytes and yields no
// elements.
func procCmdline(pid int) ([]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSuffix(data, []byte{0})
	if len(data) == 0 {
		return nil, nil
	}
	parts := bytes.Split(data, []byte{0})
	argv := make([]string, 0, len(parts))
	for _, p := range parts {
		argv = append(argv, string(p))
	}
	return argv, nil
}

// argvServesVM reports whether argv carries "--id" and vmID as two adjacent
// elements — how the jailer names the VM to the firecracker it execs.
//
// Element equality, never a substring of the joined line: every jail path is
// keyed by the VM id, so a process that merely mentions this VM in a path (the
// runner's --uds is one) would match a substring search and take a SIGKILL for
// it.
func argvServesVM(argv []string, vmID string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "--id" && argv[i+1] == vmID {
			return true
		}
	}
	return false
}

// killJailedVMM SIGKILLs the firecracker named by the pid file inside jailDir,
// when there is one and the process it names really is this VM's firecracker.
//
// Identity is what makes this safe to do at all. StartVM's MkdirAll does not
// clear the tree, so a chroot left by an earlier failed start can carry a pid
// file naming a process that exited long ago — and pids are recycled (SPEC §5.5
// asks for more than a pid). There is no starttime to compare against: the
// failure being undone is precisely that StartVM never got to read one.
//
// Two cheap reads stand in for it. /proc/<pid>/stat's comm keeps the kill off
// every process that is not a firecracker at all — but on a host whose whole job
// is running firecrackers, the process that inherits a recycled pid is
// disproportionately another VM's VMM, and comm cannot tell two firecrackers
// apart. So /proc/<pid>/cmdline must also carry "--id <vmID>": the jailer passes
// the VM id straight through to the firecracker it execs (JailerArgv builds it
// from the same id), so those two argv elements say which VM this process serves.
//
// The host cannot ask a jailed VMM where its root is. The jailer unshares a
// mount namespace and pivot_roots into the jail, so the jail root exists as a
// mount only inside that namespace and the kernel cannot express it as a path
// here — reading /proc/<pid>/root from privd never yields <jailDir>/root, and a
// check on it withholds every kill. cmdline reads the same from every namespace.
// It is also world-readable, which matters because the VMM runs as another uid.
//
// Anything that leaves identity unproven — an unparsable comm, a cmdline that
// cannot be read, an argv that does not name this VM (an empty one included: a
// zombie needs no killing) — withholds the kill and logs the argv it saw. A
// leaked VMM costs memory and disk until an operator finds it; SIGKILLing a
// healthy neighbour destroys a guest that was doing nothing wrong. The log is
// what makes a wrong guess about the argv visible: if a future jailer ever
// spelled it "--id=<vmID>", every withheld kill would print the spelling that
// defeated it.
func (r *RealOps) killJailedVMM(jailDir, vmID string) {
	pidFile := filepath.Join(jailDir, "root", "firecracker.pid")
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		return // no pid file: the jailer never got far enough to write one
	}
	raw := string(bytes.TrimSpace(pidData))
	pid, err := strconv.Atoi(raw)
	if err != nil || pid <= 1 {
		r.log.Printf("abort start %s: firecracker.pid holds %q, which is not a pid; killing nothing", vmID, raw)
		return
	}
	// The descriptor comes before the three reads that decide whether to kill.
	// This path has the longer window of the two -- stat, then comm, then cmdline,
	// then the signal -- and it is the one running while a start is already going
	// wrong, so the pid it holds is the likeliest in privd to have been freed.
	p, err := openProcess(pid)
	if err != nil {
		return // process already gone; nothing to kill
	}
	defer func() { _ = p.Release() }()

	statData, err := os.ReadFile(ProcStatPath(pid))
	if err != nil {
		return // process already gone; nothing to kill
	}
	if comm := ParseComm(string(statData)); comm != "firecracker" {
		r.log.Printf("abort start %s: pid %d is %q, not firecracker; leaving it alone — a vmm may survive this rollback", vmID, pid, comm)
		return
	}
	argv, err := procCmdline(pid)
	if err != nil {
		r.log.Printf("abort start %s: cannot read the argv of firecracker pid %d (%v); leaving it alone — a vmm may survive this rollback", vmID, pid, err)
		return
	}
	if !argvServesVM(argv, vmID) {
		r.log.Printf("abort start %s: firecracker pid %d has argv %q, which does not carry --id %s; leaving it alone — a vmm may survive this rollback", vmID, pid, argv, vmID)
		return
	}
	if err := p.Signal(unix.SIGKILL); err != nil {
		r.log.Printf("abort start %s: kill firecracker pid %d: %v", vmID, pid, err)
		return
	}
	r.log.Printf("abort start %s: killed firecracker pid %d left running by a failed start", vmID, pid)
}

// SignalVM implements OpsBackend.SignalVM.
// Re-reads /proc to verify identity before signalling (§5.5).
func (r *RealOps) SignalVM(entry VMEntry, kind string) error {
	// The kind is decided before a descriptor is taken: a caller that asked for
	// a signal privd does not send has nothing to open.
	var sig unix.Signal
	switch kind {
	case "term":
		sig = unix.SIGTERM
	case "kill":
		sig = unix.SIGKILL
	default:
		return fmt.Errorf("privd: unknown signal kind %q", kind)
	}

	// Pin the process, then check it, then signal it. A process already gone
	// gives the same answer the identity gate would have: there is nothing here
	// that matches the ledger.
	p, err := openProcess(entry.PID)
	if err != nil {
		return &BackendError{Cause: "invalid_state", Message: "pid recycled"}
	}
	defer func() { _ = p.Release() }()

	// Identity gate: re-read /proc at signal time.
	if err := CheckSignalIdentity(entry); err != nil {
		return err
	}

	if err := p.Signal(sig); err != nil {
		return fmt.Errorf("privd: kill pid %d: %w", entry.PID, err)
	}
	return nil
}

// ReleaseVM implements OpsBackend.ReleaseVM.
// Host ops only: remove <JailBase>/firecracker/<id>.
// The server gates aliveness before calling; no re-check here (single source of truth).
func (r *RealOps) ReleaseVM(entry VMEntry) error {
	jailDir := filepath.Join(r.cfg.JailBase, "firecracker", entry.VMID)
	if err := os.RemoveAll(jailDir); err != nil {
		return fmt.Errorf("privd: remove jail dir %q: %w", jailDir, err)
	}
	return nil
}

// chownTree walks dir recursively and chowns each entry to uid:gid.
// Matches jailer's expectation that it inherits a properly-owned tree.
func chownTree(dir string, uid, gid int) error {
	return filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e := os.Lchown(path, uid, gid); e != nil {
			return fmt.Errorf("chown %q: %w", path, e)
		}
		return nil
	})
}
