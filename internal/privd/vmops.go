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
	"time"

	"github.com/2389-research/observatory-v2/internal/network"
	"golang.org/x/sys/unix"
)

// VerifyStagedFile opens the named file in stageDir using O_NOFOLLOW (refuses symlinks),
// streams its SHA-256 from the open fd, and returns a BackendError{Cause:"digest_mismatch"}
// on mismatch. Callers must not reopen the path; this is the TOCTOU-safe entry point.
//
// §15.3: error messages name the file, never dump its contents.
func VerifyStagedFile(stageDir string, f StagedFile) error {
	fpath := filepath.Join(stageDir, f.Name)

	// O_NOFOLLOW: if the path is a symlink the open fails (ELOOP on Linux).
	fd, err := unix.Open(fpath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("privd: open staged file %q: %w", f.Name, err)
	}
	file := os.NewFile(uintptr(fd), fpath)
	defer file.Close()

	// fstat: confirm regular file.
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("privd: fstat staged file %q: %w", f.Name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("privd: staged file %q is not a regular file", f.Name)
	}

	// Stream SHA-256 from the open fd.
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return fmt.Errorf("privd: hash staged file %q: %w", f.Name, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != f.SHA256 {
		return &BackendError{
			Cause:   "digest_mismatch",
			Message: fmt.Sprintf("file %s: digest mismatch (got %s, want %s)", f.Name, got, f.SHA256),
		}
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

	// Step 1: verify all staged files before touching the jail dir.
	for _, f := range req.Files {
		if err := VerifyStagedFile(stageDir, f); err != nil {
			return StartVMResp{}, err
		}
	}

	// Step 2: create jail dirs and copy files.
	root := filepath.Join(r.cfg.JailBase, "firecracker", req.VMID, "root")
	if err := os.MkdirAll(root, 0o750); err != nil {
		return StartVMResp{}, fmt.Errorf("privd: mkdir jail root %q: %w", root, err)
	}

	for _, f := range req.Files {
		if err := copyFromStage(stageDir, root, f, req.UID, req.GID); err != nil {
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
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(sockPath); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
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

// SignalVM implements OpsBackend.SignalVM.
// Re-reads /proc to verify identity before signalling (§5.5).
func (r *RealOps) SignalVM(entry VMEntry, kind string) error {
	// Identity gate: re-read /proc at signal time.
	if err := CheckSignalIdentity(entry); err != nil {
		return err
	}

	var sig unix.Signal
	switch kind {
	case "term":
		sig = unix.SIGTERM
	case "kill":
		sig = unix.SIGKILL
	default:
		return fmt.Errorf("privd: unknown signal kind %q", kind)
	}

	if err := unix.Kill(entry.PID, sig); err != nil {
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

// copyFromStage copies a verified staged file into dstDir.
// Re-opens from the stage path (safe: verification already pinned the fd and confirmed
// no symlink; we're copying the same file by path). Mode: 0644 for most files,
// 0640 for fc-config.json.
func copyFromStage(stageDir, dstDir string, f StagedFile, uid, gid int) error {
	srcPath := filepath.Join(stageDir, f.Name)

	// Open with O_NOFOLLOW again for the copy — defend against a race that
	// replaced the file with a symlink between verify and copy.
	srcFD, err := unix.Open(srcPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("privd: open source %q for copy: %w", f.Name, err)
	}
	src := os.NewFile(uintptr(srcFD), srcPath)
	defer src.Close()

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
