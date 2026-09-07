// ABOUTME: Real-host rejection gate for pinned artifact admission — a tampered,
// ABOUTME: symlinked or world-writable artifact fails the launch and leaks nothing.

//go:build linux

package integration_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// disposableArtifactRoot builds a throwaway artifact root: a copy of the real
// runtime.lock.json beside images/dist entries that are hard links to the
// promoted artifacts. The lock's digests still describe those bytes, so the
// tree boots a VM unless a case deliberately breaks it.
//
// Hard links, not copies: the pinned kernel is 548 MiB and the root image is
// 1 GiB, and the host's own gate already needs ~21 GB free. Removing a link
// leaves the promoted file alone, and no case here writes through one — the
// byte-flip case replaces its link with a private copy first, and the
// world-writable case chmods the directory, which is this tree's own.
func disposableArtifactRoot(t *testing.T, repoRoot string) string {
	t.Helper()

	root := t.TempDir()
	dist := filepath.Join(root, "images", "dist")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dist, err)
	}
	if err := copyFile(filepath.Join(repoRoot, "runtime.lock.json"), filepath.Join(root, "runtime.lock.json"), 0o644); err != nil {
		t.Fatalf("copy runtime.lock.json: %v", err)
	}
	for _, name := range []string{"vmlinux", "rootfs.ext4"} {
		src := filepath.Join(repoRoot, "images", "dist", name)
		dst := filepath.Join(dist, name)
		if err := os.Link(src, dst); err != nil {
			// Different filesystem, or a link count limit: fall back to a copy
			// rather than skip. A skipped case is not a rejection proof.
			if cErr := copyFile(src, dst, 0o644); cErr != nil {
				t.Fatalf("stage %s (link: %v): %v", name, err, cErr)
			}
		}
	}
	return root
}

// privateCopyOfKernel replaces the hard-linked kernel with a private copy this
// test owns, so a later write cannot reach the promoted artifact.
func privateCopyOfKernel(t *testing.T, root, repoRoot string) string {
	t.Helper()

	dst := filepath.Join(root, "images", "dist", "vmlinux")
	if err := os.Remove(dst); err != nil {
		t.Fatalf("unlink staged kernel: %v", err)
	}
	if err := copyFile(filepath.Join(repoRoot, "images", "dist", "vmlinux"), dst, 0o644); err != nil {
		t.Fatalf("copy kernel: %v", err)
	}
	return dst
}

// flipOneByte inverts a single byte in the middle of path. One byte in the
// middle of a 548 MiB file is the tamper a whole-file digest exists to catch;
// a truncated or obviously-wrong stand-in would prove far less.
func flipOneByte(t *testing.T, path string) int64 {
	t.Helper()

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s for tamper: %v", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	off := info.Size() / 2

	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		t.Fatalf("read byte at %d: %v", off, err)
	}
	b[0] = ^b[0]
	if _, err := f.WriteAt(b[:], off); err != nil {
		t.Fatalf("write byte at %d: %v", off, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	return off
}

// TestArtifactAdmissionRejection is the Linux/KVM rejection gate for pinned
// artifact admission. It runs a real vmobsd against the installed privd on a
// host that can actually boot VMs, points it at a deliberately broken artifact
// tree, and asserts two things per case: the launch fails for the stated
// reason, and the host allocates nothing on the way to that failure.
//
// The second half is the point. A refusal that still cut a netns, a veth pair,
// a jail directory or a stage directory would be a refusal that leaks, and the
// per-boot cost of the leak would land on a host that boots VMs all day. Each
// observable is the same one AT-018 watches, read before the create and again
// after the VM reaches failed.
//
// State-directory entries are deliberately not asserted: POST /vms writes the
// VM's record before any launch runs, and that record is what lets an operator
// read the failure back. It is a row, not a host resource.
//
// Guard: VMOBS_FIXTURE=1 plus the same prerequisites as the M1a gate.
func TestArtifactAdmissionRejection(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 to run the artifact admission rejection gate (requires installed vmobs-privd; must NOT run as root)")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)

	if os.Getuid() == 0 {
		t.Fatal("must not run as root; privileged ops flow through privd socket only")
	}

	repoRoot := findRepoRoot(t)
	daemonBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd")
	runnerBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner")

	cases := []struct {
		name string
		// breakIt damages the disposable tree and returns a line of evidence
		// naming what it did, for the failure message.
		breakIt  func(t *testing.T, root string) string
		wantSaid string
	}{
		{
			name: "changed_bytes",
			breakIt: func(t *testing.T, root string) string {
				kernel := privateCopyOfKernel(t, root, repoRoot)
				off := flipOneByte(t, kernel)
				return fmt.Sprintf("inverted one byte at offset %d of %s", off, kernel)
			},
			wantSaid: "do not match the pinned digest",
		},
		{
			name: "symlinked_artifact",
			breakIt: func(t *testing.T, root string) string {
				kernel := filepath.Join(root, "images", "dist", "vmlinux")
				if err := os.Remove(kernel); err != nil {
					t.Fatalf("unlink staged kernel: %v", err)
				}
				promoted := filepath.Join(repoRoot, "images", "dist", "vmlinux")
				if err := os.Symlink(promoted, kernel); err != nil {
					t.Fatalf("symlink kernel: %v", err)
				}
				return fmt.Sprintf("replaced %s with a symlink to %s (the pinned bytes, at an untrusted name)", kernel, promoted)
			},
			wantSaid: "is a symlink",
		},
		{
			name: "world_writable_artifact_dir",
			breakIt: func(t *testing.T, root string) string {
				dist := filepath.Join(root, "images", "dist")
				if err := os.Chmod(dist, 0o777); err != nil {
					t.Fatalf("chmod %s: %v", dist, err)
				}
				return fmt.Sprintf("chmod 0777 %s (the pinned bytes, where anyone can replace them)", dist)
			},
			wantSaid: "is world-writable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			artifactRoot := disposableArtifactRoot(t, repoRoot)
			what := tc.breakIt(t, artifactRoot)
			t.Logf("%s: %s", tc.name, what)

			daemon := startDaemon(t, artifactRoot, daemonBin, runnerBin, "sd56-"+tc.name)
			daemon.disposeSubtestVMs(t)

			before := captureBaseline(t, daemon.stateDir, daemon.runtimeDir)

			vmID := daemon.createVM(t, "admission-"+tc.name)

			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			daemon.waitVMState(ctx, t, vmID, "failed")

			vm := daemon.apiGet(t, "/vms/"+vmID)
			failure, _ := vm["failure"].(map[string]any)
			if failure == nil {
				t.Fatalf("failed VM carries no failure block: %v", vm)
			}
			reason, _ := failure["reason"].(string)
			if !strings.Contains(reason, tc.wantSaid) {
				t.Errorf("launch failed for the wrong reason\n got: %s\nwant it to say: %q\n(after: %s)", reason, tc.wantSaid, what)
			}

			after := captureBaseline(t, daemon.stateDir, daemon.runtimeDir)
			for _, obs := range []struct {
				name          string
				before, after int
			}{
				{"netns", before.NetnsCount, after.NetnsCount},
				{"veth", before.VethCount, after.VethCount},
				{"jail dirs", before.JailEntries, after.JailEntries},
				{"firecracker processes", before.FcProcCount, after.FcProcCount},
				{"stage dirs", before.StageDirEntries, after.StageDirEntries},
			} {
				if obs.after > obs.before {
					t.Errorf("refused launch allocated %s: before=%d after=%d — a refusal must cost the host nothing",
						obs.name, obs.before, obs.after)
				}
			}
		})
	}
}
