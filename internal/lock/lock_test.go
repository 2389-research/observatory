// ABOUTME: Tests for runtime.lock.json loading, hash verification, and the
// ABOUTME: Unpinned helper — AT-002 coverage at the unit level.
package lock_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/lock"
)

// hashOf returns the SHA-256 hex digest of data.
func hashOf(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// makeBinary writes content to dir/name and returns the full path.
func makeBinary(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o755); err != nil {
		t.Fatalf("write binary %s: %v", name, err)
	}
	return p
}

// TestLoadUnknownSchemaError verifies that Load returns an error for an
// unrecognised schema value (the schema field is the version guard).
func TestLoadUnknownSchemaError(t *testing.T) {
	bad := map[string]any{
		"schema": "vmobs.runtime_lock.v99",
	}
	data, _ := json.Marshal(bad)
	path := filepath.Join(t.TempDir(), "bad.lock.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	_, err := lock.Load(path)
	if err == nil {
		t.Fatal("expected error for unknown schema, got nil")
	}
	if !strings.Contains(err.Error(), "vmobs.runtime_lock.v99") {
		t.Errorf("error should name the unknown schema: %v", err)
	}
}

// TestLoadNotFound verifies that Load returns an error when the file is absent.
func TestLoadNotFound(t *testing.T) {
	_, err := lock.Load(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("expected error for absent file, got nil")
	}
}

// TestVerifyBinariesNoMismatches checks that two binaries with correct hashes
// produce zero mismatches (the happy path — AT-002 baseline).
func TestVerifyBinariesNoMismatches(t *testing.T) {
	dir := t.TempDir()
	fcContent := []byte("fake-firecracker-binary")
	jlContent := []byte("fake-jailer-binary")

	fcPath := makeBinary(t, dir, "firecracker", fcContent)
	jlPath := makeBinary(t, dir, "jailer", jlContent)

	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		Firecracker: lock.FirecrackerEntry{
			SHA256:      hashOf(fcContent),
			InstallPath: fcPath,
		},
		Jailer: lock.JailerEntry{
			SHA256:      hashOf(jlContent),
			InstallPath: jlPath,
		},
	}

	mismatches := l.VerifyBinaries()
	if len(mismatches) != 0 {
		t.Errorf("expected no mismatches; got %v", mismatches)
	}
}

// TestVerifyBinariesHashMismatch verifies that flipping one byte in a binary
// produces exactly one Mismatch naming the right subject (AT-002 at unit level).
func TestVerifyBinariesHashMismatch(t *testing.T) {
	dir := t.TempDir()
	fcContent := []byte("fake-firecracker-binary")
	jlContent := []byte("fake-jailer-binary")

	fcPath := makeBinary(t, dir, "firecracker", fcContent)
	jlPath := makeBinary(t, dir, "jailer", jlContent)

	// Corrupt the firecracker binary after computing the hash.
	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		Firecracker: lock.FirecrackerEntry{
			SHA256:      hashOf(fcContent),
			InstallPath: fcPath,
		},
		Jailer: lock.JailerEntry{
			SHA256:      hashOf(jlContent),
			InstallPath: jlPath,
		},
	}

	// Flip one byte.
	corrupted := append([]byte(nil), fcContent...)
	corrupted[0] ^= 0xFF
	if err := os.WriteFile(fcPath, corrupted, 0o755); err != nil {
		t.Fatalf("corrupt binary: %v", err)
	}

	mismatches := l.VerifyBinaries()
	if len(mismatches) != 1 {
		t.Fatalf("expected exactly 1 mismatch; got %d: %v", len(mismatches), mismatches)
	}
	if !strings.Contains(strings.ToLower(mismatches[0].Subject), "firecracker") {
		t.Errorf("mismatch subject should name firecracker: %q", mismatches[0].Subject)
	}
	if mismatches[0].Want != l.Firecracker.SHA256 {
		t.Errorf("mismatch Want should be the pinned hash; got %q", mismatches[0].Want)
	}
}

// TestVerifyBinariesAbsentFile verifies that a missing binary produces a
// Mismatch with Got == "absent".
func TestVerifyBinariesAbsentFile(t *testing.T) {
	dir := t.TempDir()
	jlContent := []byte("fake-jailer-binary")
	jlPath := makeBinary(t, dir, "jailer", jlContent)

	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		Firecracker: lock.FirecrackerEntry{
			SHA256:      "deadbeef", // won't be read — file is absent
			InstallPath: filepath.Join(dir, "nonexistent-firecracker"),
		},
		Jailer: lock.JailerEntry{
			SHA256:      hashOf(jlContent),
			InstallPath: jlPath,
		},
	}

	mismatches := l.VerifyBinaries()
	if len(mismatches) != 1 {
		t.Fatalf("expected 1 mismatch for absent file; got %d: %v", len(mismatches), mismatches)
	}
	if mismatches[0].Got != "absent" {
		t.Errorf("absent file should yield Got=absent; got %q", mismatches[0].Got)
	}
}

// TestVerifyBinariesSkipsEmptySHA verifies that an empty sha256 field does NOT
// produce a Mismatch and does NOT appear in VerifyBinaries results (not pinned
// = skip silently). Unpinned() should list it instead.
func TestVerifyBinariesSkipsEmptySHA(t *testing.T) {
	dir := t.TempDir()
	jlContent := []byte("fake-jailer-binary")
	jlPath := makeBinary(t, dir, "jailer", jlContent)

	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		Firecracker: lock.FirecrackerEntry{
			SHA256:      "", // not yet pinned
			InstallPath: filepath.Join(dir, "nonexistent-firecracker"),
		},
		Jailer: lock.JailerEntry{
			SHA256:      hashOf(jlContent),
			InstallPath: jlPath,
		},
	}

	mismatches := l.VerifyBinaries()
	if len(mismatches) != 0 {
		t.Errorf("empty sha256 must be skipped, not mismatched; got %v", mismatches)
	}
}

// TestUnpinnedListsEmptySHAs verifies that Unpinned() lists all subjects whose
// sha256 is empty (not-yet-pinned artifacts).
func TestUnpinnedListsEmptySHAs(t *testing.T) {
	dir := t.TempDir()
	jlContent := []byte("fake-jailer-binary")
	jlPath := makeBinary(t, dir, "jailer", jlContent)
	rootContent := []byte("fake-rootfs")

	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		Firecracker: lock.FirecrackerEntry{
			SHA256:      "", // not pinned
			InstallPath: filepath.Join(dir, "fc"),
		},
		Jailer: lock.JailerEntry{
			SHA256:      hashOf(jlContent),
			InstallPath: jlPath,
		},
		GuestKernel: lock.GuestKernelEntry{
			VmlinuxSHA256: "", // not pinned
			VmlinuxPath:   "images/dist/vmlinux",
		},
		RootImage: lock.RootImageEntry{
			SHA256: hashOf(rootContent), // pinned — must not appear in Unpinned
			Path:   "images/dist/rootfs.ext4",
		},
	}

	unpinned := l.Unpinned()
	if len(unpinned) != 2 {
		t.Fatalf("expected 2 unpinned entries; got %d: %v", len(unpinned), unpinned)
	}
	// Both firecracker and guest_kernel.vmlinux_sha256 should be named.
	joined := strings.Join(unpinned, " ")
	if !strings.Contains(joined, "firecracker") {
		t.Errorf("unpinned should mention firecracker: %v", unpinned)
	}
	if !strings.Contains(joined, "vmlinux") || !strings.Contains(joined, "guest_kernel") {
		t.Errorf("unpinned should mention guest_kernel vmlinux: %v", unpinned)
	}
}

// TestVerifyArtifactsUnpinnedKernelNoMismatch verifies that an unpinned kernel
// (empty sha256) is skipped by VerifyArtifacts (no mismatch emitted), and
// appears in Unpinned() instead.
func TestVerifyArtifactsUnpinnedKernelNoMismatch(t *testing.T) {
	repoRoot := t.TempDir()

	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		GuestKernel: lock.GuestKernelEntry{
			VmlinuxSHA256: "", // not pinned
			VmlinuxPath:   "images/dist/vmlinux",
		},
		RootImage: lock.RootImageEntry{
			SHA256: "", // not pinned
			Path:   "images/dist/rootfs.ext4",
		},
	}

	mismatches := l.VerifyArtifacts(repoRoot)
	if len(mismatches) != 0 {
		t.Errorf("unpinned artifacts must not produce mismatches; got %v", mismatches)
	}

	unpinned := l.Unpinned()
	if len(unpinned) == 0 {
		t.Error("Unpinned should list the unpinned artifacts")
	}
}

// TestVerifyArtifactsRelativePaths checks that VerifyArtifacts resolves paths
// relative to repoRoot and correctly detects a hash mismatch.
func TestVerifyArtifactsRelativePaths(t *testing.T) {
	repoRoot := t.TempDir()
	imagesDir := filepath.Join(repoRoot, "images", "dist")
	if err := os.MkdirAll(imagesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	vmlinuxContent := []byte("fake-vmlinux-content")
	vmlinuxPath := filepath.Join(imagesDir, "vmlinux")
	if err := os.WriteFile(vmlinuxPath, vmlinuxContent, 0o644); err != nil {
		t.Fatalf("write vmlinux: %v", err)
	}

	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		GuestKernel: lock.GuestKernelEntry{
			VmlinuxSHA256: "badhash", // wrong on purpose
			VmlinuxPath:   "images/dist/vmlinux",
		},
	}

	mismatches := l.VerifyArtifacts(repoRoot)
	if len(mismatches) != 1 {
		t.Fatalf("expected 1 mismatch for wrong hash; got %d: %v", len(mismatches), mismatches)
	}
	if !strings.Contains(strings.ToLower(mismatches[0].Subject), "vmlinux") {
		t.Errorf("mismatch should name vmlinux; got subject %q", mismatches[0].Subject)
	}
}

// TestVerifyArtifactsAbsent verifies that a missing artifact file reports Got="absent".
func TestVerifyArtifactsAbsent(t *testing.T) {
	repoRoot := t.TempDir()

	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		GuestKernel: lock.GuestKernelEntry{
			VmlinuxSHA256: "deadbeef",
			VmlinuxPath:   "images/dist/vmlinux", // does not exist
		},
	}

	mismatches := l.VerifyArtifacts(repoRoot)
	if len(mismatches) != 1 {
		t.Fatalf("expected 1 mismatch for absent artifact; got %d: %v", len(mismatches), mismatches)
	}
	if mismatches[0].Got != "absent" {
		t.Errorf("absent artifact should yield Got=absent; got %q", mismatches[0].Got)
	}
}

// TestLoadRealLockFile parses the committed runtime.lock.json from the repo root
// to guarantee the Lock struct mirrors the actual schema exactly.
func TestLoadRealLockFile(t *testing.T) {
	// Locate this source file's directory so we can find the repo root regardless
	// of where `go test` is invoked from.
	_, thisFile, _, ok := goruntime.Caller(0)
	if !ok {
		t.Skip("could not determine source file path")
	}
	// internal/lock/lock_test.go → ../../.. is the repo root.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	lockPath := filepath.Join(repoRoot, "runtime.lock.json")
	if _, err := os.Stat(lockPath); err != nil {
		t.Skipf("runtime.lock.json not found at %s: %v", lockPath, err)
	}

	l, err := lock.Load(lockPath)
	if err != nil {
		t.Fatalf("Load(runtime.lock.json): %v", err)
	}
	if l.Schema != "vmobs.runtime_lock.v1" {
		t.Errorf("schema = %q, want vmobs.runtime_lock.v1", l.Schema)
	}
	if l.Firecracker.InstallPath == "" {
		t.Error("firecracker.install_path is empty")
	}
	if l.Jailer.InstallPath == "" {
		t.Error("jailer.install_path is empty")
	}
}
