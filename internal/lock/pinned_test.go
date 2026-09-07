// ABOUTME: Tests for OpenPinned — the descriptor-anchored artifact admission
// ABOUTME: gate: trusted-path refusals, digest binding, and honest classification.
package lock_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/lock"
)

// pinnedFixture builds a trusted root holding images/dist/<name> and returns
// the root and the artifact's digest. Directory modes are set with Chmod rather
// than MkdirAll's argument because umask masks the latter.
func pinnedFixture(t *testing.T, name string, content []byte) (root, digest string) {
	t.Helper()
	root = t.TempDir()
	dist := filepath.Join(root, "images", "dist")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatalf("mkdir images/dist: %v", err)
	}
	for _, d := range []string{root, filepath.Join(root, "images"), dist} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatalf("chmod %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(dist, name), content, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return root, hashOf(content)
}

// TestOpenPinnedReturnsTheDescriptorItHashed is the binding proof: what
// OpenPinned verified is what the caller reads. The path is swapped for
// different bytes by rename — a new inode, the way a real substitution would
// arrive — after OpenPinned returns and before the caller reads.
func TestOpenPinnedReturnsTheDescriptorItHashed(t *testing.T) {
	original := []byte("the bytes the lock pins")
	root, digest := pinnedFixture(t, "vmlinux", original)

	f, err := lock.OpenPinned(root, "images/dist/vmlinux", digest)
	if err != nil {
		t.Fatalf("OpenPinned: %v", err)
	}
	defer f.Close()

	// Substitute the path with a different inode holding different bytes.
	decoy := filepath.Join(root, "images", "dist", "decoy")
	if err := os.WriteFile(decoy, []byte("substituted after verification!!"), 0o644); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	if err := os.Rename(decoy, filepath.Join(root, "images", "dist", "vmlinux")); err != nil {
		t.Fatalf("rename decoy over vmlinux: %v", err)
	}

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read verified descriptor: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("verified descriptor read %q; the path was substituted after verification and the descriptor followed it", got)
	}
}

// TestOpenPinnedRefusesChangedBytes checks the digest gate itself, and that the
// refusal is classified as changed bytes rather than an unsafe path.
func TestOpenPinnedRefusesChangedBytes(t *testing.T) {
	root, _ := pinnedFixture(t, "vmlinux", []byte("actual bytes on disk"))
	pinned := hashOf([]byte("the bytes the lock expected"))

	f, err := lock.OpenPinned(root, "images/dist/vmlinux", pinned)
	if f != nil {
		f.Close()
		t.Error("OpenPinned returned a descriptor for bytes that failed verification")
	}
	if !errors.Is(err, lock.ErrBytesChanged) {
		t.Fatalf("want ErrBytesChanged, got %v", err)
	}
	if errors.Is(err, lock.ErrUnsafePath) || errors.Is(err, os.ErrNotExist) {
		t.Errorf("changed bytes must not be classified as an unsafe path or a missing file: %v", err)
	}
}

// TestOpenPinnedRefusesASymlinkedArtifact refuses a symlinked leaf. The target
// holds the pinned bytes, so the digest gate would pass it: the refusal has to
// come from the path check or not at all.
func TestOpenPinnedRefusesASymlinkedArtifact(t *testing.T) {
	content := []byte("pinned bytes reachable through a link")
	root, digest := pinnedFixture(t, "elsewhere", content)
	dist := filepath.Join(root, "images", "dist")
	if err := os.Symlink(filepath.Join(dist, "elsewhere"), filepath.Join(dist, "vmlinux")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	f, err := lock.OpenPinned(root, "images/dist/vmlinux", digest)
	if f != nil {
		f.Close()
		t.Error("OpenPinned returned a descriptor for a symlinked artifact")
	}
	if !errors.Is(err, lock.ErrUnsafePath) {
		t.Fatalf("want ErrUnsafePath, got %v", err)
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("refusal should say the path is a symlink: %v", err)
	}
}

// TestOpenPinnedRefusesASymlinkedParent covers the directory half: the leaf is a
// regular file with the pinned bytes, reached through a symlinked parent.
func TestOpenPinnedRefusesASymlinkedParent(t *testing.T) {
	content := []byte("pinned bytes under a linked directory")
	root, digest := pinnedFixture(t, "vmlinux", content)
	real := filepath.Join(root, "images", "dist")
	linked := filepath.Join(root, "images", "link")
	if err := os.Symlink(real, linked); err != nil {
		t.Fatalf("symlink dir: %v", err)
	}

	f, err := lock.OpenPinned(root, "images/link/vmlinux", digest)
	if f != nil {
		f.Close()
		t.Error("OpenPinned returned a descriptor reached through a symlinked parent")
	}
	if !errors.Is(err, lock.ErrUnsafePath) {
		t.Fatalf("want ErrUnsafePath, got %v", err)
	}
}

// TestOpenPinnedRefusesAWritableParent refuses an artifact whose parent anyone
// can replace entries in. The bytes match; the placement is the problem.
func TestOpenPinnedRefusesAWritableParent(t *testing.T) {
	content := []byte("pinned bytes in a world-writable directory")
	root, digest := pinnedFixture(t, "vmlinux", content)
	if err := os.Chmod(filepath.Join(root, "images", "dist"), 0o777); err != nil {
		t.Fatalf("chmod dist: %v", err)
	}

	f, err := lock.OpenPinned(root, "images/dist/vmlinux", digest)
	if f != nil {
		f.Close()
		t.Error("OpenPinned returned a descriptor from a world-writable directory")
	}
	if !errors.Is(err, lock.ErrUnsafePath) {
		t.Fatalf("want ErrUnsafePath, got %v", err)
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Errorf("refusal should say the parent is writable: %v", err)
	}
}

// TestOpenPinnedRefusesAWritableRoot checks the root itself, which no component
// loop reaches: it is the trust boundary the caller asserted, and asserting it
// is not the same as it being true.
func TestOpenPinnedRefusesAWritableRoot(t *testing.T) {
	content := []byte("pinned bytes under a world-writable root")
	root, digest := pinnedFixture(t, "vmlinux", content)
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatalf("chmod root: %v", err)
	}

	f, err := lock.OpenPinned(root, "images/dist/vmlinux", digest)
	if f != nil {
		f.Close()
		t.Error("OpenPinned returned a descriptor from under a world-writable root")
	}
	if !errors.Is(err, lock.ErrUnsafePath) {
		t.Fatalf("want ErrUnsafePath, got %v", err)
	}
}

// TestOpenPinnedAcceptsAGroupWritableDirectory pins the ruling that the trusted
// path check looks at the other-write bit and not the group-write bit. The real
// host ships artifacts this way — /srv/vmobs is harper:vmobs-fixture mode 0775,
// and the build tree's images/dist is 0775 — so a check that refused group
// write would refuse the deployment it is supposed to protect.
func TestOpenPinnedAcceptsAGroupWritableDirectory(t *testing.T) {
	content := []byte("pinned bytes under a group-writable dist")
	root, digest := pinnedFixture(t, "vmlinux", content)
	for _, d := range []string{root, filepath.Join(root, "images"), filepath.Join(root, "images", "dist")} {
		if err := os.Chmod(d, 0o775); err != nil {
			t.Fatalf("chmod %s: %v", d, err)
		}
	}

	f, err := lock.OpenPinned(root, "images/dist/vmlinux", digest)
	if err != nil {
		t.Fatalf("OpenPinned refused a group-writable directory: %v", err)
	}
	defer f.Close()

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("read %q, want %q", got, content)
	}
}

// TestOpenPinnedRefusesAnEscapingPath refuses a lock path that climbs out of the
// root. The target exists and holds the pinned bytes, so a refusal for any other
// reason would be indistinguishable from the file simply being absent.
func TestOpenPinnedRefusesAnEscapingPath(t *testing.T) {
	content := []byte("bytes outside the root")
	root, digest := pinnedFixture(t, "vmlinux", content)
	outside := filepath.Join(filepath.Dir(root), "outside.bin")
	if err := os.WriteFile(outside, content, 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	f, err := lock.OpenPinned(root, "../outside.bin", digest)
	if f != nil {
		f.Close()
		t.Error("OpenPinned returned a descriptor for a path outside the root")
	}
	if !errors.Is(err, lock.ErrUnsafePath) {
		t.Fatalf("want ErrUnsafePath, got %v", err)
	}
}

// TestOpenPinnedRefusesANonRegularFile refuses a directory standing where an
// artifact should be. A FIFO would block the read forever; the mode check is
// what stops that before any read happens.
func TestOpenPinnedRefusesANonRegularFile(t *testing.T) {
	root, digest := pinnedFixture(t, "placeholder", []byte("unused"))
	if err := os.Mkdir(filepath.Join(root, "images", "dist", "vmlinux"), 0o755); err != nil {
		t.Fatalf("mkdir vmlinux: %v", err)
	}

	f, err := lock.OpenPinned(root, "images/dist/vmlinux", digest)
	if f != nil {
		f.Close()
		t.Error("OpenPinned returned a descriptor for a directory")
	}
	if !errors.Is(err, lock.ErrUnsafePath) {
		t.Fatalf("want ErrUnsafePath, got %v", err)
	}
}

// TestOpenPinnedMissingArtifactIsAbsentNotUnsafe keeps the two apart. A tamper
// test whose fixture never wrote the file would otherwise read as a successful
// tamper rejection while proving nothing.
func TestOpenPinnedMissingArtifactIsAbsentNotUnsafe(t *testing.T) {
	root, digest := pinnedFixture(t, "placeholder", []byte("unused"))

	f, err := lock.OpenPinned(root, "images/dist/vmlinux", digest)
	if f != nil {
		f.Close()
		t.Error("OpenPinned returned a descriptor for a file that does not exist")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want os.ErrNotExist, got %v", err)
	}
	if errors.Is(err, lock.ErrUnsafePath) || errors.Is(err, lock.ErrBytesChanged) {
		t.Errorf("an absent artifact must not be classified as tampering: %v", err)
	}
}

// TestVerifyArtifactsClassifiesUnsafePaths checks the report shape carries the
// new refusal instead of collapsing it into "unreadable", which would tell an
// operator to check permissions on a file whose bytes are fine.
func TestVerifyArtifactsClassifiesUnsafePaths(t *testing.T) {
	content := []byte("pinned bytes in a world-writable directory")
	root, digest := pinnedFixture(t, "vmlinux", content)
	if err := os.WriteFile(filepath.Join(root, "images", "dist", "rootfs.ext4"), content, 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, "images", "dist"), 0o777); err != nil {
		t.Fatalf("chmod dist: %v", err)
	}

	l := &lock.Lock{}
	l.GuestKernel.VmlinuxSHA256 = digest
	l.GuestKernel.VmlinuxPath = "images/dist/vmlinux"
	l.RootImage.SHA256 = digest
	l.RootImage.Path = "images/dist/rootfs.ext4"

	mismatches := l.VerifyArtifacts(root)
	if len(mismatches) != 2 {
		t.Fatalf("want both artifacts refused, got %d: %+v", len(mismatches), mismatches)
	}
	for _, m := range mismatches {
		if m.Got != "unsafe_path" {
			t.Errorf("%s: got %q, want %q", m.Subject, m.Got, "unsafe_path")
		}
		if !strings.Contains(m.Detail, "writable") {
			t.Errorf("%s: detail should name the writable directory, got %q", m.Subject, m.Detail)
		}
	}
}

// TestVerifyBinariesRefusesASymlinkedBinary covers the absolute-path half.
// install_path names a file outside any root vmobs owns, so the parent walk does
// not apply, but the binary itself must still be the file the lock pins and not
// a link standing in for it.
func TestVerifyBinariesRefusesASymlinkedBinary(t *testing.T) {
	dir := t.TempDir()
	content := []byte("pinned firecracker bytes")
	real := makeBinary(t, dir, "firecracker.real", content)
	linked := filepath.Join(dir, "firecracker")
	if err := os.Symlink(real, linked); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	l := &lock.Lock{}
	l.Firecracker.SHA256 = hashOf(content)
	l.Firecracker.InstallPath = linked

	mismatches := l.VerifyBinaries()
	if len(mismatches) != 1 {
		t.Fatalf("want the symlinked binary refused, got %d: %+v", len(mismatches), mismatches)
	}
	if mismatches[0].Got != "unsafe_path" {
		t.Errorf("got %q, want %q", mismatches[0].Got, "unsafe_path")
	}
	if !strings.Contains(mismatches[0].Detail, "symlink") {
		t.Errorf("detail should say the install path is a symlink, got %q", mismatches[0].Detail)
	}
}

// TestVerifyBinariesAcceptsARegularBinary is the positive control for the test
// above: the same fixture without the symlink must still verify, so the refusal
// is attributable to the link and not to the new check refusing everything.
func TestVerifyBinariesAcceptsARegularBinary(t *testing.T) {
	dir := t.TempDir()
	content := []byte("pinned firecracker bytes")
	path := makeBinary(t, dir, "firecracker", content)

	l := &lock.Lock{}
	l.Firecracker.SHA256 = hashOf(content)
	l.Firecracker.InstallPath = path

	if mismatches := l.VerifyBinaries(); len(mismatches) != 0 {
		t.Fatalf("regular pinned binary should verify, got %+v", mismatches)
	}
}
