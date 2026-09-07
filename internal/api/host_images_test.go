// ABOUTME: GET /host/status publishes the kernel and root image this host would stage,
// ABOUTME: read from runtime.lock.json per request — the file doStage reads every launch.
package api_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/2389-research/observatory/internal/lock"
)

// testImageLock is a lock with both image entries filled in. Only the image
// entries matter here; the binary and host-support entries belong to preflight.
func testImageLock() *lock.Lock {
	return &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		GuestKernel: lock.GuestKernelEntry{
			Version:       "6.1.128",
			SourceURL:     "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.128.tar.xz",
			SourceSHA256:  "1111111111111111111111111111111111111111111111111111111111111111",
			ConfigSHA256:  "2222222222222222222222222222222222222222222222222222222222222222",
			VmlinuxSHA256: "3333333333333333333333333333333333333333333333333333333333333333",
			VmlinuxPath:   "images/dist/vmlinux-6.1.128",
		},
		RootImage: lock.RootImageEntry{
			SHA256:       "4444444444444444444444444444444444444444444444444444444444444444",
			Path:         "images/dist/rootfs.ext4",
			BaseImageRef: "debian:bookworm-20260801",
			AptSnapshot:  "20260801T000000Z",
			Inventory:    "images/dist/rootfs.inventory.json",
		},
	}
}

// TestHostStatusServesTheImagesTheHostStages: retiring kernel_image/root_image
// from the template manifest (52pj) removed a wrong answer and left no right
// one — nothing in the API said which kernel or root image a launch would use.
// The lock is the answer and it is a verified one: doStage checks the staged
// bytes against these very digests on every launch (internal/jailer/launch.go),
// so serving them is R-17's self-description generated from the source the
// implementation executes, not a second declaration of it.
func TestHostStatusServesTheImagesTheHostStages(t *testing.T) {
	srv, _, _ := newTemplateServerLock(t, testImageLock())

	var status map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &status)

	images, ok := status["images"].(map[string]any)
	if !ok {
		t.Fatalf("host/status has no images block; keys = %v", keysOf(status))
	}

	kernel, ok := images["guest_kernel"].(map[string]any)
	if !ok {
		t.Fatalf("images has no guest_kernel block; keys = %v", keysOf(images))
	}
	wantKernel := map[string]string{
		"version":        "6.1.128",
		"vmlinux_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
		"vmlinux_path":   "images/dist/vmlinux-6.1.128",
		"config_sha256":  "2222222222222222222222222222222222222222222222222222222222222222",
		"source_sha256":  "1111111111111111111111111111111111111111111111111111111111111111",
	}
	for k, want := range wantKernel {
		if got, _ := kernel[k].(string); got != want {
			t.Errorf("images.guest_kernel.%s = %q, want %q", k, got, want)
		}
	}

	root, ok := images["root_image"].(map[string]any)
	if !ok {
		t.Fatalf("images has no root_image block; keys = %v", keysOf(images))
	}
	// The provenance half is the point of the lock (SPEC §7): a digest with no
	// base image or apt snapshot beside it says what booted and not where it
	// came from, which is half an answer to the question this endpoint exists
	// to settle.
	wantRoot := map[string]string{
		"sha256":         "4444444444444444444444444444444444444444444444444444444444444444",
		"path":           "images/dist/rootfs.ext4",
		"base_image_ref": "debian:bookworm-20260801",
		"apt_snapshot":   "20260801T000000Z",
	}
	for k, want := range wantRoot {
		if got, _ := root[k].(string); got != want {
			t.Errorf("images.root_image.%s = %q, want %q", k, got, want)
		}
	}
}

// TestHostStatusOmitsImagesWithoutALock: a daemon with no lock configured knows
// nothing about what it stages, and the honest answer is no block at all. An
// empty images block would read as "no kernel pinned", which is a claim, and
// this is the same rule the preflight block already follows.
func TestHostStatusOmitsImagesWithoutALock(t *testing.T) {
	srv, _, _ := newTemplateServer(t)

	var status map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &status)

	if _, present := status["images"]; present {
		t.Errorf("host/status serves an images block with no lock behind it: %v", status["images"])
	}
}

// TestHostStatusFollowsARepinnedLock is what this block promises. The jailer's
// doStage calls lock.Load on every launch, so editing runtime.lock.json changes
// what the next launch stages without restarting anything. A daemon answering
// from a copy parsed at startup would keep describing the old pins — true of
// nothing, since no VM has booted them and none will.
func TestHostStatusFollowsARepinnedLock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "runtime.lock.json")
	writeLockFile(t, lockPath, testImageLock())
	srv, _, _ := newTemplateServerLockAt(t, lockPath)

	var before map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &before)
	if got := rootSHAOf(t, before); got != testImageLock().RootImage.SHA256 {
		t.Fatalf("host/status root sha = %q, want the pinned %q", got, testImageLock().RootImage.SHA256)
	}

	// The operator repins. The daemon keeps serving; the next launch will stage
	// these bytes, so this is now the answer.
	repinned := testImageLock()
	repinned.RootImage.SHA256 = "5555555555555555555555555555555555555555555555555555555555555555"
	repinned.GuestKernel.Version = "6.1.140"
	writeLockFile(t, lockPath, repinned)

	var after map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &after)
	if got := rootSHAOf(t, after); got != repinned.RootImage.SHA256 {
		t.Errorf("host/status root sha = %q after a repin, want the repinned %q", got, repinned.RootImage.SHA256)
	}
	images, _ := after["images"].(map[string]any)
	kernel, _ := images["guest_kernel"].(map[string]any)
	if got, _ := kernel["version"].(string); got != repinned.GuestKernel.Version {
		t.Errorf("host/status kernel version = %q after a repin, want %q", got, repinned.GuestKernel.Version)
	}
}

// TestHostStatusReportsALockItCannotRead: reading the file per request means the
// read can fail after the daemon started. Omitting the block would answer with
// the one a host that has no lock at all serves, and this host does have one —
// it is pinned to something nobody can read, which is a launch that is going to
// fail, not a host that never pinned anything.
func TestHostStatusReportsALockItCannotRead(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "runtime.lock.json")
	writeLockFile(t, lockPath, testImageLock())
	srv, _, _ := newTemplateServerLockAt(t, lockPath)

	if err := os.WriteFile(lockPath, []byte("{ this is not json"), 0o644); err != nil {
		t.Fatalf("corrupt lock file: %v", err)
	}

	var status map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &status)

	images, ok := status["images"].(map[string]any)
	if !ok {
		t.Fatalf("host/status dropped the images block for an unreadable lock, which is what no lock looks like; keys = %v", keysOf(status))
	}
	if msg, _ := images["error"].(string); msg == "" {
		t.Errorf("images block carries no error for an unreadable lock: %v", images)
	}
	if _, present := images["guest_kernel"]; present {
		t.Errorf("images block names a kernel it could not read: %v", images)
	}
	if _, present := images["root_image"]; present {
		t.Errorf("images block names a root image it could not read: %v", images)
	}
}

// rootSHAOf digs images.root_image.sha256 out of a /host/status body.
func rootSHAOf(t *testing.T, status map[string]any) string {
	t.Helper()
	images, ok := status["images"].(map[string]any)
	if !ok {
		t.Fatalf("host/status has no images block; keys = %v", keysOf(status))
	}
	root, ok := images["root_image"].(map[string]any)
	if !ok {
		t.Fatalf("images has no root_image block; keys = %v", keysOf(images))
	}
	sha, _ := root["sha256"].(string)
	return sha
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
