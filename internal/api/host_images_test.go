// ABOUTME: GET /host/status publishes the kernel and root image this host stages, read
// ABOUTME: from runtime.lock.json — the pins doStage verifies every launch against.
package api_test

import (
	"net/http"
	"testing"

	"github.com/2389-research/observatory-v2/internal/lock"
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

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
