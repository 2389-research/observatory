// ABOUTME: A VM row publishes the kernel and root image its current boot staged,
// ABOUTME: which is not what /host/status says this host would stage now.
package api_test

import (
	"net/http"
	"testing"

	"github.com/2389-research/observatory-v2/internal/lock"
)

// repinnedImages is testImageLock's pair after runtime.lock.json was edited: a
// new root filesystem, built from a later apt snapshot. Nothing else moves,
// because one changed digest is enough to make the two answers differ.
func repinnedImages() lock.Images {
	img := testImageLock().Images()
	img.RootImage.SHA256 = "5555555555555555555555555555555555555555555555555555555555555555"
	img.RootImage.AptSnapshot = "20260901T000000Z"
	return img
}

// TestVMPublishesTheImagesItsBootStaged: the host block answers "what would a
// launch stage now"; nothing answered "what did this VM boot". They are the
// same string only until the lock is edited, and a VM that has been running for
// a week is exactly the case where the difference matters.
func TestVMPublishesTheImagesItsBootStaged(t *testing.T) {
	srv, _, fake := newTemplateServerLock(t, testImageLock())
	staged := testImageLock().Images()
	fake.SetStagedImages(&staged)

	vmID := createRunningVM(t, srv.URL, fake)

	var vm map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)

	images, ok := vm["images"].(map[string]any)
	if !ok {
		t.Fatalf("VM has no images block; keys = %v", keysOf(vm))
	}
	kernel, _ := images["guest_kernel"].(map[string]any)
	if got, _ := kernel["vmlinux_sha256"].(string); got != staged.GuestKernel.VmlinuxSHA256 {
		t.Errorf("images.guest_kernel.vmlinux_sha256 = %q, want %q", got, staged.GuestKernel.VmlinuxSHA256)
	}
	root, _ := images["root_image"].(map[string]any)
	// Provenance travels with the digest for the same reason it does on the host
	// block: a hash says what booted, not where it came from.
	for key, want := range map[string]string{
		"sha256":         staged.RootImage.SHA256,
		"path":           staged.RootImage.Path,
		"base_image_ref": staged.RootImage.BaseImageRef,
		"apt_snapshot":   staged.RootImage.AptSnapshot,
	} {
		if got, _ := root[key].(string); got != want {
			t.Errorf("images.root_image.%s = %q, want %q", key, got, want)
		}
	}
}

// TestVMImagesOutliveARepinnedLock is the whole reason this field is not read
// off the host's lock at render time. The lock moves under a running VM; the VM
// keeps saying what it actually booted, and the host keeps saying what a launch
// would stage now. Two questions, two answers, neither one guessing.
func TestVMImagesOutliveARepinnedLock(t *testing.T) {
	srv, _, fake := newTemplateServerLock(t, testImageLock())
	booted := testImageLock().Images()
	fake.SetStagedImages(&booted)

	vmID := createRunningVM(t, srv.URL, fake)

	// The host's lock is edited; this VM is not restarted.
	repinned := repinnedImages()
	fake.SetStagedImages(&repinned)

	var vm map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)
	images, _ := vm["images"].(map[string]any)
	root, _ := images["root_image"].(map[string]any)
	if got, _ := root["sha256"].(string); got != booted.RootImage.SHA256 {
		t.Errorf("running VM reports root sha %q; it booted %q and was never restarted", got, booted.RootImage.SHA256)
	}

	// The same daemon, asked the host question, still answers from the lock.
	var status map[string]any
	getJSON(t, srv.URL+"/api/v1/host/status", http.StatusOK, &status)
	hostImages, _ := status["images"].(map[string]any)
	hostRoot, _ := hostImages["root_image"].(map[string]any)
	if got, _ := hostRoot["sha256"].(string); got != testImageLock().RootImage.SHA256 {
		t.Errorf("host/status root sha = %q, want the configured lock's %q", got, testImageLock().RootImage.SHA256)
	}
}

// TestVMWithNothingStagedOmitsImages: a runtime that stages no images of its own
// leaves the VM with nothing to report, and the honest answer is no block —
// the rule /host/status already follows for a daemon with no lock.
func TestVMWithNothingStagedOmitsImages(t *testing.T) {
	srv, _, fake := newTemplateServerLock(t, testImageLock())

	vmID := createRunningVM(t, srv.URL, fake)

	var vm map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vm)
	if _, present := vm["images"]; present {
		t.Errorf("VM publishes an images block although its launch staged nothing: %v", vm["images"])
	}
}
