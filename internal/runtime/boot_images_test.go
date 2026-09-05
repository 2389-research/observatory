// ABOUTME: A VM row records the kernel and root image its current boot staged,
// ABOUTME: which is not what the host would stage now once the lock changes.
package runtime_test

import (
	"errors"
	"testing"

	"github.com/2389-research/observatory-v2/internal/lock"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
)

var errLaunchRefused = errors.New("firecracker: refused to start")

func imagesV1() lock.Images {
	return lock.Images{
		GuestKernel: lock.GuestKernelEntry{Version: "6.1.186", VmlinuxSHA256: "kernel-v1", VmlinuxPath: "images/dist/vmlinux"},
		RootImage:   lock.RootImageEntry{SHA256: "rootfs-v1", Path: "images/dist/rootfs.ext4", BaseImageRef: "ubuntu:24.04", AptSnapshot: "2026-01-01"},
	}
}

func imagesV2() lock.Images {
	img := imagesV1()
	img.RootImage.SHA256 = "rootfs-v2"
	img.RootImage.AptSnapshot = "2026-06-01"
	return img
}

// TestLaunchRecordsWhatTheRuntimeStaged: the launch is the only party that knows.
// It reads the lock at stage time and verifies the copied bytes against it, so
// what it reports is host_observed, not a second read of a file that may have
// changed since.
func TestLaunchRecordsWhatTheRuntimeStaged(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	want := imagesV1()
	fk.SetStagedImages(&want)
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("alpha"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")

	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got.BootImages == nil {
		t.Fatal("a running VM records no images; the launch reported some")
	}
	if *got.BootImages != want {
		t.Errorf("recorded images = %+v, want %+v", *got.BootImages, want)
	}
}

// TestLaunchThatReportsNothingRecordsNothing: a runtime that stages no images of
// its own has nothing to say, and an empty block would be a claim rather than an
// absence.
func TestLaunchThatReportsNothingRecordsNothing(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("alpha"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")

	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got.BootImages != nil {
		t.Errorf("images recorded for a launch that reported none: %+v", got.BootImages)
	}
}

// TestRestartAcrossARepinRecordsTheNewBoot is the failure this whole field is
// for: a VM stopped and started across a rebuilt rootfs booted something the
// host status block no longer describes.
func TestRestartAcrossARepinRecordsTheNewBoot(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	first := imagesV1()
	fk.SetStagedImages(&first)
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("alpha"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// The lock is repinned while the VM sits stopped.
	second := imagesV2()
	fk.SetStagedImages(&second)
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "start", nil); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")

	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got.BootImages == nil {
		t.Fatal("no images after a restart")
	}
	if *got.BootImages != second {
		t.Errorf("images after a restart = %+v, want the new boot's %+v", *got.BootImages, second)
	}
}

// TestFailedLaunchRecordsNoImages: nothing was verified to have booted, so the
// row says nothing rather than carrying the last boot's answer forward.
func TestFailedLaunchRecordsNoImages(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	first := imagesV1()
	fk.SetStagedImages(&first)
	mgr := newManager(t, st, fk)

	vm, _, _, err := mgr.CreateVM(t.Context(), "local_operator", createReq("alpha"))
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	waitForObservedState(t, st, vm.VMID, "running")
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "stop", nil); err != nil {
		t.Fatalf("stop: %v", err)
	}

	fk.FailNext("Launch", vm.VMID, errLaunchRefused)
	if _, _, err := mgr.Action(t.Context(), vm.VMID, "start", nil); err == nil {
		t.Fatal("start succeeded although the launch was refused")
	}
	waitForObservedState(t, st, vm.VMID, "failed")

	got, err := st.GetVM(t.Context(), vm.VMID)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got.BootImages != nil {
		t.Errorf("a failed launch left images on the row: %+v", got.BootImages)
	}
}

// TestBatchMemberRecordsItsImages: batch members launch through their own code
// path, and a field that only the single-VM path fills in would be missing on
// exactly the VMs an operator created a dozen at a time.
func TestBatchMemberRecordsItsImages(t *testing.T) {
	st := openStoreForManager(t)
	fk := runtimetest.NewFake()
	want := imagesV1()
	fk.SetStagedImages(&want)
	mgr := newBatchManager(t, st, fk, 2)

	result, err := mgr.CreateBatch(t.Context(), "local_operator", batchReq("", "member-a", "member-b"))
	if err != nil {
		t.Fatalf("CreateBatch: %v", err)
	}
	for _, m := range result.Members {
		if m.VM == nil {
			t.Fatal("batch member has no VM")
		}
		waitForObservedState(t, st, m.VM.VMID, "running")
		got, err := st.GetVM(t.Context(), m.VM.VMID)
		if err != nil {
			t.Fatalf("GetVM(%s): %v", m.VM.VMID, err)
		}
		if got.BootImages == nil {
			t.Fatalf("batch member %s records no images", m.VM.Name)
		}
		if *got.BootImages != want {
			t.Errorf("batch member %s images = %+v, want %+v", m.VM.Name, *got.BootImages, want)
		}
	}
}
