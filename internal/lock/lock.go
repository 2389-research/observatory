// ABOUTME: Loads and verifies runtime.lock.json — the pinned binary and artifact
// ABOUTME: hashes for the Firecracker/jailer runtime and guest image artifacts.
package lock

import (
	"encoding/json"
	"fmt"
	"os"
)

const schemaV1 = "vmobs.runtime_lock.v1"

// Lock mirrors the runtime.lock.json schema (vmobs.runtime_lock.v1) exactly.
// Field names come from the committed runtime.lock.json; never guess them.
type Lock struct {
	Schema      string           `json:"schema"`
	Firecracker FirecrackerEntry `json:"firecracker"`
	Jailer      JailerEntry      `json:"jailer"`
	HostSupport HostSupportEntry `json:"host_support"`
	GuestKernel GuestKernelEntry `json:"guest_kernel"`
	RootImage   RootImageEntry   `json:"root_image"`
	GuestD      GuestDEntry      `json:"guestd"`
}

// FirecrackerEntry carries the pinned binary metadata for the firecracker executable.
type FirecrackerEntry struct {
	Version     string `json:"version"`
	ReleaseURL  string `json:"release_url"`
	SHA256      string `json:"sha256"`
	InstallPath string `json:"install_path"`
}

// JailerEntry carries the pinned binary metadata for the jailer executable.
type JailerEntry struct {
	SHA256      string `json:"sha256"`
	InstallPath string `json:"install_path"`
}

// HostSupportEntry records the required host platform constraints.
type HostSupportEntry struct {
	Arch      string `json:"arch"`
	MinKernel string `json:"min_kernel"`
}

// GuestKernelEntry records the guest kernel artifact and its verification hash.
// VmlinuxPath is relative to the repo root.
//
// SourceURL and VmlinuxURL name different things: SourceURL is the kernel.org
// tarball the build compiles, VmlinuxURL is the built vmlinux an install
// downloads instead of compiling. An empty VmlinuxURL is the honest state of a
// tree whose artifacts have never been published -- scripts/fetch-guest-images
// reads it as "build it yourself", not as an error.
type GuestKernelEntry struct {
	Version       string `json:"version"`
	SourceURL     string `json:"source_url"`
	SourceSHA256  string `json:"source_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
	VmlinuxSHA256 string `json:"vmlinux_sha256"`
	VmlinuxPath   string `json:"vmlinux_path"`
	VmlinuxURL    string `json:"vmlinux_url"`
}

// RootImageEntry records the root filesystem image artifact.
// Path is relative to the repo root.
type RootImageEntry struct {
	SHA256       string `json:"sha256"`
	Path         string `json:"path"`
	BaseImageRef string `json:"base_image_ref"`
	AptSnapshot  string `json:"apt_snapshot"`
	Inventory    string `json:"inventory"`
	// URL is where a built root image can be downloaded, so an install does not
	// have to debootstrap one. Empty until the artifacts are published.
	URL string `json:"url"`
}

// GuestDEntry records the guestd protocol version requirement.
type GuestDEntry struct {
	ProtocolVersion int `json:"protocol_version"`
}

// Images names the two artifacts a VM boots: the guest kernel and the root
// filesystem image, whole entries straight from the lock. Two readers share this
// one type on purpose — GET /host/status answers what a launch would stage now,
// and a VM row answers what its current boot did stage — so neither can describe
// the same fact in different words. Whole entries rather than a chosen subset:
// base_image_ref and apt_snapshot are the provenance half of SPEC §7, and a
// digest with neither beside it says what booted without saying where it came
// from. The JSON tags are the lock file's own, so storage and the wire cannot
// rename a field runtime.lock.json owns.
type Images struct {
	GuestKernel GuestKernelEntry `json:"guest_kernel"`
	RootImage   RootImageEntry   `json:"root_image"`
}

// Images returns the image half of this lock.
func (l *Lock) Images() Images {
	return Images{GuestKernel: l.GuestKernel, RootImage: l.RootImage}
}

// Mismatch reports a single hash verification failure.
type Mismatch struct {
	// Subject names the artifact or binary that failed verification.
	Subject string
	// Want is the pinned SHA-256 hex digest.
	Want string
	// Got is the computed SHA-256 hex digest, or one of three labels: "absent"
	// if the file was missing, "unsafe_path" if the artifact's placement was
	// refused before its bytes were read, and "unreadable" for any other I/O
	// error.
	Got string
	// Detail carries the refusal in words when Got is a label rather than a
	// digest — which directory is writable, which component is a symlink. Empty
	// when Got is a digest or "absent", where the label says everything.
	Detail string
}

// Load parses the lock file at path. An unknown schema value is an error.
func Load(path string) (*Lock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	defer f.Close()

	var l Lock
	if err := json.NewDecoder(f).Decode(&l); err != nil {
		return nil, fmt.Errorf("parse lock file %s: %w", path, err)
	}
	if l.Schema != schemaV1 {
		return nil, fmt.Errorf("unsupported lock schema %q (want %q)", l.Schema, schemaV1)
	}
	return &l, nil
}

// VerifyBinaries checks the SHA-256 of the installed firecracker and jailer
// binaries against the pinned values. install_path values are used as-is
// (absolute paths). A missing file yields a Mismatch with Got="absent", a
// symlinked or non-regular install_path yields Got="unsafe_path", and any other
// read error yields Got="unreadable". An empty sha256 field is skipped — call
// Unpinned to enumerate those.
//
// The trusted-path walk OpenPinned applies to repo artifacts is deliberately not
// applied here. install_path names a file on the operator's own filesystem,
// under directories vmobs neither creates nor configures, so there is no root it
// could assert the walk from: rooting it at / would refuse every install whose
// binary sits under a world-writable ancestor, starting with the temporary
// directories the tests and the gate use. What is checked is the file itself.
func (l *Lock) VerifyBinaries() []Mismatch {
	var out []Mismatch
	check := func(subject, pinnedHash, path string) {
		if pinnedHash == "" {
			return // not yet pinned; Unpinned() handles reporting
		}
		f, err := openPinnedFile(path, pinnedHash)
		if err != nil {
			got, detail := classify(err)
			out = append(out, Mismatch{Subject: subject, Want: pinnedHash, Got: got, Detail: detail})
			return
		}
		f.Close()
	}
	check("firecracker", l.Firecracker.SHA256, l.Firecracker.InstallPath)
	check("jailer", l.Jailer.SHA256, l.Jailer.InstallPath)
	return out
}

// VerifyArtifacts checks the pinned repo-relative artifacts (guest kernel
// vmlinux and root image) against the lock, resolving each under repoRoot with
// OpenPinned — so a refusal can be about the artifact's placement as well as its
// bytes. An empty sha256 is skipped (see Unpinned).
//
// This is the report shape: the verified descriptors are closed on the way out.
// A caller that is about to *use* the bytes calls OpenPinned itself and copies
// from the descriptor, which is the only way the bytes it reads are the bytes
// this verified.
func (l *Lock) VerifyArtifacts(repoRoot string) []Mismatch {
	var out []Mismatch
	check := func(subject, pinnedHash, relPath string) {
		if pinnedHash == "" {
			return // not yet pinned
		}
		f, err := OpenPinned(repoRoot, relPath, pinnedHash)
		if err != nil {
			got, detail := classify(err)
			out = append(out, Mismatch{Subject: subject, Want: pinnedHash, Got: got, Detail: detail})
			return
		}
		f.Close()
	}
	check("guest_kernel.vmlinux", l.GuestKernel.VmlinuxSHA256, l.GuestKernel.VmlinuxPath)
	check("root_image", l.RootImage.SHA256, l.RootImage.Path)
	return out
}

// Unpinned returns the names of all components whose sha256 field is empty
// (not yet pinned). These are silently skipped by VerifyBinaries /
// VerifyArtifacts; callers (e.g. preflight) may warn on them.
func (l *Lock) Unpinned() []string {
	var out []string
	if l.Firecracker.SHA256 == "" {
		out = append(out, "firecracker")
	}
	if l.Jailer.SHA256 == "" {
		out = append(out, "jailer")
	}
	if l.GuestKernel.VmlinuxSHA256 == "" {
		out = append(out, "guest_kernel.vmlinux")
	}
	if l.RootImage.SHA256 == "" {
		out = append(out, "root_image")
	}
	return out
}
