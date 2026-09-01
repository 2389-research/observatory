// ABOUTME: Loads and verifies runtime.lock.json — the pinned binary and artifact
// ABOUTME: hashes for the Firecracker/jailer runtime and guest image artifacts.
package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
type GuestKernelEntry struct {
	Version       string `json:"version"`
	SourceURL     string `json:"source_url"`
	SourceSHA256  string `json:"source_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
	VmlinuxSHA256 string `json:"vmlinux_sha256"`
	VmlinuxPath   string `json:"vmlinux_path"`
}

// RootImageEntry records the root filesystem image artifact.
// Path is relative to the repo root.
type RootImageEntry struct {
	SHA256       string `json:"sha256"`
	Path         string `json:"path"`
	BaseImageRef string `json:"base_image_ref"`
	AptSnapshot  string `json:"apt_snapshot"`
	Inventory    string `json:"inventory"`
}

// GuestDEntry records the guestd protocol version requirement.
type GuestDEntry struct {
	ProtocolVersion int `json:"protocol_version"`
}

// Mismatch reports a single hash verification failure.
type Mismatch struct {
	// Subject names the artifact or binary that failed verification.
	Subject string
	// Want is the pinned SHA-256 hex digest.
	Want string
	// Got is the computed SHA-256 hex digest, "absent" if the file was missing,
	// or "unreadable" for any other read error.
	Got string
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

// hashErrorLabel returns "absent" when err signals a missing file, and
// "unreadable" for any other I/O error (permissions, mid-stream failure, etc.).
func hashErrorLabel(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "absent"
	}
	return "unreadable"
}

// VerifyBinaries checks the SHA-256 of the installed firecracker and jailer
// binaries against the pinned values. install_path values are used as-is
// (absolute paths). A missing file yields a Mismatch with Got="absent"; any
// other read error (permissions, mid-stream I/O) yields Got="unreadable".
// An empty sha256 field is skipped — call Unpinned to enumerate those.
func (l *Lock) VerifyBinaries() []Mismatch {
	var out []Mismatch
	check := func(subject, pinnedHash, path string) {
		if pinnedHash == "" {
			return // not yet pinned; Unpinned() handles reporting
		}
		got, err := sha256File(path)
		if err != nil {
			out = append(out, Mismatch{Subject: subject, Want: pinnedHash, Got: hashErrorLabel(err)})
			return
		}
		if got != pinnedHash {
			out = append(out, Mismatch{Subject: subject, Want: pinnedHash, Got: got})
		}
	}
	check("firecracker", l.Firecracker.SHA256, l.Firecracker.InstallPath)
	check("jailer", l.Jailer.SHA256, l.Jailer.InstallPath)
	return out
}

// VerifyArtifacts checks the SHA-256 of repo-relative artifacts (guest kernel
// vmlinux and root image) against the pinned values. Paths are resolved
// relative to repoRoot. An empty sha256 is skipped (see Unpinned).
// A missing file yields Got="absent"; any other read error yields Got="unreadable".
func (l *Lock) VerifyArtifacts(repoRoot string) []Mismatch {
	var out []Mismatch
	check := func(subject, pinnedHash, relPath string) {
		if pinnedHash == "" {
			return // not yet pinned
		}
		abs := filepath.Join(repoRoot, relPath)
		got, err := sha256File(abs)
		if err != nil {
			out = append(out, Mismatch{Subject: subject, Want: pinnedHash, Got: hashErrorLabel(err)})
			return
		}
		if got != pinnedHash {
			out = append(out, Mismatch{Subject: subject, Want: pinnedHash, Got: got})
		}
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

// sha256File reads the file at path and returns its lowercase hex SHA-256 digest.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
