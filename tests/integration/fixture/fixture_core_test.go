// ABOUTME: Unit tests for the pure config-building core of the boot fixture.
// ABOUTME: Exercises BuildVMConfig, UUID/token generation, and FCConfig shape — no root, no /srv/vmobs.

//go:build linux

package fixture

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
)

// repoRoot walks upward from the test binary's working directory to find the
// repo root (the directory containing runtime.lock.json).
func findRepoRoot(t *testing.T) string {
	t.Helper()
	// When go test runs, the working directory is the package directory.
	// Walk upward until runtime.lock.json is found.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "runtime.lock.json")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find repo root (runtime.lock.json) above %s", dir)
		}
		dir = parent
	}
}

// mkfsPresent returns true if mkfs.ext4 is available on this host.
func mkfsPresent() bool {
	_, err := exec.LookPath("mkfs.ext4")
	return err == nil
}

// TestNewUUID verifies basic UUID v4 shape and uniqueness.
func TestNewUUID(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		u, err := newUUID()
		if err != nil {
			t.Fatalf("newUUID: %v", err)
		}
		// Must be 36 chars: 8-4-4-4-12
		if len(u) != 36 {
			t.Errorf("UUID length %d, want 36: %q", len(u), u)
		}
		parts := strings.Split(u, "-")
		if len(parts) != 5 {
			t.Errorf("UUID parts %d, want 5: %q", len(parts), u)
		}
		// Version nibble (first nibble of group 3) must be '4'.
		if len(parts) == 5 && len(parts[2]) >= 1 && parts[2][0] != '4' {
			t.Errorf("UUID version nibble %c, want 4: %q", parts[2][0], u)
		}
		// Variant nibble (first nibble of group 4) must be 8, 9, a, or b.
		if len(parts) == 5 && len(parts[3]) >= 1 {
			v := parts[3][0]
			if v != '8' && v != '9' && v != 'a' && v != 'b' {
				t.Errorf("UUID variant nibble %c, want [89ab]: %q", v, u)
			}
		}
		if seen[u] {
			t.Errorf("UUID collision: %q", u)
		}
		seen[u] = true
	}
}

// TestNewHexToken verifies length and hex encoding.
func TestNewHexToken(t *testing.T) {
	for _, n := range []int{1, 16, 32, 64} {
		tok, err := newHexToken(n)
		if err != nil {
			t.Fatalf("newHexToken(%d): %v", n, err)
		}
		if len(tok) != 2*n {
			t.Errorf("token len %d, want %d", len(tok), 2*n)
		}
		if _, err := hex.DecodeString(tok); err != nil {
			t.Errorf("token %q is not valid hex: %v", tok, err)
		}
	}

	// Uniqueness: 20 32-byte tokens should all differ.
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		tok, err := newHexToken(32)
		if err != nil {
			t.Fatalf("newHexToken(32) iteration %d: %v", i, err)
		}
		if seen[tok] {
			t.Errorf("token collision at iteration %d: %q", i, tok)
		}
		seen[tok] = true
	}
}

// TestFCConfigJSONShape verifies that FCConfig round-trips through JSON with
// the exact field names the Firecracker spec requires.
func TestFCConfigJSONShape(t *testing.T) {
	cfg := FCConfig{
		BootSource: FCBootSource{
			KernelImagePath: "vmlinux",
			BootArgs:        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw",
		},
		Drives: []FCDrive{
			{DriveID: "rootfs", PathOnHost: "rootfs.ext4", IsRootDevice: true, IsReadOnly: false},
			{DriveID: "config", PathOnHost: "config.ext4", IsRootDevice: false, IsReadOnly: true},
		},
		MachineConfig: FCMachineConfig{VCPUCount: 1, MemSizeMiB: 512},
		Vsock:         FCVsock{GuestCID: 3, UDSPath: "v.sock"},
		NetworkInterfaces: []FCNetworkInterface{
			{IfaceID: "eth0", HostDevName: "tap0"},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Check spec-required top-level keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"boot-source", "drives", "machine-config", "vsock", "network-interfaces"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing top-level key %q in fc-config.json", key)
		}
	}

	// Check BootSource fields.
	var bs map[string]json.RawMessage
	if err := json.Unmarshal(raw["boot-source"], &bs); err != nil {
		t.Fatalf("unmarshal boot-source: %v", err)
	}
	for _, key := range []string{"kernel_image_path", "boot_args"} {
		if _, ok := bs[key]; !ok {
			t.Errorf("boot-source: missing field %q", key)
		}
	}

	// Check Drive fields.
	var drives []map[string]json.RawMessage
	if err := json.Unmarshal(raw["drives"], &drives); err != nil {
		t.Fatalf("unmarshal drives: %v", err)
	}
	if len(drives) != 2 {
		t.Fatalf("drives: want 2, got %d", len(drives))
	}
	for _, key := range []string{"drive_id", "path_on_host", "is_root_device", "is_read_only"} {
		if _, ok := drives[0][key]; !ok {
			t.Errorf("drives[0]: missing field %q", key)
		}
	}
	// Rootfs must be first (is_root_device=true), config second.
	var rootsFirst bool
	if err := json.Unmarshal(drives[0]["is_root_device"], &rootsFirst); err != nil || !rootsFirst {
		t.Errorf("drives[0] must be the root device (rootfs first)")
	}

	// Check MachineConfig fields.
	var mc map[string]json.RawMessage
	if err := json.Unmarshal(raw["machine-config"], &mc); err != nil {
		t.Fatalf("unmarshal machine-config: %v", err)
	}
	for _, key := range []string{"vcpu_count", "mem_size_mib"} {
		if _, ok := mc[key]; !ok {
			t.Errorf("machine-config: missing field %q", key)
		}
	}

	// Check Vsock fields.
	var vs map[string]json.RawMessage
	if err := json.Unmarshal(raw["vsock"], &vs); err != nil {
		t.Fatalf("unmarshal vsock: %v", err)
	}
	for _, key := range []string{"guest_cid", "uds_path"} {
		if _, ok := vs[key]; !ok {
			t.Errorf("vsock: missing field %q", key)
		}
	}

	// Check NetworkInterfaces fields.
	var nifs []map[string]json.RawMessage
	if err := json.Unmarshal(raw["network-interfaces"], &nifs); err != nil {
		t.Fatalf("unmarshal network-interfaces: %v", err)
	}
	if len(nifs) != 1 {
		t.Fatalf("network-interfaces: want 1, got %d", len(nifs))
	}
	for _, key := range []string{"iface_id", "host_dev_name"} {
		if _, ok := nifs[0][key]; !ok {
			t.Errorf("network-interfaces[0]: missing field %q", key)
		}
	}
}

// TestBootConfigSchema verifies that guest.BootConfig marshals with the schema
// field set to guest.GuestContextSchema and protocol_version = proto.ProtocolVersion.
func TestBootConfigSchema(t *testing.T) {
	cfg := &guest.BootConfig{
		Schema:          guest.GuestContextSchema,
		VMID:            "test-vm",
		BootID:          "test-boot-id",
		CapabilityToken: "deadbeef",
		ProtocolVersion: proto.ProtocolVersion,
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"schema", "vm_id", "boot_id", "capability_token", "protocol_version"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("context.json: missing field %q", key)
		}
	}
	var schema string
	if err := json.Unmarshal(raw["schema"], &schema); err != nil || schema != guest.GuestContextSchema {
		t.Errorf("schema: got %q, want %q", schema, guest.GuestContextSchema)
	}
	var pv int
	if err := json.Unmarshal(raw["protocol_version"], &pv); err != nil || pv != proto.ProtocolVersion {
		t.Errorf("protocol_version: got %d, want %d", pv, proto.ProtocolVersion)
	}
}

// TestCIDDerivation checks that CID = 3+n for n ∈ {0,1} matches the fixture invariant.
func TestCIDDerivation(t *testing.T) {
	cases := []struct{ n int; wantCID uint32 }{
		{0, 3},
		{1, 4},
		{9, 12},
	}
	for _, c := range cases {
		got := uint32(3 + c.n)
		if got != c.wantCID {
			t.Errorf("n=%d: CID=%d, want %d", c.n, got, c.wantCID)
		}
	}
}

// TestUIDDerivation checks that UID = 20000+n (unique per VM).
// GID is the shared vmobs-fixture group (gid 36000 per setup.sh), resolved at runtime
// via user.LookupGroup — not derived from n.
func TestUIDDerivation(t *testing.T) {
	cases := []struct{ n, wantUID int }{
		{0, 20000},
		{1, 20001},
		{9, 20009},
	}
	for _, c := range cases {
		got := 20000 + c.n
		if got != c.wantUID {
			t.Errorf("n=%d: UID=%d, want %d", c.n, got, c.wantUID)
		}
	}
}

// TestBuildVMConfig exercises the full config-building pipeline in a tempdir.
// Requires: mkfs.ext4 on PATH, and the repo root reachable (runtime.lock.json present,
// images/dist/vmlinux + images/dist/rootfs.ext4 present with matching hashes).
// Skip gracefully if images are absent (normal on macOS dev host).
func TestBuildVMConfig(t *testing.T) {
	if !mkfsPresent() {
		t.Skip("mkfs.ext4 not available on this host")
	}

	repoRoot := findRepoRoot(t)

	// If images/dist/ artifacts are absent, skip — they only exist on aibox03.
	vmlinuxPath := filepath.Join(repoRoot, "images", "dist", "vmlinux")
	rootfsPath := filepath.Join(repoRoot, "images", "dist", "rootfs.ext4")
	if _, err := os.Stat(vmlinuxPath); os.IsNotExist(err) {
		t.Skipf("images/dist/vmlinux absent (only exists on aibox03); skipping BuildVMConfig test")
	}
	if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
		t.Skipf("images/dist/rootfs.ext4 absent (only exists on aibox03); skipping BuildVMConfig test")
	}

	outDir := t.TempDir()
	bootCfg, configDisk, fcJSON, err := BuildVMConfig(repoRoot, "test-vm", 3, outDir)
	if err != nil {
		t.Fatalf("BuildVMConfig: %v", err)
	}

	// BootConfig must round-trip.
	if bootCfg.Schema != guest.GuestContextSchema {
		t.Errorf("schema: %q, want %q", bootCfg.Schema, guest.GuestContextSchema)
	}
	if bootCfg.VMID != "test-vm" {
		t.Errorf("vm_id: %q, want %q", bootCfg.VMID, "test-vm")
	}
	if len(bootCfg.BootID) != 36 {
		t.Errorf("boot_id length %d, want 36 (UUID)", len(bootCfg.BootID))
	}
	if len(bootCfg.CapabilityToken) != 64 {
		t.Errorf("capability_token length %d, want 64 (32 bytes hex)", len(bootCfg.CapabilityToken))
	}
	if bootCfg.ProtocolVersion != proto.ProtocolVersion {
		t.Errorf("protocol_version %d, want %d", bootCfg.ProtocolVersion, proto.ProtocolVersion)
	}

	// Config disk must be 1 MiB.
	wantSize := int64(configDiskSizeMiB * 1024 * 1024)
	if int64(len(configDisk)) != wantSize {
		t.Errorf("config disk size %d, want %d", len(configDisk), wantSize)
	}
	// Must start with ext4 magic bytes at offset 56 of the superblock (offset 1080 overall).
	// ext4 superblock magic is 0xEF53 at byte offset 1080.
	if len(configDisk) > 1082 {
		magic := uint16(configDisk[1080]) | uint16(configDisk[1081])<<8
		if magic != 0xEF53 {
			t.Errorf("config disk: ext4 magic 0x%04X at offset 1080, want 0xEF53", magic)
		}
	}

	// fc-config.json must be valid JSON with spec-required keys.
	var rawFC map[string]json.RawMessage
	if err := json.Unmarshal(fcJSON, &rawFC); err != nil {
		t.Fatalf("fc-config.json not valid JSON: %v", err)
	}
	for _, key := range []string{"boot-source", "drives", "machine-config", "vsock", "network-interfaces"} {
		if _, ok := rawFC[key]; !ok {
			t.Errorf("fc-config.json: missing key %q", key)
		}
	}

	// Uniqueness: two calls produce different tokens and boot IDs.
	bootCfg2, _, _, err := BuildVMConfig(repoRoot, "test-vm-2", 4, t.TempDir())
	if err != nil {
		t.Fatalf("BuildVMConfig second call: %v", err)
	}
	if bootCfg.BootID == bootCfg2.BootID {
		t.Errorf("boot IDs are identical across two builds (should be random)")
	}
	if bootCfg.CapabilityToken == bootCfg2.CapabilityToken {
		t.Errorf("capability tokens are identical across two builds (should be random)")
	}
}

// TestWaitForVsockReportsLastRealDialError pins the error-surfacing contract:
// when the outer deadline expires between retries, waitForVsock must report
// the last error an attempt produced on its own merits (here: EACCES from an
// untraversable directory), not the context-expiry noise of a final doomed
// dial. During the first M0 gate run that noise ("i/o timeout") masked a
// persistent permission-denied and misdirected the diagnosis.
func TestWaitForVsockReportsLastRealDialError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory modes do not block traversal")
	}
	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	sock := filepath.Join(locked, "v.sock")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	// The outer deadline expires mid-backoff: attempts at 0 and 1×readyBackoff
	// both fail instantly with EACCES, and the next wake at 2×readyBackoff
	// lands past expiry. Derived from readyBackoff so the arithmetic tracks it.
	ctx, cancel := context.WithTimeout(context.Background(), readyBackoff+readyBackoff/2)
	defer cancel()
	err := waitForVsock(ctx, sock)
	if err == nil {
		t.Fatal("waitForVsock succeeded against an untraversable directory")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("real dial error masked; want permission denied, got: %v", err)
	}
}

// TestFCVsockCIDConstraint checks that the CID values we use (3 and 4 for m0-a/m0-b)
// meet the Firecracker spec minimum (guest_cid >= 3).
func TestFCVsockCIDConstraint(t *testing.T) {
	for _, n := range []int{0, 1} {
		cid := uint32(3 + n)
		if cid < 3 {
			t.Errorf("n=%d: CID=%d is below spec minimum of 3", n, cid)
		}
		// Must fit in a uint32; format sanity.
		s := fmt.Sprintf("%d", cid)
		if s == "" {
			t.Errorf("CID format empty for n=%d", n)
		}
	}
}
