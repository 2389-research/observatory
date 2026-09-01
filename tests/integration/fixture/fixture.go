// ABOUTME: Jailed boot fixture: prepares, starts, and stops individual Firecracker VMs
// ABOUTME: for the M0 gate test. Split so config-building is unit-testable without root.

//go:build linux

package fixture

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/lock"
	"github.com/2389-research/observatory-v2/internal/network"
)

const (
	// helperPath is the privileged root helper installed by scripts/aibox03/setup.sh.
	helperPath = "/usr/local/sbin/vmobs-root-helper"

	// stageBase is where the helper expects per-VM staging directories.
	stageBase = "/srv/vmobs/fixture"

	// jailBase is the jailer's chroot-base-dir.
	jailBase = "/srv/vmobs/jail"

	// vsockPort is the guest control-channel vsock port (guestd listens here).
	vsockPort = 10000

	// readyTimeout is the maximum time to wait for the guest vsock to answer.
	readyTimeout = 60 * time.Second

	// readyBackoff is the retry interval while waiting for guest readiness.
	readyBackoff = 500 * time.Millisecond

	// configDiskSizeMiB is the size of the per-VM config ext4 image.
	configDiskSizeMiB = 1
)

// VM is a prepared (and optionally running) fixture VM.
type VM struct {
	// ID is the VM identifier used by the root helper and jailer.
	ID string
	// UID and GID are the jailer identity for this VM.
	UID, GID int
	// CID is the vsock context ID.
	CID uint32
	// Stage is the absolute path to this VM's staging directory.
	Stage string
	// UDSPath is the host-side Unix socket path Firecracker exposes for vsock.
	UDSPath string
	// BootCfg is the per-boot config marshaled into the config disk.
	BootCfg *guest.BootConfig

	// repoRoot is stored so Start can reference artifact paths.
	repoRoot string
	// subnet is the /30 allocated for this VM's network namespace.
	subnet string
	// buildDir holds intermediate build artifacts (config.ext4, fc-config.json).
	buildDir string
}

// PrepareVM builds the per-VM staging directory artifacts — config disk,
// fc-config.json — without root. The actual staging into /srv/vmobs and
// boot happen in Start() (skip-gated path).
//
// repoRoot is the absolute path to the repository root (for lock + artifact paths).
// id must match ^[a-z0-9][a-z0-9-]{0,23}$.
// n is a zero-based index: uid = 20000+n, CID = 3+n.
// alloc supplies the /30 prefix for this VM's network namespace.
func PrepareVM(t *testing.T, repoRoot, id string, n int, alloc *network.Allocator) *VM {
	t.Helper()

	uid := 20000 + n
	gid := 20000 + n // Start overrides this from the vmobs-fixture group gid if available
	cid := uint32(3 + n)

	subnet, err := alloc.Next()
	if err != nil {
		t.Fatalf("PrepareVM %s: allocate subnet: %v", id, err)
	}

	vm := &VM{
		ID:       id,
		UID:      uid,
		GID:      gid,
		CID:      cid,
		UDSPath:  filepath.Join(jailBase, "firecracker", id, "root", "v.sock"),
		Stage:    filepath.Join(stageBase, id, "staging"),
		repoRoot: repoRoot,
		subnet:   subnet.String(),
		buildDir: t.TempDir(),
	}

	// Build config disk and fc-config.json into buildDir.
	bootCfg, configDisk, fcCfgJSON, err := BuildVMConfig(repoRoot, id, cid, vm.buildDir)
	if err != nil {
		t.Fatalf("PrepareVM %s: build config: %v", id, err)
	}
	vm.BootCfg = bootCfg

	// Write config disk and fc-config.json into buildDir for Start to copy.
	if err := os.WriteFile(filepath.Join(vm.buildDir, "config.ext4"), configDisk, 0644); err != nil {
		t.Fatalf("PrepareVM %s: write config.ext4: %v", id, err)
	}
	if err := os.WriteFile(filepath.Join(vm.buildDir, "fc-config.json"), fcCfgJSON, 0644); err != nil {
		t.Fatalf("PrepareVM %s: write fc-config.json: %v", id, err)
	}

	return vm
}

// Start stages files into /srv/vmobs and launches the VM via the root helper.
// It registers a t.Cleanup to call Stop.
func (v *VM) Start(t *testing.T) {
	t.Helper()

	// net-setup
	netSetup := exec.Command("sudo", helperPath, "net-setup", v.ID, v.subnet)
	netSetup.Stdout = os.Stdout
	netSetup.Stderr = os.Stderr
	if err := netSetup.Run(); err != nil {
		t.Fatalf("Start %s: net-setup: %v", v.ID, err)
	}

	// Register cleanup before jail-start so teardown always runs even on failure.
	t.Cleanup(func() { v.Stop(t) })

	// Stage the four required files into /srv/vmobs/fixture/<id>/staging/ via sudo.
	// Staging sources: vmlinux + rootfs.ext4 from images/dist/; others from buildDir.
	stageSources := map[string]string{
		"vmlinux":       filepath.Join(v.repoRoot, "images", "dist", "vmlinux"),
		"rootfs.ext4":   filepath.Join(v.repoRoot, "images", "dist", "rootfs.ext4"),
		"config.ext4":   filepath.Join(v.buildDir, "config.ext4"),
		"fc-config.json": filepath.Join(v.buildDir, "fc-config.json"),
	}
	if err := sudoStage(v.Stage, stageSources); err != nil {
		t.Fatalf("Start %s: stage files: %v", v.ID, err)
	}

	// jail-start
	jailStart := exec.Command("sudo", helperPath, "jail-start",
		v.ID,
		fmt.Sprintf("%d", v.UID),
		fmt.Sprintf("%d", v.GID),
		fmt.Sprintf("%d", v.CID),
	)
	jailStart.Stdout = os.Stdout
	jailStart.Stderr = os.Stderr
	if err := jailStart.Run(); err != nil {
		t.Fatalf("Start %s: jail-start: %v", v.ID, err)
	}

	// Wait for guest vsock to become available.
	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	defer cancel()
	if err := waitForVsock(ctx, v.UDSPath); err != nil {
		t.Fatalf("Start %s: guest vsock not ready: %v", v.ID, err)
	}
}

// Stop tears down the VM via the root helper. Idempotent: errors are logged, not fatal.
func (v *VM) Stop(t *testing.T) {
	t.Helper()

	jailStop := exec.Command("sudo", helperPath, "jail-stop", v.ID)
	jailStop.Stdout = os.Stdout
	jailStop.Stderr = os.Stderr
	if err := jailStop.Run(); err != nil {
		t.Logf("Stop %s: jail-stop: %v (continuing)", v.ID, err)
	}

	netTeardown := exec.Command("sudo", helperPath, "net-teardown", v.ID)
	netTeardown.Stdout = os.Stdout
	netTeardown.Stderr = os.Stderr
	if err := netTeardown.Run(); err != nil {
		t.Logf("Stop %s: net-teardown: %v (continuing)", v.ID, err)
	}
}

// DialControl opens a new vsock control connection to the running VM.
// Returns a raw net.Conn after the Firecracker UDS handshake; the caller
// drives the application-level hello/hello_ack exchange.
func (v *VM) DialControl(ctx context.Context) (net.Conn, error) {
	return proto.DialHostVsock(ctx, v.UDSPath, vsockPort)
}

// ------------------------------------------------------------------
// Pure config-building core — testable without root or /srv/vmobs
// ------------------------------------------------------------------

// FCConfig is the wire shape of fc-config.json passed to Firecracker via --config-file.
// Every field name was validated against firecracker_spec-v1.16.1.yaml:
//   - boot-source     → BootSource (kernel_image_path, boot_args required)
//   - drives          → []Drive (drive_id, path_on_host, is_root_device, is_read_only)
//   - machine-config  → MachineConfiguration (vcpu_count, mem_size_mib required)
//   - vsock           → Vsock (guest_cid min 3, uds_path required)
//   - network-interfaces → []NetworkInterface (iface_id, host_dev_name required)
//
// Drive order: rootfs first (/dev/vda), config disk second (/dev/vdb).
// guestd uses -config-dev /dev/vdb; rootfs fstab mounts /dev/vda.
type FCConfig struct {
	BootSource        FCBootSource         `json:"boot-source"`
	Drives            []FCDrive            `json:"drives"`
	MachineConfig     FCMachineConfig      `json:"machine-config"`
	Vsock             FCVsock              `json:"vsock"`
	NetworkInterfaces []FCNetworkInterface `json:"network-interfaces"`
}

// FCBootSource matches the BootSource definition in firecracker_spec-v1.16.1.yaml.
type FCBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

// FCDrive matches the Drive definition in firecracker_spec-v1.16.1.yaml.
// PathOnHost is relative to the jailer chroot root (the helper copies files there).
type FCDrive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

// FCMachineConfig matches MachineConfiguration in firecracker_spec-v1.16.1.yaml.
type FCMachineConfig struct {
	VCPUCount  int `json:"vcpu_count"`
	MemSizeMiB int `json:"mem_size_mib"`
}

// FCVsock matches the Vsock definition in firecracker_spec-v1.16.1.yaml.
// GuestCID minimum is 3 per spec.
type FCVsock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

// FCNetworkInterface matches NetworkInterface in firecracker_spec-v1.16.1.yaml.
type FCNetworkInterface struct {
	IfaceID     string `json:"iface_id"`
	HostDevName string `json:"host_dev_name"`
}

// BuildVMConfig constructs all per-VM configuration artifacts and writes
// intermediate files under outDir:
//
//   - context.json: marshaled from guest.BootConfig (one source of truth for schema)
//   - config.ext4:  1 MiB ext4 image containing context.json (mkfs.ext4 -d, works rootless)
//   - fc-config.json: Firecracker config, field names from the pinned spec
//
// Returns the BootConfig (for token/boot_id access), config disk bytes, and
// fc-config.json bytes. Does not write config.ext4 or fc-config.json to outDir —
// callers write them as needed (PrepareVM writes them; unit tests can inspect directly).
//
// lock.VerifyArtifacts is called with repoRoot; a mismatch is a hard error.
// outDir must be a writable directory (e.g., t.TempDir()).
func BuildVMConfig(repoRoot, id string, cid uint32, outDir string) (*guest.BootConfig, []byte, []byte, error) {
	// 1. Verify lock artifacts. A hash mismatch means we won't boot unverified images.
	lk, err := lock.Load(filepath.Join(repoRoot, "runtime.lock.json"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load lock: %w", err)
	}
	if mismatches := lk.VerifyArtifacts(repoRoot); len(mismatches) > 0 {
		return nil, nil, nil, fmt.Errorf("artifact hash mismatch — refusing to build config: %+v", mismatches)
	}

	// 2. Generate fresh per-boot credentials via crypto/rand.
	bootID, err := newUUID()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate boot UUID: %w", err)
	}
	token, err := newHexToken(32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate capability token: %w", err)
	}

	// 3. Marshal context.json via guest.BootConfig — THE one source of truth.
	//    Never hand-write this JSON; the struct owns the schema.
	bootCfg := &guest.BootConfig{
		Schema:          guest.GuestContextSchema,
		VMID:            id,
		BootID:          bootID,
		CapabilityToken: token,
		ProtocolVersion: proto.ProtocolVersion,
	}
	contextJSON, err := json.Marshal(bootCfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal context.json: %w", err)
	}

	// 4. Build the config disk: stage context.json into a tmpdir, then mkfs.ext4 -d.
	diskStageDir := filepath.Join(outDir, "disk-stage")
	if err := os.MkdirAll(diskStageDir, 0755); err != nil {
		return nil, nil, nil, fmt.Errorf("create disk stage dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(diskStageDir, "context.json"), contextJSON, 0644); err != nil {
		return nil, nil, nil, fmt.Errorf("write context.json: %w", err)
	}

	diskPath := filepath.Join(outDir, "config.ext4")
	// mkfs.ext4 size argument is in 1k-blocks; 1 MiB = 1024 blocks.
	mkfs := exec.Command("mkfs.ext4",
		"-d", diskStageDir,
		diskPath,
		fmt.Sprintf("%dK", configDiskSizeMiB*1024),
	)
	if mkfsOut, err := mkfs.CombinedOutput(); err != nil {
		return nil, nil, nil, fmt.Errorf("mkfs.ext4: %w\noutput:\n%s", err, mkfsOut)
	}

	configDisk, err := os.ReadFile(diskPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read config.ext4: %w", err)
	}

	// 5. Build fc-config.json.
	fcCfg := FCConfig{
		BootSource: FCBootSource{
			KernelImagePath: "vmlinux",
			BootArgs:        "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw",
		},
		Drives: []FCDrive{
			// rootfs first → /dev/vda (guestd fstab mount)
			{
				DriveID:      "rootfs",
				PathOnHost:   "rootfs.ext4",
				IsRootDevice: true,
				IsReadOnly:   false,
			},
			// config disk second → /dev/vdb (guestd -config-dev default)
			{
				DriveID:      "config",
				PathOnHost:   "config.ext4",
				IsRootDevice: false,
				IsReadOnly:   true,
			},
		},
		MachineConfig: FCMachineConfig{
			VCPUCount:  1,
			MemSizeMiB: 512,
		},
		Vsock: FCVsock{
			GuestCID: cid,
			UDSPath:  "v.sock",
		},
		NetworkInterfaces: []FCNetworkInterface{
			{
				IfaceID:     "eth0",
				HostDevName: "tap0",
			},
		},
	}
	fcJSON, err := json.MarshalIndent(fcCfg, "", "  ")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal fc-config.json: %w", err)
	}

	return bootCfg, configDisk, fcJSON, nil
}

// ------------------------------------------------------------------
// Private helpers
// ------------------------------------------------------------------

// sudoStage creates stagingDir via sudo and copies each named file into it.
// sources maps filename → absolute source path.
func sudoStage(stagingDir string, sources map[string]string) error {
	mkdirCmd := exec.Command("sudo", "mkdir", "-p", stagingDir)
	if out, err := mkdirCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir %s: %w\n%s", stagingDir, err, out)
	}
	for name, src := range sources {
		dst := filepath.Join(stagingDir, name)
		// --no-preserve=all: don't copy ownership/perms from source;
		// jail-start does chown -R <uid>:<gid> over the chroot.
		cpCmd := exec.Command("sudo", "cp", "--no-preserve=all", src, dst)
		if out, err := cpCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("cp %s → %s: %w\n%s", src, dst, err, out)
		}
	}
	return nil
}

// waitForVsock retries DialHostVsock until the socket answers or ctx expires.
func waitForVsock(ctx context.Context, udsPath string) error {
	var lastErr error
	for {
		dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := proto.DialHostVsock(dialCtx, udsPath, vsockPort)
		cancel()
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return fmt.Errorf("vsock %s not ready after %s: %w", udsPath, readyTimeout, lastErr)
		default:
		}
		time.Sleep(readyBackoff)
	}
}

// newUUID returns a random version-4 UUID string.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// newHexToken returns n random bytes as a lowercase hex string (length 2*n).
func newHexToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
