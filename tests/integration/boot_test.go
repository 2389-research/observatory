// ABOUTME: M0 gate test: jailed two-VM boot, vsock handshake, capability report, disk ownership.
// ABOUTME: Requires the gate container: run this suite with scripts/vmobs-gate.

//go:build linux

package integration_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/guest/proto"
	"github.com/2389-research/observatory/internal/lock"
	"github.com/2389-research/observatory/internal/network"
	"github.com/2389-research/observatory/tests/integration/fixture"
)

const (
	// m0IDA and m0IDB are the identifiers for the two simultaneous fixture VMs.
	// Both match the root-helper constraint ^[a-z0-9][a-z0-9-]{0,62}$.
	m0IDA = "m0-a"
	m0IDB = "m0-b"

	// evidenceDir is relative to the repo root.
	evidenceDir = "tests/integration/evidence"
)

// findRepoRoot walks up from the test working directory to find runtime.lock.json.
func findRepoRoot(t *testing.T) string {
	t.Helper()
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
			t.Fatalf("cannot find repo root above %s", dir)
		}
		dir = parent
	}
}

// gateSkipChecks runs all prerequisite probes and skips the test if any
// prerequisite is absent, with a reason naming scripts/vmobs-gate.
// This mirrors the Task 7 pattern exactly.
func gateSkipChecks(t *testing.T) {
	t.Helper()

	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 to run root-gated boot integration tests")
	}

	// All of these are provided by the gate container (deploy/Dockerfile.gate,
	// deploy/gate-entrypoint.sh), which scripts/vmobs-gate builds and runs.
	const helperPath = "/usr/local/sbin/vmobs-root-helper"
	if _, err := os.Stat(helperPath); os.IsNotExist(err) {
		t.Skipf("root helper absent at %s; run this suite with scripts/vmobs-gate", helperPath)
	}
	if _, err := os.Stat("/srv/vmobs"); os.IsNotExist(err) {
		t.Skipf("/srv/vmobs absent; run this suite with scripts/vmobs-gate")
	}
	if _, err := os.Stat("/usr/local/bin/firecracker"); os.IsNotExist(err) {
		t.Skipf("firecracker absent at /usr/local/bin/firecracker; run this suite with scripts/vmobs-gate")
	}
	// vmobs-fixture group ships in the appliance image at the fixed gid 36000.
	// user.LookupGroup may need CGO; use getent for portability.
	if err := exec.Command("getent", "group", "vmobs-fixture").Run(); err != nil {
		t.Skipf("vmobs-fixture group absent; run this suite with scripts/vmobs-gate")
	}
}

// TestM0Boot is the M0 gate: boots two jailed Firecracker VMs simultaneously,
// verifies vsock handshake, capability report, disk ownership, and teardown.
func TestM0Boot(t *testing.T) {
	gateSkipChecks(t)

	repoRoot := findRepoRoot(t)

	// Verify lock artifacts before any boot. A mismatch aborts — never boot unverified images.
	lk, err := lock.Load(filepath.Join(repoRoot, "runtime.lock.json"))
	if err != nil {
		t.Fatalf("load lock: %v", err)
	}
	if mismatches := lk.VerifyArtifacts(repoRoot); len(mismatches) > 0 {
		t.Fatalf("artifact hash mismatch — refusing to boot: %+v", mismatches)
	}

	// Build allocator from live routing table (table all to catch tailscale routes).
	routeJSON, err := exec.Command("ip", "-json", "route", "show", "table", "all").Output()
	if err != nil {
		t.Fatalf("ip -json route show table all: %v", err)
	}
	routes, err := network.ParseIPRoutes(routeJSON)
	if err != nil {
		t.Fatalf("parse ip routes: %v", err)
	}
	// Default pools. NewAllocator excludes any that overlap host routes.
	pools := []netip.Prefix{
		netip.MustParsePrefix("10.190.0.0/16"),
		netip.MustParsePrefix("10.191.0.0/16"),
	}
	alloc, err := network.NewAllocator(routes, pools)
	if err != nil {
		t.Fatalf("build allocator: %v", err)
	}

	// Prepare both VMs: pure config-building, no root needed.
	vmA := fixture.PrepareVM(t, repoRoot, m0IDA, 0, alloc)
	vmB := fixture.PrepareVM(t, repoRoot, m0IDB, 1, alloc)

	// Boot both VMs. The jailer uses --daemonize, so jail-start returns quickly
	// after the jailer forks the firecracker process into the background.
	// Start() calls waitForVsock, which waits for each VM to become ready.
	// Both VMs are alive concurrently before any assertion runs.
	vmA.Start(t)
	vmB.Start(t)

	// --- Assertion 1: Real KVM boot + vsock handshake + identity isolation ---

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer dialCancel()

	connA, err := vmA.DialControl(dialCtx)
	if err != nil {
		t.Fatalf("dial vmA control: %v", err)
	}
	defer connA.Close()

	connB, err := vmB.DialControl(dialCtx)
	if err != nil {
		t.Fatalf("dial vmB control: %v", err)
	}
	defer connB.Close()

	// A's correct token → accepted.
	ackA := sendHello(t, connA, vmA.BootCfg.VMID, vmA.BootCfg.BootID, vmA.BootCfg.CapabilityToken)
	if !ackA.Accepted {
		t.Errorf("vmA hello rejected: %s", ackA.Reason)
	}

	// B's correct token → accepted.
	ackB := sendHello(t, connB, vmB.BootCfg.VMID, vmB.BootCfg.BootID, vmB.BootCfg.CapabilityToken)
	if !ackB.Accepted {
		t.Errorf("vmB hello rejected: %s", ackB.Reason)
	}

	// Identity isolation: A's token must be REJECTED on B's socket.
	// Open a fresh connection to B for the cross-auth attempt.
	connCross, err := vmB.DialControl(dialCtx)
	if err != nil {
		t.Fatalf("cross-dial vmB for isolation check: %v", err)
	}
	defer connCross.Close()
	ackCross := sendHello(t, connCross, vmA.BootCfg.VMID, vmA.BootCfg.BootID, vmA.BootCfg.CapabilityToken)
	if ackCross.Accepted {
		t.Errorf("identity isolation FAILED: vmA's token was accepted on vmB's socket")
	}

	// --- Assertion 2: Capability report ---

	manifestA := getCapabilities(t, connA)
	manifestB := getCapabilities(t, connB)

	// The Task 6 rootfs carries all required kernel features; fanotify has
	// CAP_SYS_ADMIN (guestd runs as root in-guest) so Present=true is expected.
	requiredCaps := []string{"btf", "fanotify", "vsock", "virtio_blk", "virtio_net", "cgroup_v2", "ext4"}
	for _, capID := range requiredCaps {
		checkCapPresent(t, "vmA", manifestA, capID)
		checkCapPresent(t, "vmB", manifestB, capID)
	}

	// --- Assertion 3: Independent disk ownership ---

	ownership := statHostFiles(t, vmA, vmB)

	// --- Assertion 4: Independent teardown ---

	// Stop A; B must still answer ping.
	vmA.Stop(t)

	pingCtx, pingCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pingCancel()
	if err := sendPing(pingCtx, connB); err != nil {
		t.Errorf("vmB ping after vmA stop: %v", err)
	}

	// Stop B (cleanup also runs at test end; double-stop is idempotent).
	vmB.Stop(t)

	// After both VMs are stopped: no test VM entries remain in jail or netns.
	checkNoLeaks(t, m0IDA, m0IDB)

	// --- Step 4: Write evidence file (only when the gate actually runs) ---

	hostname, _ := os.Hostname()
	writeEvidenceFile(t, repoRoot, hostname, lk, vmA, vmB, ackA, ackB, ackCross, manifestA, manifestB, ownership)
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

// sendHello performs the hello handshake with the given credentials and returns the ack.
func sendHello(t *testing.T, conn net.Conn, vmID, bootID, token string) proto.HelloAck {
	t.Helper()
	hello := proto.Hello{
		ProtocolVersion: proto.ProtocolVersion,
		VMID:            vmID,
		BootID:          bootID,
		SourceInstance:  "fixture",
		ResumeCursor:    "0",
		AuthProof:       token,
	}
	if err := proto.WriteControl(conn, proto.KindHello, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		t.Fatalf("read hello_ack: %v", err)
	}
	if env.Kind != proto.KindHelloAck {
		t.Fatalf("expected hello_ack, got %q", env.Kind)
	}
	var ack proto.HelloAck
	if err := json.Unmarshal(env.Data, &ack); err != nil {
		t.Fatalf("unmarshal hello_ack: %v", err)
	}
	return ack
}

// getCapabilities sends get_capabilities and returns the parsed manifest.
func getCapabilities(t *testing.T, conn net.Conn) proto.CapabilityManifest {
	t.Helper()
	if err := proto.WriteControl(conn, proto.KindGetCapabilities, struct{}{}); err != nil {
		t.Fatalf("write get_capabilities: %v", err)
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		t.Fatalf("read capabilities: %v", err)
	}
	if env.Kind != proto.KindCapabilities {
		t.Fatalf("expected capabilities, got %q", env.Kind)
	}
	var manifest proto.CapabilityManifest
	if err := json.Unmarshal(env.Data, &manifest); err != nil {
		t.Fatalf("unmarshal capability manifest: %v", err)
	}
	return manifest
}

// checkCapPresent asserts that the named capability is Present:true with evidence.
func checkCapPresent(t *testing.T, vmLabel string, manifest proto.CapabilityManifest, capID string) {
	t.Helper()
	for _, f := range manifest.Features {
		if f.ID == capID {
			if !f.Present {
				t.Errorf("%s: capability %q not present (expected present)", vmLabel, capID)
			}
			if f.Evidence == "" {
				t.Errorf("%s: capability %q has no evidence string", vmLabel, capID)
			}
			return
		}
	}
	t.Errorf("%s: capability %q not in manifest (features: %v)", vmLabel, capID, manifest.Features)
}

// sendPing sends a ping and asserts the pong reply, using ctx for deadline.
func sendPing(ctx context.Context, conn net.Conn) error {
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			return fmt.Errorf("set deadline: %w", err)
		}
	}
	if err := proto.WriteControl(conn, proto.KindPing, struct{}{}); err != nil {
		return fmt.Errorf("write ping: %w", err)
	}
	env, err := proto.ReadControl(conn)
	if err != nil {
		return fmt.Errorf("read pong: %w", err)
	}
	if env.Kind != proto.KindPong {
		return fmt.Errorf("expected pong, got %q", env.Kind)
	}
	// Clear the deadline so the connection remains usable for subsequent operations.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("clear deadline: %w", err)
	}
	return nil
}

// statHostFiles checks disk and socket ownership, isolation, and write permissions from the host.
// Sockets (api.sock, v.sock) must already exist — call this after the vsock readiness wait.
// Returns the formatted observations for the evidence file — the jail dirs are gone
// by evidence-writing time, so the writer must not stat again.
func statHostFiles(t *testing.T, vmA, vmB *fixture.VM) []string {
	t.Helper()
	const jailBase = "/srv/vmobs/jail"
	var lines []string
	record := func(p string, st *syscall.Stat_t, err error) {
		if err != nil {
			lines = append(lines, fmt.Sprintf("%s: stat error: %v", p, err))
			return
		}
		lines = append(lines, fmt.Sprintf("%s: uid=%d mode=%04o inode=%d", p, st.Uid, st.Mode&0777, st.Ino))
	}

	pathA := filepath.Join(jailBase, "firecracker", vmA.ID, "root", "rootfs.ext4")
	pathB := filepath.Join(jailBase, "firecracker", vmB.ID, "root", "rootfs.ext4")

	var statA, statB syscall.Stat_t
	statAOK := true
	statBOK := true
	errA := syscall.Stat(pathA, &statA)
	record(pathA, &statA, errA)
	if errA != nil {
		t.Errorf("stat %s: %v", pathA, errA)
		statAOK = false
	}
	errB := syscall.Stat(pathB, &statB)
	record(pathB, &statB, errB)
	if errB != nil {
		t.Errorf("stat %s: %v", pathB, errB)
		statBOK = false
	}

	// Each VM's file must be owned by its own UID.
	if statAOK && int(statA.Uid) != vmA.UID {
		t.Errorf("%s: uid=%d, want %d", pathA, statA.Uid, vmA.UID)
	}
	if statBOK && int(statB.Uid) != vmB.UID {
		t.Errorf("%s: uid=%d, want %d", pathB, statB.Uid, vmB.UID)
	}

	// UIDs must differ — identity isolation at the filesystem level.
	// Guard: only compare inodes/uids when both stats succeeded.
	if statAOK && statBOK {
		if statA.Uid == statB.Uid {
			t.Errorf("vmA and vmB share uid %d (identity isolation failure)", statA.Uid)
		}

		// Independent inodes — truly separate copies, not hardlinks.
		if statA.Ino == statB.Ino {
			t.Errorf("vmA and vmB rootfs.ext4 share inode %d (hardlink detected)", statA.Ino)
		}
	}

	// Not world-writable: no other process should be able to corrupt the disk.
	if statAOK && statA.Mode&0002 != 0 {
		t.Errorf("%s: world-writable (mode %04o)", pathA, statA.Mode&0777)
	}
	if statBOK && statB.Mode&0002 != 0 {
		t.Errorf("%s: world-writable (mode %04o)", pathB, statB.Mode&0777)
	}

	// Brief assertion 3: api.sock and v.sock in each VM's chroot root must be owned
	// by that VM's own uid. The jailer creates them with chown -R uid:gid.
	for _, vm := range []*fixture.VM{vmA, vmB} {
		root := filepath.Join(jailBase, "firecracker", vm.ID, "root")
		for _, sockName := range []string{"api.sock", "v.sock"} {
			sockPath := filepath.Join(root, sockName)
			var st syscall.Stat_t
			err := syscall.Stat(sockPath, &st)
			record(sockPath, &st, err)
			if err != nil {
				t.Errorf("stat %s: %v", sockPath, err)
				continue
			}
			if int(st.Uid) != vm.UID {
				t.Errorf("%s: uid=%d, want %d (vm uid)", sockPath, st.Uid, vm.UID)
			}
		}
	}
	return lines
}

// checkNoLeaks asserts that none of the test VM ids remain in the jail or netns
// directories after teardown. Expected names are derived from the actual ids via
// the exported network package functions so a helper rename can't silently miss this.
func checkNoLeaks(t *testing.T, ids ...string) {
	t.Helper()

	// Build sets of expected jail dir names and netns names from the actual ids.
	wantJail := make(map[string]bool, len(ids))
	wantNS := make(map[string]bool, len(ids))
	for _, id := range ids {
		wantJail[id] = true
		wantNS[network.NamespaceName(id)] = true
	}

	const jailFirecracker = "/srv/vmobs/jail/firecracker"
	entries, err := os.ReadDir(jailFirecracker)
	if err != nil && !os.IsNotExist(err) {
		t.Logf("readdir %s: %v", jailFirecracker, err)
	}
	for _, e := range entries {
		if wantJail[e.Name()] {
			t.Errorf("jail leak: %s/%s still exists after both VMs stopped", jailFirecracker, e.Name())
		}
	}

	const netnsDir = "/var/run/netns"
	nsEntries, err := os.ReadDir(netnsDir)
	if err != nil && !os.IsNotExist(err) {
		t.Logf("readdir %s: %v", netnsDir, err)
	}
	for _, e := range nsEntries {
		if wantNS[e.Name()] {
			t.Errorf("netns leak: %s/%s still exists after both VMs stopped", netnsDir, e.Name())
		}
	}
}

// writeEvidenceFile writes a bounded (≤200 lines) evidence file.
// Called only when the gate actually runs — never fabricated.
func writeEvidenceFile(
	t *testing.T,
	repoRoot, hostname string,
	lk *lock.Lock,
	vmA, vmB *fixture.VM,
	ackA, ackB, ackCross proto.HelloAck,
	manifestA, manifestB proto.CapabilityManifest,
	ownership []string,
) {
	t.Helper()

	evidencePath := filepath.Join(repoRoot, evidenceDir, fmt.Sprintf("m0-boot-%s.txt", hostname))
	if err := os.MkdirAll(filepath.Join(repoRoot, evidenceDir), 0755); err != nil {
		t.Logf("writeEvidenceFile: mkdir: %v", err)
		return
	}

	var sb strings.Builder
	w := bufio.NewWriter(&sb)

	fmt.Fprintln(w, "# M0 boot gate evidence")
	fmt.Fprintf(w, "# hostname: %s\n", hostname)
	fmt.Fprintf(w, "# date: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Lock artifact verification")
	fmt.Fprintf(w, "vmlinux_sha256:  %s\n", lk.GuestKernel.VmlinuxSHA256)
	fmt.Fprintf(w, "rootfs_sha256:   %s\n", lk.RootImage.SHA256)
	fmt.Fprintln(w, "verified: true (VerifyArtifacts returned no mismatches)")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Firecracker version")
	if out, err := exec.Command("/usr/local/bin/firecracker", "--version").Output(); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			fmt.Fprintf(w, "  %s\n", l)
		}
	} else {
		fmt.Fprintf(w, "  (error reading version: %v)\n", err)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Per-VM identity")
	for _, vm := range []*fixture.VM{vmA, vmB} {
		fmt.Fprintf(w, "  vm_id=%-6s  uid=%d  gid=%d  cid=%d  netns=vmobs-%s\n",
			vm.ID, vm.UID, vm.GID, vm.CID, vm.ID)
	}
	fmt.Fprintln(w)

	// Handshake transcript: kinds only, never the token. Values are the real ack results.
	fmt.Fprintln(w, "## Handshake transcript (message kinds only; tokens omitted)")
	fmt.Fprintf(w, "  vmA: %s → %s (accepted=%v reason=%q)\n", proto.KindHello, proto.KindHelloAck, ackA.Accepted, ackA.Reason)
	fmt.Fprintf(w, "  vmB: %s → %s (accepted=%v reason=%q)\n", proto.KindHello, proto.KindHelloAck, ackB.Accepted, ackB.Reason)
	fmt.Fprintf(w, "  cross-auth: vmA token on vmB socket → %s (accepted=%v reason=%q)\n", proto.KindHelloAck, ackCross.Accepted, ackCross.Reason)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Capability manifests")
	for label, manifest := range map[string]proto.CapabilityManifest{"vmA": manifestA, "vmB": manifestB} {
		fmt.Fprintf(w, "  ### %s  kernel=%s\n", label, manifest.KernelRelease)
		for _, f := range manifest.Features {
			fmt.Fprintf(w, "    %-12s present=%-5v evidence=%q\n", f.ID, f.Present, f.Evidence)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Disk and socket ownership (host stat, captured while VMs were live)")
	for _, l := range ownership {
		fmt.Fprintf(w, "  %s\n", l)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "## Teardown proof")
	const jailBase = "/srv/vmobs/jail"
	// Build expected jail and netns names from the actual ids to stay in sync with the helper.
	expectedJail := map[string]bool{vmA.ID: true, vmB.ID: true}
	expectedNS := map[string]bool{network.NamespaceName(vmA.ID): true, network.NamespaceName(vmB.ID): true}
	jailEntries, _ := os.ReadDir(filepath.Join(jailBase, "firecracker"))
	leakedJail := []string{}
	for _, e := range jailEntries {
		if expectedJail[e.Name()] {
			leakedJail = append(leakedJail, e.Name())
		}
	}
	nsEntries, _ := os.ReadDir("/var/run/netns")
	leakedNS := []string{}
	for _, e := range nsEntries {
		if expectedNS[e.Name()] {
			leakedNS = append(leakedNS, e.Name())
		}
	}
	if len(leakedJail) == 0 && len(leakedNS) == 0 {
		fmt.Fprintln(w, "  no test VM entries remain in jail or netns (clean teardown)")
	} else {
		fmt.Fprintf(w, "  jail residue: %v\n", leakedJail)
		fmt.Fprintf(w, "  netns residue: %v\n", leakedNS)
	}

	w.Flush()

	if err := os.WriteFile(evidencePath, []byte(sb.String()), 0644); err != nil {
		t.Logf("writeEvidenceFile: %v", err)
	} else {
		t.Logf("evidence written to %s", evidencePath)
	}
}
