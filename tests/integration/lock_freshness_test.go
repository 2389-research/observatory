// ABOUTME: Real-host proof the doctor reads runtime.lock.json per request — a
// ABOUTME: re-pin flips fc_binaries and runtime availability with no restart.

//go:build linux

package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lockOnlyRoot builds a root holding nothing but a copy of the real
// runtime.lock.json. startDaemon reads that one file out of the root it is
// handed, and this test boots no VM, so hard-linking the 1.6 GiB of pinned
// artifacts beside it would buy nothing. The copy is what the test re-pins:
// the promoted lock is the host's, and every other gate reads it.
func lockOnlyRoot(t *testing.T, repoRoot string) string {
	t.Helper()

	root := t.TempDir()
	src := filepath.Join(repoRoot, "runtime.lock.json")
	if err := copyFile(src, filepath.Join(root, "runtime.lock.json"), 0o644); err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
	return root
}

// pinnedFirecrackerSHA reads the digest the lock currently pins for firecracker.
func pinnedFirecrackerSHA(t *testing.T, lockPath string) string {
	t.Helper()

	doc := readLockDoc(t, lockPath)
	fc, ok := doc["firecracker"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no firecracker section", lockPath)
	}
	sha, _ := fc["sha256"].(string)
	if sha == "" {
		t.Fatalf("%s pins no firecracker digest; this gate needs a pinned host", lockPath)
	}
	return sha
}

// repinFirecracker rewrites the firecracker digest and leaves the rest of the
// document alone — the edit a re-pin makes. Written to a sibling and renamed so
// a preflight run cannot read a half-written file and report damage that never
// existed.
func repinFirecracker(t *testing.T, lockPath, sha string) {
	t.Helper()

	doc := readLockDoc(t, lockPath)
	fc, ok := doc["firecracker"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no firecracker section", lockPath)
	}
	fc["sha256"] = sha

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	tmp := lockPath + ".repin"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		t.Fatalf("write %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, lockPath); err != nil {
		t.Fatalf("rename %s -> %s: %v", tmp, lockPath, err)
	}
}

func readLockDoc(t *testing.T, lockPath string) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read %s: %v", lockPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", lockPath, err)
	}
	return doc
}

// doctorView is what one GET /host/status says about the pinned binaries and
// about whether the host will accept a launch. The two travel together because
// the second is derived from the first: Adapter.Availability turns any failing
// check into an UnavailableError.
type doctorView struct {
	status    string
	evidence  []string
	available bool
	reason    string
}

func (v doctorView) evidenceMentions(want string) bool {
	for _, ev := range v.evidence {
		if strings.Contains(ev, want) {
			return true
		}
	}
	return false
}

func readDoctor(t *testing.T, d *m1aDaemon) doctorView {
	t.Helper()

	status, body := d.apiGetCode(t, "/host/status")
	if status != 200 {
		t.Fatalf("GET /host/status: %d: %v", status, body)
	}
	pf, _ := body["preflight"].(map[string]any)
	if pf == nil {
		t.Fatal("GET /host/status: no preflight block")
	}
	checks, _ := pf["checks"].([]any)

	var view doctorView
	found := false
	for _, c := range checks {
		cm, _ := c.(map[string]any)
		if id, _ := cm["id"].(string); id != "fc_binaries" {
			continue
		}
		found = true
		view.status, _ = cm["status"].(string)
		evs, _ := cm["evidence"].([]any)
		for _, e := range evs {
			s, _ := e.(string)
			view.evidence = append(view.evidence, s)
		}
	}
	if !found {
		t.Fatalf("GET /host/status: no fc_binaries check in %v", checks)
	}

	rt, _ := body["runtime"].(map[string]any)
	view.available, _ = rt["available"].(bool)
	view.reason, _ = rt["reason"].(string)
	return view
}

// TestDoctorFollowsTheLockWhileRunning proves on a real host what the preflight
// unit tests prove in isolation: fc_binaries answers from runtime.lock.json as
// it is now, not as it was when the daemon started. Nothing else covers the
// served path — a cache added in front of the preflight runner would leave
// every unit test green and put this behaviour back the way it was.
//
// It reaches past the doctor line. Adapter.Availability turns a failing check
// into an UnavailableError, so a stale mismatch publishes runtime.available =
// false and refuses every POST /vms. An operator who re-pinned to fix the host
// would watch it keep refusing until someone restarted the daemon.
//
// One daemon, three requests, no restart and no VM: the installed host passes;
// a pin the binary does not have fails and takes the runtime out of service;
// putting the real pin back restores both.
func TestDoctorFollowsTheLockWhileRunning(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 to run the lock freshness gate (requires installed vmobs-privd; must NOT run as root)")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)

	if os.Getuid() == 0 {
		t.Fatal("must not run as root; privileged ops flow through privd socket only")
	}

	repoRoot := findRepoRoot(t)
	daemonBin := buildBinary(t, "github.com/2389-research/observatory-v2/cmd/vmobsd")
	runnerBin := buildBinary(t, "github.com/2389-research/observatory-v2/cmd/vmobs-runner")

	root := lockOnlyRoot(t, repoRoot)
	lockPath := filepath.Join(root, "runtime.lock.json")
	installedSHA := pinnedFirecrackerSHA(t, lockPath)

	daemon := startDaemon(t, root, daemonBin, runnerBin, "f8f2-repin")

	view := readDoctor(t, daemon)
	if view.status != "pass" {
		t.Fatalf("fc_binaries on the installed host = %q, want pass; gate is honestly red, fix the host: %v", view.status, view.evidence)
	}
	if !view.available {
		t.Fatalf("runtime.available = false on a passing host: %s", view.reason)
	}

	// A digest the installed firecracker does not have. 64 lowercase hex: the
	// shape a real re-pin writes, so nothing downstream can dismiss it as
	// malformed input rather than a wrong answer.
	const wrongPin = "1111111111111111111111111111111111111111111111111111111111111111"
	repinFirecracker(t, lockPath, wrongPin)

	view = readDoctor(t, daemon)
	if view.status != "fail" {
		t.Errorf("fc_binaries after a re-pin the binary does not match = %q, want fail — the daemon is answering from the lock it parsed at startup: %v",
			view.status, view.evidence)
	}
	if !view.evidenceMentions(wrongPin) {
		t.Errorf("evidence does not name the pin now in the file: %v", view.evidence)
	}
	if view.available {
		t.Error("runtime.available stayed true while fc_binaries failed; a host that will not verify its binaries must not accept launches")
	}
	if !strings.Contains(view.reason, "fc_binaries") {
		t.Errorf("runtime.reason = %q, want it to name the failing check", view.reason)
	}

	// The operator re-pins to the truth. This is the case the fix exists for.
	repinFirecracker(t, lockPath, installedSHA)

	view = readDoctor(t, daemon)
	if view.status != "pass" {
		t.Errorf("fc_binaries after re-pinning to the installed digest = %q, want pass — a daemon that cannot see the fix keeps refusing launches until someone restarts it: %v",
			view.status, view.evidence)
	}
	if !view.available {
		t.Errorf("runtime.available = false after the re-pin that fixed the host: %s", view.reason)
	}
}
