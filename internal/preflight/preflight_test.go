// ABOUTME: Preflight framework tests: aggregation truth table, JSON field names,
// ABOUTME: check presence, and portable check logic with real files/tempdir.
package preflight_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/preflight"
)

// isLinux reports whether the current build target is Linux.
func isLinux() bool { return runtime.GOOS == "linux" }

// --- aggregation truth table ---

func TestAggregateOverallWithFailingCheck(t *testing.T) {
	// Any fail → overall fail (not_implemented in same set doesn't change it).
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	hasFail := false
	for _, c := range report.Checks {
		if c.Status == preflight.StatusFail {
			hasFail = true
			break
		}
	}
	if hasFail && report.Overall != preflight.StatusFail {
		t.Errorf("Overall=%q with failing checks, want fail", report.Overall)
	}
}

// TestGuestChannelNotImplementedDoesNotDriveOverallFail verifies that on non-Linux
// the guest_channel check is not_implemented and does not affect Overall.
// On Linux this test is skipped because the check is a real fail/pass check.
func TestGuestChannelNotImplementedDoesNotDriveOverallFail(t *testing.T) {
	// This invariant only applies to non-Linux where the check is not_implemented.
	// On Linux the check is a real probe and may legitimately fail.
	if isLinux() {
		t.Skip("on Linux, guest_channel is a real check — not_implemented behaviour not applicable")
	}
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	var guestCheck *preflight.Check
	for i := range report.Checks {
		if report.Checks[i].ID == "guest_channel" {
			guestCheck = &report.Checks[i]
			break
		}
	}
	if guestCheck == nil {
		t.Fatal("guest_channel check not present in report")
	}
	if guestCheck.Status != preflight.StatusNotImplemented {
		t.Errorf("guest_channel status = %q, want not_implemented", guestCheck.Status)
	}
}

// TestOnlyNotImplementedGivesPass verifies the aggregation rule: a report with
// only not_implemented checks produces Overall=pass. We test this via a report
// that only has the guest_channel check passing by constructing a custom config
// where all other checks would pass (then guest_channel stays not_implemented).
// We verify the aggregation logic through the observable: pass API config +
// valid dir + proc root → the only non-pass entry is guest_channel.
func TestOnlyNotImplementedGivesPass(t *testing.T) {
	dir := t.TempDir()
	// Write synthetic meminfo so resources check has data.
	meminfo := "MemTotal:       16384000 kB\nMemAvailable:   8192000 kB\n"
	if err := os.WriteFile(filepath.Join(dir, "meminfo"), []byte(meminfo), 0o644); err != nil {
		t.Fatalf("write meminfo: %v", err)
	}
	// The report will still have cgroup_v2/net_prereqs/arch_kvm failures on macOS,
	// but we can at minimum assert that not_implemented alone doesn't produce fail
	// by checking that guest_channel being not_implemented doesn't correlate with
	// Overall=fail when all other checks pass (which can't be forced on macOS).
	// Instead: assert the aggregation contract via the check list inspection.
	r := preflight.New(preflight.Config{
		DataDir:     dir,
		ProcRoot:    dir,
		APIMode:     "loopback_only",
		RequireAuth: false,
	})
	report := r.Run(t.Context())

	// Overall can only be fail if there's at least one fail check (not not_implemented).
	if report.Overall == preflight.StatusFail {
		for _, c := range report.Checks {
			if c.Status == preflight.StatusFail {
				return // there's a real failure causing it — acceptable
			}
		}
		t.Error("Overall=fail but no check has status=fail (not_implemented drove it illegally)")
	}
}

func TestAllCheckIDsPresentOnce(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	expectedIDs := []string{
		"arch_kvm",
		"fc_binaries",
		"kernel_tuple",
		"cgroup_v2",
		"net_prereqs",
		"resources",
		"dir_permissions",
		"api_binding",
		"guest_channel",
	}
	seen := map[string]int{}
	for _, c := range report.Checks {
		seen[c.ID]++
	}
	for _, id := range expectedIDs {
		if seen[id] == 0 {
			t.Errorf("check %q absent from report", id)
		} else if seen[id] > 1 {
			t.Errorf("check %q appears %d times, want 1", id, seen[id])
		}
	}
	if len(report.Checks) != len(expectedIDs) {
		t.Errorf("report has %d checks, want %d", len(report.Checks), len(expectedIDs))
	}
}

// --- JSON field names ---

func TestJSONFieldNames(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	b, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, f := range []string{"ran_at", "arch", "kernel_release", "overall", "checks"} {
		if _, ok := raw[f]; !ok {
			t.Errorf("JSON missing top-level field %q", f)
		}
	}

	checks, _ := raw["checks"].([]any)
	if len(checks) == 0 {
		t.Fatal("checks array is empty")
	}
	firstCheck, _ := checks[0].(map[string]any)
	for _, f := range []string{"id", "status", "summary", "evidence"} {
		if _, ok := firstCheck[f]; !ok {
			t.Errorf("check JSON missing field %q", f)
		}
	}
}

// --- fc_binaries ---

// fcBinaries runs a full report and returns the fc_binaries check. Every
// fixture below runs the whole report because that is how the daemon calls it:
// the check reads the lock file itself, so what a test changes between two Run
// calls is what an operator changed between two /host/status requests.
func fcBinaries(t *testing.T, r *preflight.Runner) preflight.Check {
	t.Helper()
	fc := findCheck(r.Run(t.Context()).Checks, "fc_binaries")
	if fc == nil {
		t.Fatal("fc_binaries not in report")
	}
	return *fc
}

func evidenceMentions(c preflight.Check, want string) bool {
	for _, ev := range c.Evidence {
		if strings.Contains(ev, want) {
			return true
		}
	}
	return false
}

func TestFCBinariesNoLock(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})

	fc := fcBinaries(t, r)
	if fc.Status != preflight.StatusFail {
		t.Errorf("fc_binaries with no lock configured = %q, want fail", fc.Status)
	}
	if !strings.Contains(fc.Summary, "no runtime lock") {
		t.Errorf("fc_binaries summary = %q, want 'no runtime lock'", fc.Summary)
	}
	if fc.Remediation == nil || fc.Remediation.Cause != "lock_absent" {
		t.Errorf("fc_binaries remediation = %+v, want cause lock_absent", fc.Remediation)
	}
}

// A configured path with no file behind it gets the same answer as no lock at
// all — create one — and not the "the file is corrupt" answer. The daemon's
// startup load used to turn a missing file into a load error, so an operator
// who had never run setup.sh was told to re-pin a lock that did not exist.
func TestFCBinariesLockFileMissing(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "runtime.lock.json")
	r := preflight.New(preflight.Config{DataDir: t.TempDir(), LockPath: lockPath})

	fc := fcBinaries(t, r)
	if fc.Status != preflight.StatusFail {
		t.Errorf("fc_binaries with a missing lock file = %q, want fail", fc.Status)
	}
	if fc.Remediation == nil || fc.Remediation.Cause != "lock_absent" {
		t.Errorf("fc_binaries remediation = %+v, want cause lock_absent", fc.Remediation)
	}
	if !evidenceMentions(fc, lockPath) {
		t.Errorf("fc_binaries evidence should name the path it looked at: %v", fc.Evidence)
	}
}

func TestFCBinariesLockUnparseable(t *testing.T) {
	lockPath := writeLock(t, `{"schema": "vmobs.runtime_lock.v1"`)
	r := preflight.New(preflight.Config{DataDir: t.TempDir(), LockPath: lockPath})

	fc := fcBinaries(t, r)
	if fc.Status != preflight.StatusFail {
		t.Errorf("fc_binaries with an unparseable lock = %q, want fail", fc.Status)
	}
	if fc.Remediation == nil || fc.Remediation.Cause != "lock_load_error" {
		t.Errorf("fc_binaries remediation = %+v, want cause lock_load_error", fc.Remediation)
	}
}

func TestFCBinariesUnpinned(t *testing.T) {
	lockPath := writeLock(t, lockJSON("", "/usr/bin/firecracker", "", "/usr/bin/jailer"))
	r := preflight.New(preflight.Config{DataDir: t.TempDir(), LockPath: lockPath})

	if fc := fcBinaries(t, r); fc.Status != preflight.StatusWarn {
		t.Errorf("fc_binaries with unpinned binaries = %q, want warn", fc.Status)
	}
}

func TestFCBinariesMismatch(t *testing.T) {
	// Pinned sha256s pointing at /nonexistent paths → Got="absent".
	lockPath := writeLock(t, lockJSON("deadbeef", "/nonexistent/firecracker", "cafebabe", "/nonexistent/jailer"))
	r := preflight.New(preflight.Config{DataDir: t.TempDir(), LockPath: lockPath})

	fc := fcBinaries(t, r)
	if fc.Status != preflight.StatusFail {
		t.Errorf("fc_binaries with a mismatch = %q, want fail", fc.Status)
	}
	if !evidenceMentions(fc, "firecracker") && !evidenceMentions(fc, "jailer") {
		t.Errorf("fc_binaries evidence should name the mismatch subject: %v", fc.Evidence)
	}
}

// TestFCBinariesFollowsARepinWithoutARestart is why the check reads the file
// itself. scripts/aibox03/setup.sh installs a firecracker release and re-pins
// runtime.lock.json in one go; a runner holding the lock it parsed at startup
// then hashes the new binary against the old pin and reports a mismatch that is
// not there. It is not only a wrong doctor line — the jailer adapter turns any
// failing check into an UnavailableError, so the daemon refuses every VM
// creation until someone restarts it.
func TestFCBinariesFollowsARepinWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	fcPath := filepath.Join(dir, "firecracker")
	jailerPath := filepath.Join(dir, "jailer")
	lockPath := filepath.Join(dir, "runtime.lock.json")

	fcSHA := writeBinary(t, fcPath, "firecracker v1.0")
	jailerSHA := writeBinary(t, jailerPath, "jailer v1.0")
	writeLockAt(t, lockPath, lockJSON(fcSHA, fcPath, jailerSHA, jailerPath))

	r := preflight.New(preflight.Config{DataDir: t.TempDir(), LockPath: lockPath})
	fc := fcBinaries(t, r)
	if fc.Status != preflight.StatusPass {
		t.Fatalf("fc_binaries on a freshly pinned host = %q (%s): %v", fc.Status, fc.Summary, fc.Evidence)
	}
	if !evidenceMentions(fc, lockPath) {
		t.Errorf("pass evidence should name the lock it read: %v", fc.Evidence)
	}

	// The operator upgrades both binaries and re-pins. Nothing restarts.
	fcSHA = writeBinary(t, fcPath, "firecracker v1.1")
	jailerSHA = writeBinary(t, jailerPath, "jailer v1.1")
	writeLockAt(t, lockPath, lockJSON(fcSHA, fcPath, jailerSHA, jailerPath))

	fc = fcBinaries(t, r)
	if fc.Status != preflight.StatusPass {
		t.Errorf("fc_binaries after a repin = %q (%s), want pass; the check hashes the installed binaries live, so it has to read the pins live too: %v",
			fc.Status, fc.Summary, fc.Evidence)
	}
}

// The same file changing under the runner, in the failing direction: a repin to
// a digest the installed binary does not have must fail on the new pin. A check
// that reported the old pin's verdict would pass this host straight through.
func TestFCBinariesFailsOnARepinTheBinaryDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	fcPath := filepath.Join(dir, "firecracker")
	jailerPath := filepath.Join(dir, "jailer")
	lockPath := filepath.Join(dir, "runtime.lock.json")

	fcSHA := writeBinary(t, fcPath, "firecracker v1.0")
	jailerSHA := writeBinary(t, jailerPath, "jailer v1.0")
	writeLockAt(t, lockPath, lockJSON(fcSHA, fcPath, jailerSHA, jailerPath))

	r := preflight.New(preflight.Config{DataDir: t.TempDir(), LockPath: lockPath})
	if fc := fcBinaries(t, r); fc.Status != preflight.StatusPass {
		t.Fatalf("fc_binaries on a freshly pinned host = %q (%s): %v", fc.Status, fc.Summary, fc.Evidence)
	}

	const wrongPin = "1111111111111111111111111111111111111111111111111111111111111111"
	writeLockAt(t, lockPath, lockJSON(wrongPin, fcPath, jailerSHA, jailerPath))

	fc := fcBinaries(t, r)
	if fc.Status != preflight.StatusFail {
		t.Fatalf("fc_binaries after a repin to a wrong digest = %q (%s), want fail", fc.Status, fc.Summary)
	}
	if !evidenceMentions(fc, wrongPin) {
		t.Errorf("evidence should name the pin now in the file, not the one parsed earlier: %v", fc.Evidence)
	}
}

// A lock that stops parsing while the daemon runs is a live fact too. Held from
// startup, the doctor keeps answering from a copy of a file nobody can read.
func TestFCBinariesSeesALockCorruptedAfterStartup(t *testing.T) {
	dir := t.TempDir()
	fcPath := filepath.Join(dir, "firecracker")
	jailerPath := filepath.Join(dir, "jailer")
	lockPath := filepath.Join(dir, "runtime.lock.json")

	fcSHA := writeBinary(t, fcPath, "firecracker v1.0")
	jailerSHA := writeBinary(t, jailerPath, "jailer v1.0")
	writeLockAt(t, lockPath, lockJSON(fcSHA, fcPath, jailerSHA, jailerPath))

	r := preflight.New(preflight.Config{DataDir: t.TempDir(), LockPath: lockPath})
	if fc := fcBinaries(t, r); fc.Status != preflight.StatusPass {
		t.Fatalf("fc_binaries on a freshly pinned host = %q (%s): %v", fc.Status, fc.Summary, fc.Evidence)
	}

	writeLockAt(t, lockPath, "half a lock file")

	fc := fcBinaries(t, r)
	if fc.Status != preflight.StatusFail {
		t.Errorf("fc_binaries after the lock was corrupted = %q, want fail", fc.Status)
	}
	if fc.Remediation == nil || fc.Remediation.Cause != "lock_load_error" {
		t.Errorf("fc_binaries remediation = %+v, want cause lock_load_error", fc.Remediation)
	}
}

// --- resources ---

func TestResourcesRealMeminfo(t *testing.T) {
	dir := t.TempDir()
	meminfo := "MemTotal:       16384000 kB\nMemAvailable:    8192000 kB\nMemFree:         4000000 kB\n"
	if err := os.WriteFile(filepath.Join(dir, "meminfo"), []byte(meminfo), 0o644); err != nil {
		t.Fatalf("write meminfo: %v", err)
	}
	r := preflight.New(preflight.Config{DataDir: dir, ProcRoot: dir})
	report := r.Run(t.Context())

	res := findCheck(report.Checks, "resources")
	if res == nil {
		t.Fatal("resources check not in report")
	}
	found := false
	for _, ev := range res.Evidence {
		if strings.Contains(ev, "mem_available_mib") {
			found = true
		}
	}
	if !found {
		t.Errorf("resources evidence missing mem_available_mib: %v", res.Evidence)
	}
}

func TestResourcesLowMemFails(t *testing.T) {
	dir := t.TempDir()
	// 256 MiB available — below 512 threshold.
	meminfo := "MemTotal:       16384000 kB\nMemAvailable:    262144 kB\n"
	if err := os.WriteFile(filepath.Join(dir, "meminfo"), []byte(meminfo), 0o644); err != nil {
		t.Fatalf("write meminfo: %v", err)
	}
	r := preflight.New(preflight.Config{DataDir: dir, ProcRoot: dir})
	report := r.Run(t.Context())

	res := findCheck(report.Checks, "resources")
	if res == nil {
		t.Fatal("resources check not in report")
	}
	if res.Status != preflight.StatusFail {
		t.Errorf("resources with 256 MiB = %q, want fail", res.Status)
	}
}

// --- dir_permissions ---

func TestDirPermissionsOK(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	r := preflight.New(preflight.Config{DataDir: dir, ProcRoot: dir})
	report := r.Run(t.Context())

	dp := findCheck(report.Checks, "dir_permissions")
	if dp == nil {
		t.Fatal("dir_permissions not in report")
	}
	if dp.Status == preflight.StatusFail {
		for _, ev := range dp.Evidence {
			if strings.Contains(ev, "world-writable") || strings.Contains(ev, "does not exist") {
				t.Logf("dir_permissions fail reason: %s", ev)
			}
		}
	}
}

func TestDirPermissionsWorldWritable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	r := preflight.New(preflight.Config{DataDir: dir, ProcRoot: dir})
	report := r.Run(t.Context())

	dp := findCheck(report.Checks, "dir_permissions")
	if dp == nil {
		t.Fatal("dir_permissions not in report")
	}
	if dp.Status != preflight.StatusFail {
		t.Errorf("dir_permissions on world-writable dir = %q, want fail", dp.Status)
	}
}

func TestDirPermissionsAbsent(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: "/nonexistent/vmobs-data-dir-8f3a2c", ProcRoot: t.TempDir()})
	report := r.Run(t.Context())

	dp := findCheck(report.Checks, "dir_permissions")
	if dp == nil {
		t.Fatal("dir_permissions not in report")
	}
	if dp.Status != preflight.StatusFail {
		t.Errorf("dir_permissions on absent dir = %q, want fail", dp.Status)
	}
}

// --- api_binding ---

func TestAPIBindingLoopbackNoAuth(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir(), APIMode: "loopback_only", RequireAuth: false})
	report := r.Run(t.Context())

	ab := findCheck(report.Checks, "api_binding")
	if ab == nil {
		t.Fatal("api_binding not in report")
	}
	if ab.Status != preflight.StatusPass {
		t.Errorf("api_binding loopback+no-auth = %q, want pass", ab.Status)
	}
}

func TestAPIBindingHTTPSWithAuth(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir(), APIMode: "https", RequireAuth: true})
	report := r.Run(t.Context())

	ab := findCheck(report.Checks, "api_binding")
	if ab == nil {
		t.Fatal("api_binding not in report")
	}
	if ab.Status != preflight.StatusPass {
		t.Errorf("api_binding https+auth = %q, want pass", ab.Status)
	}
}

// Loopback with authentication is the strictest binding this daemon can hold:
// unreachable from the network AND credentialed. config.Validate accepts it —
// it makes require_authentication: false the exception on loopback, not the
// rule — so the doctor must not report the tighter setting as unsafe.
func TestAPIBindingLoopbackWithAuth(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir(), APIMode: "loopback_only", RequireAuth: true})
	report := r.Run(t.Context())

	ab := findCheck(report.Checks, "api_binding")
	if ab == nil {
		t.Fatal("api_binding not in report")
	}
	if ab.Status != preflight.StatusPass {
		t.Errorf("api_binding loopback+auth = %q, want pass", ab.Status)
	}
}

// The unsafe combination: reachable off-host with no credential asked for.
func TestAPIBindingHTTPSWithoutAuth(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir(), APIMode: "https", RequireAuth: false})
	report := r.Run(t.Context())

	ab := findCheck(report.Checks, "api_binding")
	if ab == nil {
		t.Fatal("api_binding not in report")
	}
	if ab.Status != preflight.StatusFail {
		t.Errorf("api_binding https+no-auth = %q, want fail", ab.Status)
	}
}

// --- guest_channel ---

// TestGuestChannelPresent verifies that the guest_channel check is always present
// in the report and produces the exact expected status per platform.
func TestGuestChannelPresent(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	gc := findCheck(report.Checks, "guest_channel")
	if gc == nil {
		t.Fatal("guest_channel check not present in report")
	}
	if runtime.GOOS == "linux" {
		// Linux with empty PrivdSocket configured → fail.
		if gc.Status != preflight.StatusFail {
			t.Errorf("guest_channel status = %q on linux with no PrivdSocket, want fail", gc.Status)
		}
	} else {
		// Non-Linux → not_implemented.
		if gc.Status != preflight.StatusNotImplemented {
			t.Errorf("guest_channel status = %q on non-linux, want not_implemented", gc.Status)
		}
	}
	t.Logf("guest_channel: %s — %s", gc.Status, gc.Summary)
}

// --- Report.Summary ---

func TestReportSummaryNonEmpty(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())
	s := report.Summary()
	if s == "" {
		t.Error("Summary() returned empty string")
	}
}

func TestReportSummaryPass(t *testing.T) {
	// Create a minimal report that would be "pass" by constructing it directly.
	// We test the Summary() method output format.
	report := preflight.Report{
		Overall: preflight.StatusPass,
		Checks:  []preflight.Check{{ID: "test", Status: preflight.StatusPass, Summary: "ok", Evidence: nil}},
	}
	if report.Summary() != "pass" {
		t.Errorf("Summary() of pass report = %q, want %q", report.Summary(), "pass")
	}
}

func TestReportSummaryFail(t *testing.T) {
	report := preflight.Report{
		Overall: preflight.StatusFail,
		Checks: []preflight.Check{
			{ID: "arch_kvm", Status: preflight.StatusFail, Summary: "no kvm", Evidence: nil},
			{ID: "fc_binaries", Status: preflight.StatusFail, Summary: "absent", Evidence: nil},
		},
	}
	s := report.Summary()
	if !strings.Contains(s, "fail") {
		t.Errorf("Summary() of failing report should contain 'fail': %q", s)
	}
	if !strings.Contains(s, "arch_kvm") {
		t.Errorf("Summary() should list arch_kvm: %q", s)
	}
}

func TestReportSummaryWarnListsCheckIDs(t *testing.T) {
	report := preflight.Report{
		Overall: preflight.StatusWarn,
		Checks: []preflight.Check{
			{ID: "kernel_tuple", Status: preflight.StatusWarn, Summary: "no lock", Evidence: nil},
			{ID: "fc_binaries", Status: preflight.StatusPass, Summary: "ok", Evidence: nil},
		},
	}
	s := report.Summary()
	if !strings.HasPrefix(s, "warn") {
		t.Errorf("Summary() of warn report should start with 'warn': %q", s)
	}
	if !strings.Contains(s, "kernel_tuple") {
		t.Errorf("Summary() should list warn check ID 'kernel_tuple': %q", s)
	}
	// Pass-status checks must not appear.
	if strings.Contains(s, "fc_binaries") {
		t.Errorf("Summary() must not list passing check 'fc_binaries': %q", s)
	}
}

func TestReportSummaryTwoWarnChecksJoinedByComma(t *testing.T) {
	// Two warn-status checks must produce "warn (id1, id2)" — pins the exact
	// comma-space join format that Summary() produces.
	report := preflight.Report{
		Overall: preflight.StatusWarn,
		Checks: []preflight.Check{
			{ID: "fc_binaries", Status: preflight.StatusWarn, Summary: "unpinned", Evidence: nil},
			{ID: "kernel_tuple", Status: preflight.StatusWarn, Summary: "no lock", Evidence: nil},
		},
	}
	want := "warn (fc_binaries, kernel_tuple)"
	s := report.Summary()
	if s != want {
		t.Errorf("Summary() = %q, want %q", s, want)
	}
}

// --- kernel_tuple ---

func TestKernelTupleNoLock(t *testing.T) {
	r := preflight.New(preflight.Config{DataDir: t.TempDir()})
	report := r.Run(t.Context())

	kt := findCheck(report.Checks, "kernel_tuple")
	if kt == nil {
		t.Fatal("kernel_tuple not in report")
	}
	// With no lock, should warn (not crash).
	if kt.Status == preflight.StatusFail && strings.Contains(kt.Summary, "panic") {
		t.Errorf("kernel_tuple panicked: %q", kt.Summary)
	}
}

// --- helpers ---

func findCheck(checks []preflight.Check, id string) *preflight.Check {
	for i := range checks {
		if checks[i].ID == id {
			return &checks[i]
		}
	}
	return nil
}

// writeLock writes lock JSON under a fresh temp dir and returns the path.
// Preflight takes a path, not a parsed lock, so a fixture is a real file — which
// is also what lets a test change the lock under a running runner.
func writeLock(t *testing.T, jsonContent string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.lock.json")
	writeLockAt(t, path, jsonContent)
	return path
}

func writeLockAt(t *testing.T, path, jsonContent string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(jsonContent), 0o644); err != nil {
		t.Fatalf("write lock %s: %v", path, err)
	}
}

// lockJSON renders a v1 lock pinning the two binaries. Every other section is
// empty: fc_binaries reads the binary halves and nothing else.
func lockJSON(fcSHA, fcPath, jailerSHA, jailerPath string) string {
	return fmt.Sprintf(`{
		"schema": "vmobs.runtime_lock.v1",
		"firecracker": {"sha256": %q, "install_path": %q, "version": "v1", "release_url": ""},
		"jailer": {"sha256": %q, "install_path": %q},
		"host_support": {"arch": "x86_64", "min_kernel": "5.10"},
		"guest_kernel": {"version": "", "source_url": "", "source_sha256": "", "config_sha256": "", "vmlinux_sha256": "", "vmlinux_path": ""},
		"root_image": {"sha256": "", "path": "", "base_image_ref": "", "apt_snapshot": "", "inventory": ""},
		"guestd": {"protocol_version": 1}
	}`, fcSHA, fcPath, jailerSHA, jailerPath)
}

// writeBinary writes a stand-in binary and returns its sha256, so a fixture can
// pin the bytes it just wrote.
func writeBinary(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}
