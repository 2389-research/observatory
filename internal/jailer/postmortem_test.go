// ABOUTME: Portable tests for the failed-launch rescue: what it keeps, what it never keeps, and its bound.
// ABOUTME: No linux build tag — the rescue is filesystem work and runs on any OS.
package jailer

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// seedVMStateDir builds the on-disk shape a launch leaves in <stateDir>/vms/<id>:
// the two runner artifacts worth keeping, plus the two files that must not be
// copied anywhere — the capability token (§15.3) and the control socket's name.
func seedVMStateDir(t *testing.T, stateDir, vmID, log string) string {
	t.Helper()
	dir := filepath.Join(stateDir, "vms", vmID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir vm state dir: %v", err)
	}
	files := map[string]string{
		"runner.log":        log,
		"runner-state.json": `{"phase":"spawned"}`,
		"token":             "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"manifest.json":     `{"vm_id":"` + vmID + `"}`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func rescuedNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read rescue dir %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestRescueFailedLaunchKeepsTheRunnerArtifactsAndNeverTheToken(t *testing.T) {
	stateDir := t.TempDir()
	const vmID = "vm-01J000000000000000000000"
	const bootID = "boot-0000-1111"
	const logBody = "runner: dialing v.sock\nrunner: exit status 1\n"
	seedVMStateDir(t, stateDir, vmID, logBody)

	dir, err := rescueFailedLaunch(stateDir, vmID, bootID)
	if err != nil {
		t.Fatalf("rescueFailedLaunch: %v", err)
	}
	if dir == "" {
		t.Fatal("rescueFailedLaunch returned no directory for a VM whose runner log exists")
	}
	if !strings.HasPrefix(dir, filepath.Join(stateDir, failedDirName)+string(filepath.Separator)) {
		t.Errorf("rescue dir = %q, want it under %q", dir, filepath.Join(stateDir, failedDirName))
	}
	// The name has to say which VM and which boot attempt, or a directory of
	// them is unreadable to the operator who has one failed launch to explain.
	base := filepath.Base(dir)
	if !strings.Contains(base, vmID) || !strings.Contains(base, bootID) {
		t.Errorf("rescue dir name %q names neither the vm (%s) nor the boot (%s)", base, vmID, bootID)
	}

	if got := rescuedNames(t, dir); !equalStrings(got, []string{"runner-state.json", "runner.log"}) {
		t.Fatalf("rescued %v, want exactly [runner-state.json runner.log]", got)
	}
	body, err := os.ReadFile(filepath.Join(dir, "runner.log"))
	if err != nil {
		t.Fatalf("read rescued log: %v", err)
	}
	if string(body) != logBody {
		t.Errorf("rescued log = %q, want the original %q", body, logBody)
	}

	// The source is left alone: doRollback removes the state dir immediately
	// after, and a rescue that moved files would break a caller that does not.
	if _, err := os.Stat(filepath.Join(stateDir, "vms", vmID, "runner.log")); err != nil {
		t.Errorf("rescue disturbed the source log: %v", err)
	}
}

func TestRescueFailedLaunchKeepsTheTailAndSaysItDroppedTheRest(t *testing.T) {
	stateDir := t.TempDir()
	const vmID = "vm-noisy"
	// One byte over the cap, so exactly one byte of the head must be dropped.
	head := strings.Repeat("x", maxRescueBytes-len("TAIL\n")+1)
	logBody := head + "TAIL\n"
	seedVMStateDir(t, stateDir, vmID, logBody)

	dir, err := rescueFailedLaunch(stateDir, vmID, "boot-noisy")
	if err != nil {
		t.Fatalf("rescueFailedLaunch: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "runner.log"))
	if err != nil {
		t.Fatalf("read rescued log: %v", err)
	}
	// A truncated log that looks whole is a lie: the first line has to say so.
	first, rest, ok := bytes.Cut(body, []byte("\n"))
	if !ok {
		t.Fatalf("rescued log has no newline: %q", body[:min(80, len(body))])
	}
	if !bytes.HasPrefix(first, []byte(truncationMarkerPrefix)) {
		t.Errorf("rescued log starts with %q, want the truncation marker %q", first, truncationMarkerPrefix)
	}
	if want := logBody[len(logBody)-maxRescueBytes:]; string(rest) != want {
		t.Errorf("rescued log body is %d bytes, want the last %d bytes of the original", len(rest), maxRescueBytes)
	}
	if !bytes.HasSuffix(rest, []byte("TAIL\n")) {
		t.Error("rescued log does not end at the original's tail, which is where the fatal step is")
	}
}

func TestRescueFailedLaunchRescuesNothingWhenTheRunnerNeverRan(t *testing.T) {
	stateDir := t.TempDir()
	const vmID = "vm-early"
	dir := filepath.Join(stateDir, "vms", vmID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// A launch that failed at stage reserved or staged: a manifest and a token,
	// and no runner artifact at all.
	for _, name := range []string{"manifest.json", "token"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	got, err := rescueFailedLaunch(stateDir, vmID, "boot-early")
	if err != nil {
		t.Fatalf("rescueFailedLaunch: %v", err)
	}
	if got != "" {
		t.Errorf("rescueFailedLaunch = %q, want \"\" when there is nothing to rescue", got)
	}
	// An empty archive per early failure would bury the ones that hold something.
	if _, err := os.Stat(filepath.Join(stateDir, failedDirName)); !os.IsNotExist(err) {
		t.Errorf("rescue created %s with nothing in it (err: %v)", failedDirName, err)
	}
}

func TestRescueFailedLaunchKeepsOnlyTheNewestArchives(t *testing.T) {
	stateDir := t.TempDir()
	failedDir := filepath.Join(stateDir, failedDirName)
	if err := os.MkdirAll(failedDir, 0o700); err != nil {
		t.Fatalf("mkdir failed dir: %v", err)
	}
	// Names sort chronologically because they lead with the timestamp, so these
	// stand in for older archives regardless of their mtimes.
	var older []string
	for i := 0; i < maxRescuedLaunches+2; i++ {
		name := "19700101T00000" + string(rune('0'+i)) + "Z-old-boot"
		if err := os.MkdirAll(filepath.Join(failedDir, name), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		older = append(older, name)
	}

	const vmID = "vm-newest"
	seedVMStateDir(t, stateDir, vmID, "runner: exit status 1\n")
	dir, err := rescueFailedLaunch(stateDir, vmID, "boot-newest")
	if err != nil {
		t.Fatalf("rescueFailedLaunch: %v", err)
	}

	names := rescuedNames(t, failedDir)
	if len(names) != maxRescuedLaunches {
		t.Fatalf("kept %d archives (%v), want the cap of %d", len(names), names, maxRescuedLaunches)
	}
	// The one just written is the newest and must be among them, or the rescue
	// discarded the log it was called to save.
	if !contains(names, filepath.Base(dir)) {
		t.Errorf("the archive just written (%s) was pruned; kept %v", filepath.Base(dir), names)
	}
	// The oldest go first.
	if contains(names, older[0]) {
		t.Errorf("kept the oldest archive %s while pruning newer ones; kept %v", older[0], names)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func TestRescueFailedLaunchReportsAnArchiveItCouldNotCreate(t *testing.T) {
	stateDir := t.TempDir()
	const vmID = "vm-blocked"
	seedVMStateDir(t, stateDir, vmID, "runner: exit status 1\n")
	// A regular file where the archive directory has to go.
	if err := os.WriteFile(filepath.Join(stateDir, failedDirName), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("plant file: %v", err)
	}

	got, err := rescueFailedLaunch(stateDir, vmID, "boot-blocked")
	if err == nil {
		t.Error("rescueFailedLaunch returned no error for an archive it could not create")
	}
	// A path the caller would print into the launch error, pointing at nothing,
	// is worse than the caller saying nothing at all.
	if got != "" {
		t.Errorf("rescueFailedLaunch = %q, want \"\" when the archive could not be created", got)
	}
}

func TestArchiveNameCannotLeaveTheFailedDirectory(t *testing.T) {
	at := time.Date(2026, 9, 6, 5, 27, 36, 0, time.UTC)
	// Both ids are server-minted today. The name is still built by concatenation,
	// so a separator reaching it would put a rollback's writes outside the state
	// directory.
	name := archiveName(at, "../../etc", "boot/../..")
	// The property that matters is where the join lands: a name is safe when
	// joining it to the failed directory stays inside the failed directory.
	// ".." inside a longer component traverses nothing; a separator does.
	const base = "/state/failed"
	if got := filepath.Dir(filepath.Join(base, name)); got != base {
		t.Errorf("archiveName = %q, which joins to a path under %q, not in it", name, got)
	}
	if !strings.HasPrefix(name, "20260906T052736Z-") {
		t.Errorf("archiveName = %q, want it to lead with the UTC timestamp so archives sort by age", name)
	}
}
