// ABOUTME: Kills a real process mid-write and checks the ledger a survivor would read.
// ABOUTME: Proves atomic publication across a crash; says plainly what it does not prove.
package privd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A crash mid-publication is the failure this ledger is shaped against: privd
// dies holding resources whose only record is the file it was writing. The
// successor has to read a complete entry or no entry, because a half-written
// one names a uid, cid and pid it could hand to a second VM.
//
// What this proves: the publication is atomic against a process death at any
// point in the sequence. A reader after the kill sees one whole record.
//
// What it does not prove: durability. Killing a process does not empty the page
// cache — the kernel still holds the bytes and writes them out on its own
// schedule, so this test passes identically with every fsync removed. Only
// power loss, a kernel panic, or a fault-injecting block layer collects on what
// fsync promises, and none of those is available to a unit suite. The barriers
// are argued for in ledger.go and mutation-proven in internal/durable, not
// here.
const crashChildDirEnv = "VMOBS_LEDGER_CRASH_DIR"

const crashVMID = "crash-vm"

func TestLedgerSurvivesAProcessCrash(t *testing.T) {
	if os.Getenv(crashChildDirEnv) != "" {
		t.Skip("this process is the crash child; the parent drives it")
	}
	dir := t.TempDir()

	// Five kills, each landing at whatever point in the write sequence the
	// child happens to have reached. The child alternates between two entries,
	// so every surviving record must be exactly one of them.
	for round := 0; round < 5; round++ {
		// Clear the record first, or waitForRecord answers from the previous
		// round and the kill lands before this child has written anything.
		if err := os.Remove(filepath.Join(dir, crashVMID+".json")); err != nil && !os.IsNotExist(err) {
			t.Fatalf("round %d: clear previous record: %v", round, err)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestLedgerCrashChild$")
		child.Env = append(os.Environ(), crashChildDirEnv+"="+dir)
		if err := child.Start(); err != nil {
			t.Fatalf("round %d: start crash child: %v", round, err)
		}
		waitForRecord(t, dir, round)
		if err := child.Process.Kill(); err != nil {
			t.Fatalf("round %d: kill crash child: %v", round, err)
		}
		_ = child.Wait() // always "signal: killed"

		entry, err := newLedger(dir).get(crashVMID)
		if err != nil {
			t.Fatalf("round %d: ledger unreadable after the crash: %v", round, err)
		}
		if entry.VMID != crashVMID {
			t.Fatalf("round %d: entry names %q; want %q", round, entry.VMID, crashVMID)
		}
		if entry.UID != 10000 && entry.UID != 10001 {
			t.Fatalf("round %d: entry uid = %d; want one of the two complete records", round, entry.UID)
		}
		if entry.CID != uint32(entry.UID-10000+3) {
			t.Fatalf("round %d: entry mixes two records: uid %d with cid %d", round, entry.UID, entry.CID)
		}
	}

	// A process killed mid-write cannot clean up after itself, so its temporary
	// file stays. That is tolerable and worth stating: the name is a dotfile the
	// ledger never looks up, get() reads only <vm_id>.json, and nothing
	// enumerates the directory. The deployed directory is a tmpfs that clears at
	// reboot, which is the only sweep these orphans get.
	for _, name := range ledgerDirNames(t, dir) {
		if name == crashVMID+".json" {
			continue
		}
		if !strings.HasPrefix(name, ".publish-") {
			t.Errorf("crash left %q behind; want only the record and its abandoned temporaries", name)
		}
	}
}

// TestLedgerCrashChild is the helper process: it publishes ledger entries until
// its parent kills it. It skips in an ordinary run.
func TestLedgerCrashChild(t *testing.T) {
	dir := os.Getenv(crashChildDirEnv)
	if dir == "" {
		t.Skip("helper process for TestLedgerSurvivesAProcessCrash; not run on its own")
	}
	l := newLedger(dir)
	for i := 0; ; i++ {
		uid := 10000 + i%2
		entry := VMEntry{
			VMID:          crashVMID,
			UID:           uid,
			GID:           2000,
			CID:           uint32(uid - 10000 + 3),
			PID:           4000 + i%2,
			StartTime:     "123",
			NetCIDR:       "10.199.0.0/30",
			CreatedAtUnix: 1,
		}
		if err := l.put(entry); err != nil {
			t.Fatalf("crash child: put: %v", err)
		}
	}
}

// waitForRecord blocks until the child has published at least once, so the kill
// lands during a write rather than before the first one.
func waitForRecord(t *testing.T, dir string, round int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, crashVMID+".json")); err == nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("round %d: crash child published nothing within 30s", round)
}

func ledgerDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read ledger dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
