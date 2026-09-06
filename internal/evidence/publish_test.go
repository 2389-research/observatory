// ABOUTME: Tests publication and reading against a real filesystem — no fakes.
// ABOUTME: A record is written once, never rewritten, and re-read only if its bytes still match.
package evidence_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/evidence"
)

func TestPublishWritesARecordThatReadsBack(t *testing.T) {
	dir := t.TempDir()
	want := passingExecution()

	if err := evidence.Publish(dir, want); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	got, err := evidence.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Load returned %d records, want 1", len(got))
	}
	if got[0].ExecutionID != want.ExecutionID || got[0].TestID != want.TestID {
		t.Errorf("Load returned %+v, want the record just published", got[0])
	}
	if !got[0].CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("created_at = %v, want %v", got[0].CreatedAt, want.CreatedAt)
	}
	if got[0].Manifest.RuntimeLock != want.Manifest.RuntimeLock {
		t.Errorf("runtime_lock_digest = %q, want %q", got[0].Manifest.RuntimeLock, want.Manifest.RuntimeLock)
	}
}

func TestPublishRefusesToOverwriteARecord(t *testing.T) {
	// Immutability is this line: the same execution ID cannot be written twice,
	// so a rerun that wants to look better has to be a new record.
	dir := t.TempDir()
	first := passingExecution()
	if err := evidence.Publish(dir, first); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	second := first
	second.Outcome.Result = evidence.Fail
	second.Outcome.Summary = "rewritten to say something else"
	err := evidence.Publish(dir, second)
	if err == nil {
		t.Fatal("Publish overwrote an existing record")
	}
	if !strings.Contains(err.Error(), first.ExecutionID) {
		t.Errorf("rejection %q should name the record it refused to replace", err)
	}

	got, err := evidence.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || got[0].Outcome.Result != evidence.Pass {
		t.Errorf("after the refused overwrite the record reads %+v, want the original pass", got)
	}
}

func TestPublishRefusesASymlinkPlantedAtTheRecordName(t *testing.T) {
	dir := t.TempDir()
	e := passingExecution()
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.Symlink(target, filepath.Join(dir, e.ExecutionID+".json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := evidence.Publish(dir, e); err == nil {
		t.Fatal("Publish followed a symlink standing where the record goes")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("the symlink target exists (%v); the record was written through the link", err)
	}
}

func TestPublishWritesNothingWhenTheRecordIsInvalid(t *testing.T) {
	dir := t.TempDir()
	e := passingExecution()
	e.Manifest.Class = evidence.Portable // a portable pass is not a record

	if err := evidence.Publish(dir, e); err == nil {
		t.Fatal("Publish accepted a record Validate rejects")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("evidence directory holds %d entries after a refused publish, want 0", len(entries))
	}
}

func TestPublishedRecordsArePrivate(t *testing.T) {
	dir := t.TempDir()
	e := passingExecution()
	if err := evidence.Publish(dir, e); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, e.ExecutionID+".json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestLoadOrdersRecordsByWhenTheyRan(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	late := passingExecution()
	late.ExecutionID = "0192f0a1-0000-4000-8000-0000000000b0"
	late.CreatedAt = base.Add(time.Hour)
	early := passingExecution()
	early.ExecutionID = "0192f0a1-0000-4000-8000-0000000000a0"
	early.CreatedAt = base

	if err := evidence.Publish(dir, late); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := evidence.Publish(dir, early); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	got, err := evidence.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 2 || got[0].ExecutionID != early.ExecutionID {
		t.Errorf("Load order = %v, want the earlier run first", ids(got))
	}
}

func TestLoadReportsARecordItCannotTrustAndKeepsTheRest(t *testing.T) {
	dir := t.TempDir()
	good := passingExecution()
	if err := evidence.Publish(dir, good); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Hand-edit a published record into a portable pass — the exact promotion
	// the validator refuses at write time. Reading must refuse it too, or the
	// rule only holds for records nobody touched.
	tampered := passingExecution()
	tampered.ExecutionID = "0192f0a1-0000-4000-8000-0000000000ff"
	tampered.Manifest.Class = evidence.Portable
	body, err := json.Marshal(tampered)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, tampered.ExecutionID+".json"), body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, loadErr := evidence.Load(dir)
	if loadErr == nil {
		t.Fatal("Load accepted a tampered record")
	}
	if !strings.Contains(loadErr.Error(), tampered.ExecutionID) {
		t.Errorf("Load error %q should name the record it refused", loadErr)
	}
	if len(got) != 1 || got[0].ExecutionID != good.ExecutionID {
		t.Errorf("Load returned %v, want the untouched record kept", ids(got))
	}
}

func TestLoadRejectsARecordFilenameThatDisagreesWithItsID(t *testing.T) {
	// The filename is how a record is addressed; if it can disagree with the ID
	// inside, two names can point at one record and Publish's exclusivity leaks.
	dir := t.TempDir()
	e := passingExecution()
	body, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "renamed.json"), body, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, loadErr := evidence.Load(dir)
	if loadErr == nil {
		t.Fatal("Load accepted a record whose filename is not its execution ID")
	}
	if len(got) != 0 {
		t.Errorf("Load returned %v, want nothing trusted", ids(got))
	}
}

func TestLoadOnAnEmptyOrAbsentDirectoryIsQuiet(t *testing.T) {
	got, err := evidence.Load(t.TempDir())
	if err != nil || len(got) != 0 {
		t.Errorf("Load on an empty directory = (%v, %v), want no records and no error", ids(got), err)
	}

	got, err = evidence.Load(filepath.Join(t.TempDir(), "never-created"))
	if err != nil || len(got) != 0 {
		t.Errorf("Load on an absent directory = (%v, %v), want no records and no error", ids(got), err)
	}
}

// ---------------------------------------------------------------------------
// Artifacts — the bytes a record points at, and the digest that binds them.
// ---------------------------------------------------------------------------

func TestPublishArtifactBindsTheBytesItWrote(t *testing.T) {
	dir := t.TempDir()
	art, err := evidence.PublishArtifact(dir, "m1a-transcript.txt", []byte("subtest 1: pass\n"))
	if err != nil {
		t.Fatalf("PublishArtifact: %v", err)
	}
	if art.Path != "m1a-transcript.txt" {
		t.Errorf("artifact path = %q, want the name published", art.Path)
	}

	e := passingExecution()
	e.Manifest.Artifacts = []evidence.Artifact{art}
	if err := evidence.Publish(dir, e); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := evidence.Verify(dir, e); err != nil {
		t.Errorf("Verify rejected the bytes it just wrote: %v", err)
	}
}

func TestVerifyRefusesARecordWhoseArtifactChanged(t *testing.T) {
	dir := t.TempDir()
	art, err := evidence.PublishArtifact(dir, "m1a-transcript.txt", []byte("subtest 1: pass\n"))
	if err != nil {
		t.Fatalf("PublishArtifact: %v", err)
	}
	e := passingExecution()
	e.Manifest.Artifacts = []evidence.Artifact{art}

	if err := os.WriteFile(filepath.Join(dir, art.Path), []byte("subtest 1: pass (edited)\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	err = evidence.Verify(dir, e)
	if err == nil {
		t.Fatal("Verify accepted an artifact whose bytes changed under it")
	}
	if !strings.Contains(err.Error(), art.Path) || !strings.Contains(err.Error(), art.SHA256) {
		t.Errorf("Verify error %q should name the artifact and the digest it expected", err)
	}
}

func TestVerifyRefusesARecordWhoseArtifactIsGone(t *testing.T) {
	dir := t.TempDir()
	e := passingExecution()
	e.Manifest.Artifacts = []evidence.Artifact{{Path: "vanished.txt", SHA256: digestA}}

	err := evidence.Verify(dir, e)
	if err == nil {
		t.Fatal("Verify accepted a record pointing at a file that is not there")
	}
	if !strings.Contains(err.Error(), "vanished.txt") {
		t.Errorf("Verify error %q should name the missing artifact", err)
	}
}

func TestPublishArtifactRefusesToOverwriteAndRefusesUnsafeNames(t *testing.T) {
	dir := t.TempDir()
	if _, err := evidence.PublishArtifact(dir, "once.txt", []byte("first")); err != nil {
		t.Fatalf("PublishArtifact: %v", err)
	}
	if _, err := evidence.PublishArtifact(dir, "once.txt", []byte("second")); err == nil {
		t.Error("PublishArtifact overwrote an existing artifact")
	}
	body, err := os.ReadFile(filepath.Join(dir, "once.txt"))
	if err != nil || string(body) != "first" {
		t.Errorf("artifact reads %q (%v), want the original bytes", body, err)
	}

	for _, name := range []string{"../escape.txt", "/tmp/absolute.txt", "", "sub/dir.txt", "Upper.txt"} {
		if _, err := evidence.PublishArtifact(dir, name, []byte("x")); err == nil {
			t.Errorf("PublishArtifact accepted the unsafe name %q", name)
		}
	}
}

func TestPublishArtifactRefusesEmptyBytes(t *testing.T) {
	// An empty artifact carries no observation; its digest is the digest of
	// nothing, which would verify forever and prove nothing.
	if _, err := evidence.PublishArtifact(t.TempDir(), "empty.txt", nil); err == nil {
		t.Error("PublishArtifact accepted an empty artifact")
	}
}

func TestNewIDIsUniqueAndUsableAsARecordName(t *testing.T) {
	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		id := evidence.NewID()
		if seen[id] {
			t.Fatalf("NewID repeated %q", id)
		}
		seen[id] = true

		e := passingExecution()
		e.ExecutionID = id
		if err := evidence.Validate(e); err != nil {
			t.Fatalf("NewID produced an ID Validate rejects: %v", err)
		}
	}
}

func ids(executions []evidence.Execution) []string {
	out := make([]string, 0, len(executions))
	for _, e := range executions {
		out = append(out, e.ExecutionID)
	}
	return out
}
