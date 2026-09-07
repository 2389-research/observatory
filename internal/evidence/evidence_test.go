// ABOUTME: Tests the honesty rules a gate execution must satisfy before it is a record.
// ABOUTME: Every rule here exists to stop a run from claiming more than it observed.
package evidence_test

import (
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/evidence"
)

const (
	digestA = "1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "2222222222222222222222222222222222222222222222222222222222222222"
	headRev = "3333333333333333333333333333333333333333"
)

// passingExecution is a record that satisfies every rule. Each test below
// breaks exactly one thing about it, so a failure names the rule it broke.
func passingExecution() evidence.Execution {
	return evidence.Execution{
		SchemaVersion: 1,
		ExecutionID:   "0192f0a1-0000-4000-8000-000000000001",
		TestID:        "AT-011",
		GateID:        "m1a",
		CreatedAt:     time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC),
		Manifest: evidence.Manifest{
			SchemaVersion:  1,
			Class:          evidence.RealHost,
			SourceRevision: headRev,
			Binaries:       map[string]string{"vmobsd": digestA, "vmobs-runner": digestB},
			RuntimeLock:    digestA,
			Command:        []string{"go", "test", "-run", "TestM1aGate"},
		},
		Outcome: evidence.Outcome{
			SchemaVersion: 1,
			Procedure:     evidence.Executed,
			Result:        evidence.Pass,
			Summary:       "graceful stop reached exited without a kill",
		},
	}
}

func inventory(t time.Time, netns int64) *evidence.Inventory {
	return &evidence.Inventory{ObservedAt: t, Counts: map[string]int64{"netns": netns}}
}

// mustFail asserts Validate rejects e and that the reason mentions want, so a
// rule cannot pass its test by failing for an unrelated reason.
func mustFail(t *testing.T, e evidence.Execution, want string) {
	t.Helper()
	err := evidence.Validate(e)
	if err == nil {
		t.Fatalf("Validate accepted the record, want a rejection mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("Validate rejected for %q, want a reason mentioning %q", err, want)
	}
}

func TestValidateAcceptsACompleteRealHostPass(t *testing.T) {
	if err := evidence.Validate(passingExecution()); err != nil {
		t.Fatalf("Validate rejected a complete record: %v", err)
	}
}

func TestPortableEvidenceCannotClaimPass(t *testing.T) {
	// The rule the whole kata turns on: a run that did not touch real KVM
	// cannot promote a real-KVM acceptance row, however green it was.
	e := passingExecution()
	e.Manifest.Class = evidence.Portable
	mustFail(t, e, "portable")

	e.Outcome.Result = evidence.Fail
	if err := evidence.Validate(e); err != nil {
		t.Errorf("portable evidence may report a failure: %v", err)
	}
}

func TestPassRequiresAnExecutedProcedure(t *testing.T) {
	// "specified" means written down and not run. A skipped subtest lands here.
	e := passingExecution()
	e.Outcome.Procedure = evidence.Specified
	mustFail(t, e, "executed")
}

func TestRealHostEvidenceNeedsTheRevisionThatRan(t *testing.T) {
	e := passingExecution()
	e.Manifest.SourceRevision = ""
	mustFail(t, e, "source_revision")

	e = passingExecution()
	e.Manifest.SourceRevision = "HEAD"
	mustFail(t, e, "source_revision")
}

func TestExecutedRealHostEvidenceNeedsTheBinariesThatRan(t *testing.T) {
	// The source binding is the bytes that executed, not the tree they came
	// from — the gate rsyncs a working copy that is usually dirty.
	e := passingExecution()
	e.Manifest.Binaries = nil
	mustFail(t, e, "binary")

	e = passingExecution()
	e.Manifest.Binaries = map[string]string{"vmobsd": "not-a-digest"}
	mustFail(t, e, "vmobsd")
}

func TestAMissingRuntimeLockBlocksTheRunAndSaysWhy(t *testing.T) {
	e := passingExecution()
	e.Manifest.RuntimeLock = ""
	mustFail(t, e, "runtime_lock")

	// Blocked plus a reason is the honest shape when the lock is unreadable.
	e.Outcome.Result = evidence.Blocked
	e.Manifest.RuntimeLockUnavailable = "runtime.lock.json absent on this host"
	if err := evidence.Validate(e); err != nil {
		t.Errorf("a blocked run with a stated reason is valid evidence: %v", err)
	}

	// A reason beside a digest is a contradiction: either it was read or it was not.
	e.Manifest.RuntimeLock = digestA
	mustFail(t, e, "runtime_lock")
}

func TestCleanupClaimsNeedBeforeAndAfterInventories(t *testing.T) {
	before := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	after := before.Add(time.Minute)

	e := passingExecution()
	e.Manifest.CleanupClaimed = true
	e.Manifest.Terminal = []evidence.Terminal{{Subject: "vm:m1a-01", State: "deleted", Observed: "GET /vms/m1a-01 → 404"}}
	mustFail(t, e, "inventor")

	e.Manifest.Before = inventory(before, 3)
	e.Manifest.After = inventory(after, 4)
	mustFail(t, e, "inventor")

	e.Manifest.After = inventory(after, 3)
	if err := evidence.Validate(e); err != nil {
		t.Errorf("equal before/after inventories prove the cleanup claim: %v", err)
	}

	// A leak is still evidence — it just cannot be a pass.
	e.Manifest.After = inventory(after, 4)
	e.Outcome.Result = evidence.Fail
	if err := evidence.Validate(e); err != nil {
		t.Errorf("a failing run may record unequal inventories: %v", err)
	}
}

func TestCleanupClaimsNeedAnObservedTerminalState(t *testing.T) {
	// Matching counts alone prove nothing was left behind; they do not prove
	// the VM ever reached a terminal state. Both, or it is not a cleanup proof.
	before := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	e := passingExecution()
	e.Manifest.CleanupClaimed = true
	e.Manifest.Before = inventory(before, 3)
	e.Manifest.After = inventory(before.Add(time.Minute), 3)
	mustFail(t, e, "terminal")
}

func TestTerminalStatesNameASubjectAndAnObservation(t *testing.T) {
	e := passingExecution()
	e.Manifest.Terminal = []evidence.Terminal{{Subject: "vm:m1a-01", State: "deleted"}}
	mustFail(t, e, "terminal")

	e.Manifest.Terminal = []evidence.Terminal{{State: "deleted", Observed: "GET /vms/m1a-01 → 404"}}
	mustFail(t, e, "terminal")
}

func TestIdentityFieldsMustBeUsableAsARecordName(t *testing.T) {
	for _, tc := range []struct{ name, id, want string }{
		{"escape", "../../etc/passwd", "execution_id"},
		{"empty", "", "execution_id"},
		{"space", "m1a run 1", "execution_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := passingExecution()
			e.ExecutionID = tc.id
			mustFail(t, e, tc.want)
		})
	}
}

func TestTestIDMustBeARegisteredAcceptanceRow(t *testing.T) {
	for _, id := range []string{"", "AT-000", "AT-103", "AT-11", "at-011", "M1a"} {
		e := passingExecution()
		e.TestID = id
		mustFail(t, e, "test_id")
	}
	for _, id := range []string{"AT-001", "AT-011", "AT-102"} {
		e := passingExecution()
		e.TestID = id
		if err := evidence.Validate(e); err != nil {
			t.Errorf("test_id %q is a registered row: %v", id, err)
		}
	}
}

func TestCreatedAtIsAnAbsoluteUTCInstant(t *testing.T) {
	e := passingExecution()
	e.CreatedAt = time.Time{}
	mustFail(t, e, "created_at")

	e.CreatedAt = time.Date(2026, 9, 5, 12, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	mustFail(t, e, "created_at")
}

func TestARecordSaysWhatItRanAndWhatItFound(t *testing.T) {
	e := passingExecution()
	e.Manifest.Command = nil
	mustFail(t, e, "command")

	e = passingExecution()
	e.Outcome.Summary = ""
	mustFail(t, e, "summary")
}

func TestArtifactsBindAPathToADigestExactlyOnce(t *testing.T) {
	e := passingExecution()
	e.Manifest.Artifacts = []evidence.Artifact{{Path: "transcript.txt", SHA256: digestA}}
	if err := evidence.Validate(e); err != nil {
		t.Fatalf("one artifact with a clean path and a digest is valid: %v", err)
	}

	e.Manifest.Artifacts = []evidence.Artifact{
		{Path: "transcript.txt", SHA256: digestA},
		{Path: "transcript.txt", SHA256: digestB},
	}
	mustFail(t, e, "transcript.txt")

	for _, bad := range []evidence.Artifact{
		{Path: "../escape.txt", SHA256: digestA},
		{Path: "/etc/passwd", SHA256: digestA},
		{Path: "transcript.txt", SHA256: "ABCD"},
		{Path: "", SHA256: digestA},
	} {
		e.Manifest.Artifacts = []evidence.Artifact{bad}
		mustFail(t, e, "artifact")
	}
}

func TestUnknownResultsAndProceduresAreRefused(t *testing.T) {
	e := passingExecution()
	e.Outcome.Result = "green"
	mustFail(t, e, "result")

	e = passingExecution()
	e.Outcome.Procedure = "attempted"
	mustFail(t, e, "procedure")

	e = passingExecution()
	e.Manifest.Class = "host"
	mustFail(t, e, "class")
}

func TestSchemaVersionsAreExplicit(t *testing.T) {
	e := passingExecution()
	e.SchemaVersion = 0
	mustFail(t, e, "schema_version")

	e = passingExecution()
	e.Manifest.SchemaVersion = 2
	mustFail(t, e, "schema_version")

	e = passingExecution()
	e.Outcome.SchemaVersion = 0
	mustFail(t, e, "schema_version")
}

func TestUnmeasuredFactsAreCarriedNotSwallowed(t *testing.T) {
	// A pass that names what it could not observe is the point of the field;
	// an empty entry is a gap disguised as a disclosure.
	e := passingExecution()
	e.Manifest.Unmeasured = []string{"cgroup membership: no host probe implemented"}
	if err := evidence.Validate(e); err != nil {
		t.Fatalf("a pass may declare what it did not measure: %v", err)
	}

	e.Manifest.Unmeasured = []string{""}
	mustFail(t, e, "unmeasured")
}

// ---------------------------------------------------------------------------
// Status — what an acceptance row may claim from a pile of executions.
// ---------------------------------------------------------------------------

func TestStatusReturnsTheLatestExecutedRealHostRun(t *testing.T) {
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	older := passingExecution()
	older.ExecutionID = "0192f0a1-0000-4000-8000-00000000000a"
	older.CreatedAt = base
	older.Outcome.Result = evidence.Fail
	older.Outcome.Summary = "stop timed out"

	newer := passingExecution()
	newer.ExecutionID = "0192f0a1-0000-4000-8000-00000000000b"
	newer.CreatedAt = base.Add(time.Hour)

	got, ok := evidence.Status([]evidence.Execution{newer, older}, "AT-011")
	if !ok {
		t.Fatal("two executed real-host runs promote the row")
	}
	if got.Result != evidence.Pass {
		t.Errorf("Status = %q, want the later run's %q", got.Result, evidence.Pass)
	}
}

func TestStatusRefusesToPromoteWhatDidNotRun(t *testing.T) {
	base := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	portable := passingExecution()
	portable.ExecutionID = "0192f0a1-0000-4000-8000-00000000000c"
	portable.Manifest.Class = evidence.Portable
	portable.Outcome.Result = evidence.Fail

	blocked := passingExecution()
	blocked.ExecutionID = "0192f0a1-0000-4000-8000-00000000000d"
	blocked.CreatedAt = base.Add(time.Hour)
	blocked.Outcome.Result = evidence.Blocked
	blocked.Manifest.RuntimeLock = ""
	blocked.Manifest.RuntimeLockUnavailable = "host has no runtime lock"

	skipped := passingExecution()
	skipped.ExecutionID = "0192f0a1-0000-4000-8000-00000000000e"
	skipped.CreatedAt = base.Add(2 * time.Hour)
	skipped.Outcome.Procedure = evidence.Specified
	skipped.Outcome.Result = evidence.Blocked

	if _, ok := evidence.Status([]evidence.Execution{portable, blocked, skipped}, "AT-011"); ok {
		t.Error("portable, blocked and skipped runs must leave the row unclaimed")
	}

	real := passingExecution()
	real.CreatedAt = base.Add(3 * time.Hour)
	got, ok := evidence.Status([]evidence.Execution{portable, blocked, skipped, real}, "AT-011")
	if !ok || got.Result != evidence.Pass {
		t.Errorf("Status = (%v, %v), want the real run's pass", got.Result, ok)
	}
}

func TestStatusAnswersForOneRowAtATime(t *testing.T) {
	other := passingExecution()
	other.TestID = "AT-018"
	if _, ok := evidence.Status([]evidence.Execution{other}, "AT-011"); ok {
		t.Error("an AT-018 run must not claim AT-011")
	}
}
