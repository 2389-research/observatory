// ABOUTME: Publishes one immutable evidence record per acceptance row a gate covers.
// ABOUTME: A record binds the row's outcome to the revision, binaries and lock that ran it.

//go:build linux

package integration_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/evidence"
	"github.com/2389-research/observatory-v2/internal/lock"
)

// gateRecorder turns each subtest of a real-host gate into one published
// evidence record. The manifest it carries is the context every row of the run
// shares — the revision, the binaries, the pinned artifacts — so a row's record
// names what ran without the row having to repeat it.
//
// Recording is a claim about provenance, so it is refused rather than guessed:
// with no source revision to bind to (see sourceRevision), the recorder stays
// off and says why. The gate still runs and still writes its transcript.
type gateRecorder struct {
	dir      string
	gateID   string
	manifest evidence.Manifest
	off      string // why recording is off; empty when it is on
	written  []string
	failures []string
}

// rowEvidence is what one subtest adds to the record for its acceptance row.
// Everything on it is a measurement the subtest took, timestamped where it took
// it — the recorder never invents one after the fact.
type rowEvidence struct {
	summary    string
	expected   string
	actual     string
	claim      bool
	before     *evidence.Inventory
	after      *evidence.Inventory
	terminal   []evidence.Terminal
	unmeasured []string
}

// claimsCleanup marks this row as one that proves the host came back to its
// idle baseline. A row that claims it must carry both inventories and at least
// one observed terminal state, or evidence.Validate refuses to publish it.
func (r *rowEvidence) claimsCleanup() { r.claim = true }

// observedBefore and observedAfter stamp a host inventory at the moment the
// subtest captured it, which is the only moment the counts are true.
func (r *rowEvidence) observedBefore(b m1aBaseline) { r.before = inventoryNow(b) }
func (r *rowEvidence) observedAfter(b m1aBaseline)  { r.after = inventoryNow(b) }

// observedTerminal records that a named subject was seen in a terminal state.
// The subject names the thing (a VMM's pid and start time, a workspace path);
// state names what it reached; the observation is the host's, not a guest's.
func (r *rowEvidence) observedTerminal(subject, state string) {
	r.terminal = append(r.terminal, evidence.Terminal{
		Subject:  subject,
		State:    state,
		Observed: "host_observed",
	})
}

// notMeasured records a fact this row's acceptance text names but this row does
// not check. Carrying it is the difference between a bounded proof and a
// pretended one.
func (r *rowEvidence) notMeasured(what string) { r.unmeasured = append(r.unmeasured, what) }

// says sets the one-line outcome summary. Without it the recorder writes a
// summary naming only the row and its result.
func (r *rowEvidence) says(format string, args ...any) {
	r.summary = fmt.Sprintf(format, args...)
}

// inventoryNow stamps the six host observables the gate counts.
func inventoryNow(b m1aBaseline) *evidence.Inventory {
	return &evidence.Inventory{
		ObservedAt: time.Now().UTC(),
		Counts: map[string]int64{
			"netns":             int64(b.NetnsCount),
			"veth":              int64(b.VethCount),
			"jail_entries":      int64(b.JailEntries),
			"firecracker_procs": int64(b.FcProcCount),
			"state_dir_entries": int64(b.StateDirEntries),
			"stage_dir_entries": int64(b.StageDirEntries),
		},
	}
}

// newGateRecorder gathers the provenance every record of this run shares.
// binaries maps a role ("vmobsd") to the path of the executable that filled it.
func newGateRecorder(t *testing.T, gateID, repoRoot string, binaries map[string]string) *gateRecorder {
	t.Helper()

	r := &gateRecorder{dir: evidenceRoot(), gateID: gateID}
	r.manifest = evidence.Manifest{
		SchemaVersion: 1,
		Class:         evidence.RealHost,
		Command:       append([]string{}, os.Args...),
		Binaries:      map[string]string{},
		Fixture:       map[string]string{},
		Host:          map[string]string{},
	}

	rev, dirty, why := sourceRevision(repoRoot)
	if rev == "" {
		r.off = why
		t.Logf("evidence: not recording — %s", why)
		return r
	}
	r.manifest.SourceRevision = rev
	r.manifest.SourceDirty = dirty

	// The bytes that ran. A role whose binary cannot be digested is dropped
	// rather than named with an unknown digest; Validate refuses a run that
	// digested none of them.
	for role, path := range binaries {
		digest, err := fileDigest(path)
		if err != nil {
			t.Logf("evidence: no digest for %s (%s): %v", role, path, err)
			continue
		}
		r.manifest.Binaries[role] = digest
	}

	lockPath := filepath.Join(repoRoot, "runtime.lock.json")
	if digest, err := fileDigest(lockPath); err != nil {
		r.manifest.RuntimeLockUnavailable = fmt.Sprintf("%s: %v", lockPath, err)
	} else {
		r.manifest.RuntimeLock = digest
	}

	// The platform under test is pinned by digest in the lock already; copying
	// those digests binds each record to the exact kernel and image that booted.
	if l, err := lock.Load(lockPath); err != nil {
		r.manifest.Unmeasured = append(r.manifest.Unmeasured,
			fmt.Sprintf("pinned artifact digests: %v", err))
	} else {
		r.manifest.Fixture["firecracker"] = l.Firecracker.SHA256
		r.manifest.Fixture["jailer"] = l.Jailer.SHA256
		r.manifest.Fixture["guest_kernel.vmlinux"] = l.GuestKernel.VmlinuxSHA256
		r.manifest.Fixture["root_image"] = l.RootImage.SHA256
	}

	hostname, _ := os.Hostname()
	r.manifest.Host["hostname"] = hostname
	r.manifest.Host["goos_goarch"] = runtime.GOOS + "/" + runtime.GOARCH
	r.manifest.Host["go_version"] = runtime.Version()
	if release, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		r.manifest.Host["kernel_release"] = strings.TrimSpace(string(release))
	}
	return r
}

// hostFact adds one fact about the host every later record carries. The gate's
// preconditions land here: a row's record should say what the host looked like
// when the row ran, not only what the row did.
func (r *gateRecorder) hostFact(key, value string) {
	if r.manifest.Host == nil {
		r.manifest.Host = map[string]string{}
	}
	r.manifest.Host[key] = value
}

// row runs one subtest and publishes the record its outcome earns. The text the
// subtest appended to sb becomes that record's artifact, bound by digest, so the
// transcript and the verdict cannot drift apart.
//
// The outcome is read from the framework, never from the body: a skipped subtest
// proves nothing and records `blocked`; a failed one records `fail`. Only a
// subtest that ran to green records a pass.
func (r *gateRecorder) row(t *testing.T, sb *strings.Builder, testID, name string, fn func(*testing.T, *rowEvidence)) {
	t.Helper()

	row := &rowEvidence{}
	start := sb.Len()
	skipped := false
	// t.Run reports failure after cleanups have run, so read it from the return
	// value; only the skip needs reading from inside, where t is still the
	// subtest's.
	ok := t.Run(name, func(t *testing.T) {
		defer func() { skipped = t.Skipped() }()
		fn(t, row)
	})
	r.publish(t, row, testID, name, sb.String()[start:], ok, skipped)
}

func (r *gateRecorder) publish(t *testing.T, row *rowEvidence, testID, name, transcript string, ok, skipped bool) {
	t.Helper()
	if r.off != "" {
		return
	}

	outcome := evidence.Outcome{
		SchemaVersion: 1,
		Procedure:     evidence.Executed,
		Result:        evidence.Pass,
		Expected:      row.expected,
		Actual:        row.actual,
		Summary:       row.summary,
	}
	switch {
	case skipped:
		outcome.Procedure = evidence.Specified
		outcome.Result = evidence.Blocked
		if outcome.Summary == "" {
			outcome.Summary = fmt.Sprintf("subtest %s skipped; the row was not exercised", name)
		}
	case !ok:
		outcome.Result = evidence.Fail
		if outcome.Summary == "" {
			outcome.Summary = fmt.Sprintf("subtest %s failed; the assertion is in the gate log", name)
		}
	default:
		if outcome.Summary == "" {
			outcome.Summary = fmt.Sprintf("subtest %s passed", name)
		}
	}

	id := evidence.NewID()
	// A subtest that ends on t.Fatal never reaches its evidenceSubtest call, so
	// the artifact says that rather than being empty.
	if strings.TrimSpace(transcript) == "" {
		transcript = fmt.Sprintf("# %s recorded no transcript before it ended\n", name)
	}
	artifact, err := evidence.PublishArtifact(r.dir, id+".txt", []byte(transcript))
	if err != nil {
		r.problem(t, "%s: publish transcript: %v", testID, err)
		return
	}

	manifest := r.manifest
	manifest.Artifacts = []evidence.Artifact{artifact}
	manifest.CleanupClaimed = row.claim
	manifest.Before = row.before
	manifest.After = row.after
	manifest.Terminal = row.terminal
	manifest.Unmeasured = append(append([]string{}, r.manifest.Unmeasured...), row.unmeasured...)

	record := evidence.Execution{
		SchemaVersion: 1,
		ExecutionID:   id,
		TestID:        testID,
		GateID:        r.gateID,
		CreatedAt:     time.Now().UTC(),
		Manifest:      manifest,
		Outcome:       outcome,
	}
	if err := evidence.Publish(r.dir, record); err != nil {
		r.problem(t, "%s: publish record: %v", testID, err)
		return
	}
	r.written = append(r.written, fmt.Sprintf("%s %s %s", testID, outcome.Result, id))
}

// problem records that a row could not be recorded. A gate that proved
// something and could not say so has not finished its job, so this reddens the
// gate — see finish.
func (r *gateRecorder) problem(t *testing.T, format string, args ...any) {
	t.Helper()
	msg := fmt.Sprintf(format, args...)
	t.Logf("evidence: %s", msg)
	r.failures = append(r.failures, msg)
}

// finish reports what was recorded, for the gate's own transcript, and fails the
// gate if a row's record could not be written.
func (r *gateRecorder) finish(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	if r.off != "" {
		fmt.Fprintf(&b, "\n## Evidence records\nnot recorded: %s\n", r.off)
		return b.String()
	}
	fmt.Fprintf(&b, "\n## Evidence records\nroot: %s\nrevision: %s (dirty=%v)\n",
		r.dir, r.manifest.SourceRevision, r.manifest.SourceDirty)
	for _, line := range r.written {
		fmt.Fprintf(&b, "%s\n", line)
	}
	for _, f := range r.failures {
		t.Errorf("evidence: %s", f)
		fmt.Fprintf(&b, "unrecorded: %s\n", f)
	}
	return b.String()
}

// evidenceRoot is where published records live. It is deliberately outside the
// repository: scripts/linux rsyncs the working tree with --delete, so anything a
// remote gate writes inside the tree is destroyed by the next invocation.
func evidenceRoot() string {
	if root := os.Getenv("VMOBS_EVIDENCE_ROOT"); root != "" {
		return root
	}
	return filepath.Join(os.TempDir(), "vmobs-evidence")
}

// sourceRevision answers which revision produced the tree under test, and
// whether that tree was modified. VMOBS_SOURCE_REVISION comes first because the
// gate's usual home is a host that received the tree by rsync without its .git —
// scripts/linux sets it from the local repository before the copy.
//
// A missing revision returns an empty one and the reason. Recording a real-host
// run that cannot name its source would put a provenance claim on the record
// that nothing backs.
func sourceRevision(repoRoot string) (rev string, dirty bool, why string) {
	if env := strings.TrimSpace(os.Getenv("VMOBS_SOURCE_REVISION")); env != "" {
		if len(env) != 40 || strings.TrimLeft(env, "0123456789abcdef") != "" {
			return "", false, fmt.Sprintf("VMOBS_SOURCE_REVISION=%q is not a 40-character commit", env)
		}
		return env, os.Getenv("VMOBS_SOURCE_DIRTY") == "1", ""
	}
	out, err := exec.Command("git", "-C", repoRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", false, fmt.Sprintf("no source revision: %s has no readable git metadata (%v) "+
			"and VMOBS_SOURCE_REVISION is unset", repoRoot, err)
	}
	status, err := exec.Command("git", "-C", repoRoot, "status", "--porcelain").Output()
	if err != nil {
		return "", false, fmt.Sprintf("no source revision: cannot tell whether %s is modified (%v)", repoRoot, err)
	}
	return strings.TrimSpace(string(out)), len(strings.TrimSpace(string(status))) > 0, ""
}

// fileDigest is the sha256 of a file's bytes, lowercase hex.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
