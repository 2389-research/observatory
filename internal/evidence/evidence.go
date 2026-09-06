// ABOUTME: The record one acceptance gate execution leaves behind: what ran, on what, and what it found.
// ABOUTME: Validate is the honesty boundary — a run cannot claim more here than it observed.
package evidence

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"
)

// An acceptance gate answers one question — did AT-011 pass on this host? —
// and the answer is worth nothing without the context that produced it. Until
// now a gate wrote a text transcript per host and the next run overwrote it,
// so the only provenance a reader had was a date line and the only defence
// against an edit was nobody's inclination to make one.
//
// A record here is one execution of one acceptance row. It is published once
// under an id that cannot be reused, it names the exact bytes that ran, and
// every artifact it points at is bound by digest so a later reader can tell
// whether the file still says what the record claims.
//
// The rules in Validate are all one rule wearing different hats: a record may
// not claim more than the run observed. A portable run cannot promote a
// real-KVM row. A skipped subtest is blocked, not passing. A cleanup claim
// needs the before and after it rests on. Refusing these at the write boundary
// is cheaper than arguing about a published claim later.

// Procedure says whether the acceptance procedure ran at all.
type Procedure string

const (
	// Specified: the procedure is written down and was not run. A subtest that
	// skipped for a missing prerequisite lands here.
	Specified Procedure = "specified"
	// Executed: the procedure ran to a verdict on this host.
	Executed Procedure = "executed"
)

// Result is the verdict. Blocked and Inconclusive exist so a run never has to
// round an unknown up to a pass or down to a failure.
type Result string

const (
	Pass         Result = "pass"
	Fail         Result = "fail"
	Blocked      Result = "blocked"
	Inconclusive Result = "inconclusive"
)

// Class says what kind of host produced the record. Only RealHost can promote
// an acceptance row; Portable covers everything that ran without real
// Firecracker on real KVM — a darwin workstation, a unit seam, a fake runtime.
type Class string

const (
	RealHost Class = "real_host"
	Portable Class = "portable"
)

// Artifact binds one file published beside the record to the bytes it held.
// Path is a single name inside the evidence directory, never a subpath: the
// directory is flat so that a record's own id prefixes its files and no
// traversal is possible.
type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Inventory is one observation of the host resources a gate can leak. Counts
// are ordinary integers — namespace and process counts cannot approach the
// JSON safe-integer bound, unlike the event counters that are decimal strings.
type Inventory struct {
	ObservedAt time.Time        `json:"observed_at"`
	Counts     map[string]int64 `json:"counts"`
}

// equal reports whether two inventories describe the same resources. Times
// differ by construction — before and after — so only the counts compare.
func (i *Inventory) equal(other *Inventory) bool {
	if i == nil || other == nil || len(i.Counts) != len(other.Counts) {
		return false
	}
	for name, count := range i.Counts {
		if other.Counts[name] != count {
			return false
		}
	}
	return true
}

// Terminal is one observed end state: which resource, what state it reached,
// and how that was seen. Matching inventory counts show nothing was left
// behind; they do not show a VM ever stopped. A cleanup claim needs both.
type Terminal struct {
	Subject  string `json:"subject"`
	State    string `json:"state"`
	Observed string `json:"observed_by"`
}

// Manifest is the context a verdict is only meaningful inside.
type Manifest struct {
	SchemaVersion int   `json:"schema_version"`
	Class         Class `json:"class"`

	// SourceRevision is HEAD at run time and SourceDirty says whether the tree
	// differed from it. Together they place the run in history; they do not
	// pin it, because the gate runs from an rsynced working copy that is
	// usually dirty. Binaries is the pin: the sha256 of each executable that
	// actually ran, which is the only source binding a reader can recheck.
	SourceRevision string            `json:"source_revision"`
	SourceDirty    bool              `json:"source_dirty"`
	Binaries       map[string]string `json:"binary_digests,omitempty"`

	// RuntimeLock is the digest of the runtime.lock.json the daemon used.
	// RuntimeLockUnavailable replaces it when there was no readable lock, which
	// is only honest alongside a blocked result. Never both.
	RuntimeLock            string `json:"runtime_lock_digest,omitempty"`
	RuntimeLockUnavailable string `json:"runtime_lock_unavailable,omitempty"`

	// Fixture holds the guest artifact digests the run booted from, as pinned
	// in the lock. The launch path verifies those bytes at stage time; this
	// record repeats the pins rather than rehashing a gigabyte per subtest.
	Fixture map[string]string `json:"fixture_digests,omitempty"`

	Command []string          `json:"command"`
	Host    map[string]string `json:"host,omitempty"`

	// CleanupClaimed marks a record that asserts it left the host as it found
	// it. Making the claim explicit means a gate that makes it must prove it,
	// and a gate that does not must say so.
	CleanupClaimed bool       `json:"cleanup_claimed"`
	Before         *Inventory `json:"before_inventory,omitempty"`
	After          *Inventory `json:"after_inventory,omitempty"`
	Terminal       []Terminal `json:"terminal_states,omitempty"`

	// Unmeasured names, in the run's own words, what it could not observe. A
	// pass that lists its blind spots is worth more than one that implies none.
	Unmeasured []string `json:"unmeasured,omitempty"`

	Artifacts []Artifact `json:"artifacts,omitempty"`
}

// Outcome is the verdict and the sentence that explains it.
type Outcome struct {
	SchemaVersion int       `json:"schema_version"`
	Procedure     Procedure `json:"procedure"`
	Result        Result    `json:"result"`
	Expected      string    `json:"expected,omitempty"`
	Actual        string    `json:"actual,omitempty"`
	Summary       string    `json:"summary"`
}

// Execution is one run of one acceptance row: identity, context, verdict.
type Execution struct {
	SchemaVersion int       `json:"schema_version"`
	ExecutionID   string    `json:"execution_id"`
	TestID        string    `json:"test_id"`
	GateID        string    `json:"gate_id"`
	CreatedAt     time.Time `json:"created_at"`
	Manifest      Manifest  `json:"manifest"`
	Outcome       Outcome   `json:"outcome"`
}

// schemaVersion is the only version this package writes or reads. A record
// from a different version is refused rather than guessed at.
const schemaVersion = 1

// acceptanceRows is the number of AT-NNN rows docs/ACCEPTANCE.md defines.
// docs/validation/check.py asserts this constant matches the document, so the
// document stays the source of truth and this stays a mirror of it.
const acceptanceRows = 102

var (
	testIDPattern = regexp.MustCompile(`^AT-(\d{3})$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	revPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// NewID returns an execution id no earlier record can hold.
func NewID() string { return uuid.NewString() }

// ValidTestID reports whether id names a row docs/ACCEPTANCE.md defines.
func ValidTestID(id string) bool {
	m := testIDPattern.FindStringSubmatch(id)
	if m == nil {
		return false
	}
	n := 0
	for _, c := range m[1] {
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= acceptanceRows
}

// safeName reports whether s can name a file in the evidence directory: one
// lowercase component, no separators, no leading dot. The same rule governs
// execution ids, gate ids and artifact names so every record and every file
// beside it is addressable by exactly one name.
func safeName(s string) bool { return namePattern.MatchString(s) }

// Validate reports why a record may not be published. Every rule is a claim a
// run could otherwise make without having earned it.
func Validate(e Execution) error {
	if e.SchemaVersion != schemaVersion {
		return fmt.Errorf("schema_version = %d, want %d", e.SchemaVersion, schemaVersion)
	}
	if !safeName(e.ExecutionID) {
		return fmt.Errorf("execution_id %q must be one lowercase name usable as a filename", e.ExecutionID)
	}
	if !ValidTestID(e.TestID) {
		return fmt.Errorf("test_id %q is not a row docs/ACCEPTANCE.md defines (AT-001..AT-%03d)", e.TestID, acceptanceRows)
	}
	if !safeName(e.GateID) {
		return fmt.Errorf("gate_id %q must be one lowercase name", e.GateID)
	}
	if e.CreatedAt.IsZero() || e.CreatedAt.Location() != time.UTC {
		return fmt.Errorf("created_at %v must be a non-zero UTC instant", e.CreatedAt)
	}
	if err := validateOutcome(e.Outcome); err != nil {
		return err
	}
	return validateManifest(e.Manifest, e.Outcome)
}

func validateOutcome(o Outcome) error {
	if o.SchemaVersion != schemaVersion {
		return fmt.Errorf("outcome schema_version = %d, want %d", o.SchemaVersion, schemaVersion)
	}
	switch o.Procedure {
	case Specified, Executed:
	default:
		return fmt.Errorf("procedure %q is neither %q nor %q", o.Procedure, Specified, Executed)
	}
	switch o.Result {
	case Pass, Fail, Blocked, Inconclusive:
	default:
		return fmt.Errorf("result %q is not one of pass, fail, blocked, inconclusive", o.Result)
	}
	if o.Summary == "" {
		return errors.New("summary is empty: a verdict without a sentence explaining it is not evidence")
	}
	// A verdict that is not "we could not run this" requires having run it.
	if o.Result != Blocked && o.Procedure != Executed {
		return fmt.Errorf("result %q requires procedure %q; a procedure that did not run reports %q", o.Result, Executed, Blocked)
	}
	return nil
}

func validateManifest(m Manifest, o Outcome) error {
	if m.SchemaVersion != schemaVersion {
		return fmt.Errorf("manifest schema_version = %d, want %d", m.SchemaVersion, schemaVersion)
	}
	switch m.Class {
	case RealHost, Portable:
	default:
		return fmt.Errorf("class %q is neither %q nor %q", m.Class, RealHost, Portable)
	}
	if m.Class == Portable && o.Result == Pass {
		return errors.New("portable evidence cannot claim pass: only a real-host run promotes an acceptance row")
	}
	if len(m.Command) == 0 {
		return errors.New("command is empty: a record must say what to run to see this again")
	}
	if err := validateSource(m, o); err != nil {
		return err
	}
	if err := validateRuntimeLock(m, o); err != nil {
		return err
	}
	if err := validateCleanup(m, o); err != nil {
		return err
	}
	for i, u := range m.Unmeasured {
		if u == "" {
			return fmt.Errorf("unmeasured[%d] is empty: name the gap or drop the entry", i)
		}
	}
	for name, digest := range m.Fixture {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("fixture_digests[%q] = %q, want lowercase sha256 hex", name, digest)
		}
	}
	return validateArtifacts(m.Artifacts)
}

func validateSource(m Manifest, o Outcome) error {
	if m.Class != RealHost {
		return nil
	}
	if !revPattern.MatchString(m.SourceRevision) {
		return fmt.Errorf("source_revision %q must be the 40-character commit the run started from", m.SourceRevision)
	}
	if o.Procedure == Executed && len(m.Binaries) == 0 {
		return errors.New("no binary_digests: a real-host run is bound to the bytes that ran, not the tree they came from")
	}
	for name, digest := range m.Binaries {
		if !digestPattern.MatchString(digest) {
			return fmt.Errorf("binary_digests[%q] = %q, want lowercase sha256 hex", name, digest)
		}
	}
	return nil
}

func validateRuntimeLock(m Manifest, o Outcome) error {
	if m.RuntimeLock != "" && m.RuntimeLockUnavailable != "" {
		return errors.New("runtime_lock_digest and runtime_lock_unavailable are both set: the lock was either read or it was not")
	}
	if m.RuntimeLock != "" {
		if !digestPattern.MatchString(m.RuntimeLock) {
			return fmt.Errorf("runtime_lock_digest = %q, want lowercase sha256 hex", m.RuntimeLock)
		}
		return nil
	}
	if m.Class != RealHost || o.Procedure != Executed {
		return nil
	}
	if o.Result != Blocked || m.RuntimeLockUnavailable == "" {
		return errors.New("no runtime_lock_digest: a real-host run without a readable lock is blocked and says why in runtime_lock_unavailable")
	}
	return nil
}

func validateCleanup(m Manifest, o Outcome) error {
	for i, term := range m.Terminal {
		if term.Subject == "" || term.State == "" || term.Observed == "" {
			return fmt.Errorf("terminal_states[%d] must name a subject, a state and how it was observed, got %+v", i, term)
		}
	}
	if !m.CleanupClaimed || o.Result != Pass {
		return nil
	}
	if m.Before == nil || m.After == nil {
		return errors.New("cleanup_claimed with a passing result needs before and after inventories")
	}
	if !m.Before.equal(m.After) {
		return fmt.Errorf("cleanup_claimed but the inventories differ: before %v, after %v", m.Before.Counts, m.After.Counts)
	}
	if len(m.Terminal) == 0 {
		return errors.New("cleanup_claimed with a passing result needs at least one observed terminal state: equal counts do not prove anything reached one")
	}
	return nil
}

func validateArtifacts(artifacts []Artifact) error {
	seen := make(map[string]struct{}, len(artifacts))
	for _, a := range artifacts {
		if !safeName(a.Path) {
			return fmt.Errorf("artifact path %q must be one lowercase name inside the evidence directory", a.Path)
		}
		if !digestPattern.MatchString(a.SHA256) {
			return fmt.Errorf("artifact %q sha256 = %q, want lowercase hex", a.Path, a.SHA256)
		}
		if _, dup := seen[a.Path]; dup {
			return fmt.Errorf("duplicate artifact path %q: one name binds one digest", a.Path)
		}
		seen[a.Path] = struct{}{}
	}
	return nil
}

// Status reports what an acceptance row may claim from the executions given,
// and whether anything claims it at all. Only an executed real-host run with a
// verdict counts: portable runs, skipped subtests and blocked runs leave the
// row exactly where it was. The latest such run wins, because a rerun after a
// fix is the point of rerunning.
//
// It expects records that came from Load, which validates them.
func Status(executions []Execution, testID string) (Outcome, bool) {
	var claiming []Execution
	for _, e := range executions {
		if e.TestID != testID || e.Manifest.Class != RealHost {
			continue
		}
		if e.Outcome.Procedure != Executed || e.Outcome.Result == Blocked {
			continue
		}
		claiming = append(claiming, e)
	}
	if len(claiming) == 0 {
		return Outcome{}, false
	}
	sortExecutions(claiming)
	return claiming[len(claiming)-1].Outcome, true
}

// sortExecutions orders records oldest first, breaking ties on the id so the
// order is total and two records written in the same instant do not swap.
func sortExecutions(executions []Execution) {
	sort.Slice(executions, func(a, b int) bool {
		if executions[a].CreatedAt.Equal(executions[b].CreatedAt) {
			return executions[a].ExecutionID < executions[b].ExecutionID
		}
		return executions[a].CreatedAt.Before(executions[b].CreatedAt)
	})
}
