// ABOUTME: Preflight types, runner, and report aggregation for host readiness.
// ABOUTME: Run() is bounded <1s; every check ID is present in every report.
package preflight

import (
	"context"
	"runtime"
	"time"
)

// Status is the machine-readable verdict for a check or overall report.
type Status string

const (
	StatusPass           Status = "pass"
	StatusFail           Status = "fail"
	StatusWarn           Status = "warn"
	StatusNotImplemented Status = "not_implemented"
)

// Remediation carries operator-facing guidance when a check does not pass.
type Remediation struct {
	Cause  string            `json:"cause"`
	Action string            `json:"action"`
	Params map[string]string `json:"params,omitempty"`
}

// Check is the result of one preflight check.
type Check struct {
	ID          string       `json:"id"`
	Status      Status       `json:"status"`
	Summary     string       `json:"summary"`
	Evidence    []string     `json:"evidence,omitempty"`
	Remediation *Remediation `json:"remediation,omitempty"`
}

// Report is the complete preflight result for one Run call.
type Report struct {
	RanAt         time.Time `json:"ran_at"`
	Arch          string    `json:"arch"`
	KernelRelease string    `json:"kernel_release"`
	Overall       Status    `json:"overall"`
	Checks        []Check   `json:"checks"`
}

// Config is the input to New: what the runner needs to run checks.
type Config struct {
	// LockPath is runtime.lock.json. Empty means no lock is configured, which
	// fc_binaries reports as such. The path and not a parsed lock: fc_binaries
	// hashes the installed binaries on every run, so it has to read the pins on
	// every run too, or a re-pin turns a matching host into a reported mismatch
	// until the daemon restarts. Same reason Manager.StagedImages reads it per
	// call and the jailer's doStage reads it per launch.
	LockPath    string
	DataDir     string // path to the state data directory (for disk/permissions checks)
	ProcRoot    string // root for /proc reads; defaults to "/proc" if empty
	APIMode     string // "loopback_only" or "https"
	RequireAuth bool   // from config.Auth.RequireAuthentication

	// PrivdSocket is the unix socket path for vmobs-privd. Empty → guest_channel fails.
	// On Linux, the guest_channel check connects (1s timeout) + closes to verify reachability.
	PrivdSocket string

	// StageRoot is the staging directory root. Empty → guest_channel fails.
	// On Linux, stat'd for existence and write access.
	StageRoot string
}

// Runner holds pre-resolved config and runs checks on demand.
type Runner struct {
	cfg Config
}

// New creates a Runner with the given config. Config is captured by value.
func New(cfg Config) *Runner {
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	return &Runner{cfg: cfg}
}

// Run executes all checks and returns a Report. All checks are cheap (no
// network, no spawned processes except ip/nft lookups); the call is bounded <1s.
func (r *Runner) Run(ctx context.Context) Report {
	var checks []Check

	lk, lkErr := r.loadLock()
	checks = append(checks, r.checkFCBinaries(lk, lkErr))
	checks = append(checks, r.checkKernelTuple(lk))
	checks = append(checks, r.checkArchKVM())
	checks = append(checks, r.checkCgroupV2())
	checks = append(checks, r.checkNetPrereqs())
	checks = append(checks, r.checkResources())
	checks = append(checks, r.checkDirPermissions())
	checks = append(checks, r.checkAPIBinding())
	checks = append(checks, r.checkGuestChannel())

	overall := aggregateOverall(checks)

	return Report{
		RanAt:         time.Now().UTC(),
		Arch:          runtime.GOARCH,
		KernelRelease: kernelRelease(),
		Overall:       overall,
		Checks:        checks,
	}
}

// aggregateOverall computes the overall status from a set of checks.
// not_implemented does not affect Overall.
// fail in any check → fail. warn in any check (no fail) → warn. else pass.
func aggregateOverall(checks []Check) Status {
	overall := StatusPass
	for _, c := range checks {
		switch c.Status {
		case StatusFail:
			overall = StatusFail
		case StatusWarn:
			if overall != StatusFail {
				overall = StatusWarn
			}
		case StatusNotImplemented, StatusPass:
			// not_implemented is listed but does not change overall
		}
	}
	return overall
}

// Summary returns a one-line summary of the report for embedding in error messages.
// Format: "pass", "fail (arch_kvm, fc_binaries)", or "warn (kernel_tuple)" listing
// check IDs that match the overall status.
func (rep *Report) Summary() string {
	if rep.Overall == StatusPass {
		return "pass"
	}
	var listed []string
	for _, c := range rep.Checks {
		if c.Status == StatusFail || (rep.Overall == StatusWarn && c.Status == StatusWarn) {
			listed = append(listed, c.ID)
		}
	}
	if len(listed) == 0 {
		return string(rep.Overall)
	}
	result := string(rep.Overall) + " ("
	for i, id := range listed {
		if i > 0 {
			result += ", "
		}
		result += id
	}
	return result + ")"
}
