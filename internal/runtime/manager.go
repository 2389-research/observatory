// ABOUTME: Lifecycle manager: the single authority for VM state changes (SPEC §5.3–5.5).
// ABOUTME: All transitions go through store.TransitionVM; no raw SQL state updates.
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/lock"
	"github.com/2389-research/observatory-v2/internal/store"
)

// CapacitySnapshot is the three-dimension capacity view served by /host/status
// and used by /situation to populate capacity_free_mib.
type CapacitySnapshot struct {
	// Usable is the max allowed per Policy.
	UsableMemoryMiB int64
	UsableVCPU      float64
	UsableDiskMiB   int64
	// Reserved is what the reservation table currently holds.
	ReservedMemoryMiB int64
	ReservedVCPU      int64
	ReservedDiskMiB   int64
	ActiveVMs         int
	// Free = Usable − Reserved (negative means overcommit or reservation error).
	FreeMemoryMiB int64
	FreeVCPU      float64
	FreeDiskMiB   int64
}

// ErrTemplateUnknown is returned by CreateVM when the requested template ID is
// not in the approved registry. KnownIDs populates the remediation response.
type ErrTemplateUnknown struct {
	Requested string
	KnownIDs  []string
}

func (e *ErrTemplateUnknown) Error() string {
	return fmt.Sprintf("template %q not found in approved registry (known: %s)",
		e.Requested, strings.Join(e.KnownIDs, ", "))
}

// ErrInvalidRequest is returned for validation failures that are clearly the
// caller's fault — missing name, name too long, etc.
type ErrInvalidRequest struct{ Reason string }

func (e *ErrInvalidRequest) Error() string { return "invalid request: " + e.Reason }

// ErrReleaseFailed is returned by Delete when the runtime could not release a
// VM's resources. It exists so the failure keeps its own name on the wire: an
// untyped error falls through the API's mapping to a 500 that blames storage,
// which sends the operator to the database while the actual leak — a live VMM,
// a jail chroot, a ledger entry — sits on the host. The VM row stays at
// "deleting", so the remediation is to read it and retry.
type ErrReleaseFailed struct {
	VMID   string
	Reason string
}

func (e *ErrReleaseFailed) Error() string {
	return fmt.Sprintf("release vm resources for %s: %s", e.VMID, e.Reason)
}

// ErrRuntimeOpFailed is returned when a host verb fails: the VMM would not
// launch, the guest would not stop, the hypervisor refused a pause. It exists
// for the same reason ErrReleaseFailed does — an untyped error falls through
// the API's mapping to a 500 that blames storage, which sends the operator to
// the database while the fault sits on the machine. Op is the runtime verb, and
// the runtime's own error stays unwrappable so a runtime that cannot run at all
// still reads as unavailable rather than as a host that tried and failed.
type ErrRuntimeOpFailed struct {
	VMID string
	Op   string // launch, pause, resume, stop, force_stop
	Err  error
}

func (e *ErrRuntimeOpFailed) Error() string {
	return fmt.Sprintf("runtime %s for %s: %s", e.Op, e.VMID, e.Err)
}

func (e *ErrRuntimeOpFailed) Unwrap() error { return e.Err }

// ErrUnknownAction is returned when Action receives an unrecognised action name.
type ErrUnknownAction struct{ Known []string }

func (e *ErrUnknownAction) Error() string {
	return fmt.Sprintf("unknown action (valid: %s)", strings.Join(e.Known, ", "))
}

var validActions = []string{"start", "pause", "resume", "stop", "force_stop"}

// AdmissionParams returns the admission settings this manager admits on.
//
// The launch UI shows a reservation preview, and SPEC §13's opening rule says
// the browser may display only what the API published with the same values.
// Returning the live config — rather than a copy kept elsewhere — is what
// makes the published number and the enforced number the same number.
func (m *Manager) AdmissionParams() config.Admission {
	return m.cfg.Admission
}

// DefaultParams returns the per-VM defaults this manager applies when a create
// request leaves a resource at zero.
//
// The launch form prefills from these and shows the fields it cannot yet set
// (guest privilege, network profile) at their effective values. A browser that
// carried its own copy of these numbers would show a default the host does not
// actually apply.
func (m *Manager) DefaultParams() config.VMDefaults {
	return m.cfg.VMDefaults
}

// ManagerConfig carries the host-level configuration the manager acts on.
type ManagerConfig struct {
	Admission  config.Admission
	VMDefaults config.VMDefaults
	Templates  map[string]Template
	Host       HostResources

	// LockPath is the path to runtime.lock.json, or "" when this daemon has none.
	// A path and not a parsed lock: the jailer re-reads this same file on every
	// launch, so a copy parsed once at startup describes a pin that may no longer
	// be the one the next launch stages from.
	LockPath string

	// AdoptedVMs names the VMs a runtime-level scan found still running when this
	// daemon started: their VMM alive, and a runner attached to it that names the
	// VM in its own argv. Reconcile leaves those rows exactly as it found them.
	//
	// The scan is the runtime's to make and cannot be made from here — firecracker
	// is started daemonized and reparented to init, so the only evidence is on the
	// host — and it has to happen before the manager exists, because Reconcile runs
	// inside NewManager. So the findings arrive as a decision already taken.
	//
	// Empty for a runtime that cannot observe a previous run's VMs, and Reconcile
	// then keeps its old answer: a running VM nobody could account for is failed.
	// Absent evidence is not evidence of health.
	AdoptedVMs map[string]bool
}

// StagedImages returns the kernel and root image a launch would stage now, read
// from runtime.lock.json at call time. Three answers, all distinct: (nil, nil)
// when no lock is configured, (nil, err) when one is configured and unreadable,
// and the entries otherwise.
//
// Read now rather than held from startup because the jailer's doStage calls
// lock.Load on every launch (internal/jailer/launch.go). Whoever edits the file
// changes what the next launch stages without restarting anything, so the file
// is the answer and a startup copy of it is only a record of an earlier one.
// This reads the pins; it does not verify the artifacts against them — that
// hashes a multi-gigabyte root image, and preflight owns the question.
func (m *Manager) StagedImages() (*lock.Images, error) {
	if m.cfg.LockPath == "" {
		return nil, nil
	}
	lk, err := lock.Load(m.cfg.LockPath)
	if err != nil {
		return nil, err
	}
	img := lk.Images()
	return &img, nil
}

// Manager is the single lifecycle authority. It owns a bounded worker pool for
// launch jobs so concurrent create requests do not exceed MaxParallelProvisions.
// Close blocks until all in-flight tracked goroutines finish.
type Manager struct {
	st     *store.Store
	rt     Runtime
	cfg    ManagerConfig
	policy Policy

	// sem limits parallel provisioning to cfg.Admission.MaxParallelProvisions.
	sem chan struct{}
	wg  sync.WaitGroup

	// closeMu / closed form the close gate. GoTracked holds an RLock while
	// adding to wg; Close holds the write lock to flip closed before wg.Wait.
	// This prevents the wg.Add/wg.Wait race described in gotchas.md.
	closeMu sync.RWMutex
	closed  bool

	// ctx is the manager's root context; cancelled by Close to interrupt launches.
	ctx    context.Context
	cancel context.CancelFunc

	// reportGen is called after every run reaches a terminal phase. Task 7 wires
	// the real generator. Nil means no-op (safe). Use SetReportGen to inject.
	reportGen func(runID string)

	// deleting names the VMs a Delete call is inside right now. The row's own
	// "deleting" state cannot stand in for this: a delete that stalled leaves the
	// row reading "deleting" too, and the two cases want opposite answers — an
	// in-flight delete owns the VM and a second caller must not race it, while a
	// stalled one has resources still on the host and must be resumed.
	deletingMu sync.Mutex
	deleting   map[string]bool
}

// NewManager creates a Manager and immediately runs Reconcile to clean up any
// state left over from a previous controller run.
func NewManager(st *store.Store, rt Runtime, cfg ManagerConfig) (*Manager, error) {
	return NewManagerWithReportGen(st, rt, cfg, nil)
}

// NewManagerWithReportGen creates a Manager with a pre-wired report generator,
// then runs Reconcile. The generator is available during the initial reconcile,
// which re-enqueues report generation for terminal runs missing stored reports.
func NewManagerWithReportGen(st *store.Store, rt Runtime, cfg ManagerConfig, reportGen func(runID string)) (*Manager, error) {
	n := cfg.Admission.MaxParallelProvisions
	if n <= 0 {
		n = 2
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		st:        st,
		rt:        rt,
		cfg:       cfg,
		policy:    Policy{Admission: cfg.Admission, Host: cfg.Host},
		sem:       make(chan struct{}, n),
		ctx:       ctx,
		cancel:    cancel,
		reportGen: reportGen,
		deleting:  map[string]bool{},
	}
	if err := m.Reconcile(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("reconcile on startup: %w", err)
	}
	return m, nil
}

// Templates returns a copy of the approved template registry, keyed by ID.
// A copy, because the registry is the admission trust surface: no caller may
// mutate what this host considers approved.
func (m *Manager) Templates() map[string]Template { return maps.Clone(m.cfg.Templates) }

// Availability delegates to the underlying Runtime. Callers check the returned
// error for *UnavailableError to surface honest host-status information.
func (m *Manager) Availability(ctx context.Context) error { return m.rt.Availability(ctx) }

// GoTracked runs fn on a goroutine tracked by the close gate. It returns
// false (and does not run fn) once Close has begun: work enqueued during
// shutdown would race wg.Wait. Every manager goroutine must start here.
func (m *Manager) GoTracked(fn func()) bool {
	m.closeMu.RLock()
	defer m.closeMu.RUnlock()
	if m.closed {
		return false
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		fn()
	}()
	return true
}

// Close waits for all in-flight tracked goroutines, then releases the
// manager's context. The gate flips first so no new goroutine can slip in
// between wg.Wait and cancel.
func (m *Manager) Close() {
	m.closeMu.Lock()
	m.closed = true
	m.closeMu.Unlock()
	m.wg.Wait()
	m.cancel()
}

// operationSlack is the non-grace part of a stop-shaped mutation's budget: the
// fixed timeouts the real (jailer) runtime can burn around the graceful poll,
// worst case, plus room for the store writes that record the outcome. Every
// row below is a step of the stop path, so this is the wrong budget for
// anything that is not one — a start action derives its own from launchBudget.
//
//	runner ctl shutdown_guest:  5s dial + ctlDeadline (G + 15s)     = G + 20s
//	graceful exit poll:         grace + 5s                          = G +  5s
//	SIGTERM/SIGKILL escalation: 10s signal + 5s wait                =     15s
//	runner ctl finalize:        5s dial + 30s deadline              =     35s
//	chroot release retry:                                                 10s
//	                                                                 --------
//	                                                                2G + 85s
//
// G is the configured stop grace. Two rows scale with it, and the first is the
// one that is easy to get wrong. The runner answers shutdown_guest once the
// guest acks or grace + runner.ShutdownReplySlack passes, but the client waits
// ctlDeadline(G) = G + ShutdownReplySlack + ctlTransportSlack — G + 15s at
// today's constants (internal/jailer/stop.go). A reply that arrives late,
// having spent that transport slack on a loaded host, is still a reply: the
// adapter takes the accepted branch and runs the exit poll for a fresh
// grace + 5s. The two rows are additive, not alternatives — a guest that acks
// at the last moment still leaves the VMM to exit on its own clock.
//
// The other two branches are shorter at every grace, and for the same reason:
// neither reaches the exit poll. The ctl exchange can get no answer at all — a
// dead runner, a stale socket, an expired deadline — or the runner can answer
// and refuse, which is the guest's account of why it will not go down
// (internal/jailer/stop.go). Either way the adapter burns 5s dial + the same
// G + 15s ceiling and then the same 60s tail — G + 80s, which never overtakes
// 2G + 85.
//
// Rounded up to 120s so the transitions that record the terminal state are
// inside the budget too. This is a backstop against a wedged host, not a
// service-level target: a healthy stop finishes well inside the grace period.
//
// The budget below is G + operationSlack, so it covers 2G + 85 while G <= 35.
// The documented default of 30 fits, but not comfortably: a 150s budget against
// a 145s worst case is 5s of margin. Any deployment that raises
// stop_grace_seconds needs this derivation redone before it reaches 35, because
// the worst case grows twice as fast as the budget does.
const operationSlack = 120 * time.Second

// OperationContext derives the context a stop-shaped lifecycle mutation runs
// on: stop, force_stop, pause, resume, and the delete path that stops first. A
// start action takes the same shape from detachedContext with launchBudget
// instead, because its worst case is file IO rather than the guest's patience.
//
// A lifecycle mutation has host side effects — signals delivered, a chroot
// released, a reservation freed — and the store writes that record them. Once
// it starts it must finish, so it must not ride the caller's context: an HTTP
// client that hangs up mid-stop would otherwise cancel the graceful poll, the
// SIGTERM/SIGKILL step and the chroot release together, leaving a live VM
// behind a row that reads "stopping" and an operation that reads "running"
// forever.
//
// The returned context keeps the caller's values (authenticated identity,
// tracing) and drops the caller's cancellation; it is cancelled when the
// manager closes, so a mutation still dies with the daemon rather than
// outliving it; and it carries its own budget, so a wedged host cannot pin the
// work indefinitely. Callers must call the returned cancel when the mutation
// returns — deferring it at the top of a handler is correct, because the
// mutation is synchronous within the handler.
func (m *Manager) OperationContext(parent context.Context) (context.Context, context.CancelFunc) {
	return m.detachedContext(parent, time.Duration(m.cfg.VMDefaults.StopGraceSeconds)*time.Second+operationSlack)
}

// detachedContext builds a context that keeps parent's values, drops its
// cancellation and deadline, carries the given budget, and dies when the
// manager closes. It is the shape every lifecycle mutation runs on; the budget
// is what tells the shapes apart.
func (m *Manager) detachedContext(parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), budget)
	stop := context.AfterFunc(m.ctx, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// launchBudget is a start action's budget. A launch is not a stop with the
// arrow reversed: nothing in it waits on the guest's patience, and almost all
// of it is file IO that no timeout interrupts (jailer copyFile takes no
// context at all).
//
// Every staged byte is read five times and written twice — hashed against the
// lock, copied into the stage dir, hashed again for privd, hashed once more by
// privd, then copied into the jail (internal/jailer/launch.go doStage and
// computeStagedFiles, internal/privd/vmops.go StartVM). The shipped rootfs is
// 1 GiB (images/rootfs/build.sh:158) and the workspace image is created at the
// VM's configured size, so a default VM moves roughly 12 GiB of file IO.
//
//	staging + jail copy: ~12 GiB at an assumed 100 MiB/s          = 120s
//	firecracker start through privd: jailer exec, API, boot       =  15s
//	runner spawn and guest attach (jailer readyTimeout, :34)      =  60s
//	store writes recording starting → running                     =  15s
//	                                                                ----
//	                                                                210s
//
// Rounded up to 240s. The host assumption is the load-bearing part: 100 MiB/s
// of sustained staging IO, which is a floor well under this host's NVMe and
// leaves room for the parallel provisions admission allows. Two things make it
// wrong rather than merely tight — a workspace_disk_mib far above the default
// (the copy scales with it), and a host whose disk is slower than the floor.
// Both are deployment facts, so a deployment that has either needs this number
// recomputed, not raised by feel.
//
// This is deliberately not operationSlack: that budget is derived from the stop
// path — grace, ctl deadlines, signal escalation — and nothing in it is about
// launching.
const launchBudget = 240 * time.Second

// recoveryBudget bounds the work that records how a mutation ended once the
// mutation's own context is gone. It is sized by the largest such job, the
// cleanup ForceStop behind a failed launch (10s signal + 35s finalize ctl + 10s
// chroot release = 55s worst case against the jailer runtime), plus the store
// writes that say what happened; the paths that only write are far inside it.
const recoveryBudget = 75 * time.Second

// recoveryContext derives the context for the writes that record how a mutation
// ended, when the context the mutation ran on may already be spent. Both
// outcomes need it, not just the unhappy one. A failure usually *is* that
// context expiring — the branch that records a failed launch, the cleanup
// behind it, the operation row that carries the verdict. A success can outrun
// its budget just as easily, because what fills the budget is largely work no
// timeout interrupts: jailer copies gigabytes through helpers that take no
// context, and returns nil with nothing left on the clock.
//
// Writes on a spent context do nothing at all. The VM is left in a transitional
// state and the operation stays "running" for ever, which is worse than either
// verdict they were meant to carry — and worse on the success path than the
// failure one, because the VM behind that row is alive.
//
// Unlike detachedContext this is not tied to m.ctx. The work is synchronous
// inside a call the caller is still blocked on, so it cannot outlive the
// manager unless that caller does; tying it to m.ctx would switch the
// bookkeeping off exactly during shutdown, when mutations are most likely to be
// interrupted mid-flight.
//
// That caller can outlive the manager, and an operator should know what it
// costs. HTTP handlers are not tracked by m.wg and srv.Shutdown stops waiting
// after 10s (cmd/vmobsd/main.go), after which Manager.Close and then st.Close
// run on the way out — so bookkeeping started just before shutdown can still be
// writing up to recoveryBudget later, against a store that is closing under it.
// sql.DB.Close serialises with statements already in flight, so the cost is a
// lost write, not a corrupt one: a mutation interrupted by shutdown may leave no
// terminal record at all. Reconcile settles those on the next start — in-flight
// operations become failed and transitional VMs are resolved — which is why
// losing the write is survivable and switching the bookkeeping off is not.
//
// One budget per mutation tail, not one per derivation. Two of the four call
// sites hand their recovery context on to failAction, which asks for one of its
// own: the shared tail below and the start path's success branch. Stacking a
// second recoveryBudget there priced a stop at 150 + 75 + 75 and a start at
// 240 + 75 + 75, outrunning a gate client priced off these same constants
// (tests/integration/m1a_gate_test.go, which owns the composed per-request
// ceilings) — and contradicted the sizing above, which covers the largest
// single such job plus its writes, not two of them end to end. So a context
// this function already made is returned unchanged, with a no-op cancel: the
// caller that made it owns the cancel.
//
// The cost is real and small. failAction's writes no longer get a guaranteed
// budget of their own; they run on whatever the caller's tail has left. What
// spends that tail is one TransitionVM, and the failure that reaches failAction
// is nearly always a fast one — an invalid transition, a refused revision pin —
// with the whole 75s still on the clock. The case that loses is a store wedged
// badly enough that a single write burns 75s, and a store in that state is
// unlikely to answer a second 75s either — though a writer that freed at ~74s
// would have; Reconcile settles the record on the next start.
//
// The marker rides context values, and values survive both WithoutCancel and
// WithTimeout. Anything that derives a *new* mutation budget from a recovery
// context — detachedContext, OperationContext — would carry the marker into it
// and silently deny that mutation a tail of its own. Nothing does today: every
// such derivation starts from a caller's request context.
func (m *Manager) recoveryContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent.Value(recoveryTail{}) != nil {
		return parent, func() {}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), recoveryBudget)
	return context.WithValue(ctx, recoveryTail{}, true), cancel
}

// recoveryTail is the private key recoveryContext stamps on the contexts it
// makes, so a later derivation on the same tail can recognise one.
type recoveryTail struct{}

// SetReportGen installs the run-report generation callback. It is called once
// per terminal run with the runID. Task 7 wires the real generator; tests use
// a recording stub on this seam.
func (m *Manager) SetReportGen(fn func(runID string)) {
	m.reportGen = fn
}

// Capacity returns the current usable/reserved/free view of host resources.
func (m *Manager) Capacity(ctx context.Context) (CapacitySnapshot, error) {
	totals, err := m.st.ReservationTotals(ctx)
	if err != nil {
		return CapacitySnapshot{}, fmt.Errorf("read reservations: %w", err)
	}
	usableMem := m.policy.UsableMemoryMiB()
	usableVCPU := m.policy.UsableVCPU()
	usableDisk := m.policy.UsableDiskMiB()
	return CapacitySnapshot{
		UsableMemoryMiB:   usableMem,
		UsableVCPU:        usableVCPU,
		UsableDiskMiB:     usableDisk,
		ReservedMemoryMiB: totals.MemoryMiB,
		ReservedVCPU:      totals.VCPU,
		ReservedDiskMiB:   totals.DiskMiB,
		ActiveVMs:         totals.ActiveVMs,
		FreeMemoryMiB:     usableMem - totals.MemoryMiB,
		FreeVCPU:          usableVCPU - float64(totals.VCPU),
		FreeDiskMiB:       usableDisk - totals.DiskMiB,
	}, nil
}

// CreateRequest is the external input for a create-VM request.
type CreateRequest struct {
	Name             string
	TemplateID       string
	IdempotencyKey   *string
	VCPUCount        int
	MemoryMiB        int64
	RootDiskMiB      int64
	WorkspaceDiskMiB int64
	Labels           map[string]string
	// Run is an optional launch-attached run. When non-nil, CreateVMWithOperation
	// creates the run (phase pending) in the same tx as the VM. The manager's
	// VM lifecycle hooks then advance it to running or conclude it on failure.
	Run *store.RunAttachment
}

// CreateVM validates and creates a VM, then asynchronously provisions it.
// owner is the authenticated caller's identity (never from a request body).
// On idempotent replay the bool is true and the stored result is returned
// without re-provisioning.
func (m *Manager) CreateVM(ctx context.Context, owner string, req CreateRequest) (*store.VM, *store.Operation, bool, error) {
	// AT-001: check runtime availability first; nothing persisted on failure.
	if err := m.rt.Availability(ctx); err != nil {
		return nil, nil, false, fmt.Errorf("runtime not available: %w", err)
	}

	// Template lookup.
	if req.TemplateID == "" {
		return nil, nil, false, &ErrInvalidRequest{Reason: "template_id is required"}
	}
	tpl, ok := m.cfg.Templates[req.TemplateID]
	if !ok {
		known := make([]string, 0, len(m.cfg.Templates))
		for id := range m.cfg.Templates {
			known = append(known, id)
		}
		return nil, nil, false, &ErrTemplateUnknown{Requested: req.TemplateID, KnownIDs: known}
	}

	// Name validation.
	if req.Name == "" {
		return nil, nil, false, &ErrInvalidRequest{Reason: "name is required"}
	}
	if len(req.Name) > 128 {
		return nil, nil, false, &ErrInvalidRequest{Reason: "name exceeds 128 bytes"}
	}
	for _, r := range req.Name {
		if r < ' ' || r > '~' {
			return nil, nil, false, &ErrInvalidRequest{Reason: "name contains non-printable characters"}
		}
	}

	// Apply defaults for zero-valued resource fields.
	vcpu := req.VCPUCount
	if vcpu <= 0 {
		vcpu = m.cfg.VMDefaults.VCPUCount
	}
	memMiB := req.MemoryMiB
	if memMiB <= 0 {
		memMiB = m.cfg.VMDefaults.MemoryMiB
	}
	rootDisk := req.RootDiskMiB
	if rootDisk <= 0 {
		rootDisk = m.cfg.VMDefaults.RootDiskMiB
	}
	wsDisk := req.WorkspaceDiskMiB
	if wsDisk <= 0 {
		wsDisk = m.cfg.VMDefaults.WorkspaceDiskMiB
	}
	if vcpu <= 0 || memMiB <= 0 || rootDisk <= 0 || wsDisk <= 0 {
		return nil, nil, false, &ErrInvalidRequest{Reason: "resource values must be positive"}
	}

	memTotal := memMiB + m.cfg.Admission.ReservePerVMHostOverheadMiB
	diskTotal := rootDisk + wsDisk

	// Request hash over the effective (post-default) request; json.Marshal of a
	// struct with sorted fields is deterministic.
	type effectiveReq struct {
		TemplateID string `json:"template_id"`
		Name       string `json:"name"`
		VCPU       int    `json:"vcpu"`
		MemoryMiB  int64  `json:"memory_mib"`
		RootDisk   int64  `json:"root_disk_mib"`
		WSDisk     int64  `json:"workspace_disk_mib"`
	}
	hashBytes, _ := json.Marshal(effectiveReq{
		TemplateID: req.TemplateID,
		Name:       req.Name,
		VCPU:       vcpu,
		MemoryMiB:  memMiB,
		RootDisk:   rootDisk,
		WSDisk:     wsDisk,
	})
	sum := sha256.Sum256(hashBytes)
	requestHash := hex.EncodeToString(sum[:])

	vmID := uuid.NewString()
	admit := func(totals store.ReservationTotals) error {
		return m.policy.Admit(totals, memTotal, vcpu, diskTotal)
	}

	vm, op, replayed, err := m.st.CreateVMWithOperation(ctx, store.CreateVMInput{
		VMID:             vmID,
		Name:             req.Name,
		Owner:            owner,
		TemplateID:       tpl.TemplateID,
		TemplateDigest:   tpl.Digest,
		VCPUCount:        vcpu,
		MemoryMiB:        memMiB,
		RootDiskMiB:      rootDisk,
		WorkspaceDiskMiB: wsDisk,
		MemoryTotalMiB:   memTotal,
		NetworkProfile:   m.cfg.VMDefaults.NetworkProfile,
		NetworkPolicyID:  m.cfg.VMDefaults.NetworkPolicyID,
		Labels:           req.Labels,
		Kind:             "vm.create",
		IdempotencyKey:   req.IdempotencyKey,
		RequestHash:      requestHash,
		Admit:            admit,
		Run:              req.Run,
	})
	if err != nil {
		return vm, op, replayed, err
	}
	if vm == nil {
		// Idempotent replay of a refused create; op carries the refusal.
		return nil, op, replayed, err
	}
	if replayed {
		// Replay of a completed create: return the stored result without
		// enqueueing another launch. A relaunch could revive a VM that was
		// stopped after the original create succeeded.
		return vm, op, true, nil
	}

	// Admission succeeded — enqueue the async launch job.
	m.enqueueLaunch(vm, op.OperationID, tpl, vcpu, memMiB, rootDisk, wsDisk)
	return vm, op, false, nil
}

// enqueueLaunch acquires a semaphore slot and runs the launch job in a goroutine.
// If GoTracked returns false the manager is closing; the VM stays in provisioning
// until the next Reconcile repairs it — that is exactly what reconcile is for.
func (m *Manager) enqueueLaunch(vm *store.VM, opID int64, tpl Template, vcpu int, memMiB, rootDisk, wsDisk int64) {
	m.GoTracked(func() {
		// Acquire a provisioning slot.
		select {
		case m.sem <- struct{}{}:
		case <-m.ctx.Done():
			// Manager is closing before the slot was acquired; abandon.
			m.failLaunch(m.ctx, vm.VMID, opID, "enqueue", "manager closed before slot acquired")
			return
		}
		defer func() { <-m.sem }()
		m.runLaunch(vm, opID, tpl, vcpu, memMiB, rootDisk, wsDisk)
	})
}

// runLaunch executes the provisioning sequence: provisioning→starting→running
// (§5.3). On any failure, transitions to failed and releases compute.
func (m *Manager) runLaunch(vm *store.VM, opID int64, tpl Template, vcpu int, memMiB, rootDisk, wsDisk int64) {
	ctx := m.ctx
	vmID := vm.VMID
	bootID := uuid.NewString()

	spec := VMSpec{
		VMID:             vmID,
		BootID:           bootID,
		VCPUCount:        vcpu,
		MemoryMiB:        memMiB,
		RootDiskMiB:      rootDisk,
		WorkspaceDiskMiB: wsDisk,
		NetworkProfile:   vm.NetworkProfile,
		NetworkPolicyID:  vm.NetworkPolicyID,
		TemplateID:       tpl.TemplateID,
		TemplateDigest:   tpl.Digest,
	}

	// provisioning → starting. The From pin keeps a VM that was stopped while
	// this job was queued in its stopped state: without it, stopped→starting
	// is a legal restart edge and the launch would revive it.
	from := "provisioning"
	if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
		VMID:        vmID,
		From:        &from,
		To:          "starting",
		Reason:      "launch",
		OperationID: opID,
		BootID:      &bootID,
	}); err != nil {
		if errors.Is(err, new(store.InvalidTransitionError)) {
			// A concurrent stop raced us; abandon without overwriting stop's state.
			return
		}
		m.failLaunch(ctx, vmID, opID, "starting", err.Error())
		return
	}

	// Launch the VMM. What it reports having staged rides the transition below:
	// the boot id was established before any of it existed, so this is the first
	// write that can say what this boot actually runs.
	staged, err := m.rt.Launch(ctx, spec)
	if err != nil {
		m.failLaunch(ctx, vmID, opID, "launch", err.Error())
		_ = m.rt.ForceStop(ctx, vmID) // best-effort cleanup
		return
	}

	// starting → running
	from = "starting"
	if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
		VMID:        vmID,
		From:        &from,
		To:          "running",
		Reason:      "launch_complete",
		OperationID: opID,
		Images:      staged,
	}); err != nil {
		if errors.Is(err, new(store.InvalidTransitionError)) {
			return // stop raced us after launch; leave cleanup to the stop path
		}
		m.failLaunch(ctx, vmID, opID, "running", err.Error())
		_ = m.rt.ForceStop(ctx, vmID)
		return
	}

	// Hook: pending run → running when VM reaches running.
	m.onVMRunning(ctx, vmID)

	// Mark operation succeeded.
	errCause := (*string)(nil)
	errMsg := (*string)(nil)
	if _, err := m.st.UpdateOperation(ctx, store.OperationUpdate{
		OperationID:  opID,
		IfState:      "running",
		Phase:        "running",
		State:        "succeeded",
		ErrorCause:   errCause,
		ErrorMessage: errMsg,
	}); err != nil {
		// Operation update failure is logged implicitly; VM is running correctly.
		_ = err
	}
}

// failLaunch transitions a VM to failed state and marks its operation failed.
func (m *Manager) failLaunch(ctx context.Context, vmID string, opID int64, stage, reason string) {
	_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
		VMID:           vmID,
		To:             "failed",
		Reason:         reason,
		OperationID:    opID,
		FailureStage:   &stage,
		FailureReason:  &reason,
		ReleaseCompute: true,
	})
	// Hook: conclude any active run on the VM with the launch-fail trigger (R8).
	m.onVMLaunchFailed(ctx, vmID)

	cause := "launch_failed"
	// IfState pins the update to a still-running operation: a batch stop wave
	// may already have finalized this op, and its verdict must stand.
	_, _ = m.st.UpdateOperation(ctx, store.OperationUpdate{
		OperationID:  opID,
		IfState:      "running",
		Phase:        stage,
		State:        "failed",
		ErrorCause:   &cause,
		ErrorMessage: &reason,
	})
}

// Action performs a typed lifecycle action on a VM synchronously.
// Each invocation creates its own operation row (kind="vm.action").
func (m *Manager) Action(ctx context.Context, vmID, action string, expectedRevision *int64) (*store.VM, *store.Operation, error) {
	switch action {
	case "start", "pause", "resume", "stop", "force_stop":
	default:
		return nil, nil, &ErrUnknownAction{Known: validActions}
	}

	vm, err := m.st.GetVM(ctx, vmID)
	if err != nil {
		return nil, nil, err
	}

	// Attribute the action to the VM's stored owner (ruling A10: system-initiated
	// operations carry the affected resource's owner).
	opID, err := m.st.InsertActionOperation(ctx, store.ActionOperationInput{
		Owner:       vm.Owner,
		VMID:        vmID,
		Phase:       action,
		RequestHash: fmt.Sprintf("%s:%s:%d", action, vmID, vm.Revision),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("insert action operation: %w", err)
	}

	return m.doAction(ctx, vm, action, opID, expectedRevision)
}

func (m *Manager) doAction(ctx context.Context, vm *store.VM, action string, opID int64, expectedRevision *int64) (*store.VM, *store.Operation, error) {
	vmID := vm.VMID
	grace := time.Duration(m.cfg.VMDefaults.StopGraceSeconds) * time.Second

	var (
		newState string
		reason   string
		releaseC bool
	)

	// An action states its intent on the first transition it makes, not only on
	// the last. Both matter: desired_state is written once at create and would
	// otherwise say "running" for the life of a VM the operator deliberately
	// stopped, and an action interrupted between its two transitions would
	// settle at a state nobody appears to have asked for. Every action here
	// wants the state it ends in, so the tail passes newState straight through.
	wantStopped := "stopped"

	// The caller's revision pin is an optimistic-concurrency precondition, and a
	// precondition is checked once: on the first transition this action makes.
	// Actions that pass through an intermediate state (stop, force_stop →
	// stopping) hand that first transition the pin and clear tailRevision, so the
	// tail transition below runs unpinned — the store still validates from→to.
	// Re-pinning the tail to the bumped revision would fail every time; re-pinning
	// to a freshly read one would re-open a race against anything that
	// legitimately touches the VM while rt.Stop runs.
	tailRevision := expectedRevision

	switch action {
	case "start":
		if vm.ObservedState != "stopped" {
			return m.failAction(ctx, vmID, opID, action, &store.InvalidTransitionError{From: vm.ObservedState, To: "starting"})
		}
		// The whole start runs on a launch-derived budget, not the caller's
		// stop-derived one (see launchBudget). Staging copies gigabytes and the
		// guest then gets 60s to attach, so the operation budget would abort a
		// launch that is behaving perfectly and leave the VM in "starting" with
		// its stage dir already written.
		startCtx, startCancel := m.detachedContext(ctx, launchBudget)
		defer startCancel()
		// The stop handed this VM's RAM and vCPU back to the host, and the start
		// has to ask for them again — the memory may have gone to another VM in
		// the meantime. Ask for exactly what the reservation row holds rather
		// than recomputing from the VM row and current config: that row is what
		// admission sums, so re-acquiring anything else would admit against one
		// number and hold another. Disk is 0 because the row never released it.
		res, err := m.st.GetReservation(startCtx, vmID)
		if err != nil {
			return m.failAction(startCtx, vmID, opID, action, fmt.Errorf("read reservation: %w", err))
		}
		bootID := uuid.NewString()
		wantRunning := "running"
		updVM, err := m.st.TransitionVM(startCtx, store.TransitionInput{
			VMID:             vmID,
			ExpectedRevision: expectedRevision,
			To:               "starting",
			Reason:           "start",
			OperationID:      opID,
			DesiredState:     &wantRunning,
			BootID:           &bootID,
			AcquireCompute:   true,
			Admit: func(totals store.ReservationTotals) error {
				return m.policy.Admit(totals, res.MemoryTotalMiB, res.VCPU, 0)
			},
		})
		if err != nil {
			return m.failAction(startCtx, vmID, opID, action, err)
		}
		staged, err := m.rt.Launch(startCtx, VMSpec{
			VMID:             vmID,
			BootID:           bootID,
			VCPUCount:        vm.VCPUCount,
			MemoryMiB:        vm.MemoryMiB,
			RootDiskMiB:      vm.RootDiskMiB,
			WorkspaceDiskMiB: vm.WorkspaceDiskMiB,
			NetworkProfile:   vm.NetworkProfile,
			NetworkPolicyID:  vm.NetworkPolicyID,
			TemplateID:       vm.TemplateID,
			TemplateDigest:   vm.TemplateDigest,
		})
		if err != nil {
			// A launch fails most often because its budget ran out, so this
			// branch must assume startCtx is already dead. Recording the failure
			// and cleaning up on that context would do neither.
			recCtx, recCancel := m.recoveryContext(startCtx)
			defer recCancel()
			m.failLaunch(recCtx, vmID, opID, "launch", err.Error())
			_ = m.rt.ForceStop(recCtx, vmID)
			op, _ := m.st.GetOperation(recCtx, opID)
			return updVM, op, &ErrRuntimeOpFailed{VMID: vmID, Op: "launch", Err: err}
		}
		// The launch worked, and everything below is the record of that. It must
		// not ride startCtx either: a launch that returns nil with its budget
		// spent would leave these writes doing nothing, and a live VM sitting
		// behind a row that still reads "starting".
		okCtx, okCancel := m.recoveryContext(startCtx)
		defer okCancel()
		updVM, err = m.st.TransitionVM(okCtx, store.TransitionInput{
			VMID:        vmID,
			To:          "running",
			Reason:      "start_complete",
			OperationID: opID,
			Images:      staged,
		})
		if err != nil {
			return m.failAction(okCtx, vmID, opID, action, err)
		}
		// Hook: pending run → running when VM starts.
		m.onVMRunning(okCtx, vmID)
		// start never reaches the shared tail below, so its pin is spent on the →starting transition; a future edit that lets it fall through would re-introduce the double-spend.
		return m.succeedAction(okCtx, vmID, opID, "running", updVM)

	case "pause":
		if vm.ObservedState != "running" {
			return m.failAction(ctx, vmID, opID, action, &store.InvalidTransitionError{From: vm.ObservedState, To: "paused"})
		}
		if err := m.rt.Pause(ctx, vmID); err != nil {
			return m.failAction(ctx, vmID, opID, action, &ErrRuntimeOpFailed{VMID: vmID, Op: "pause", Err: err})
		}
		newState, reason = "paused", "pause"

	case "resume":
		if vm.ObservedState != "paused" {
			return m.failAction(ctx, vmID, opID, action, &store.InvalidTransitionError{From: vm.ObservedState, To: "running"})
		}
		if err := m.rt.Resume(ctx, vmID); err != nil {
			return m.failAction(ctx, vmID, opID, action, &ErrRuntimeOpFailed{VMID: vmID, Op: "resume", Err: err})
		}
		newState, reason = "running", "resume"

	case "stop":
		switch vm.ObservedState {
		case "running", "paused", "stopping":
		default:
			return m.failAction(ctx, vmID, opID, action, &store.InvalidTransitionError{From: vm.ObservedState, To: "stopping"})
		}
		// Transition to stopping first (required by §5.2 matrix for running and paused).
		if vm.ObservedState != "stopping" {
			if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:             vmID,
				ExpectedRevision: expectedRevision,
				To:               "stopping",
				Reason:           "stop_requested",
				OperationID:      opID,
				DesiredState:     &wantStopped,
			}); err != nil {
				return m.failAction(ctx, vmID, opID, action, err)
			}
			tailRevision = nil // pin spent on running/paused→stopping
		}
		forced, err := m.rt.Stop(ctx, vmID, grace)
		if err != nil {
			return m.failAction(ctx, vmID, opID, action, &ErrRuntimeOpFailed{VMID: vmID, Op: "stop", Err: err})
		}
		if forced {
			reason = "forced_stop"
		} else {
			reason = "graceful_stop"
		}
		newState, releaseC = "stopped", true

	case "force_stop":
		switch vm.ObservedState {
		case "running", "paused", "stopping":
		default:
			return m.failAction(ctx, vmID, opID, action, &store.InvalidTransitionError{From: vm.ObservedState, To: "stopping"})
		}
		// Transition through stopping first (§5.2 matrix: running/paused→stopping→stopped).
		if vm.ObservedState != "stopping" {
			if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:             vmID,
				ExpectedRevision: expectedRevision,
				To:               "stopping",
				Reason:           "force_stop_requested",
				OperationID:      opID,
				DesiredState:     &wantStopped,
			}); err != nil {
				return m.failAction(ctx, vmID, opID, action, err)
			}
			tailRevision = nil // pin spent on running/paused→stopping
		}
		if err := m.rt.ForceStop(ctx, vmID); err != nil {
			return m.failAction(ctx, vmID, opID, action, &ErrRuntimeOpFailed{VMID: vmID, Op: "force_stop", Err: err})
		}
		newState, reason, releaseC = "stopped", "forced_stop", true
	}

	// The runtime call is over; everything below records what it did, and it
	// gets its own context for the same reason the start path does. The
	// operation budget is sized for the runtime call plus these writes, but at
	// the documented stop grace the worst case leaves 5s of it (see
	// operationSlack) and a host slower than that model spends the lot. This
	// transition carries the compute release as well as the terminal state, so
	// losing it strands the VM in "stopping" with its memory still held against
	// admission until the next reconcile.
	tailCtx, tailCancel := m.recoveryContext(ctx)
	defer tailCancel()

	updVM, err := m.st.TransitionVM(tailCtx, store.TransitionInput{
		VMID:             vmID,
		ExpectedRevision: tailRevision,
		To:               newState,
		Reason:           reason,
		OperationID:      opID,
		DesiredState:     &newState,
		ReleaseCompute:   releaseC,
	})
	if err != nil {
		return m.failAction(tailCtx, vmID, opID, action, err)
	}
	// VM lifecycle hooks: conclude active runs on terminal transitions.
	switch newState {
	case "stopped":
		m.onVMTerminal(tailCtx, vmID)
	case "running":
		m.onVMRunning(tailCtx, vmID)
	}
	return m.succeedAction(tailCtx, vmID, opID, action, updVM)
}

// failAction records a failed action on the operation row and reads the VM back.
//
// Its writes run on a recovery context because the commonest reason an action
// fails is that its own context expired — a stop whose runtime call ran out of
// budget, a launch that outlived its own. Recording that on the expired context
// writes nothing, and the operation is then stranded at "running" describing
// work that is over.
func (m *Manager) failAction(ctx context.Context, vmID string, opID int64, action string, cause error) (*store.VM, *store.Operation, error) {
	ctx, cancel := m.recoveryContext(ctx)
	defer cancel()

	// A typed refusal already names its own cause and the shortfall that
	// produced it; flattening those to "action_failed" would throw away the
	// only evidence of why the host said no, and the API maps causes to status
	// codes. The create path persists the same two fields (CreateVMWithOperation),
	// so a refused start and a refused create leave the same durable record.
	causeStr := "action_failed"
	msg := cause.Error()
	var refusal *store.AdmissionRefusal
	if errors.As(cause, &refusal) {
		causeStr = refusal.Cause
		msg = refusal.Message
	}
	op, _ := m.st.UpdateOperation(ctx, store.OperationUpdate{
		OperationID:  opID,
		Phase:        action,
		State:        "failed",
		ErrorCause:   &causeStr,
		ErrorMessage: &msg,
	})
	vm, _ := m.st.GetVM(ctx, vmID)
	return vm, op, cause
}

func (m *Manager) succeedAction(ctx context.Context, vmID string, opID int64, phase string, vm *store.VM) (*store.VM, *store.Operation, error) {
	op, err := m.st.UpdateOperation(ctx, store.OperationUpdate{
		OperationID: opID,
		Phase:       phase,
		State:       "succeeded",
	})
	if err != nil {
		return vm, nil, fmt.Errorf("update action op: %w", err)
	}
	return vm, op, nil
}

// Delete removes VM compute resources. Already-deleted or deleting VMs are
// idempotent returns. Live VMs require force=true.
//
// expectedRevision is an optimistic-concurrency precondition, and a
// precondition is checked once: on the first transition this call makes. The
// force path walks running/paused→stopping→stopped→deleting, so the pin rides
// whichever of those runs first and every later transition goes unpinned — the
// store still validates from→to on each. Re-pinning a later transition to the
// caller's revision would fail every time, because the earlier transitions
// already bumped it. The first transition also precedes rt.ForceStop, so a
// refused pin costs the caller nothing.
// beginDelete claims vmID for the calling Delete. It reports false when another
// Delete call already holds it; it never blocks.
func (m *Manager) beginDelete(vmID string) bool {
	m.deletingMu.Lock()
	defer m.deletingMu.Unlock()
	if m.deleting[vmID] {
		return false
	}
	m.deleting[vmID] = true
	return true
}

// endDelete releases the claim beginDelete took.
func (m *Manager) endDelete(vmID string) {
	m.deletingMu.Lock()
	delete(m.deleting, vmID)
	m.deletingMu.Unlock()
}

func (m *Manager) Delete(ctx context.Context, vmID string, force bool, expectedRevision *int64) (*store.VM, error) {
	vm, err := m.st.GetVM(ctx, vmID)
	if err != nil {
		return nil, err
	}
	if vm.ObservedState == "deleted" {
		return vm, nil // already done, and its resources went with it
	}
	// A VM another Delete call is working on is that call's to finish. A row
	// reading "deleting" with no such call behind it is a stalled delete, and
	// this one resumes it: the transition below is skipped, the signal and the
	// release are not. Delete used to return early for that state as well, which
	// answered every retry with success while the netns, the jail chroot and
	// privd's ledger entry stayed on the host — Reconcile, which runs at startup
	// only, was the sole retry there was (issue vexd).
	if !m.beginDelete(vmID) {
		return vm, nil // in progress, by another call
	}
	defer m.endDelete(vmID)

	// A resume consumes no revision pin, and cannot: the only edge out of
	// "deleting" is "deleted", and only TransitionVM bumps a row's revision
	// (internal/store/vms.go). So a caller's stale pin on a "deleting" row means
	// the row reached "deleted", which the early return above already answers.
	pin := expectedRevision

	// From this call on the operator wants the VM gone, and every state it passes
	// through on the way — stopping, stopped, deleting — is honest drift toward
	// that. Every transition below carries the intent rather than only the last,
	// so a delete that stalls mid-way still reads as unfinished work instead of a
	// VM someone apparently wanted stopped.
	wantDeleted := "deleted"

	// Live states require force. signalled records whether this call has already
	// asked the VMM to die, so the pre-release guard below does not ask twice.
	signalled := false
	liveStates := map[string]bool{
		"provisioning": true, "starting": true,
		"running": true, "paused": true, "stopping": true,
	}
	if liveStates[vm.ObservedState] {
		if !force {
			return vm, store.ErrVMLive
		}
		// §5.2: running/paused→stopping→stopped (no direct live→stopped transition).
		// The transition runs BEFORE rt.ForceStop, the order doAction's stop
		// already uses: the caller's precondition is then checked before anything
		// is destroyed, so a refused delete leaves the VM alone instead of killing
		// it and answering 409. If ForceStop then fails, the row stays at
		// "stopping" — the honest record of "we asked the VM to die and do not
		// know how it ended"; Reconcile owns the recovery.
		//
		// A transition refused as invalid is tolerated — the reconciler or a
		// concurrent stop may have moved the row already — and consumes nothing,
		// so the pin travels on to the next transition. A stale pin is refused
		// with *store.RevisionMismatchError, which the tolerance does not match
		// and which reaches the API as 409 through the %w wrapping.
		if vm.ObservedState != "stopping" {
			stopping, stopErr := m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:             vmID,
				ExpectedRevision: pin,
				To:               "stopping",
				Reason:           "forced_stop_for_delete",
				OperationID:      0,
				DesiredState:     &wantDeleted,
			})
			switch {
			case stopErr == nil:
				vm = stopping
				pin = nil // spent on live→stopping
			case !errors.Is(stopErr, new(store.InvalidTransitionError)):
				return vm, fmt.Errorf("stopping before delete: %w", stopErr)
			}
		}
		if err := m.rt.ForceStop(ctx, vmID); err != nil {
			var ue *UnavailableError
			if !errors.As(err, &ue) { // unavailable runtime is fine — VM not running
				return vm, &ErrRuntimeOpFailed{VMID: vmID, Op: "force_stop", Err: err}
			}
		}
		signalled = true
		_, stopErr := m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:             vmID,
			ExpectedRevision: pin,
			To:               "stopped",
			Reason:           "forced_stop_for_delete",
			OperationID:      0,
			DesiredState:     &wantDeleted,
			ReleaseCompute:   true,
		})
		switch {
		case stopErr == nil:
			pin = nil // spent here when the VM was already stopping
		case !errors.Is(stopErr, new(store.InvalidTransitionError)):
			return vm, fmt.Errorf("stop before delete: %w", stopErr)
		}
		if vm, err = m.st.GetVM(ctx, vmID); err != nil {
			return nil, err
		}
	}

	// failed → deleting is valid in the matrix.
	if vm.ObservedState == "failed" || vm.ObservedState == "stopped" {
		vm, err = m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:             vmID,
			ExpectedRevision: pin,
			To:               "deleting",
			Reason:           "delete_requested",
			OperationID:      0,
			DesiredState:     &wantDeleted,
		})
		if err != nil {
			return vm, err
		}
	}

	// Signal before releasing. Every path arriving here leaves a row reading
	// "deleting", and a row is a record, not a reading of the host: the launch
	// rollbacks write "failed" and then discard the error from their best-effort
	// ForceStop (failLaunch's call sites), doStop's forced path writes "stopped"
	// while dropping its SignalVM errors, and Reconcile settles a "stopping" row
	// it has no finding for without observing anything. Each of those can leave a
	// live VMM behind a terminal row, and privd answers release_vm with invalid_state "vm process is
	// still alive; signal first" (internal/privd/server.go). The delete then fails
	// and the row parks at "deleting" with nothing to unstick it but the root
	// helper — observed on aibox03 2026-09-04, issue ffxv.
	//
	// The guard runs after the transition rather than before it, so the caller's
	// revision pin is checked before anything is destroyed: a "stopped" VM that
	// someone restarted under us fails that transition and keeps its process.
	//
	// A ForceStop returning nil is not proof of death either — the forced path
	// drops SignalVM's errors — so this narrows the window rather than closing it.
	// What it removes is the case where nobody asked at all.
	if !signalled {
		if err := m.rt.ForceStop(ctx, vmID); err != nil {
			var ue *UnavailableError
			if !errors.As(err, &ue) {
				return vm, &ErrRuntimeOpFailed{VMID: vmID, Op: "force_stop", Err: err}
			}
		}
	}

	// R1: release before flipping the row to "deleted". The invariant this keeps
	// is scoped to what Release owns -- the network allocation, the stage dir,
	// <StateDir>/vms/<id>/, the jail chroot and privd's ledger entry
	// (internal/jailer/stop.go): no VM row reads "deleted" while any of those
	// survive, because a real error here fails the delete and leaves the row in
	// "deleting". UnavailableError is the one tolerated failure -- a runtime
	// absent on startup reconcile is normal and must not wedge deletes.
	//
	// Release owns that list whether or not the VM still has a manifest. It used
	// to own the last two only when the manifest was already gone, which left
	// exactly one hole: a guest that shuts itself down is never force-stopped --
	// NotifyVMMExit takes the row to "stopped" without a runtime call, and the
	// force-stop above runs only from a live state -- so it arrived here with its
	// manifest intact and nothing had ever called release_vm. Its chroot and
	// ledger entry outlived the "deleted" row. doRelease runs both release verbs
	// unconditionally now, and takes its verdict from stat'ing the chroot rather
	// than from what privd returned.
	//
	// A VM process that is still alive no longer slips through either: release_vm
	// answers invalid_state while privd can see it, releaseVMWhenDead retries for
	// its budget, and a VMM that outlasts that fails this call and holds the row
	// at "deleting" where it is visible. What remains unswept is the runner: the
	// force-stop returns nil whether or not it killed anything (doStop's forced
	// path drops its SignalVM errors and logs-and-discards the final ReleaseVM
	// failure rather than report a genuinely-dead VM's stop as failed), and
	// Release never signals a runner at all. That one needs the M1b cleanup
	// backlog, not this call.
	if err := m.rt.Release(ctx, vmID); err != nil {
		var ue *UnavailableError
		if !errors.As(err, &ue) {
			// The typed error below tells this caller everything, and tells
			// nobody else anything: it is a response body, and the row parked at
			// "deleting" outlives the request that produced it. Record the
			// reason beside the row so the next operator to look -- days later,
			// after a restart, from the event stream -- finds the same answer
			// this caller got (SPEC 5.3: record cleanup failures and retry them).
			_ = m.st.RecordCleanupFailure(ctx, vmID, "deleting", err.Error())
			return nil, &ErrReleaseFailed{VMID: vmID, Reason: err.Error()}
		}
		// UnavailableError is tolerated: an absent runtime must not wedge deletes.
	}

	vm, err = m.st.TransitionVM(ctx, store.TransitionInput{
		VMID:         vmID,
		To:           "deleted",
		Reason:       "deleted",
		OperationID:  0,
		DesiredState: &wantDeleted,
		ReleaseAll:   true,
	})
	return vm, err
}

// Reconcile cleans up state left over from a previous controller run (§5.5).
// Operations in flight → failed; VMs in transitional states → failed/stopped/deleted,
// except the running and paused VMs cfg.AdoptedVMs names, which are left alone.
// Runs: pending/running/concluding runs whose VM is no longer live are concluded
// inconclusive with an interrupted reason (AT-093). Terminal runs missing reports
// have report generation re-enqueued (R7).
func (m *Manager) Reconcile(ctx context.Context) error {
	// Fail in-flight operations (pending/running).
	for _, state := range []string{"pending", "running"} {
		ops, err := m.st.ListOperationsByState(ctx, state)
		if err != nil {
			return fmt.Errorf("list %s operations: %w", state, err)
		}
		cause := "controller_restart"
		msg := "the controller restarted while this operation was in progress"
		for _, op := range ops {
			if _, err := m.st.UpdateOperation(ctx, store.OperationUpdate{
				OperationID:  op.OperationID,
				Phase:        op.Phase,
				State:        "failed",
				ErrorCause:   &cause,
				ErrorMessage: &msg,
			}); err != nil {
				return fmt.Errorf("fail operation %d: %w", op.OperationID, err)
			}
		}
	}

	// Reconcile VMs in transitional states.
	allVMs, err := m.st.ListVMs(ctx, store.VMQuery{Limit: store.MaxPageLimit})
	if err != nil {
		return fmt.Errorf("list vms for reconcile: %w", err)
	}
	for _, vm := range allVMs {
		switch vm.ObservedState {
		case "provisioning", "starting":
			// VMM never started or never reached running; mark failed.
			stage := vm.ObservedState
			reason := "controller_restart"
			_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:           vm.VMID,
				To:             "failed",
				Reason:         reason,
				OperationID:    0,
				FailureStage:   &stage,
				FailureReason:  &reason,
				ReleaseCompute: true,
			})
		case "running", "paused":
			// Adopted: the runtime's startup scan found this VM's VMM alive with a
			// runner attached to it. Firecracker is started daemonized and
			// reparented to init (internal/privd/vmops.go), so surviving a
			// controller restart is the normal case, not the exception — and
			// failing the row records a fleet outage that did not happen, on a VM
			// an operator's next move would be to delete.
			//
			// Adoption is the absence of a write. Transitioning to "running" from
			// "running" is not a valid edge (§5.2) and would bump a revision every
			// operator pin depends on; the row is already correct.
			if m.cfg.AdoptedVMs[vm.VMID] {
				continue
			}
			// VMM disappeared — §5.5: mark with explicit reason.
			reason := "vmm_disappeared_on_restart"
			_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:           vm.VMID,
				To:             "failed",
				Reason:         reason,
				OperationID:    0,
				ReleaseCompute: true,
			})
		case "stopping":
			// A stop the controller began and did not finish. The runtime's
			// findings tell the two cases apart, and until M2a there were no
			// findings to tell them apart with.
			//
			// Adopted: the VMM is alive with a runner attached to it, so this
			// stop was interrupted, not completed. Firecracker is started
			// --daemonize'd and reparented to init (internal/privd/vmops.go),
			// which is exactly why the row cannot be settled on the
			// controller's absence — the old comment here said as much and
			// settled it anyway, because the portable core had nothing to ask.
			// Recording "stopped" released the compute of a running microVM and
			// admission handed the same memory out twice, on a VM whose stop
			// never happened. So the stop is finished the way the "deleting"
			// branch finishes a delete: force-stop first, settle on the answer,
			// and leave the row alone when the answer is no. Tolerance mirrors
			// that branch exactly — an absent runtime must not wedge the row,
			// and any other failure leaves it at "stopping" for the next
			// restart. The row is retained and the reason is recorded beside
			// it as vm.cleanup_failed, which is the whole of the report: this
			// package logs nowhere, and Reconcile does not fail either, because
			// a stop that will not complete must not stop the daemon from
			// starting. A store that cannot take the record is a bigger problem
			// than the stop, and one that startup will hit again on its own.
			//
			// Not adopted: nothing looked, or the runtime cannot look. Absent
			// evidence is not evidence of health — but it is not evidence of a
			// live VMM either, and there is no host verb worth calling on a VM
			// nobody can see. The row settles at "stopped" with its compute
			// released. That is the deviation this branch has always carried,
			// now narrowed to the case where it is the only answer available.
			// Ledgered in PLAN.md's deviations log.
			if m.cfg.AdoptedVMs[vm.VMID] {
				if err := m.rt.ForceStop(ctx, vm.VMID); err != nil {
					var ue *UnavailableError
					if !errors.As(err, &ue) {
						_ = m.st.RecordCleanupFailure(ctx, vm.VMID, "stopping", err.Error())
						continue
					}
				}
			}
			_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:           vm.VMID,
				To:             "stopped",
				Reason:         "controller_restart",
				OperationID:    0,
				ReleaseCompute: true,
			})
		case "deleting":
			// Complete the idempotent delete, keeping the R1 invariant Delete
			// states above: no VM row reads "deleted" while the resources
			// Release owns -- the network allocation, the stage dir,
			// <StateDir>/vms/<id>/, the jail chroot and privd's ledger entry --
			// survive it. A row that reaches here is disproportionately one
			// whose manifest is already gone: it is a delete that was
			// interrupted, and doRollback removes the state dir
			// whether or not its own release landed (internal/jailer/launch.go). A controller that died
			// mid-delete can leave the row at "deleting" with the release never
			// attempted, and Delete refuses to retry: it returns early for both
			// "deleted" and "deleting". So this is the only retry there is, and
			// finalizing without it would record a reclamation that never
			// happened -- with every surviving manifest still counted against
			// MaxSlots by allocateSlot (internal/jailer/manifest.go), so the
			// slot never comes back either.
			//
			// Tolerance mirrors Delete's exactly. An *UnavailableError is
			// expected here -- reconcile runs at startup, where the runtime may
			// legitimately be absent -- and must not wedge the delete. Any
			// other failure leaves the row at "deleting" for the next restart to
			// retry, with the reason recorded beside it as vm.cleanup_failed
			// (SPEC 5.3 asks for cleanup failures to be recorded, not only
			// retried). That pair is the whole of the report: this package logs
			// nowhere, and Reconcile does not fail either, because a release
			// error must not stop the daemon from starting.
			// The signal comes first here for the same reason it does in Delete:
			// a row parked at "deleting" is disproportionately one privd refused
			// to release because the VM's process was still alive, and releasing
			// without asking it to die again just reproduces that refusal on
			// every restart. A ForceStop that fails for any reason but an absent
			// runtime skips the release entirely — the retained row is the record.
			releaseOK := true
			var stalled error
			if err := m.rt.ForceStop(ctx, vm.VMID); err != nil {
				var ue *UnavailableError
				if releaseOK = errors.As(err, &ue); !releaseOK {
					stalled = err
				}
			}
			if releaseOK {
				if err := m.rt.Release(ctx, vm.VMID); err != nil {
					var ue *UnavailableError
					if releaseOK = errors.As(err, &ue); !releaseOK {
						stalled = err
					}
				}
			}
			if stalled != nil {
				_ = m.st.RecordCleanupFailure(ctx, vm.VMID, "deleting", stalled.Error())
			}
			if releaseOK {
				wantDeleted := "deleted"
				_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
					VMID:         vm.VMID,
					To:           "deleted",
					Reason:       "controller_restart",
					OperationID:  0,
					DesiredState: &wantDeleted,
					ReleaseAll:   true,
				})
			}
		}
		// stopped, failed, deleted: no action needed.
	}

	// Reconcile runs: conclude interrupted runs and re-enqueue missing reports.
	if err := m.reconcileRuns(ctx); err != nil {
		return fmt.Errorf("reconcile runs: %w", err)
	}

	return nil
}

// NotifyVMMExit is called by the spool importer when it sees a vm.vmm_exited
// envelope for a VM. It transitions the VM to stopped (graceful) or failed
// (not graceful) using the manager's existing transition helpers — one write path.
//
// bootID names the boot whose VMM was observed to exit; "" means the observer
// identified no boot (Reconcile stats the runner that is live now, so its
// findings are about whatever boot is current). An exit notice reaches the
// manager late — the spool importer polls, so a boot can end and the next one
// begin before its notice is delivered — and an exit of a boot that is over
// says nothing about the boot running now.
//
// Already-terminal VMs (failed, stopped, deleted, …) are a no-op: importer
// replays are normal and must not cause errors. VMs in "stopping" are a no-op
// as well — that stop belongs to whoever started it. Unknown VMs return nil.
func (m *Manager) NotifyVMMExit(ctx context.Context, vmID, bootID, reason string, graceful bool) error {
	vm, err := m.st.GetVM(ctx, vmID)
	if err != nil {
		// Unknown VM — no-op.
		return nil
	}

	// A notice about another boot. Stop and start inside one importer poll and
	// the first boot's exit lands on the second boot's VM: acting on it fails a
	// VM that is booting correctly. Only a notice that names a boot can be
	// judged this way, and only against a VM that has one.
	if bootID != "" && vm.CurrentBootID != "" && bootID != vm.CurrentBootID {
		return nil
	}

	// Terminal states: already done, nothing to do.
	switch vm.ObservedState {
	case "stopped", "failed", "deleted", "deleting":
		return nil
	}

	// "stopping" is not terminal — it is owned. Whoever put the VM there (a stop
	// or force_stop action, Delete's force path, a batch stop wave) holds the
	// graceful-vs-forced determination that only rt.Stop knows, and will record
	// the terminal transition itself with that reason; its operation record
	// depends on making that write. Finishing the stop here steals the
	// transition, loses the determination, and leaves the initiator's tail
	// answering 409 invalid_transition stopped→stopped for a stop that worked.
	// An orphaned "stopping" row — initiator died — is Reconcile's to recover.
	if vm.ObservedState == "stopping" {
		return nil
	}

	// provisioning/starting VMs never reached running: the VMM did not fully start.
	// Route directly to failed regardless of graceful — stopped is not a valid
	// destination from those states (§5.2 matrix), and "graceful" has no meaning
	// for a VM that never ran.
	earlyExit := vm.ObservedState == "provisioning" || vm.ObservedState == "starting"
	if earlyExit {
		stage := "vmm_exit"
		_, err = m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:           vmID,
			To:             "failed",
			Reason:         reason,
			OperationID:    0,
			FailureStage:   &stage,
			FailureReason:  &reason,
			ReleaseCompute: true,
		})
		if err == nil {
			m.onVMTerminal(ctx, vmID)
		}
	} else {
		// running/paused: §5.2 requires passing through stopping first.
		_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:        vmID,
			To:          "stopping",
			Reason:      reason,
			OperationID: 0,
		})

		// Final transition: stopped (graceful) or failed (not graceful).
		if graceful {
			_, err = m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:           vmID,
				To:             "stopped",
				Reason:         reason,
				OperationID:    0,
				ReleaseCompute: true,
			})
			if err == nil {
				m.onVMTerminal(ctx, vmID)
			}
		} else {
			stage := "vmm_exit"
			_, err = m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:           vmID,
				To:             "failed",
				Reason:         reason,
				OperationID:    0,
				FailureStage:   &stage,
				FailureReason:  &reason,
				ReleaseCompute: true,
			})
			if err == nil {
				m.onVMTerminal(ctx, vmID)
			}
		}
	}

	// Ignore InvalidTransitionError: a concurrent stop/action may have already
	// moved the VM — that is fine. Any other error is a real store failure.
	if errors.Is(err, new(store.InvalidTransitionError)) {
		return nil
	}
	return err
}

// reconcileRuns is the run portion of Reconcile. It processes two categories:
//  1. Non-terminal runs (pending/running/concluding) whose VM is no longer live
//     → conclude inconclusive with the interrupted reason (AT-093).
//  2. Terminal runs with no stored report and no running/pending report operation
//     → re-enqueue report generation (R7). Guard uses HasRunningReportOp
//     (store.report.go) which queries for kind=run.report_generate, state IN
//     (running, pending). Any previously running ops are failed by category 1's
//     reconcile before this check runs.
func (m *Manager) reconcileRuns(ctx context.Context) error {
	// Category 1: active runs whose VM is no longer live.
	activeRuns, err := m.st.ListRunsInPhases(ctx, "pending", "running", "concluding")
	if err != nil {
		return fmt.Errorf("list active runs: %w", err)
	}

	// Determine "live" VM states: only running/paused VMs are live.
	// After the VM reconcile above, transitional VMs have been moved to terminal.
	liveStates := map[string]bool{
		"running": true, "paused": true,
	}

	for _, run := range activeRuns {
		vm, err := m.st.GetVM(ctx, run.VMID)
		if err != nil {
			// VM deleted or unknown → conclude the run.
			_, _ = m.concludeRun(ctx, run.RunID, triggerInterrupted)
			continue
		}
		if !liveStates[vm.ObservedState] {
			// VM is stopped/failed/starting/provisioning/stopping/deleting/deleted
			// — no longer live; conclude with interrupted reason.
			_, _ = m.concludeRun(ctx, run.RunID, triggerInterrupted)
		}
		// VM live: event-driven hooks own it; leave alone.
	}

	// Category 2: terminal runs missing reports (R7).
	if m.reportGen == nil {
		return nil // no generator installed yet; skip
	}
	// We need terminal runs without stored reports. There's no direct store method
	// for this, so we use ListRunsInPhases for terminal phases and check reports.
	terminalPhases := []string{"succeeded", "failed", "inconclusive", "aborted"}
	terminalRuns, err := m.st.ListRunsInPhases(ctx, terminalPhases...)
	if err != nil {
		return fmt.Errorf("list terminal runs: %w", err)
	}
	for _, run := range terminalRuns {
		if _, err := m.st.GetRunReport(ctx, run.RunID); errors.Is(err, store.ErrReportNotFound) {
			// No report stored. Check whether a report op is already running so we
			// don't pile up duplicate ops (guard closed in Task 7 now that the
			// run.report_generate op kind exists and HasRunningReportOp queries it).
			// Note: category 1 above has already failed any previously-running ops,
			// so this guard catches only ops created by a concurrent goroutine, not
			// stale ones from the previous controller run.
			hasOp, err := m.st.HasRunningReportOp(ctx, run.RunID)
			if err == nil && hasOp {
				continue // already in flight; skip
			}
			// Call the generator directly: reconcile runs synchronously at startup,
			// before any external requests arrive, so blocking here is safe and keeps
			// the test's enqueued-check simple. The real generator (MakeReportGenFn)
			// is async internally via its own goroutine in MakeReportGenFn; here we
			// just call the wrapper that is assigned to m.reportGen.
			m.reportGen(run.RunID)
		}
	}
	return nil
}
