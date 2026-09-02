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

// ErrUnknownAction is returned when Action receives an unrecognised action name.
type ErrUnknownAction struct{ Known []string }

func (e *ErrUnknownAction) Error() string {
	return fmt.Sprintf("unknown action (valid: %s)", strings.Join(e.Known, ", "))
}

var validActions = []string{"start", "pause", "resume", "stop", "force_stop"}

// ManagerConfig carries the host-level configuration the manager acts on.
type ManagerConfig struct {
	Admission  config.Admission
	VMDefaults config.VMDefaults
	Templates  map[string]Template
	Host       HostResources
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

	// Launch the VMM.
	if err := m.rt.Launch(ctx, spec); err != nil {
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
			return m.failAction(ctx, vmID, opID, action, fmt.Errorf("start requires stopped state, got %s", vm.ObservedState))
		}
		bootID := uuid.NewString()
		updVM, err := m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:             vmID,
			ExpectedRevision: expectedRevision,
			To:               "starting",
			Reason:           "start",
			OperationID:      opID,
			BootID:           &bootID,
		})
		if err != nil {
			return m.failAction(ctx, vmID, opID, action, err)
		}
		if err := m.rt.Launch(ctx, VMSpec{
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
		}); err != nil {
			m.failLaunch(ctx, vmID, opID, "launch", err.Error())
			_ = m.rt.ForceStop(ctx, vmID)
			op, _ := m.st.GetOperation(ctx, opID)
			return updVM, op, fmt.Errorf("launch: %w", err)
		}
		updVM, err = m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:        vmID,
			To:          "running",
			Reason:      "start_complete",
			OperationID: opID,
		})
		if err != nil {
			return m.failAction(ctx, vmID, opID, action, err)
		}
		// Hook: pending run → running when VM starts.
		m.onVMRunning(ctx, vmID)
		return m.succeedAction(ctx, vmID, opID, "running", updVM)

	case "pause":
		if vm.ObservedState != "running" {
			return m.failAction(ctx, vmID, opID, action, fmt.Errorf("pause requires running state, got %s", vm.ObservedState))
		}
		if err := m.rt.Pause(ctx, vmID); err != nil {
			return m.failAction(ctx, vmID, opID, action, err)
		}
		newState, reason = "paused", "pause"

	case "resume":
		if vm.ObservedState != "paused" {
			return m.failAction(ctx, vmID, opID, action, fmt.Errorf("resume requires paused state, got %s", vm.ObservedState))
		}
		if err := m.rt.Resume(ctx, vmID); err != nil {
			return m.failAction(ctx, vmID, opID, action, err)
		}
		newState, reason = "running", "resume"

	case "stop":
		switch vm.ObservedState {
		case "running", "paused", "stopping":
		default:
			return m.failAction(ctx, vmID, opID, action, fmt.Errorf("stop requires running/paused/stopping state, got %s", vm.ObservedState))
		}
		// Transition to stopping first (required by §5.2 matrix for running and paused).
		if vm.ObservedState != "stopping" {
			if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:             vmID,
				ExpectedRevision: expectedRevision,
				To:               "stopping",
				Reason:           "stop_requested",
				OperationID:      opID,
			}); err != nil {
				return m.failAction(ctx, vmID, opID, action, err)
			}
			tailRevision = nil // pin spent on running/paused→stopping
		}
		forced, err := m.rt.Stop(ctx, vmID, grace)
		if err != nil {
			return m.failAction(ctx, vmID, opID, action, err)
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
			return m.failAction(ctx, vmID, opID, action, fmt.Errorf("force_stop requires running/paused/stopping state, got %s", vm.ObservedState))
		}
		// Transition through stopping first (§5.2 matrix: running/paused→stopping→stopped).
		if vm.ObservedState != "stopping" {
			if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:             vmID,
				ExpectedRevision: expectedRevision,
				To:               "stopping",
				Reason:           "force_stop_requested",
				OperationID:      opID,
			}); err != nil {
				return m.failAction(ctx, vmID, opID, action, err)
			}
			tailRevision = nil // pin spent on running/paused→stopping
		}
		if err := m.rt.ForceStop(ctx, vmID); err != nil {
			return m.failAction(ctx, vmID, opID, action, err)
		}
		newState, reason, releaseC = "stopped", "forced_stop", true
	}

	updVM, err := m.st.TransitionVM(ctx, store.TransitionInput{
		VMID:             vmID,
		ExpectedRevision: tailRevision,
		To:               newState,
		Reason:           reason,
		OperationID:      opID,
		ReleaseCompute:   releaseC,
	})
	if err != nil {
		return m.failAction(ctx, vmID, opID, action, err)
	}
	// VM lifecycle hooks: conclude active runs on terminal transitions.
	switch newState {
	case "stopped":
		m.onVMTerminal(ctx, vmID)
	case "running":
		m.onVMRunning(ctx, vmID)
	}
	return m.succeedAction(ctx, vmID, opID, action, updVM)
}

func (m *Manager) failAction(ctx context.Context, vmID string, opID int64, action string, cause error) (*store.VM, *store.Operation, error) {
	causeStr := "action_failed"
	msg := cause.Error()
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
func (m *Manager) Delete(ctx context.Context, vmID string, force bool, expectedRevision *int64) (*store.VM, error) {
	vm, err := m.st.GetVM(ctx, vmID)
	if err != nil {
		return nil, err
	}
	switch vm.ObservedState {
	case "deleted":
		return vm, nil // already done
	case "deleting":
		return vm, nil // in progress
	}

	// Live states require force.
	liveStates := map[string]bool{
		"provisioning": true, "starting": true,
		"running": true, "paused": true, "stopping": true,
	}
	if liveStates[vm.ObservedState] {
		if !force {
			return vm, store.ErrVMLive
		}
		// Force-stop, then fall through to deletion.
		if err := m.rt.ForceStop(ctx, vmID); err != nil {
			var ue *UnavailableError
			if !errors.As(err, &ue) { // unavailable runtime is fine — VM not running
				return vm, fmt.Errorf("force-stop before delete: %w", err)
			}
		}
		// §5.2: running/paused→stopping→stopped (no direct live→stopped transition).
		if vm.ObservedState != "stopping" {
			if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:        vmID,
				To:          "stopping",
				Reason:      "forced_stop_for_delete",
				OperationID: 0,
			}); err != nil && !errors.Is(err, new(store.InvalidTransitionError)) {
				return vm, fmt.Errorf("stopping before delete: %w", err)
			}
		}
		vm, err = m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:           vmID,
			To:             "stopped",
			Reason:         "forced_stop_for_delete",
			OperationID:    0,
			ReleaseCompute: true,
		})
		if err != nil && !errors.Is(err, new(store.InvalidTransitionError)) {
			return vm, fmt.Errorf("stop before delete: %w", err)
		}
		if vm, err = m.st.GetVM(ctx, vmID); err != nil {
			return nil, err
		}
	}

	// failed → deleting is valid in the matrix.
	if vm.ObservedState == "failed" || vm.ObservedState == "stopped" {
		vm, err = m.st.TransitionVM(ctx, store.TransitionInput{
			VMID:             vmID,
			ExpectedRevision: expectedRevision,
			To:               "deleting",
			Reason:           "delete_requested",
			OperationID:      0,
		})
		if err != nil {
			return vm, err
		}
	}

	// R1: call Release before flipping the row to "deleted" so jail resources
	// are always freed before the VM is considered gone. Tolerate UnavailableError
	// (runtime absent on startup reconcile is normal) but fail on real errors so a
	// VM row never reads "deleted" while jail resources remain.
	if err := m.rt.Release(ctx, vmID); err != nil {
		var ue *UnavailableError
		if !errors.As(err, &ue) {
			return nil, fmt.Errorf("release vm resources: %w", err)
		}
		// UnavailableError is tolerated: an absent runtime must not wedge deletes.
	}

	vm, err = m.st.TransitionVM(ctx, store.TransitionInput{
		VMID:        vmID,
		To:          "deleted",
		Reason:      "deleted",
		OperationID: 0,
		ReleaseAll:  true,
	})
	return vm, err
}

// Reconcile cleans up state left over from a previous controller run (§5.5).
// Portable core: no real runtime exists here, so nothing can be adopted.
// Operations in flight → failed; VMs in transitional states → failed/stopped/deleted.
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
			// VMM disappeared — §5.5: mark with explicit reason; adoption is L0.
			reason := "vmm_disappeared_on_restart"
			_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:           vm.VMID,
				To:             "failed",
				Reason:         reason,
				OperationID:    0,
				ReleaseCompute: true,
			})
		case "stopping":
			// Safe to mark stopped — we're not running, so the VMM is gone.
			_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:           vm.VMID,
				To:             "stopped",
				Reason:         "controller_restart",
				OperationID:    0,
				ReleaseCompute: true,
			})
		case "deleting":
			// Complete the idempotent delete.
			_, _ = m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:        vm.VMID,
				To:          "deleted",
				Reason:      "controller_restart",
				OperationID: 0,
				ReleaseAll:  true,
			})
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
// Already-terminal VMs (failed, stopped, deleted, …) are a no-op: importer
// replays are normal and must not cause errors. Unknown VMs return nil.
func (m *Manager) NotifyVMMExit(ctx context.Context, vmID, reason string, graceful bool) error {
	vm, err := m.st.GetVM(ctx, vmID)
	if err != nil {
		// Unknown VM — no-op.
		return nil
	}

	// Terminal states: already done, nothing to do.
	switch vm.ObservedState {
	case "stopped", "failed", "deleted", "deleting":
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
