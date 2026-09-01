// ABOUTME: Batch VM creation: atomic_reservation and best_effort modes (SPEC §6.3).
// ABOUTME: stop_successful coordination stops admitted siblings when any member fails (AT-014).
package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/2389-research/observatory-v2/internal/store"
)

// BatchMemberRequest is one member spec from the API caller.
// Defaults are applied by the manager before the store is called.
type BatchMemberRequest struct {
	Name             string
	TemplateID       string
	VCPUCount        int
	MemoryMiB        int64
	RootDiskMiB      int64
	WorkspaceDiskMiB int64
	Labels           map[string]string
	// Run is an optional launch-attached run. When non-nil the member's run
	// is created in the same tx as the VM. Same validation as CreateRequest.Run.
	Run *store.RunAttachment
}

// CreateBatchRequest is the top-level batch create input.
type CreateBatchRequest struct {
	Members         []BatchMemberRequest
	ReservationMode string // "atomic_reservation" | "best_effort"
	OnFailure       string // "keep_successful" | "stop_successful"
	IdempotencyKey  *string
}

// batchLaunchMember pairs a store member result with its template and resolved
// resource values — everything the launch goroutine needs without going back to
// the store.
type batchLaunchMember struct {
	result   *store.BatchMemberResult
	tpl      Template
	vcpu     int
	memMiB   int64
	rootDisk int64
	wsDisk   int64
}

// CreateBatch validates each member, applies defaults, and calls the store to
// atomically record the batch. Admitted members are launched asynchronously.
// AT-001: runtime Availability is checked first; nothing is persisted on failure.
// AT-015: idempotent replay returns the original batch without re-running admission.
func (m *Manager) CreateBatch(ctx context.Context, req CreateBatchRequest) (*store.CreateVMBatchResult, error) {
	// AT-001: availability first.
	if err := m.rt.Availability(ctx); err != nil {
		return nil, fmt.Errorf("runtime not available: %w", err)
	}

	if len(req.Members) == 0 {
		return nil, &ErrInvalidRequest{Reason: "batch must have at least one member"}
	}
	if req.ReservationMode != "atomic_reservation" && req.ReservationMode != "best_effort" {
		return nil, &ErrInvalidRequest{Reason: "reservation_mode must be atomic_reservation or best_effort"}
	}
	if req.OnFailure == "" {
		req.OnFailure = "keep_successful" // SPEC §6.3: keep_successful by default
	}
	if req.OnFailure != "keep_successful" && req.OnFailure != "stop_successful" {
		return nil, &ErrInvalidRequest{Reason: "on_failure must be keep_successful or stop_successful"}
	}

	// Validate and resolve every member before touching the store.
	resolved := make([]store.BatchMemberInput, len(req.Members))
	for i, mr := range req.Members {
		si, err := m.resolveMember(mr)
		if err != nil {
			return nil, fmt.Errorf("member[%d]: %w", i, err)
		}
		resolved[i] = si
	}

	// Request hash: deterministic over effective (post-default) member specs.
	type memberSig struct {
		Name     string            `json:"name"`
		Tpl      string            `json:"template_id"`
		Digest   string            `json:"template_digest"`
		VCPU     int               `json:"vcpu"`
		Mem      int64             `json:"memory_mib"`
		Root     int64             `json:"root_disk_mib"`
		WS       int64             `json:"workspace_disk_mib"`
		Profile  string            `json:"network_profile"`
		PolicyID string            `json:"network_policy_id"`
		Labels   map[string]string `json:"labels"`
	}
	sigs := make([]memberSig, len(resolved))
	for i, r := range resolved {
		labels := r.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		sigs[i] = memberSig{
			Name: r.Name, Tpl: r.TemplateID, Digest: r.TemplateDigest,
			VCPU: r.VCPUCount, Mem: r.MemoryMiB, Root: r.RootDiskMiB, WS: r.WorkspaceDiskMiB,
			Profile: r.NetworkProfile, PolicyID: r.NetworkPolicyID, Labels: labels,
		}
	}
	type batchSig struct {
		Mode      string      `json:"mode"`
		OnFailure string      `json:"on_failure"`
		Members   []memberSig `json:"members"`
	}
	hashBytes, _ := json.Marshal(batchSig{
		Mode:      req.ReservationMode,
		OnFailure: req.OnFailure,
		Members:   sigs,
	})
	sum := sha256.Sum256(hashBytes)
	requestHash := hex.EncodeToString(sum[:])

	// Build store callbacks.
	var storeIn store.CreateVMBatchInput
	storeIn.Owner = m.cfg.Owner
	storeIn.IdempotencyKey = req.IdempotencyKey
	storeIn.RequestHash = requestHash
	storeIn.ReservationMode = req.ReservationMode
	storeIn.OnFailure = req.OnFailure
	storeIn.Members = resolved

	if req.ReservationMode == "atomic_reservation" {
		var totalMem, totalDisk int64
		var totalVCPU int
		for _, r := range resolved {
			totalMem += r.MemoryTotalMiB
			totalVCPU += r.VCPUCount
			totalDisk += r.RootDiskMiB + r.WorkspaceDiskMiB
		}
		storeIn.AdmitBatch = func(totals store.ReservationTotals) error {
			return m.policy.Admit(totals, totalMem, totalVCPU, totalDisk)
		}
	} else {
		storeIn.AdmitMember = func(totals store.ReservationTotals, memTotal int64, vcpu int, diskTotal int64) error {
			return m.policy.Admit(totals, memTotal, vcpu, diskTotal)
		}
	}

	result, err := m.st.CreateVMBatch(ctx, storeIn)
	if err != nil {
		return nil, err
	}

	// Replays: no launches to enqueue.
	if result.IsReplay {
		return result, nil
	}

	// Collect admitted members with launch specs.
	var launchable []batchLaunchMember
	for i, mr := range result.Members {
		if mr.VM == nil || mr.Operation == nil {
			continue // refused
		}
		if i >= len(req.Members) {
			continue
		}
		si := resolved[i]
		tpl, ok := m.cfg.Templates[req.Members[i].TemplateID]
		if !ok {
			// The validation above ensured this exists; just being defensive.
			continue
		}
		launchable = append(launchable, batchLaunchMember{
			result:   mr,
			tpl:      tpl,
			vcpu:     si.VCPUCount,
			memMiB:   si.MemoryMiB,
			rootDisk: si.RootDiskMiB,
			wsDisk:   si.WorkspaceDiskMiB,
		})
	}

	if len(launchable) == 0 {
		// All refused; batch-level op is already failed in the store.
		return result, nil
	}

	// Enqueue launch goroutines with stop_successful coordination.
	var batchOpID int64
	if result.BatchOp != nil {
		batchOpID = result.BatchOp.OperationID
	}
	coord := newBatchCoord(m, req.OnFailure, batchOpID, launchable)
	for _, lm := range launchable {
		lm := lm // capture
		// GoTracked returns false if the manager is closing; the member stays in
		// provisioning until the next Reconcile repairs it — that is exactly what
		// reconcile is for.
		m.GoTracked(func() {
			select {
			case m.sem <- struct{}{}:
			case <-m.ctx.Done():
				m.failLaunch(m.ctx, lm.result.VM.VMID, lm.result.Operation.OperationID,
					"enqueue", "manager closed before slot acquired")
				coord.memberDone(false)
				return
			}
			defer func() { <-m.sem }()
			if coord.stopWaveStarted() {
				// The stop wave already parked this member while it was queued
				// behind the semaphore; launching now would defeat the wave.
				coord.memberDone(false)
				return
			}
			ok := m.runBatchMemberLaunch(lm, coord)
			coord.memberDone(ok)
		})
	}

	return result, nil
}

// resolveMember validates one member request and applies defaults.
func (m *Manager) resolveMember(mr BatchMemberRequest) (store.BatchMemberInput, error) {
	if mr.TemplateID == "" {
		return store.BatchMemberInput{}, &ErrInvalidRequest{Reason: "template_id is required"}
	}
	tpl, ok := m.cfg.Templates[mr.TemplateID]
	if !ok {
		known := make([]string, 0, len(m.cfg.Templates))
		for id := range m.cfg.Templates {
			known = append(known, id)
		}
		return store.BatchMemberInput{}, &ErrTemplateUnknown{Requested: mr.TemplateID, KnownIDs: known}
	}
	if mr.Name == "" {
		return store.BatchMemberInput{}, &ErrInvalidRequest{Reason: "name is required"}
	}
	if len(mr.Name) > 128 {
		return store.BatchMemberInput{}, &ErrInvalidRequest{Reason: "name exceeds 128 bytes"}
	}
	for _, r := range mr.Name {
		if r < ' ' || r > '~' {
			return store.BatchMemberInput{}, &ErrInvalidRequest{Reason: "name contains non-printable characters"}
		}
	}
	vcpu := mr.VCPUCount
	if vcpu <= 0 {
		vcpu = m.cfg.VMDefaults.VCPUCount
	}
	mem := mr.MemoryMiB
	if mem <= 0 {
		mem = m.cfg.VMDefaults.MemoryMiB
	}
	root := mr.RootDiskMiB
	if root <= 0 {
		root = m.cfg.VMDefaults.RootDiskMiB
	}
	ws := mr.WorkspaceDiskMiB
	if ws <= 0 {
		ws = m.cfg.VMDefaults.WorkspaceDiskMiB
	}
	if vcpu <= 0 || mem <= 0 || root <= 0 || ws <= 0 {
		return store.BatchMemberInput{}, &ErrInvalidRequest{Reason: "resource values must be positive"}
	}
	return store.BatchMemberInput{
		Name:             mr.Name,
		VMID:             uuid.NewString(),
		TemplateID:       tpl.TemplateID,
		TemplateDigest:   tpl.Digest,
		VCPUCount:        vcpu,
		MemoryMiB:        mem,
		RootDiskMiB:      root,
		WorkspaceDiskMiB: ws,
		MemoryTotalMiB:   mem + m.cfg.Admission.ReservePerVMHostOverheadMiB,
		NetworkProfile:   m.cfg.VMDefaults.NetworkProfile,
		NetworkPolicyID:  m.cfg.VMDefaults.NetworkPolicyID,
		Labels:           mr.Labels,
		Run:              mr.Run,
	}, nil
}

// runBatchMemberLaunch runs one member's launch sequence and returns true on success.
func (m *Manager) runBatchMemberLaunch(lm batchLaunchMember, coord *batchCoord) bool {
	ctx := m.ctx
	vm := lm.result.VM
	opID := lm.result.Operation.OperationID
	bootID := uuid.NewString()

	spec := VMSpec{
		VMID:             vm.VMID,
		BootID:           bootID,
		VCPUCount:        lm.vcpu,
		MemoryMiB:        lm.memMiB,
		RootDiskMiB:      lm.rootDisk,
		WorkspaceDiskMiB: lm.wsDisk,
		NetworkProfile:   vm.NetworkProfile,
		NetworkPolicyID:  vm.NetworkPolicyID,
		TemplateID:       lm.tpl.TemplateID,
		TemplateDigest:   lm.tpl.Digest,
	}

	// From pins on both transitions keep this launch from reviving a VM the
	// stop wave (or a concurrent stop) has already moved: a refused pin means
	// someone superseded the launch, which is not a member failure — walk away
	// without firing a wave of our own.
	from := "provisioning"
	if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
		VMID:        vm.VMID,
		From:        &from,
		To:          "starting",
		Reason:      "launch",
		OperationID: opID,
		BootID:      &bootID,
	}); err != nil {
		if errors.Is(err, new(store.InvalidTransitionError)) {
			return false
		}
		m.failLaunch(ctx, vm.VMID, opID, "starting", err.Error())
		coord.stopSiblings(vm.VMID)
		return false
	}

	if err := m.rt.Launch(ctx, spec); err != nil {
		m.failLaunch(ctx, vm.VMID, opID, "launch", err.Error())
		_ = m.rt.ForceStop(ctx, vm.VMID)
		coord.stopSiblings(vm.VMID)
		return false
	}

	from = "starting"
	if _, err := m.st.TransitionVM(ctx, store.TransitionInput{
		VMID:        vm.VMID,
		From:        &from,
		To:          "running",
		Reason:      "launch_complete",
		OperationID: opID,
	}); err != nil {
		if errors.Is(err, new(store.InvalidTransitionError)) {
			return false
		}
		m.failLaunch(ctx, vm.VMID, opID, "running", err.Error())
		_ = m.rt.ForceStop(ctx, vm.VMID)
		coord.stopSiblings(vm.VMID)
		return false
	}

	// Hook: pending run → running when batch member VM reaches running.
	m.onVMRunning(ctx, vm.VMID)

	errCause := (*string)(nil)
	_, _ = m.st.UpdateOperation(ctx, store.OperationUpdate{
		OperationID:  opID,
		IfState:      "running",
		Phase:        "running",
		State:        "succeeded",
		ErrorCause:   errCause,
		ErrorMessage: errCause,
	})
	return true
}

// batchCoord tracks batch-member outcomes for stop_successful and batch-op finalization.
type batchCoord struct {
	m         *Manager
	onFailure string
	batchOpID int64
	total     int
	members   []batchLaunchMember

	mu      sync.Mutex
	stopped bool // stop-siblings already triggered

	succeeded atomic.Int64
	failed    atomic.Int64
	remaining atomic.Int64 // counts down from total; when 0 finalize the batch op
}

func newBatchCoord(m *Manager, onFailure string, batchOpID int64, members []batchLaunchMember) *batchCoord {
	c := &batchCoord{m: m, onFailure: onFailure, batchOpID: batchOpID, total: len(members), members: members}
	c.remaining.Store(int64(len(members)))
	return c
}

// stopWaveStarted reports whether the stop wave has been triggered.
func (c *batchCoord) stopWaveStarted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped
}

// stopSiblings stops every other admitted member when on_failure=stop_successful
// and a member fails (AT-014). Idempotent: only the first failure starts the wave.
// Each member gets a short read-act retry loop because its launch goroutine may
// be moving it concurrently; every transition carries a From pin, so a lost race
// shows up as a refused pin and the loop re-reads instead of clobbering.
func (c *batchCoord) stopSiblings(failedVMID string) {
	if c.onFailure != "stop_successful" {
		return
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	c.mu.Unlock()

	ctx := c.m.ctx
	grace := time.Duration(c.m.cfg.VMDefaults.StopGraceSeconds) * time.Second
	cause := "batch_stop_successful"
	msg := "sibling member failed, on_failure=stop_successful"
	failOp := func(opID int64) {
		// IfState keeps an already-succeeded launch op honest: the wave stops
		// the VM but must not rewrite evidence of a launch that did succeed.
		_, _ = c.m.st.UpdateOperation(ctx, store.OperationUpdate{
			OperationID:  opID,
			IfState:      "running",
			Phase:        "stopped",
			State:        "failed",
			ErrorCause:   &cause,
			ErrorMessage: &msg,
		})
	}

	for _, lm := range c.members {
		if lm.result.VM == nil || lm.result.VM.VMID == failedVMID {
			continue
		}
		vmID := lm.result.VM.VMID
		opID := lm.result.Operation.OperationID
		for attempt := 0; attempt < 3; attempt++ {
			vm, err := c.m.st.GetVM(ctx, vmID)
			if err != nil {
				break
			}
			state := vm.ObservedState
			if state == "stopped" || state == "failed" || state == "deleting" || state == "deleted" {
				break // already down; nothing to stop
			}
			if state == "stopping" {
				// A synchronous stop is mid-flight and will land the VM in
				// stopped; mark the launch op and leave the VM to it.
				failOp(opID)
				break
			}
			from := state
			if _, err := c.m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:        vmID,
				From:        &from,
				To:          "stopping",
				Reason:      cause,
				OperationID: opID,
			}); err != nil {
				continue // state moved under us; re-read
			}
			// A member still in provisioning was queued behind the semaphore:
			// no VMM exists yet, so there is nothing for the runtime to stop.
			if state != "provisioning" {
				_, _ = c.m.rt.Stop(ctx, vmID, grace)
			}
			fromStopping := "stopping"
			if _, err := c.m.st.TransitionVM(ctx, store.TransitionInput{
				VMID:           vmID,
				From:           &fromStopping,
				To:             "stopped",
				Reason:         cause,
				OperationID:    opID,
				ReleaseCompute: true,
			}); err != nil {
				continue
			}
			failOp(opID)
			break
		}
	}
}

// memberDone is called by each batch member goroutine on exit.
// When the last member finishes, the batch-level operation is finalized.
func (c *batchCoord) memberDone(ok bool) {
	if ok {
		c.succeeded.Add(1)
	} else {
		c.failed.Add(1)
	}
	if c.remaining.Add(-1) != 0 {
		return
	}
	// Last member done — finalize the batch op.
	if c.batchOpID == 0 {
		return
	}
	ctx := c.m.ctx
	succeeded := c.succeeded.Load()
	failed := c.failed.Load()
	switch {
	case c.onFailure == "stop_successful" && failed > 0:
		// The contract was "all or stop": any failure fails the batch even
		// though some members launched before the wave stopped them. The
		// per-member operations carry each member's own story.
		cause := "member_failed"
		msg := fmt.Sprintf("batch stopped: %d of %d members did not complete (on_failure=stop_successful)", failed, c.total)
		_, _ = c.m.st.UpdateOperation(ctx, store.OperationUpdate{
			OperationID:  c.batchOpID,
			IfState:      "running",
			Phase:        "complete",
			State:        "failed",
			ErrorCause:   &cause,
			ErrorMessage: &msg,
		})
	case succeeded > 0:
		_, _ = c.m.st.UpdateOperation(ctx, store.OperationUpdate{
			OperationID: c.batchOpID,
			IfState:     "running",
			Phase:       "complete",
			State:       "succeeded",
		})
	default:
		cause := "all_members_failed"
		msg := "every admitted batch member failed to launch"
		_, _ = c.m.st.UpdateOperation(ctx, store.OperationUpdate{
			OperationID:  c.batchOpID,
			IfState:      "running",
			Phase:        "complete",
			State:        "failed",
			ErrorCause:   &cause,
			ErrorMessage: &msg,
		})
	}
}
