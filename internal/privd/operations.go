// ABOUTME: Durable mutation receipts preserve identity across lost replies and daemon restart.
// ABOUTME: Unfinished work retains host ownership until its outcome can be proved.
package privd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/2389-research/observatory/internal/durable"
	"github.com/2389-research/observatory/internal/network"
)

// OperationOutcome is a durable mutation result. Unknown and pending never authorize cleanup.
type OperationOutcome struct {
	OpID     string    `json:"op_id"`
	State    string    `json:"state"` // pending | succeeded | failed | unknown | not_found
	Response *Response `json:"response,omitempty"`
}

type operationRecord struct {
	Request  Request   `json:"request"`
	State    string    `json:"state"`
	Response *Response `json:"response,omitempty"`
}

type operationStore struct {
	mu      sync.Mutex
	records map[string]operationRecord
	err     error
}

func (s *Server) saveOperation(r operationRecord) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	dir := filepath.Join(s.cfg.LedgerDir, ".operations")
	if err := durable.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return durable.WriteFile(filepath.Join(dir, r.Request.OpID+".json"), 0o600, data)
}

func (s *Server) loadOperations() {
	s.operations.records = make(map[string]operationRecord)
	dir := filepath.Join(s.cfg.LedgerDir, ".operations")
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		s.operations.err = err
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		id := name[:len(name)-5]
		if !ValidVMID(id) {
			s.operations.err = fmt.Errorf("invalid operation record")
			return
		}
		data, err := readOwnershipFile(filepath.Join(dir, name))
		if err != nil {
			s.operations.err = err
			return
		}
		var record operationRecord
		if err := json.Unmarshal(data, &record); err != nil || record.Request.OpID != id {
			s.operations.err = fmt.Errorf("invalid operation record")
			return
		}
		switch record.State {
		case "pending", "unknown":
			record.State = "unknown"
			record = s.recoverCommittedOperation(record)
			if err := s.saveOperation(record); err != nil {
				s.operations.err = err
				return
			}
		case "succeeded", "failed":
			if record.Response == nil {
				s.operations.err = fmt.Errorf("missing operation response")
				return
			}
		default:
			s.operations.err = fmt.Errorf("invalid operation state")
			return
		}
		s.operations.records[id] = record
	}
}

func (s *Server) queryOperation(id string) OperationOutcome {
	if s.mu.TryLock() {
		s.operations.mu.Lock()
		if record, ok := s.operations.records[id]; ok && record.State == "unknown" && s.operations.err == nil {
			recovered := s.recoverCommittedOperation(record)
			if recovered.State == "succeeded" {
				if err := s.saveOperation(recovered); err != nil {
					s.operations.err = err
				} else {
					s.operations.records[id] = recovered
				}
			}
		}
		s.operations.mu.Unlock()
		s.mu.Unlock()
	}

	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	if s.operations.err != nil {
		return OperationOutcome{OpID: id, State: "unknown"}
	}
	r, ok := s.operations.records[id]
	if !ok {
		return OperationOutcome{OpID: id, State: "not_found"}
	}
	return OperationOutcome{OpID: id, State: r.State, Response: r.Response}
}

func (s *Server) dispatchMutation(req Request) Response {
	if !ValidVMID(req.OpID) {
		return errResp("bad_request", "valid op_id required for mutations")
	}
	s.operations.mu.Lock()
	if s.operations.err != nil {
		s.operations.mu.Unlock()
		return errResp("outcome_unknown", "operation journal unavailable; preserve host ownership")
	}
	if old, ok := s.operations.records[req.OpID]; ok {
		s.operations.mu.Unlock()
		if old.Request.Verb != req.Verb || !bytes.Equal(old.Request.Payload, req.Payload) {
			return errResp("invalid_state", "op_id belongs to a different request")
		}
		if old.Response != nil {
			return *old.Response
		}
		return errResp("outcome_"+old.State, "query operation before reclaiming resources")
	}
	// Keep the existing global execution mutex. An interrupted backend may hold
	// any global identity, so restart uncertainty stops new host mutations.
	for _, old := range s.operations.records {
		if old.State == "unknown" && (req.Verb == "allocate_network" || req.Verb == "start_vm" || operationVMID(old.Request) == operationVMID(req)) {
			s.operations.mu.Unlock()
			return errResp("outcome_unknown", fmt.Sprintf("interrupted operation %s owns unresolved host resources; query that operation and verify host cleanup before repairing its root-owned receipt", old.Request.OpID))
		}
	}
	record := operationRecord{Request: req, State: "pending"}
	if err := s.saveOperation(record); err != nil {
		s.operations.err = err
		s.operations.mu.Unlock()
		return errResp("outcome_unknown", "cannot durably record mutation; ownership retained")
	}
	s.operations.records[req.OpID] = record
	s.operations.mu.Unlock()
	budget := s.cfg.ExecutionTimeout
	if budget <= 0 {
		budget = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	ctx = WithOperationID(ctx, req.OpID)
	// Serialize through receipt publication, not merely through the host effect.
	// A queued claim must see any uncertainty produced by its predecessor.
	s.mu.Lock()
	defer s.mu.Unlock()
	var response Response
	s.operations.mu.Lock()
	if s.operations.err != nil {
		response = errResp("invalid_state", "mutation not executed: operation journal unavailable")
	}
	for _, old := range s.operations.records {
		if old.State == "unknown" && (req.Verb == "start_vm" || req.Verb == "allocate_network" || operationVMID(old.Request) == operationVMID(req)) {
			response = errResp("invalid_state", fmt.Sprintf("mutation not executed: operation %s retains unresolved ownership", old.Request.OpID))
			break
		}
	}
	s.operations.mu.Unlock()
	if response.Cause == "" {
		response = s.execute(ctx, req)
	}
	record.State = "failed"
	if response.OK {
		record.State = "succeeded"
	}
	// A failed durability barrier or rollback cannot prove that effects are gone.
	if response.Cause == "internal" || response.Cause == "outcome_unknown" {
		record.State = "unknown"
	} else {
		record.Response = &response
	}
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	if err := s.saveOperation(record); err != nil {
		s.operations.err = err
		return errResp("outcome_unknown", "mutation result could not be persisted; ownership retained")
	}
	s.operations.records[req.OpID] = record
	if record.State == "unknown" {
		return errResp("outcome_unknown", response.Message+"; host mutation outcome requires recovery; ownership retained")
	}
	return response
}

func (s *Server) networkLeases() Response {
	if !s.mu.TryLock() {
		return errResp("outcome_pending", "host mutation is in progress; retry lease inventory")
	}
	defer s.mu.Unlock()
	s.operations.mu.Lock()
	defer s.operations.mu.Unlock()
	if s.operations.err != nil {
		return errResp("outcome_unknown", "operation journal unavailable")
	}
	for _, record := range s.operations.records {
		if record.State == "pending" {
			return errResp("outcome_pending", "host mutation is pending; retry lease inventory")
		}
		if record.State == "unknown" {
			return errResp("outcome_unknown", "interrupted mutation retains unknown claims")
		}
	}
	entries, err := s.ledger.all()
	if err != nil {
		return errResp("internal", err.Error())
	}
	leases := make(map[string]string)
	for _, entry := range entries {
		if entry.NetCIDR != "" {
			leases[entry.VMID] = entry.NetCIDR
		}
	}
	raw, err := json.Marshal(leases)
	if err != nil || len(raw) > MaxMsgBytes/2 {
		return errResp("internal", "network lease inventory exceeds response bound")
	}
	return okResp(raw)
}

func operationVMID(req Request) string {
	var payload struct {
		VMID string `json:"vm_id"`
	}
	if json.Unmarshal(req.Payload, &payload) != nil {
		return ""
	}
	return payload.VMID
}

// recoverCommittedOperation uses only durable daemon-owned ledger witnesses.
// Caller holds the execution mutex, or is still in single-threaded startup.
func (s *Server) recoverCommittedOperation(record operationRecord) operationRecord {
	vmID := operationVMID(record.Request)
	if !ValidVMID(vmID) {
		return record
	}
	vm, err := s.ledger.get(vmID)
	if err != nil {
		return record
	}
	var response Response
	switch record.Request.Verb {
	case "start_vm":
		if vm.StartOpID != record.Request.OpID || vm.PID <= 0 {
			return record
		}
		payload, _ := json.Marshal(StartVMResp{PID: vm.PID, StartTime: vm.StartTime})
		response = okResp(payload)
	case "allocate_network":
		if vm.NetworkOpID != record.Request.OpID || vm.NetCIDR == "" || !vm.NetworkComplete || !network.IsHostNFLogGroup(vm.NetworkHostNFLogGroup) {
			return record
		}
		response = okResp(nil)
	default:
		return record
	}
	record.State, record.Response = "succeeded", &response
	return record
}
