// ABOUTME: privd server core: peer-cred auth, verb dispatch, and resource ledger management.
// ABOUTME: One goroutine per connection; ledger writes serialised by a single mutex.
package privd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// backendErrResp converts a backend error to a Response.
// If err is a *BackendError, its Cause is used; otherwise "exec_failed" is the cause.
func backendErrResp(err error) Response {
	var be *BackendError
	if errors.As(err, &be) {
		return errResp(be.Cause, be.Message)
	}
	return errResp("exec_failed", err.Error())
}

// OpsBackend is the interface the server calls after validating a request.
// The real implementation (wired in Task 3/4) requires root; linux tests use a recording backend.
type OpsBackend interface {
	AllocateNetwork(VMEntry, AllocateNetworkReq) error
	ReleaseNetwork(VMEntry) error
	StartVM(*VMEntry, StartVMReq) (StartVMResp, error)
	SignalVM(VMEntry, string) error
	ReleaseVM(VMEntry) error
}

// ServerCfg holds the static configuration for a Server.
type ServerCfg struct {
	AllowedUID int    // only this UID's connections are served
	LedgerDir  string // directory for per-VM JSON ledger files
	StageRoot  string // approved root for VM stage directories
	JailBase   string // root for jailer workdirs (not validated here; passed to Ops)
	UIDMin     int    // start_vm: UID must be in [UIDMin, UIDMax)
	UIDMax     int    // start_vm: UID must be in [UIDMin, UIDMax)
	Ops        OpsBackend
	// Log overrides the default logger (os.Stderr). Useful in tests to redirect to t.Logf.
	Log *log.Logger
}

// Server is the privd root daemon server. Create with NewServer; run with Serve.
type Server struct {
	cfg    ServerCfg
	mu     sync.Mutex
	ledger *ledger
	log    *log.Logger
}

// NewServer creates a new Server. It loads any pre-existing ledger entries from LedgerDir.
func NewServer(cfg ServerCfg) *Server {
	logger := cfg.Log
	if logger == nil {
		logger = log.New(os.Stderr, "privd: ", log.LstdFlags)
	}
	s := &Server{
		cfg:    cfg,
		ledger: newLedger(cfg.LedgerDir),
		log:    logger,
	}
	return s
}

// Serve accepts connections on ln until ctx is cancelled. Returns nil on context cancellation.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// handleConn processes a single connection: peer auth, decode, dispatch, respond.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	// Peer UID check — linux only; on other platforms peerUID returns -1.
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		s.log.Printf("non-unix connection rejected")
		return
	}
	uid, err := peerUID(uc)
	if err != nil {
		s.log.Printf("peercred error: %v", err)
		return
	}
	if uid != s.cfg.AllowedUID {
		s.log.Printf("rejected connection from uid %d (allowed: %d)", uid, s.cfg.AllowedUID)
		// Close without response — per spec.
		return
	}

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	var req Request
	if err := ReadMsg(conn, &req); err != nil {
		// io.EOF on the first byte means the client closed after sending its request
		// on a previous connection — clean disconnect, not an error worth logging.
		if errors.Is(err, io.EOF) {
			return
		}
		s.log.Printf("read request: %v", err)
		return
	}

	resp := s.dispatch(req)
	if err := WriteMsg(conn, resp); err != nil {
		s.log.Printf("write response: %v", err)
	}
}

// dispatch validates the envelope and routes to the appropriate handler.
func (s *Server) dispatch(req Request) Response {
	if req.V != ProtoVersion {
		return errResp("bad_request", fmt.Sprintf("unsupported protocol version %d", req.V))
	}
	switch req.Verb {
	case "allocate_network":
		return s.handleAllocateNetwork(req.Payload)
	case "release_network":
		return s.handleReleaseNetwork(req.Payload)
	case "start_vm":
		return s.handleStartVM(req.Payload)
	case "signal_vm":
		return s.handleSignalVM(req.Payload)
	case "release_vm":
		return s.handleReleaseVM(req.Payload)
	default:
		return errResp("bad_request", fmt.Sprintf("unknown verb %q", req.Verb))
	}
}

func (s *Server) handleAllocateNetwork(raw json.RawMessage) Response {
	var r AllocateNetworkReq
	if err := json.Unmarshal(raw, &r); err != nil {
		return errResp("bad_request", "invalid payload")
	}
	if !ValidVMID(r.VMID) {
		return errResp("bad_request", "invalid vm_id")
	}
	if r.CIDR == "" {
		return errResp("bad_request", "cidr required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.ledger.get(r.VMID)
	if err == nil {
		// Already in ledger.
		if existing.NetCIDR == r.CIDR {
			// Idempotent: same CIDR, return OK without calling backend again.
			return okResp(nil)
		}
		return errResp("invalid_state", "vm already has a different network allocation")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errResp("internal", "ledger read failed")
	}

	entry := VMEntry{
		VMID:          r.VMID,
		NetCIDR:       r.CIDR,
		CreatedAtUnix: time.Now().Unix(),
	}
	if err := s.cfg.Ops.AllocateNetwork(entry, r); err != nil {
		// Setup can fail partway through (e.g. the veth step), leaving a netns
		// or tap on the host with no ledger entry to track it — an orphan that
		// release_network could never find. Roll back best-effort (mirrors the
		// jailer's launch-rollback discipline) and surface the original cause
		// unchanged; the ledger write below never runs, so no entry is recorded.
		_ = s.cfg.Ops.ReleaseNetwork(entry)
		return errResp("exec_failed", err.Error())
	}
	if err := s.ledger.put(entry); err != nil {
		return errResp("internal", "ledger write failed")
	}
	return okResp(nil)
}

func (s *Server) handleReleaseNetwork(raw json.RawMessage) Response {
	var r ReleaseNetworkReq
	if err := json.Unmarshal(raw, &r); err != nil {
		return errResp("bad_request", "invalid payload")
	}
	if !ValidVMID(r.VMID) {
		return errResp("bad_request", "invalid vm_id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.ledger.get(r.VMID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errResp("not_found", "vm not in ledger")
		}
		return errResp("internal", "ledger read failed")
	}
	if err := s.cfg.Ops.ReleaseNetwork(entry); err != nil {
		return errResp("exec_failed", err.Error())
	}
	// Clear the network half. Whichever release empties the last half deletes the file.
	entry.NetCIDR = ""
	if entry.PID == 0 {
		// VM half is also gone — delete the entry file.
		if err := s.ledger.delete(r.VMID); err != nil {
			return errResp("internal", "ledger delete failed")
		}
	} else {
		// VM half still active — write the partial entry back.
		if err := s.ledger.put(entry); err != nil {
			return errResp("internal", "ledger write failed")
		}
	}
	return okResp(nil)
}

func (s *Server) handleStartVM(raw json.RawMessage) Response {
	var r StartVMReq
	if err := json.Unmarshal(raw, &r); err != nil {
		return errResp("bad_request", "invalid payload")
	}
	if !ValidVMID(r.VMID) {
		return errResp("bad_request", "invalid vm_id")
	}

	// UID range check.
	if r.UID < s.cfg.UIDMin || r.UID >= s.cfg.UIDMax {
		return errResp("bad_request", fmt.Sprintf("uid %d outside allowed range [%d, %d)", r.UID, s.cfg.UIDMin, s.cfg.UIDMax))
	}

	// StageDir must resolve under StageRoot.
	// Both sides get EvalSymlinks so a symlink StageRoot (e.g. /var/vmobs/stage →
	// /mnt/storage/stage) doesn't produce a false containment failure.
	resolved, err := filepath.EvalSymlinks(r.StageDir)
	if err != nil {
		return errResp("bad_request", fmt.Sprintf("stage_dir resolve: %v", err))
	}
	resolvedRoot, err := filepath.EvalSymlinks(s.cfg.StageRoot)
	if err != nil {
		return errResp("internal", "stage root resolve failed")
	}
	rootPrefix := filepath.Clean(resolvedRoot) + string(filepath.Separator)
	resolvedClean := filepath.Clean(resolved) + string(filepath.Separator)
	if len(resolvedClean) <= len(rootPrefix) || resolvedClean[:len(rootPrefix)] != rootPrefix {
		return errResp("bad_request", "stage_dir not under stage root")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.ledger.get(r.VMID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errResp("bad_request", "vm has no network allocation")
		}
		return errResp("internal", "ledger read failed")
	}

	// Already started check.
	if entry.PID != 0 {
		return errResp("invalid_state", "vm already started")
	}

	// Populate entry fields from request before calling backend.
	entry.UID = r.UID
	entry.GID = r.GID
	entry.CID = r.CID

	startResp, err := s.cfg.Ops.StartVM(&entry, r)
	if err != nil {
		return backendErrResp(err)
	}

	// Update entry with process identity.
	entry.PID = startResp.PID
	entry.StartTime = startResp.StartTime

	if err := s.ledger.put(entry); err != nil {
		return errResp("internal", "ledger write failed")
	}

	payload, err := json.Marshal(startResp)
	if err != nil {
		return errResp("internal", "response encode failed")
	}
	return okResp(json.RawMessage(payload))
}

func (s *Server) handleSignalVM(raw json.RawMessage) Response {
	var r SignalVMReq
	if err := json.Unmarshal(raw, &r); err != nil {
		return errResp("bad_request", "invalid payload")
	}
	if !ValidVMID(r.VMID) {
		return errResp("bad_request", "invalid vm_id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.ledger.get(r.VMID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errResp("not_found", "vm not in ledger")
		}
		return errResp("internal", "ledger read failed")
	}

	if err := s.cfg.Ops.SignalVM(entry, r.Kind); err != nil {
		return backendErrResp(err)
	}
	return okResp(nil)
}

func (s *Server) handleReleaseVM(raw json.RawMessage) Response {
	var r ReleaseVMReq
	if err := json.Unmarshal(raw, &r); err != nil {
		return errResp("bad_request", "invalid payload")
	}
	if !ValidVMID(r.VMID) {
		return errResp("bad_request", "invalid vm_id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.ledger.get(r.VMID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errResp("not_found", "vm not in ledger")
		}
		return errResp("internal", "ledger read failed")
	}

	// If the ledger says the VM has a PID and the process is still alive with the
	// same identity, the caller must signal first.
	if entry.PID != 0 && entry.StartTime != "" && PIDAlive(entry.PID, entry.StartTime) {
		return errResp("invalid_state", "vm process is still alive; signal first")
	}

	if err := s.cfg.Ops.ReleaseVM(entry); err != nil {
		return backendErrResp(err)
	}
	// Clear the VM half only. The network half (NetCIDR) is released separately via
	// release_network, so the manager can restart the VM without losing the netns.
	entry.UID = 0
	entry.GID = 0
	entry.CID = 0
	entry.PID = 0
	entry.StartTime = ""
	if entry.NetCIDR != "" {
		// Network half still allocated — write the partial entry back.
		if err := s.ledger.put(entry); err != nil {
			return errResp("internal", "ledger write failed")
		}
	} else {
		// Both halves now empty — remove the entry file.
		if err := s.ledger.delete(r.VMID); err != nil {
			return errResp("internal", "ledger delete failed")
		}
	}
	return okResp(nil)
}

// peerUID is defined in peer_linux.go (linux) and peer_other.go (other platforms).

// okResp builds a successful Response, optionally with a JSON payload.
func okResp(payload json.RawMessage) Response {
	return Response{OK: true, Payload: payload}
}

// errResp builds a failed Response with a typed cause and message.
func errResp(cause, message string) Response {
	return Response{OK: false, Cause: cause, Message: message}
}
