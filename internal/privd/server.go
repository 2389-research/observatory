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
	// AbortStartVM undoes a StartVM that failed partway. StartVM creates the
	// jail tree and copies gigabytes into it before it can fail, and it can
	// also leave a live firecracker whose pid it never got to report, so the
	// undo owns both: kill what is running, then remove the tree. It does not
	// touch the network allocation — allocate_network owns that half and
	// release_network reclaims it.
	AbortStartVM(VMEntry) error
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

	if holder, err := s.subnetHolder(r.CIDR); err != nil {
		return errResp("internal", err.Error())
	} else if holder != "" {
		return errResp("invalid_state", fmt.Sprintf("subnet %s is already allocated to vm %s", r.CIDR, holder))
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

// minGuestCID is the lowest vsock CID a guest may use. The spec reserves 0
// (hypervisor), 1 (local) and 2 (host).
const minGuestCID = 3

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

	// CID range check. The vsock spec reserves 0-2 and firecracker refuses a
	// guest_cid below 3, so a request carrying one could never have booted. It is
	// checked here because identityHolder treats a zero CID in the ledger as an
	// identity a released VM gave back: with cid_base set to 0 -- which config
	// accepts -- slot 0 would produce a live VM whose CID reads as released, and
	// the second claim on it would be granted. Refusing the request keeps the two
	// meanings of zero apart.
	if r.CID < minGuestCID {
		return errResp("bad_request", fmt.Sprintf("cid %d is reserved by the vsock spec; a guest cid starts at %d", r.CID, minGuestCID))
	}

	// Every staged file must be one privd knows. The name is joined onto the
	// stage dir to read the file and onto the jail root to write it, so a name
	// that is not a bare filename reaches two different places -- and privd is
	// root where its caller is not. Refused here, before the backend creates a
	// jail tree or opens an fd on the caller's behalf.
	//
	// The offending name is echoed back truncated: it is the caller's own bytes
	// and the caller needs to see which entry was refused, but an unbounded echo
	// hands a 64 KiB request a 64 KiB response.
	for i, f := range r.Files {
		if !ValidStagedName(f.Name) {
			return errResp("bad_request", fmt.Sprintf("files[%d]: %q is not a staged file name", i, truncateName(f.Name)))
		}
	}

	// stage_dir does not choose the directory privd reads from. The backend
	// derives <StageRoot>/<vm_id> and opens it against the stage root, so
	// containment is structural: there is no caller-supplied path left to
	// resolve, and no EvalSymlinks race to lose.
	//
	// The field stays on the wire and stays checked for one thing it can still
	// disagree about: which VM it names. An install whose adapter and privd were
	// given different stage roots is caught by the backend's open, which names
	// the directory privd looked in; an adapter that staged under a different id
	// is caught here, before a jail tree exists.
	if filepath.Base(filepath.Clean(r.StageDir)) != r.VMID {
		return errResp("bad_request", "stage_dir does not name this vm's stage directory")
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

	if holder, what, err := s.identityHolder(r.UID, r.CID); err != nil {
		return errResp("internal", err.Error())
	} else if holder != "" {
		return errResp("invalid_state", fmt.Sprintf("%s is already held by vm %s", what, holder))
	}

	// Populate entry fields from request before calling backend.
	entry.UID = r.UID
	entry.GID = r.GID
	entry.CID = r.CID

	startResp, err := s.cfg.Ops.StartVM(&entry, r)
	if err != nil {
		// StartVM fails after it has already built <JailBase>/firecracker/<id>
		// and copied the boot artifacts into it, and it can fail with
		// firecracker already running and its pid reported to no one.
		//
		// Of those two survivors, the tree is the one another verb could still
		// reach: allocate_network's entry is in the ledger with PID 0, so
		// handleReleaseVM's alive gate does not apply to it and Ops.ReleaseVM
		// removes the tree unconditionally. The live VMM is what nothing else
		// can reach. Its pid is recorded nowhere — the ledger write below never
		// runs, and the jailer's manifest is written only after start_vm
		// returns — so no verb can name it and no scan will find it. That alone
		// is why this rollback exists. Roll back best-effort and surface the
		// original cause unchanged — the same discipline handleAllocateNetwork
		// uses above.
		//
		// Removing the tree here cannot destroy a previous boot's live chroot.
		// A VM whose start succeeded has a non-zero entry.PID and is refused
		// above with invalid_state before the backend is reached; PID returns to
		// 0 only through handleReleaseVM, which clears it after Ops.ReleaseVM
		// removed the tree. So any tree standing when StartVM runs is the debris
		// of a start that already failed, never a running VM's chroot.
		if abortErr := s.cfg.Ops.AbortStartVM(entry); abortErr != nil {
			s.log.Printf("start_vm %s failed and the rollback did not finish: %v; "+
				"jail tree and any live vmm may survive under jail base", r.VMID, abortErr)
		}
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
	alive, err := entryAlive(entry)
	if err != nil {
		return errResp("invalid_state", err.Error())
	}
	if alive {
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
	entry.BootID = ""
	entry.PIDNamespace = ""
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

// Host identities are claimed per daemon and spent per host. A vmobsd derives a
// VM's jail uid and guest CID from a slot it allocated by scanning its own state
// directory, and its subnet from an allocator that counts only its own VMs
// (internal/jailer/manifest.go, internal/jailer/launch.go). Two vmobsd processes
// on one host therefore hand out the same slot 0, the same uid, the same CID and
// the same subnet, and neither can see the other.
//
// privd can. It is the single process every claim passes through, and its ledger
// already records which VM holds which identity. The two functions below turn
// that record into a refusal, so the second claim fails here, by name, instead of
// succeeding and surfacing several stages later as a VM that would not boot.
//
// That rests on there being one privd per host, which the systemd unit gives us
// and the binary does not: a second privd unlinks the first one's socket and
// binds its own (kata c3f2). Two privds is two ledgers, or one ledger behind two
// mutexes, and either way a claim can be granted twice.
//
// Both are called with s.mu held.

// subnetHolder returns the vm_id already allocated cidr, or "" when it is free.
//
// An entry whose network was released carries an empty CIDR and cannot match
// here, because handleAllocateNetwork refuses an empty cidr before reaching this
// -- the same rule that keeps a released uid or CID from matching below.
//
// The scan includes the requesting VM and does not need to exclude it: the
// caller reaches this only after ledger.get returned ErrNotExist, so the
// requesting VM has no entry here to match.
func (s *Server) subnetHolder(cidr string) (string, error) {
	entries, err := s.ledger.all()
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.NetCIDR == cidr {
			return e.VMID, nil
		}
	}
	return "", nil
}

// identityHolder returns the vm_id already running under uid or on cid, and
// which of the two it was, or "" when both are free.
//
// release_vm zeroes a VM's uid and CID together, so a zero in either field is an
// entry that has given its identities back and the slot allocator is right to
// hand them out again. That makes this a lease rather than a tombstone: only a
// VM that still holds an identity can refuse a claim on it. Zero needs no guard
// of its own here -- handleStartVM refuses a uid outside [UIDMin, UIDMax) and a
// CID below 3, so no valid request can ask for the value a released entry holds.
//
// The scan includes the requesting VM and does not need to exclude it. Its own
// entry carries a uid and a CID only once handleStartVM has written the ledger,
// which happens after StartVM has returned a pid -- and an entry with a pid is
// refused by the already-started guard above, before reaching here. So the only
// entry a VM can meet for itself is one whose identities are zero.
func (s *Server) identityHolder(uid int, cid uint32) (string, string, error) {
	entries, err := s.ledger.all()
	if err != nil {
		return "", "", err
	}
	for _, e := range entries {
		if e.UID == uid {
			return e.VMID, fmt.Sprintf("jail uid %d", uid), nil
		}
		if e.CID == cid {
			return e.VMID, fmt.Sprintf("guest cid %d", cid), nil
		}
	}
	return "", "", nil
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
