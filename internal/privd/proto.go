// ABOUTME: Wire protocol types and framing for the privd privilege daemon.
// ABOUTME: 4-byte big-endian length prefix + JSON body; max 64 KiB; one request per connection.
package privd

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// Protocol constants.
const (
	// ProtoVersion is the current envelope version field value.
	ProtoVersion = 1
	// MaxMsgBytes is the maximum wire size (length prefix + body) in either direction.
	MaxMsgBytes = 64 * 1024
)

// vmIDRe is the compiled validation regex for VM identifiers.
// Rule: starts with [a-z0-9], followed by 0–62 chars from [a-z0-9-]; total 1–63 chars.
var vmIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidVMID reports whether id satisfies the VM-ID format required by privd.
// Same class enforced by the root helper: ^[a-z0-9][a-z0-9-]{0,62}$
func ValidVMID(id string) bool {
	return vmIDRe.MatchString(id)
}

// StagedFileNames is every file a launch may stage into a VM's jail, in the
// order a launch copies them. It is the allowlist ValidStagedName enforces and
// the list the jailer builds its request from, so the two cannot drift: privd
// refusing a name the controller sends would fail every launch, and privd
// accepting one the controller never sends is the hole this list closes.
var StagedFileNames = []string{
	"vmlinux",
	"rootfs.ext4",
	"config.ext4",
	"workspace.ext4",
	"fc-config.json",
}

// ValidStagedName reports whether name is one of the files a launch stages.
//
// The name is not a path and privd must not treat it as one. StartVM joins it
// onto two different bases -- the caller's stage dir when the file is opened and
// digest-verified, and the jail root when it is copied -- and those bases sit at
// different depths, so a name carrying ".." can resolve inside the stage root on
// the read and outside the jail on the write. privd runs as root and its one
// permitted caller does not; SPEC 3.3 makes validating path roots privd's job.
//
// An allowlist rather than a hunt for hostile syntax, because the set of files a
// launch stages is closed and privd knows all of it. A predicate that cleaned
// the name first and compared after would accept "./vmlinux" and
// "vmlinux/../vmlinux" -- names no launch sends -- and would then rest on
// filepath.Clean agreeing with the kernel about every input, which is the
// argument this avoids having.
func ValidStagedName(name string) bool {
	for _, allowed := range StagedFileNames {
		if name == allowed {
			return true
		}
	}
	return false
}

// Request is the request envelope sent to privd.
type Request struct {
	V       int             `json:"v"`
	Verb    string          `json:"verb"`
	OpID    string          `json:"op_id"` // required durable identity for mutations; omitted for read-only queries
	Payload json.RawMessage `json:"payload"`
}

// Response is the response envelope returned by privd.
type Response struct {
	OK      bool            `json:"ok"`
	Cause   string          `json:"cause,omitempty"`   // typed: bad_request | not_owner | invalid_state | digest_mismatch | exec_failed | not_found | internal
	Message string          `json:"message,omitempty"` // safe detail; never secrets, never raw host paths outside approved roots
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Verb payload types.

// AllocateNetworkReq requests a per-VM network namespace and TAP device.
type AllocateNetworkReq struct {
	VMID        string `json:"vm_id"`
	CIDR        string `json:"cidr"` // /30, host side .1, guest side .2
	Profile     string `json:"profile"`
	PolicyID    string `json:"policy_id"`
	GuestBootID string `json:"guest_boot_id"`
}

// ReleaseNetworkReq tears down the network resources for a VM.
type ReleaseNetworkReq struct {
	VMID string `json:"vm_id"`
}

// StagedFile is a file to be copied into a VM's jail directory.
// privd verifies the SHA-256 against the opened fd before copying.
type StagedFile struct {
	Name   string `json:"name"`   // basename only: vmlinux | rootfs.ext4 | config.ext4 | workspace.ext4 | fc-config.json
	SHA256 string `json:"sha256"` // hex; privd verifies on the opened fd before copying
}

// StartVMReq requests jailer launch of a Firecracker VM.
type StartVMReq struct {
	VMID     string       `json:"vm_id"`
	UID      int          `json:"uid"`
	GID      int          `json:"gid"`
	CID      uint32       `json:"cid"`
	StageDir string       `json:"stage_dir"` // must resolve under the approved stage root
	Files    []StagedFile `json:"files"`
}

// StartVMResp carries the PID and start-time tick of the launched Firecracker process.
type StartVMResp struct {
	PID       int    `json:"pid"`
	StartTime string `json:"starttime_ticks"` // decimal string: /proc/<pid>/stat field 22
}

// SignalVMReq sends a signal to a running VM process.
type SignalVMReq struct {
	VMID string `json:"vm_id"`
	Kind string `json:"kind"` // "term" | "kill"
}

// ReleaseVMReq removes the VM's jail directory and cleans up resources.
type ReleaseVMReq struct {
	VMID string `json:"vm_id"`
}

// RemoteError is returned when privd responds with ok=false.
type RemoteError struct {
	Cause   string
	Message string
}

func (e *RemoteError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("privd: %s: %s", e.Cause, e.Message)
	}
	return fmt.Sprintf("privd: %s", e.Cause)
}

// WriteMsg encodes v as JSON and writes it with a 4-byte big-endian length prefix.
// Returns an error if the encoded body exceeds MaxMsgBytes.
func WriteMsg(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("privd: marshal message: %w", err)
	}
	if len(body) > MaxMsgBytes {
		return fmt.Errorf("privd: message too large: %d bytes (max %d)", len(body), MaxMsgBytes)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	if _, err := w.Write(prefix[:]); err != nil {
		return fmt.Errorf("privd: write length prefix: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("privd: write body: %w", err)
	}
	return nil
}

// ReadMsg reads a length-prefixed JSON message from r and decodes it into dst.
// Rejects oversized length prefixes BEFORE allocating the body buffer.
func ReadMsg(r io.Reader, dst any) error {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return fmt.Errorf("privd: read length prefix: %w", err)
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n > MaxMsgBytes {
		return fmt.Errorf("privd: message too large: %d bytes (max %d)", n, MaxMsgBytes)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return fmt.Errorf("privd: read body: %w", err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("privd: decode message: %w", err)
	}
	return nil
}

// truncateName bounds a caller-supplied name before it is echoed into a
// response message. Long enough to recognise the entry that was refused, short
// enough that a maximal request cannot buy a maximal reply.
func truncateName(name string) string {
	const max = 64
	if len(name) > max {
		return name[:max] + "…"
	}
	return name
}
