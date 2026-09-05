// ABOUTME: Tests for the privd wire protocol: message round-trips, oversize rejection,
// ABOUTME: truncated-body handling, the ValidVMID and ValidStagedName tables, and
// ABOUTME: the client↔fake-listener round-trip.
package privd_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/2389-research/observatory-v2/internal/privd"
)

// TestMsgRoundTrip verifies WriteMsg/ReadMsg preserve a Request intact.
func TestMsgRoundTrip(t *testing.T) {
	req := privd.Request{
		V:       privd.ProtoVersion,
		Verb:    "start_vm",
		OpID:    "op-000042",
		Payload: json.RawMessage(`{"vm_id":"vm-abc"}`),
	}

	var buf bytes.Buffer
	if err := privd.WriteMsg(&buf, req); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}

	var got privd.Request
	if err := privd.ReadMsg(&buf, &got); err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}

	if got.V != req.V || got.Verb != req.Verb || got.OpID != req.OpID {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, req)
	}
	if string(got.Payload) != string(req.Payload) {
		t.Errorf("payload mismatch: got %q, want %q", got.Payload, req.Payload)
	}
}

// TestMsgOversizeRejected verifies ReadMsg rejects a length prefix of MaxMsgBytes+1
// WITHOUT allocating the body buffer (prefix written by hand).
func TestMsgOversizeRejected(t *testing.T) {
	var buf bytes.Buffer
	// Write a 4-byte big-endian length prefix of MaxMsgBytes+1.
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(privd.MaxMsgBytes+1))
	buf.Write(prefix[:])
	// No body follows — ReadMsg must reject on the length check alone.

	var dst privd.Request
	err := privd.ReadMsg(&buf, &dst)
	if err == nil {
		t.Fatal("ReadMsg: expected error for oversized message, got nil")
	}
	if got := err.Error(); !contains(got, "message too large") {
		t.Errorf("ReadMsg error %q does not mention 'message too large'", got)
	}
}

// TestMsgTruncatedBody verifies ReadMsg returns an io.ErrUnexpectedEOF-wrapped error
// when the body is shorter than the declared length.
func TestMsgTruncatedBody(t *testing.T) {
	var buf bytes.Buffer
	// Write a valid 4-byte length prefix (100), but supply only 10 bytes of body.
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], 100)
	buf.Write(prefix[:])
	buf.Write(make([]byte, 10))

	var dst privd.Request
	err := privd.ReadMsg(&buf, &dst)
	if err == nil {
		t.Fatal("ReadMsg: expected error for truncated body, got nil")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("ReadMsg error %v is not wrapping io.ErrUnexpectedEOF", err)
	}
}

// TestValidVMID exercises the VM-ID validation rule: ^[a-z0-9][a-z0-9-]{0,62}$
func TestValidVMID(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		// Accept
		{"m1-a", true},
		{"vm-000042", true},
		{"a", true},
		{"abc123", true},
		{"a-b-c", true},
		// Reject
		{"", false},
		{"VM-UPPER", false},
		{"../etc", false},
		{"a_b", false},
		{"-leadingdash", false},
		// 64 chars → reject (max 63: 1 leading + up to 62 tail chars)
		{"a123456789012345678901234567890123456789012345678901234567890123", false},
		// 63 chars → accept
		{"a12345678901234567890123456789012345678901234567890123456789012", true},
	}
	for _, tc := range cases {
		got := privd.ValidVMID(tc.id)
		if got != tc.want {
			t.Errorf("ValidVMID(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

// TestClientRoundTrip starts a fake unix-socket listener, serves one canned Response,
// and asserts Client.StartVM decodes it. It also checks that a {"ok":false,"cause":"digest_mismatch"}
// reply surfaces as *privd.RemoteError with that cause.
func TestClientRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "privd.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	goodResp := privd.Response{
		OK:      true,
		Payload: json.RawMessage(`{"pid":12345,"starttime_ticks":"54321"}`),
	}
	errResp := privd.Response{
		OK:    false,
		Cause: "digest_mismatch",
	}

	serve := func(resp privd.Response) {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Drain the incoming request.
		var req privd.Request
		_ = privd.ReadMsg(conn, &req)
		// Write the canned response.
		_ = privd.WriteMsg(conn, resp)
	}

	// First call: success.
	go serve(goodResp)

	c := &privd.Client{SocketPath: sockPath}
	resp, err := c.StartVM(t.Context(), privd.StartVMReq{VMID: "vm-test", UID: 1000, GID: 1000, CID: 3})
	if err != nil {
		t.Fatalf("StartVM success case: %v", err)
	}
	if resp.PID != 12345 {
		t.Errorf("StartVM: got PID %d, want 12345", resp.PID)
	}
	if resp.StartTime != "54321" {
		t.Errorf("StartVM: got StartTime %q, want %q", resp.StartTime, "54321")
	}

	// Second call: error response → expect *RemoteError with digest_mismatch.
	go serve(errResp)

	_, err = c.StartVM(t.Context(), privd.StartVMReq{VMID: "vm-test", UID: 1000, GID: 1000, CID: 3})
	if err == nil {
		t.Fatal("StartVM error case: expected error, got nil")
	}
	var re *privd.RemoteError
	if !errors.As(err, &re) {
		t.Fatalf("StartVM error case: got %T %v, want *privd.RemoteError", err, err)
	}
	if re.Cause != "digest_mismatch" {
		t.Errorf("RemoteError.Cause = %q, want %q", re.Cause, "digest_mismatch")
	}
}

// contains is a simple substring check.
func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// compile-time import use sentinel.
var _ = os.DevNull

// TestValidStagedName: the set of files a launch may stage is closed and privd
// knows it, so the predicate is an allowlist rather than a search for hostile
// syntax. That matters for the rejects below: "vmlinux/../vmlinux" and
// "./vmlinux" both clean to a legal name, and neither is a name a launch sends.
// A predicate that cleaned first and compared after would take them, and would
// then be one Clean bug away from taking their neighbours.
func TestValidStagedName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		// Accept: every name computeStagedFiles builds, and nothing else.
		{"vmlinux", true},
		{"rootfs.ext4", true},
		{"config.ext4", true},
		{"workspace.ext4", true},
		{"fc-config.json", true},
		// Reject: traversal, in both directions and both separators' worth of it.
		{"../../victim/owned.txt", false},
		{"../vmlinux", false},
		{"sub/vmlinux", false},
		{"vmlinux/../vmlinux", false},
		{"./vmlinux", false},
		{"/etc/cron.d/pwn", false},
		{"/vmlinux", false},
		// Reject: the directory names themselves.
		{".", false},
		{"..", false},
		{"", false},
		// Reject: a plausible file that is still not one of ours.
		{"initrd", false},
		{"vmlinux.bak", false},
		{"VMLINUX", false},
		{"vmlinux\x00", false},
	}
	for _, c := range cases {
		if got := privd.ValidStagedName(c.name); got != c.want {
			t.Errorf("ValidStagedName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestStagedFileNamesAreBasenames guards the allowlist itself: a name added to
// it later must still be a bare filename, or the allowlist becomes the hole it
// was written to close.
func TestStagedFileNamesAreBasenames(t *testing.T) {
	if len(privd.StagedFileNames) == 0 {
		t.Fatal("StagedFileNames is empty; no launch could stage anything")
	}
	for _, name := range privd.StagedFileNames {
		if name != filepath.Base(name) || name == "." || name == ".." || name == "" {
			t.Errorf("StagedFileNames contains %q, which is not a bare filename", name)
		}
		if !privd.ValidStagedName(name) {
			t.Errorf("ValidStagedName rejects %q, which is in StagedFileNames", name)
		}
	}
}
