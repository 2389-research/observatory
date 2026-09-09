// ABOUTME: Tests rtnetlink reply validation and resolver creation boundaries.
// ABOUTME: Rejects truncated or non-kernel ACKs before guest readiness.
//go:build linux

package guest

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseNetlinkAckRejectsTruncatedReply(t *testing.T) {
	message := netlinkErrorMessage(7, 0)
	if _, err := parseNetlinkAck(7, message, unix.MSG_TRUNC, &unix.SockaddrNetlink{Pid: 0}); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("parseNetlinkAck error = %v", err)
	}
}

func TestParseNetlinkAckRequiresKernelSender(t *testing.T) {
	message := netlinkErrorMessage(7, 0)
	if _, err := parseNetlinkAck(7, message, 0, &unix.SockaddrNetlink{Pid: 42}); err == nil || !strings.Contains(err.Error(), "sender") {
		t.Fatalf("parseNetlinkAck error = %v", err)
	}
}

func TestValidateLinkDumpMessage(t *testing.T) {
	tests := []struct {
		name      string
		message   syscall.NetlinkMessage
		wantError string
		wantErrno error
	}{
		{name: "empty success", message: syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}}},
		{name: "zero success", message: netlinkDoneMessage(0, 0)},
		{name: "interrupted", message: netlinkDoneMessage(unix.NLM_F_DUMP_INTR, 0), wantError: "interrupted"},
		{name: "interrupted data message", message: syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWLINK, Flags: unix.NLM_F_DUMP_INTR}}, wantError: "interrupted"},
		{name: "short status", message: syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}, Data: []byte{0, 0}}, wantError: "malformed"},
		{name: "trailing status data", message: syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE}, Data: make([]byte, 5)}, wantError: "malformed"},
		{name: "kernel error", message: netlinkDoneMessage(0, -int32(unix.EINTR)), wantErrno: unix.EINTR},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLinkDumpMessage(tt.message)
			if tt.wantErrno != nil && !errors.Is(err, tt.wantErrno) {
				t.Fatalf("validateLinkDumpMessage error = %v, want %v", err, tt.wantErrno)
			}
			if tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("validateLinkDumpMessage error = %v, want text %q", err, tt.wantError)
			}
			if tt.wantErrno == nil && tt.wantError == "" && err != nil {
				t.Fatalf("validateLinkDumpMessage: %v", err)
			}
		})
	}
}

func TestWriteResolverFileCreatesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writeResolverFile(ctx, path, "172.31.255.1"); err != nil {
		t.Fatalf("writeResolverFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "nameserver 172.31.255.1\n" {
		t.Fatalf("resolver = %q", got)
	}
}

func TestWriteResolverFileDoesNotBlockOnFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := writeResolverFile(ctx, path, "172.31.255.1")
	if err == nil {
		t.Fatal("writeResolverFile accepted a FIFO")
	}
	if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
		t.Fatalf("FIFO handling blocked for %s: %v", elapsed, err)
	}
}

func TestWriteResolverFileHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := writeResolverFile(ctx, filepath.Join(t.TempDir(), "resolv.conf"), "172.31.255.1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("writeResolverFile error = %v, want context canceled", err)
	}
}

func netlinkErrorMessage(sequence uint32, code int32) []byte {
	message := make([]byte, unix.NLMSG_HDRLEN+4)
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	binary.NativeEndian.PutUint32(message[unix.NLMSG_HDRLEN:], uint32(code))
	return message
}

func netlinkDoneMessage(flags uint16, code int32) syscall.NetlinkMessage {
	data := make([]byte, 4)
	binary.NativeEndian.PutUint32(data, uint32(code))
	return syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{Type: unix.NLMSG_DONE, Flags: flags},
		Data:   data,
	}
}
