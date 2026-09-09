// ABOUTME: Authenticates root privd and validates every received observer descriptor.
// ABOUTME: Closes the complete bundle on any framing, binding or socket mismatch.
//go:build linux

package privd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const observerAcquisitionTimeout = 5 * time.Second

func (c *Client) AcquireNetworkObservers(parent context.Context, req AcquireNetworkObserversReq) (*NetworkObserverBundle, error) {
	if err := validateObserverRequest(req); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, observerAcquisitionTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("dial observer acquisition: %w", err)
	}
	defer conn.Close()
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("observer acquisition requires Unix socket")
	}
	uid, err := peerUID(unixConn)
	if err != nil || uid != 0 {
		return nil, fmt.Errorf("observer peer is not authenticated root")
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if err := WriteMsg(conn, Request{V: ProtoVersion, Verb: observerVerb, Payload: payload}); err != nil {
		return nil, fmt.Errorf("send observer acquisition: %w", err)
	}
	var raw json.RawMessage
	files, err := readMsgFiles(unixConn, &raw)
	if err != nil {
		return nil, fmt.Errorf("read observer acquisition: %w", err)
	}
	bundle := &NetworkObserverBundle{Files: files}
	failed := true
	defer func() {
		if failed {
			_ = bundle.Close()
		}
	}()
	var response Response
	if err := decodeObserverJSON(raw, &response); err != nil {
		return nil, fmt.Errorf("invalid observer response: %w", err)
	}
	if !response.OK {
		if len(files) != 0 || len(response.Cause) == 0 || len(response.Cause) > 64 || len(response.Message) > 4096 || len(response.Payload) != 0 {
			return nil, fmt.Errorf("invalid observer refusal")
		}
		return nil, &RemoteError{Cause: response.Cause, Message: response.Message}
	}
	if response.Cause != "" || response.Message != "" {
		return nil, fmt.Errorf("contradictory observer success response")
	}
	// Decode into metadata only: files are exclusively the received rights.
	var metadata NetworkObserverBundle
	if err := decodeObserverJSON(response.Payload, &metadata); err != nil {
		return nil, fmt.Errorf("invalid observer metadata: %w", err)
	}
	bundle.Binding = metadata.Binding
	bundle.Sockets = metadata.Sockets
	if err := validateObserverMetadata(req, bundle); err != nil {
		return nil, err
	}
	if err := validateObserverFiles(bundle); err != nil {
		return nil, err
	}
	failed = false
	return bundle, nil
}

// ValidateObserverDescriptors re-checks that the bundle's files are the exact
// netlink sockets its metadata names. A process that received the descriptors by
// inheritance rather than by acquisition proves the pairing with it.
func ValidateObserverDescriptors(bundle *NetworkObserverBundle) error {
	if err := ValidateObserverBinding(bundle); err != nil {
		return err
	}
	return validateObserverFiles(bundle)
}

func validateObserverFiles(bundle *NetworkObserverBundle) error {
	if len(bundle.Files) != 3 || len(bundle.Sockets) != 3 {
		return fmt.Errorf("observer reply requires exactly three files")
	}
	for i, file := range bundle.Files {
		if err := validateObserverFile(file, bundle.Sockets[i]); err != nil {
			return fmt.Errorf("observer file %d: %w", i, err)
		}
	}
	return nil
}
func validateObserverFile(file *os.File, info ObserverSocket) error {
	if file == nil {
		return fmt.Errorf("missing descriptor")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var validateErr error
	if err := raw.Control(func(value uintptr) {
		fd := int(value)
		for _, check := range []struct{ option, want int }{{unix.SO_DOMAIN, unix.AF_NETLINK}, {unix.SO_PROTOCOL, unix.NETLINK_NETFILTER}, {unix.SO_TYPE, unix.SOCK_RAW}} {
			actual, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, check.option)
			if err != nil || actual != check.want {
				validateErr = fmt.Errorf("not a NETLINK_NETFILTER RAW socket")
				return
			}
		}
		flags, err := unix.FcntlInt(value, unix.F_GETFL, 0)
		if err != nil || flags&unix.O_NONBLOCK == 0 {
			validateErr = fmt.Errorf("observer socket is not nonblocking")
			return
		}
		descriptorFlags, err := unix.FcntlInt(value, unix.F_GETFD, 0)
		if err != nil || descriptorFlags&unix.FD_CLOEXEC == 0 {
			validateErr = fmt.Errorf("observer socket is not close-on-exec")
			return
		}
		address, err := unix.Getsockname(fd)
		if err != nil {
			validateErr = err
			return
		}
		local, ok := address.(*unix.SockaddrNetlink)
		if !ok || local.Pid != info.PortID || local.Pid == 0 {
			validateErr = fmt.Errorf("observer socket port ID mismatch")
			return
		}
		wantGroups := uint32(0)
		if info.Kind == "conntrack" {
			wantGroups = 7
		}
		if local.Groups != wantGroups {
			validateErr = fmt.Errorf("observer subscription groups mismatch")
		}
	}); err != nil {
		return err
	}
	return validateErr
}
