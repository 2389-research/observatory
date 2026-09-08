// ABOUTME: Enables IPv4 forwarding on one current-namespace interface via rtnetlink.
// ABOUTME: Never changes namespace/global defaults, policy rules, routes or sysctl files.
package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"golang.org/x/sys/unix"
)

// EnableIPv4Forwarding enables only the given interface in the current network
// namespace. The caller must hold NET_ADMIN and keep the interface and namespace
// alive for the call. Namespace selection belongs to the caller.
func EnableIPv4Forwarding(ctx context.Context, ifindex int) error {
	request, err := forwardingRequest(ifindex, 1, 0)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open forwarding netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind forwarding netlink socket: %w", err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return fmt.Errorf("get forwarding netlink address: %w", err)
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok {
		return fmt.Errorf("unexpected forwarding socket address")
	}
	binary.NativeEndian.PutUint32(request[12:], local.Pid)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("send forwarding request: %w", err)
	}
	return receiveForwardingAck(ctx, fd, request)
}

func forwardingRequest(ifindex int, sequence, port uint32) ([]byte, error) {
	if ifindex <= 0 || int64(ifindex) > math.MaxInt32 {
		return nil, fmt.Errorf("invalid forwarding interface index %d", ifindex)
	}
	b := make([]byte, 52)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], unix.RTM_NEWLINK)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(b[8:], sequence)
	binary.NativeEndian.PutUint32(b[12:], port)
	binary.NativeEndian.PutUint32(b[20:], uint32(ifindex))
	// inet_set_link_af consumes nested IPv4 devconf attributes, unlike its GET
	// response's flat array. IPV4_DEVCONF_FORWARDING is 1 in linux/ip.h.
	for _, a := range []struct {
		offset, length int
		kind           uint16
	}{
		{32, 20, unix.IFLA_AF_SPEC | unix.NLA_F_NESTED},
		{36, 16, unix.AF_INET | unix.NLA_F_NESTED},
		{40, 12, unix.IFLA_INET_CONF | unix.NLA_F_NESTED},
		{44, 8, 1},
	} {
		binary.NativeEndian.PutUint16(b[a.offset:], uint16(a.length))
		binary.NativeEndian.PutUint16(b[a.offset+2:], a.kind)
	}
	binary.NativeEndian.PutUint32(b[48:], 1)
	return b, nil
}

func validateForwardingAck(data, request []byte, sender uint32, flags int) error {
	if sender != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return fmt.Errorf("untrusted or truncated forwarding ACK")
	}
	if len(request) < 16 || len(data) < 36 || uint64(binary.NativeEndian.Uint32(data)) != uint64(len(data)) {
		return fmt.Errorf("invalid forwarding ACK length")
	}
	if binary.NativeEndian.Uint16(data[4:]) != unix.NLMSG_ERROR || !bytes.Equal(data[8:16], request[8:16]) || !bytes.Equal(data[20:36], request[:16]) {
		return fmt.Errorf("forwarding ACK does not match request")
	}
	code := int32(binary.NativeEndian.Uint32(data[16:]))
	if code > 0 || code < -4095 {
		return fmt.Errorf("invalid forwarding ACK errno")
	}
	if binary.NativeEndian.Uint16(data[6:])&unix.NLM_F_CAPPED == 0 {
		if len(data) < 20+len(request) || !bytes.Equal(data[20:20+len(request)], request) {
			return fmt.Errorf("forwarding ACK has invalid original payload")
		}
	}
	if code != 0 {
		return fmt.Errorf("kernel rejected interface forwarding: %w", unix.Errno(-code))
	}
	return nil
}

func receiveForwardingAck(ctx context.Context, fd int, request []byte) error {
	buffer := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		// A short bounded poll allows cancellation without a second goroutine or
		// racing descriptor closure. The public operation also has a total deadline.
		wait := 50
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return context.DeadlineExceeded
			}
			if milliseconds := int((remaining + time.Millisecond - 1) / time.Millisecond); milliseconds < wait {
				wait = milliseconds
			}
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, wait)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll forwarding ACK: %w", err)
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&unix.POLLNVAL != 0 {
			return fmt.Errorf("forwarding ACK socket closed")
		}
		n, _, flags, address, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return fmt.Errorf("receive forwarding ACK: %w", err)
		}
		sender, ok := address.(*unix.SockaddrNetlink)
		if !ok || sender.Family != unix.AF_NETLINK || sender.Groups != 0 {
			return fmt.Errorf("invalid forwarding ACK sender")
		}
		return validateForwardingAck(buffer[:n], request, sender.Pid, flags)
	}
}
