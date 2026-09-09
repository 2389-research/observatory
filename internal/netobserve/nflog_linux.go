// ABOUTME: Acquires one bounded current-namespace NFLOG group for denial evidence.
// ABOUTME: Requires NET_ADMIN for group binding, packet-copy configuration and local sequencing.
//go:build linux

package netobserve

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	nfLogCopyBytes          = 128
	nfLogReceiveBufferBytes = 256 * 1024
	nfLogSetupTimeout       = 2 * time.Second
	nfLogACKBytes           = 4096

	nfLogConfigMessage = 0x401 // NFNL_SUBSYS_ULOG << 8 | NFULNL_MSG_CONFIG.
	nfLogConfigCommand = 1     // NFULA_CFG_CMD.
	nfLogConfigMode    = 2     // NFULA_CFG_MODE.
	nfLogConfigFlags   = 6     // NFULA_CFG_FLAGS.
	nfLogCommandBind   = 1     // NFULNL_CFG_CMD_BIND.
	nfLogCopyPacket    = 2     // NFULNL_COPY_PACKET.
	nfLogFlagSequence  = 1     // NFULNL_CFG_F_SEQ.
)

// NFLogSocketInfo binds a caller-owned descriptor to its immutable group.
// PortID identifies the socket that owns the group in the current namespace.
type NFLogSocketInfo struct {
	PortID uint32 `json:"port_id"`
	Group  uint16 `json:"group"`
}

// OpenNFLog requires NET_ADMIN in the current namespace. The caller supplies
// an allocated nonzero group and owns the returned descriptor. This function
// binds no protocol family logger and changes no nftables policy. It copies at
// most 128 packet bytes and enables instance-local NFLOG sequence attributes.
func OpenNFLog(ctx context.Context, group uint16) (*os.File, NFLogSocketInfo, error) {
	var info NFLogSocketInfo
	if group == 0 {
		return nil, info, fmt.Errorf("invalid NFLOG group 0")
	}
	if err := ctx.Err(); err != nil {
		return nil, info, err
	}
	setupContext, cancel := context.WithTimeout(ctx, nfLogSetupTimeout)
	defer cancel()

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, info, fmt.Errorf("open NFLOG socket: %w", err)
	}
	failed := true
	defer func() {
		if failed {
			_ = unix.Close(fd)
		}
	}()
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, nfLogReceiveBufferBytes); err != nil {
		return nil, info, fmt.Errorf("bound NFLOG receive buffer: %w", err)
	}
	// Linux success ACKs are capped. NETLINK_CAP_ACK also bounds error ACKs
	// while retaining the nlmsgerr code and original request header.
	if err := unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_CAP_ACK, 1); err != nil {
		return nil, info, fmt.Errorf("cap NFLOG ACKs: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, info, fmt.Errorf("bind NFLOG socket: %w", err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, info, fmt.Errorf("get NFLOG socket address: %w", err)
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, info, fmt.Errorf("invalid NFLOG socket address")
	}
	info = NFLogSocketInfo{PortID: local.Pid, Group: group}

	request := nflogSetupRequest(group, 1, info.PortID)
	if err := setupContext.Err(); err != nil {
		return nil, info, err
	}
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, info, fmt.Errorf("send NFLOG configuration: %w", err)
	}
	if err := receiveNFLogACK(setupContext, fd, request); err != nil {
		return nil, info, fmt.Errorf("configure NFLOG group %d: %w", group, err)
	}
	if err := setupContext.Err(); err != nil {
		return nil, info, err
	}

	failed = false
	return os.NewFile(uintptr(fd), "vmobs-nflog"), info, nil
}

func nflogSetupRequest(group uint16, sequence, port uint32) []byte {
	mode := make([]byte, 6)
	binary.BigEndian.PutUint32(mode, nfLogCopyBytes)
	mode[4] = nfLogCopyPacket
	flags := make([]byte, 2)
	binary.BigEndian.PutUint16(flags, nfLogFlagSequence)
	return nflogConfigRequest(group, sequence, port,
		nflogAttribute(nfLogConfigCommand, []byte{nfLogCommandBind}),
		nflogAttribute(nfLogConfigMode, mode),
		nflogAttribute(nfLogConfigFlags, flags),
	)
}

func nflogConfigRequest(group uint16, sequence, port uint32, attributes ...[]byte) []byte {
	length := 20
	for _, attribute := range attributes {
		length += len(attribute)
	}
	request := make([]byte, length)
	binary.NativeEndian.PutUint32(request, uint32(length))
	binary.NativeEndian.PutUint16(request[4:], nfLogConfigMessage)
	binary.NativeEndian.PutUint16(request[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:], sequence)
	binary.NativeEndian.PutUint32(request[12:], port)
	request[16] = unix.AF_UNSPEC
	binary.BigEndian.PutUint16(request[18:], group)
	offset := 20
	for _, attribute := range attributes {
		copy(request[offset:], attribute)
		offset += len(attribute)
	}
	return request
}

func nflogAttribute(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	attribute := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(attribute, uint16(length))
	binary.NativeEndian.PutUint16(attribute[2:], kind)
	copy(attribute[4:], value)
	return attribute
}

func receiveNFLogACK(ctx context.Context, fd int, request []byte) error {
	buffer := make([]byte, nfLogACKBytes)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
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
		ready, err := unix.Poll(poll, wait)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll NFLOG ACK: %w", err)
		}
		if ready == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLNVAL|unix.POLLHUP) != 0 {
			return fmt.Errorf("NFLOG ACK socket closed")
		}
		n, _, flags, address, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return fmt.Errorf("receive NFLOG ACK: %w", err)
		}
		sender, ok := address.(*unix.SockaddrNetlink)
		if !ok {
			return fmt.Errorf("invalid NFLOG ACK sender")
		}
		return validateNFLogACK(buffer[:n], request, sender, flags)
	}
}

func validateNFLogACK(data, request []byte, sender *unix.SockaddrNetlink, flags int) error {
	if sender == nil || sender.Family != unix.AF_NETLINK || sender.Pid != 0 || sender.Groups != 0 {
		return fmt.Errorf("untrusted NFLOG ACK sender")
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return fmt.Errorf("truncated NFLOG ACK")
	}
	if len(request) < 20 || int(binary.NativeEndian.Uint32(request)) != len(request) || len(data) < 36 || int(binary.NativeEndian.Uint32(data)) != len(data) {
		return fmt.Errorf("invalid NFLOG ACK framing")
	}
	if binary.NativeEndian.Uint16(data[4:]) != unix.NLMSG_ERROR || !bytes.Equal(data[8:16], request[8:16]) || !bytes.Equal(data[20:36], request[:16]) {
		return fmt.Errorf("NFLOG ACK does not match request")
	}
	code := int32(binary.NativeEndian.Uint32(data[16:]))
	if code > 0 || code < -4095 {
		return fmt.Errorf("invalid NFLOG ACK errno")
	}
	ackFlags := binary.NativeEndian.Uint16(data[6:])
	if ackFlags & ^uint16(unix.NLM_F_CAPPED) != 0 {
		return fmt.Errorf("unexpected NFLOG ACK flags")
	}
	if ackFlags&unix.NLM_F_CAPPED != 0 {
		if len(data) != 36 {
			return fmt.Errorf("invalid capped NFLOG ACK length")
		}
	} else if len(data) != 20+len(request) || !bytes.Equal(data[20:20+len(request)], request) {
		return fmt.Errorf("invalid NFLOG ACK original request")
	}
	if code != 0 {
		return fmt.Errorf("kernel rejected NFLOG request: %w", unix.Errno(-code))
	}
	return nil
}
