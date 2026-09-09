// ABOUTME: Applies the host-minted static eth0 address, route, and managed DNS.
// ABOUTME: Uses Linux netlink directly so the minimal guest needs no iproute package.
//go:build linux

package guest

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	guestInterface = "eth0"
	resolverPath   = "/etc/resolv.conf"
	requestTimeout = 100 * time.Millisecond
)

// ConfigureNetwork applies the validated boot configuration to the guest link.
// The caller must provide a deadline so a missing kernel acknowledgement cannot
// hold guest startup forever.
func ConfigureNetwork(ctx context.Context, cfg NetworkConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		return fmt.Errorf("configure network: context requires a deadline")
	}
	address, err := netip.ParsePrefix(cfg.Address)
	if err != nil || !address.Addr().Is4() || address.Addr().Is4In6() {
		return fmt.Errorf("configure network: invalid IPv4 address %q", cfg.Address)
	}
	gateway, err := netip.ParseAddr(cfg.Gateway)
	if err != nil || !gateway.Is4() || gateway.Is4In6() {
		return fmt.Errorf("configure network: invalid IPv4 gateway %q", cfg.Gateway)
	}
	if cfg.DNS != cfg.Gateway {
		return fmt.Errorf("configure network: DNS %q differs from managed gateway %q", cfg.DNS, cfg.Gateway)
	}
	wantMAC, err := net.ParseMAC(cfg.MAC)
	if err != nil || len(wantMAC) != 6 {
		return fmt.Errorf("configure network: invalid MAC %q", cfg.MAC)
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("configure network: open rtnetlink: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("configure network: bind rtnetlink: %w", err)
	}
	// Replace any image-build resolver before touching the link. If a later
	// netlink operation fails, the guest still cannot silently use that resolver.
	if err := writeResolver(ctx, cfg.DNS); err != nil {
		return fmt.Errorf("configure network: write managed resolver: %w", err)
	}
	iface, err := lookupLink(ctx, fd, guestInterface, 1)
	if err != nil {
		return fmt.Errorf("configure network: find %s: %w", guestInterface, err)
	}
	if !bytes.Equal(iface.hardwareAddr, wantMAC) {
		return fmt.Errorf("configure network: %s MAC %s differs from boot config %s", guestInterface, iface.hardwareAddr, wantMAC)
	}

	if err := netlinkAck(ctx, fd, unix.RTM_NEWLINK, uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK), 2, linkPayload(iface.index)); err != nil {
		return fmt.Errorf("configure network: bring %s up: %w", guestInterface, err)
	}
	if err := netlinkAck(ctx, fd, unix.RTM_NEWADDR, uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE), 3, addressPayload(iface.index, address)); err != nil {
		return fmt.Errorf("configure network: assign %s: %w", cfg.Address, err)
	}
	if err := netlinkAck(ctx, fd, unix.RTM_NEWROUTE, uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_REPLACE), 4, routePayload(iface.index, gateway)); err != nil {
		return fmt.Errorf("configure network: install default route through %s: %w", cfg.Gateway, err)
	}
	return ctx.Err()
}

func linkPayload(index int) []byte {
	payload := make([]byte, 16)
	payload[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(payload[4:8], uint32(index))
	binary.NativeEndian.PutUint32(payload[8:12], unix.IFF_UP)
	binary.NativeEndian.PutUint32(payload[12:16], unix.IFF_UP)
	return payload
}

func addressPayload(index int, prefix netip.Prefix) []byte {
	payload := make([]byte, 8)
	payload[0] = unix.AF_INET
	payload[1] = byte(prefix.Bits())
	payload[3] = unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(payload[4:8], uint32(index))
	address := prefix.Addr().As4()
	payload = append(payload, routeAttribute(unix.IFA_LOCAL, address[:])...)
	payload = append(payload, routeAttribute(unix.IFA_ADDRESS, address[:])...)
	return payload
}

func routePayload(index int, gateway netip.Addr) []byte {
	payload := make([]byte, 12)
	payload[0] = unix.AF_INET
	payload[4] = unix.RT_TABLE_MAIN
	payload[5] = unix.RTPROT_BOOT
	payload[6] = unix.RT_SCOPE_UNIVERSE
	payload[7] = unix.RTN_UNICAST
	address := gateway.As4()
	payload = append(payload, routeAttribute(unix.RTA_GATEWAY, address[:])...)
	device := make([]byte, 4)
	binary.NativeEndian.PutUint32(device, uint32(index))
	payload = append(payload, routeAttribute(unix.RTA_OIF, device)...)
	return payload
}

func routeAttribute(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	attribute := make([]byte, (length+3)&^3)
	binary.NativeEndian.PutUint16(attribute[0:2], uint16(length))
	binary.NativeEndian.PutUint16(attribute[2:4], kind)
	copy(attribute[4:], value)
	return attribute
}

type linkInfo struct {
	index        int
	hardwareAddr net.HardwareAddr
}

func lookupLink(ctx context.Context, fd int, name string, sequence uint32) (linkInfo, error) {
	query := make([]byte, 16)
	query[0] = unix.AF_UNSPEC
	if err := sendNetlink(fd, unix.RTM_GETLINK, uint16(unix.NLM_F_REQUEST|unix.NLM_F_DUMP), sequence, query); err != nil {
		return linkInfo{}, err
	}
	var found linkInfo
	seen := 0
	for {
		messages, err := receiveNetlink(ctx, fd)
		if err != nil {
			return linkInfo{}, err
		}
		for _, message := range messages {
			if message.Header.Seq != sequence {
				continue
			}
			if err := validateLinkDumpMessage(message); err != nil {
				return linkInfo{}, err
			}
			switch message.Header.Type {
			case unix.NLMSG_DONE:
				if found.index == 0 {
					return linkInfo{}, fmt.Errorf("interface %q not found", name)
				}
				return found, nil
			case unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return linkInfo{}, fmt.Errorf("incomplete netlink interface error")
				}
				code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
				if code != 0 {
					return linkInfo{}, syscall.Errno(-code)
				}
			case unix.RTM_NEWLINK:
				seen++
				if seen > 256 || len(message.Data) < 16 {
					return linkInfo{}, fmt.Errorf("netlink interface inventory exceeds bound or is malformed")
				}
				attributes, err := syscall.ParseNetlinkRouteAttr(&message)
				if err != nil {
					return linkInfo{}, err
				}
				var currentName string
				var hardware net.HardwareAddr
				for _, attribute := range attributes {
					switch attribute.Attr.Type {
					case unix.IFLA_IFNAME:
						currentName = string(bytes.TrimRight(attribute.Value, "\x00"))
					case unix.IFLA_ADDRESS:
						hardware = append(net.HardwareAddr(nil), attribute.Value...)
					}
				}
				if currentName == name {
					found = linkInfo{
						index:        int(int32(binary.NativeEndian.Uint32(message.Data[4:8]))),
						hardwareAddr: hardware,
					}
				}
			}
		}
	}
}

func validateLinkDumpMessage(message syscall.NetlinkMessage) error {
	if message.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
		return fmt.Errorf("netlink interface inventory interrupted")
	}
	if message.Header.Type != unix.NLMSG_DONE {
		return nil
	}
	if len(message.Data) == 0 {
		return nil
	}
	if len(message.Data) != 4 {
		return fmt.Errorf("malformed netlink interface completion")
	}
	code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
	if code > 0 {
		return fmt.Errorf("malformed netlink interface completion status %d", code)
	}
	if code < 0 {
		return syscall.Errno(-code)
	}
	return nil
}

func sendNetlink(fd int, kind, flags uint16, sequence uint32, payload []byte) error {
	message := make([]byte, unix.NLMSG_HDRLEN+len(payload))
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], kind)
	binary.NativeEndian.PutUint16(message[6:8], flags)
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	copy(message[unix.NLMSG_HDRLEN:], payload)
	return unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func netlinkAck(ctx context.Context, fd int, kind, flags uint16, sequence uint32, payload []byte) error {
	if err := sendNetlink(fd, kind, flags, sequence, payload); err != nil {
		return err
	}
	for {
		messages, err := receiveNetlink(ctx, fd)
		if err != nil {
			return err
		}
		matched, err := parseNetlinkMessagesAck(sequence, messages)
		if err != nil {
			return err
		}
		if matched {
			return nil
		}
	}
}

func parseNetlinkAck(sequence uint32, payload []byte, recvFlags int, from unix.Sockaddr) (bool, error) {
	messages, err := parseNetlinkPacket(payload, recvFlags, from)
	if err != nil {
		return false, err
	}
	return parseNetlinkMessagesAck(sequence, messages)
}

func parseNetlinkPacket(payload []byte, recvFlags int, from unix.Sockaddr) ([]syscall.NetlinkMessage, error) {
	if recvFlags&unix.MSG_TRUNC != 0 {
		return nil, fmt.Errorf("truncated netlink reply")
	}
	sender, ok := from.(*unix.SockaddrNetlink)
	if !ok || sender.Pid != 0 {
		return nil, fmt.Errorf("netlink reply has non-kernel sender")
	}
	messages, err := syscall.ParseNetlinkMessage(payload)
	if err != nil {
		return nil, err
	}
	return messages, nil
}

func parseNetlinkMessagesAck(sequence uint32, messages []syscall.NetlinkMessage) (bool, error) {
	for _, reply := range messages {
		if reply.Header.Seq != sequence {
			continue
		}
		// nlmsg_pid names the destination port for a kernel reply; the sender
		// sockaddr above is the authority that proves pid 0 originated it.
		if reply.Header.Type != unix.NLMSG_ERROR || len(reply.Data) < 4 {
			return false, fmt.Errorf("netlink reply is not a complete kernel acknowledgement")
		}
		code := int32(binary.NativeEndian.Uint32(reply.Data[:4]))
		if code == 0 {
			return true, nil
		}
		return false, syscall.Errno(-code)
	}
	return false, nil
}

func receiveNetlink(ctx context.Context, fd int) ([]syscall.NetlinkMessage, error) {
	buffer := make([]byte, 16*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		deadline, _ := ctx.Deadline()
		wait := min(time.Until(deadline), requestTimeout)
		if wait <= 0 {
			return nil, context.DeadlineExceeded
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, int(wait.Milliseconds()+1))
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if ready == 0 {
			continue
		}
		n, _, recvFlags, from, err := unix.Recvmsg(fd, buffer, nil, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		return parseNetlinkPacket(buffer[:n], recvFlags, from)
	}
}

func writeResolver(ctx context.Context, address string) error {
	return writeResolverFile(ctx, resolverPath, address)
}

func writeResolverFile(ctx context.Context, path, address string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return fmt.Errorf("resolver path is not a regular file")
	}
	content := []byte("nameserver " + address + "\n")
	for len(content) > 0 {
		if err := ctx.Err(); err != nil {
			_ = unix.Close(fd)
			return err
		}
		n, err := unix.Write(fd, content)
		if err != nil {
			_ = unix.Close(fd)
			return err
		}
		if n == 0 {
			_ = unix.Close(fd)
			return fmt.Errorf("resolver write made no progress")
		}
		content = content[n:]
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	return ctx.Err()
}
