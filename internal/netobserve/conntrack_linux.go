// ABOUTME: Acquires a current-namespace conntrack stream before guest traffic starts.
// ABOUTME: Subscribes before requesting a privileged initial snapshot for later unprivileged reading.
//go:build linux

package netobserve

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type ConntrackSocketInfo struct {
	PortID           uint32 `json:"port_id"`
	SnapshotSequence uint32 `json:"snapshot_sequence"`
}

// OpenConntrack requires NET_ADMIN in the current namespace. Namespace selection
// and owned-VM validation belong to privd. The returned file is caller-owned;
// handoff does not transfer NET_ADMIN, so later snapshots require reacquisition.
// Receiving the initial NLMSG_DONE without NLM_F_DUMP_INTR is the reader's job;
// a successful send alone is not a complete baseline or healthy coverage.
func OpenConntrack(ctx context.Context) (*os.File, ConntrackSocketInfo, error) {
	var info ConntrackSocketInfo
	if err := ctx.Err(); err != nil {
		return nil, info, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, info, fmt.Errorf("open conntrack socket: %w", err)
	}
	file := os.NewFile(uintptr(fd), "vmobs-conntrack")
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 256*1024); err != nil {
		return nil, info, fmt.Errorf("bound conntrack receive buffer: %w", err)
	}
	// nfnetlink.h: NEW, UPDATE and DESTROY are groups 1, 2 and 3. Subscribe
	// before the dump so flows arriving during the baseline remain observable.
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 7}); err != nil {
		return nil, info, fmt.Errorf("subscribe conntrack: %w", err)
	}
	address, err := unix.Getsockname(fd)
	if err != nil {
		return nil, info, err
	}
	local, ok := address.(*unix.SockaddrNetlink)
	if !ok || local.Pid == 0 {
		return nil, info, fmt.Errorf("invalid conntrack socket address")
	}
	info = ConntrackSocketInfo{PortID: local.Pid, SnapshotSequence: 1}
	if err := ctx.Err(); err != nil {
		return nil, info, err
	}
	if err := unix.Sendto(fd, conntrackSnapshotRequest(info.SnapshotSequence, info.PortID), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, info, fmt.Errorf("request conntrack baseline: %w", err)
	}
	failed = false
	return file, info, nil
}

func conntrackSnapshotRequest(sequence, port uint32) []byte {
	b := make([]byte, 20)
	binary.NativeEndian.PutUint32(b, uint32(len(b)))
	// NFNL_SUBSYS_CTNETLINK=1 and IPCTNL_MSG_CT_GET=1.
	binary.NativeEndian.PutUint16(b[4:], 0x101)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(b[8:], sequence)
	binary.NativeEndian.PutUint32(b[12:], port)
	b[16] = unix.AF_INET
	return b
}
