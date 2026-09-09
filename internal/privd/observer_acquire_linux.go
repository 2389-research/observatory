// ABOUTME: Acquires real namespace and host observers from the durable gateway binding.
// ABOUTME: Pins namespace identity and restores or retires the dedicated acquisition thread.
//go:build linux

package privd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/2389-research/observatory/internal/netobserve"
	"github.com/2389-research/observatory/internal/network"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// AcquireNetworkObservers does not activate transport or claim the dump is read.
// The server calls it while holding the ledger/allocation lock.
func (r *RealOps) AcquireNetworkObservers(parent context.Context, entry VMEntry, req AcquireNetworkObserversReq) (*NetworkObserverBundle, error) {
	ctx, cancel := context.WithTimeout(parent, observerAcquisitionTimeout)
	defer cancel()
	if err := validateObserverRequest(req); err != nil {
		return nil, err
	}
	if !entry.NetworkComplete || entry.VMID != req.VMID || entry.NetworkGuestBootID != req.GuestBootID {
		return nil, fmt.Errorf("network observer allocation binding mismatch")
	}
	probe := AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: entry.NetworkProfile, PolicyID: entry.NetworkPolicyID, GuestBootID: entry.NetworkGuestBootID}
	if err := r.ProbeNetworkContext(ctx, entry, probe); err != nil {
		return nil, err
	}
	fd, err := unix.Open("/run/netns/"+network.NamespaceName(entry.VMID), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	namespace := os.NewFile(uintptr(fd), "observer-network-namespace")
	defer namespace.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Ino != entry.NetworkNamespaceInode || uint64(stat.Dev) != entry.NetworkNamespaceDevice || entry.NetworkNamespaceInode == 0 {
		return nil, fmt.Errorf("pinned observer namespace identity mismatch")
	}
	bundle := &NetworkObserverBundle{Binding: NetworkObserverBinding{VMID: entry.VMID, GuestBootID: entry.NetworkGuestBootID, HostBootID: entry.NetworkHostBootID, GatewayGeneration: entry.GatewayGeneration, NamespaceDevice: strconv.FormatUint(entry.NetworkNamespaceDevice, 10), NamespaceInode: strconv.FormatUint(entry.NetworkNamespaceInode, 10), PolicyID: entry.NetworkPolicyID, PolicyDigest: entry.NetworkPolicyDigest, Profile: entry.NetworkProfile}}
	failed := true
	defer func() {
		if failed {
			_ = bundle.Close()
		}
	}()
	type result struct {
		files   []*os.File
		sockets []ObserverSocket
		err     error
	}
	done := make(chan result, 1)
	go func() {
		files, sockets, err := openNamespaceObservers(ctx, namespace)
		done <- result{files, sockets, err}
	}()
	resultValue := <-done
	bundle.Files = resultValue.files
	bundle.Sockets = resultValue.sockets
	if resultValue.err != nil {
		return nil, resultValue.err
	}
	host, info, err := netobserve.OpenNFLog(ctx, entry.NetworkHostNFLogGroup)
	if err != nil {
		return nil, err
	}
	bundle.Files = append(bundle.Files, host)
	bundle.Sockets = append(bundle.Sockets, ObserverSocket{Kind: "nflog", Boundary: "host_veth", PortID: info.PortID, Group: info.Group})
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	bundle.Binding.AcquisitionID = id.String()
	if err := validateObserverMetadata(req, bundle); err != nil {
		return nil, err
	}
	if err := validateObserverFiles(bundle); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	failed = false
	return bundle, nil
}
func openNamespaceObservers(ctx context.Context, target *os.File) (files []*os.File, sockets []ObserverSocket, resultErr error) {
	runtime.LockOSThread()
	restored := true
	defer func() {
		if restored {
			runtime.UnlockOSThread()
		}
		if resultErr != nil {
			closeFiles(files)
			files = nil
			sockets = nil
		}
	}()
	current, err := os.Open("/proc/self/task/" + strconv.Itoa(unix.Gettid()) + "/ns/net")
	if err != nil {
		return nil, nil, err
	}
	defer current.Close()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return nil, nil, err
	}
	restored = false
	defer func() {
		err := unix.Setns(int(current.Fd()), unix.CLONE_NEWNET)
		restored = err == nil
		resultErr = errors.Join(resultErr, err)
	}()
	ct, ctInfo, err := netobserve.OpenConntrack(ctx)
	if err != nil {
		return nil, nil, err
	}
	files = append(files, ct)
	sockets = append(sockets, ObserverSocket{Kind: "conntrack", Boundary: "namespace_gateway", PortID: ctInfo.PortID, SnapshotSequence: ctInfo.SnapshotSequence})
	nflog, logInfo, err := netobserve.OpenNFLog(ctx, network.NamespaceNFLogGroup)
	if err != nil {
		return files, sockets, err
	}
	files = append(files, nflog)
	sockets = append(sockets, ObserverSocket{Kind: "nflog", Boundary: "namespace_gateway", PortID: logInfo.PortID, Group: logInfo.Group})
	return files, sockets, nil
}
