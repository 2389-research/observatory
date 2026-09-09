// ABOUTME: Reads live network coverage from the runner bound to a VM manifest.
// ABOUTME: Authenticates the Unix peer and rechecks process ownership after the reply.

//go:build linux

package jailer

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
	"golang.org/x/sys/unix"
)

const networkCoverageDeadline = 2 * time.Second

// Coverage returns live host network capture coverage for vm's current boot.
func (a *Adapter) Coverage(ctx context.Context, vm *store.VM) ([]situation.CollectorCoverage, error) {
	if vm == nil || vm.VMID == "" || vm.CurrentBootID == "" {
		return nil, fmt.Errorf("jailer: network coverage requires a current VM boot")
	}
	requestCtx, cancel := context.WithTimeout(ctx, networkCoverageDeadline)
	defer cancel()

	manifest, state, err := a.liveCoverageOwner(vm)
	if err != nil {
		return nil, err
	}
	socketPath := filepath.Join(a.cfg.StateDir, "vms", vm.VMID, "runner.sock")
	socketIdentity, err := fileIdentity(socketPath)
	if err != nil {
		return nil, fmt.Errorf("jailer: identify runner control socket: %w", err)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(requestCtx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("jailer: dial runner network status: %w", err)
	}
	peer, err := unixPeerCredential(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("jailer: authenticate runner control peer: %w", err)
	}
	wantUID, err := processUID(manifest.RunnerPID)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("jailer: identify runner uid: %w", err)
	}
	if peer.Pid != int32(manifest.RunnerPID) || peer.Uid != wantUID {
		conn.Close()
		return nil, fmt.Errorf("jailer: runner control peer does not match live runner identity")
	}

	reply, err := runner.NewCtlClient(conn).Do(requestCtx, runner.CtlRequest{Cmd: "network-status"})
	if err != nil {
		return nil, fmt.Errorf("jailer: request runner network status: %w", err)
	}
	if reply.Network == nil {
		return nil, fmt.Errorf("jailer: runner omitted network status")
	}
	afterManifest, afterState, err := a.liveCoverageOwner(vm)
	if err != nil || !sameCoverageOwner(manifest, state, afterManifest, afterState) {
		return nil, fmt.Errorf("jailer: runner ownership changed during network status request")
	}
	afterSocket, err := fileIdentity(socketPath)
	if err != nil || socketIdentity != afterSocket {
		return nil, fmt.Errorf("jailer: runner control socket changed during network status request")
	}
	if reply.Network.InstanceID != state.InstanceID {
		return nil, fmt.Errorf("jailer: network status names another runner instance")
	}
	return coverageFromNetworkStatus(*reply.Network, vm, time.Now().UTC())
}

func (a *Adapter) liveCoverageOwner(vm *store.VM) (Manifest, runner.State, error) {
	m, err := readManifest(a.cfg.StateDir, vm.VMID)
	if err != nil {
		return Manifest{}, runner.State{}, fmt.Errorf("jailer: read network coverage manifest: %w", err)
	}
	if m.VMID != vm.VMID || m.BootID != vm.CurrentBootID || m.RunnerPID <= 0 || m.RunnerStart == "" ||
		m.VMMPID <= 0 || m.VMMStart == "" || !runnerAlive(m.RunnerPID, m.RunnerStart, vm.VMID) || !privd.PIDAlive(m.VMMPID, m.VMMStart) {
		return Manifest{}, runner.State{}, fmt.Errorf("jailer: manifest does not name the current live runner and VMM")
	}
	statePath := filepath.Join(a.cfg.StateDir, "vms", vm.VMID, "runner-state.json")
	s, err := runner.ReadState(statePath)
	if err != nil {
		return Manifest{}, runner.State{}, fmt.Errorf("jailer: read runner state for network coverage: %w", err)
	}
	if s.VMID != m.VMID || s.BootID != m.BootID || s.RunnerPID != m.RunnerPID || s.InstanceID == "" ||
		s.VMMPID != m.VMMPID || s.VMMStartTime != m.VMMStart || (s.Phase != runner.PhaseAttached && s.Phase != runner.PhaseDegraded) {
		return Manifest{}, runner.State{}, fmt.Errorf("jailer: runner state does not match the live manifest")
	}
	return m, s, nil
}

func sameCoverageOwner(beforeM Manifest, beforeS runner.State, afterM Manifest, afterS runner.State) bool {
	return beforeM.VMID == afterM.VMID && beforeM.BootID == afterM.BootID &&
		beforeM.RunnerPID == afterM.RunnerPID && beforeM.RunnerStart == afterM.RunnerStart &&
		beforeM.VMMPID == afterM.VMMPID && beforeM.VMMStart == afterM.VMMStart &&
		beforeS.VMID == afterS.VMID && beforeS.BootID == afterS.BootID && beforeS.InstanceID == afterS.InstanceID &&
		beforeS.RunnerPID == afterS.RunnerPID && beforeS.VMMPID == afterS.VMMPID && beforeS.VMMStartTime == afterS.VMMStartTime
}

type socketFileIdentity struct{ device, inode uint64 }

func fileIdentity(path string) (socketFileIdentity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return socketFileIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return socketFileIdentity{}, fmt.Errorf("unsupported socket stat type %T", info.Sys())
	}
	return socketFileIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func processUID(pid int) (uint32, error) {
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unsupported process stat type %T", info.Sys())
	}
	return stat.Uid, nil
}

func unixPeerCredential(conn net.Conn) (*unix.Ucred, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("connection does not expose syscall credentials")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credential *unix.Ucred
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return credential, credentialErr
}
