// ABOUTME: Builds one runner invocation from the VM manifest and host configuration.
// ABOUTME: The adapter acquires the network observers and hands them across exec.
package jailer

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/2389-research/observatory/internal/privd"
	"github.com/2389-research/observatory/internal/runner"
)

// runnerArguments builds the argument vector for one runner. Exactly one of
// bundle and reason is used: with a bundle the runner adopts the descriptors it
// inherits, and without one it publishes unavailable network coverage carrying
// the bounded reason. No privileged socket path ever reaches the runner.
func (a *Adapter) runnerArguments(m Manifest, instanceID string, bundle *privd.NetworkObserverBundle, reason string) ([]string, error) {
	stateDir := filepath.Join(a.cfg.StateDir, "vms", m.VMID)
	network := []string{"--network-unavailable-reason", boundObserverReason(reason)}
	if bundle != nil {
		binding, err := privd.EncodeObserverBinding(bundle)
		if err != nil {
			return nil, fmt.Errorf("encode observer binding: %w", err)
		}
		network = []string{"--network-observers", string(binding)}
	} else if reason == "" {
		return nil, fmt.Errorf("a runner launched without observers needs a reason for their absence")
	}
	return append([]string{
		a.cfg.RunnerBin,
		"--vm-id", m.VMID,
		"--boot-id", m.BootID,
		"--instance-id", instanceID,
		"--uds", filepath.Join(a.cfg.JailBase, "firecracker", m.VMID, "root", "v.sock"),
		"--token-file", filepath.Join(stateDir, "token"),
		"--spool-dir", filepath.Join(a.cfg.SpoolRoot, m.VMID),
		"--state-file", filepath.Join(stateDir, "runner-state.json"),
		"--ctl-sock", filepath.Join(stateDir, "runner.sock"),
		"--vmm-pid", strconv.Itoa(m.VMMPID),
		"--vmm-starttime", m.VMMStart,
		"--ping-interval", "5s",
	}, network...), nil
}

// acquireRunnerObservers asks privd for this VM's network observers. The adapter
// is the privd client of record: the runner never dials it. A refusal never
// blocks the launch — it becomes the runner's bounded unavailable reason, and
// recovery then needs a runner respawn or a VM restart.
func (a *Adapter) acquireRunnerObservers(ctx context.Context, m Manifest) (*privd.NetworkObserverBundle, string) {
	bundle, err := a.pc.AcquireNetworkObservers(ctx, privd.AcquireNetworkObserversReq{VMID: m.VMID, GuestBootID: m.BootID})
	if err != nil {
		return nil, boundObserverReason("network observer acquisition refused: " + err.Error())
	}
	if bundle == nil {
		return nil, boundObserverReason("network observer acquisition returned no binding")
	}
	return bundle, ""
}

// boundObserverReason keeps every reason inside the runner's published bound, so
// a launch never fails on a reason string the runner would refuse.
func boundObserverReason(reason string) string {
	return runner.BoundNetworkReason(reason)
}
