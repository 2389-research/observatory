// ABOUTME: Admission policy: maps host resources to usable capacity and enforces
// ABOUTME: per-request checks inside the store's admission transaction (SPEC §6).
package runtime

import (
	"fmt"
	goruntime "runtime"

	"github.com/2389-research/observatory/internal/config"
	"github.com/2389-research/observatory/internal/store"
)

// HostResources are the raw measured totals of this host, probed once at
// startup and re-used throughout the session. They are never invented.
type HostResources struct {
	TotalMemoryMiB   int64
	CPUCores         int
	StateDiskFreeMiB int64
}

// ProbeHost measures real host resources. statePath is the state directory
// whose filesystem is checked for free space (disk free is already net of
// existing files; reservations guard the gap between probed free and committed
// writes).
func ProbeHost(statePath string) (HostResources, error) {
	mem, err := hostMemoryMiB()
	if err != nil {
		return HostResources{}, fmt.Errorf("probe memory: %w", err)
	}
	disk, err := diskFreeMiB(statePath)
	if err != nil {
		return HostResources{}, fmt.Errorf("probe disk: %w", err)
	}
	return HostResources{
		TotalMemoryMiB:   mem,
		CPUCores:         goruntime.NumCPU(),
		StateDiskFreeMiB: disk,
	}, nil
}

// Policy applies the host configuration to the measured resources and enforces
// admission checks inside the store's writer transaction. All Admit calls
// receive a ReservationTotals snapshot taken inside the tx for consistency
// (AT-012: concurrent creates must not oversubscribe the same capacity).
type Policy struct {
	Admission config.Admission
	Host      HostResources
}

// UsableMemoryMiB is the RAM available for VM guests and their per-VM overhead,
// after the host reserve and inspector slots are subtracted.
func (p Policy) UsableMemoryMiB() int64 {
	hostReserve := p.Admission.ReserveHostMemoryMinMiB
	if fraction := int64(float64(p.Host.TotalMemoryMiB) * p.Admission.ReserveHostMemoryFraction); fraction > hostReserve {
		hostReserve = fraction
	}
	inspectorReserve := p.Admission.ReserveInspectorMemoryMiB * int64(p.Admission.ReserveInspectionSlots)
	usable := p.Host.TotalMemoryMiB - hostReserve - inspectorReserve
	if usable < 0 {
		return 0
	}
	return usable
}

// UsableVCPU is the CPU capacity available for VMs, after host and inspector
// reserves, multiplied by the overcommit ratio.
func (p Policy) UsableVCPU() float64 {
	raw := float64(p.Host.CPUCores) -
		float64(p.Admission.ReserveHostCPUCores) -
		float64(p.Admission.ReserveInspectorCPUCores)*float64(p.Admission.ReserveInspectionSlots)
	if raw < 0 {
		raw = 0
	}
	return raw * p.Admission.CPUOvercommitRatio
}

// UsableDiskMiB is the disk available for VM images. The measured free space
// already excludes existing files; reservations guard pending allocations.
func (p Policy) UsableDiskMiB() int64 {
	usable := p.Host.StateDiskFreeMiB - p.Admission.ReserveInspectorScratchMiB
	if usable < 0 {
		return 0
	}
	return usable
}

// Admit checks whether a single VM of the given size fits in the remaining
// capacity. It is designed to be called inside the store's writer transaction
// as the CreateVMInput.Admit callback, where totals are a consistent snapshot.
// Returns nil or *store.AdmissionRefusal naming the exhausted dimension.
func (p Policy) Admit(totals store.ReservationTotals, memTotalMiB int64, vcpu int, diskMiB int64) error {
	if !p.Admission.AllowMemoryOvercommit {
		usableMem := p.UsableMemoryMiB()
		if totals.MemoryMiB+memTotalMiB > usableMem {
			free := usableMem - totals.MemoryMiB
			return &store.AdmissionRefusal{
				Cause: "insufficient_capacity",
				Message: fmt.Sprintf("memory: need %d MiB, only %d MiB free (usable %d, reserved %d)",
					memTotalMiB, free, usableMem, totals.MemoryMiB),
			}
		}
	}

	usableVCPU := p.UsableVCPU()
	if float64(totals.VCPU)+float64(vcpu) > usableVCPU {
		free := usableVCPU - float64(totals.VCPU)
		return &store.AdmissionRefusal{
			Cause: "insufficient_capacity",
			Message: fmt.Sprintf("cpu: need %d vCPU, only %.1f vCPU free (usable %.1f, reserved %d)",
				vcpu, free, usableVCPU, totals.VCPU),
		}
	}

	usableDisk := p.UsableDiskMiB()
	if totals.DiskMiB+diskMiB > usableDisk {
		free := usableDisk - totals.DiskMiB
		// The two numbers behind "usable" are named because neither is visible
		// from outside: the reserve is a flat figure that can swallow most of a
		// nearly-full disk, and free space is probed once, so clearing disk now
		// does not move this number until the daemon restarts. Without them a
		// refusal on a visibly empty disk reads as a defect in the daemon.
		return &store.AdmissionRefusal{
			Cause: "insufficient_capacity",
			Message: fmt.Sprintf(
				"disk: need %d MiB, only %d MiB free (usable %d; host had %d MiB free at startup, %d MiB held for inspection scratch; %d MiB reserved by VMs)",
				diskMiB, free, usableDisk,
				p.Host.StateDiskFreeMiB, p.Admission.ReserveInspectorScratchMiB, totals.DiskMiB),
		}
	}

	return nil
}
