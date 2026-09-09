// ABOUTME: Tests durable per-VM ownership of host NFLOG groups.
// ABOUTME: Uncertain claims stay reserved and malformed ledgers cannot look free.
package privd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/2389-research/observatory/internal/network"
)

func TestHostNFLogGroupClaimsSurviveLedgerReload(t *testing.T) {
	dir := t.TempDir()
	l := newLedger(dir)
	first, err := l.nextHostNFLogGroup()
	if err != nil || first == 0 || first == 100 {
		t.Fatalf("first host group = %d, %v", first, err)
	}
	if err := l.put(VMEntry{VMID: "vm-a", NetCIDR: "10.90.0.0/30", NetworkHostNFLogGroup: first}); err != nil {
		t.Fatal(err)
	}
	// Even an incomplete allocation owns its group until verified cleanup.
	reloaded := newLedger(dir)
	second, err := reloaded.nextHostNFLogGroup()
	if err != nil || second == first || second == 0 {
		t.Fatalf("second host group = %d, %v; first = %d", second, err, first)
	}
	if err := reloaded.put(VMEntry{VMID: "vm-b", NetCIDR: "10.90.0.4/30", NetworkHostNFLogGroup: second}); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.delete("vm-a"); err != nil {
		t.Fatal(err)
	}
	again, err := reloaded.nextHostNFLogGroup()
	if err != nil || again != first {
		t.Fatalf("released group = %d, %v; want %d", again, err, first)
	}
}

func TestHostNFLogGroupRefusesUncertainLedger(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vm-broken.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if group, err := newLedger(dir).nextHostNFLogGroup(); err == nil || group != 0 {
		t.Fatalf("malformed ownership acquired group %d, %v", group, err)
	}
}

func TestHostNFLogGroupRefusesNetworkClaimWithoutGroup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry VMEntry
	}{
		{name: "complete CIDR", entry: VMEntry{NetCIDR: "10.90.0.8/30", NetworkComplete: true}},
		{name: "complete with damaged CIDR", entry: VMEntry{NetworkComplete: true}},
		{name: "kernel identity with damaged CIDR", entry: VMEntry{NetworkNamespaceDevice: 9, NetworkNamespaceInode: 42}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := newLedger(t.TempDir())
			tc.entry.VMID = "vm-missing-group"
			if err := l.put(tc.entry); err != nil {
				t.Fatal(err)
			}
			if group, err := l.nextHostNFLogGroup(); err == nil || group != 0 {
				t.Fatalf("network ownership without group acquired %d, %v", group, err)
			}
		})
	}
}

func TestHostNFLogGroupRefusesBelowOwnedRange(t *testing.T) {
	dir := t.TempDir()
	l := newLedger(dir)
	if err := l.put(VMEntry{VMID: "vm-low-group", NetCIDR: "10.90.0.12/30", NetworkHostNFLogGroup: 100}); err != nil {
		t.Fatal(err)
	}
	if group, err := l.nextHostNFLogGroup(); err == nil || group != 0 {
		t.Fatalf("out-of-range ownership acquired %d, %v", group, err)
	}
}

func TestHostNFLogGroupRefusesDuplicateClaim(t *testing.T) {
	dir := t.TempDir()
	l := newLedger(dir)
	for _, vmID := range []string{"vm-first", "vm-second"} {
		if err := l.put(VMEntry{VMID: vmID, NetCIDR: "10.90.0.16/30", NetworkHostNFLogGroup: 1024}); err != nil {
			t.Fatal(err)
		}
	}
	if group, err := l.nextHostNFLogGroup(); err == nil || group != 0 {
		t.Fatalf("duplicate ownership acquired %d, %v", group, err)
	}
}

func TestHostNFLogGroupReportsExhaustedOwnedRange(t *testing.T) {
	count := int(^uint16(0)-network.MinHostNFLogGroup) + 1
	entries := make([]VMEntry, count)
	for i := range entries {
		entries[i].NetworkHostNFLogGroup = network.MinHostNFLogGroup + uint16(i)
	}
	if group, err := nextHostNFLogGroup(entries); err == nil || group != 0 {
		t.Fatalf("exhausted ownership acquired %d, %v", group, err)
	}
}
