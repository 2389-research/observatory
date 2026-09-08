// ABOUTME: Pins the authoritative routed namespace address and guest MAC layout.
// ABOUTME: Invalid transit leases and VM identities fail before privileged setup.
package network_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/network"
)

func TestNewLayoutDerivesRoutedAddressesAndStableGuestMAC(t *testing.T) {
	t.Parallel()

	transit := netip.MustParsePrefix("10.190.4.8/30")
	got, err := network.NewLayout("vm-test", transit)
	if err != nil {
		t.Fatalf("NewLayout: %v", err)
	}

	if got.TransitPrefix != transit {
		t.Errorf("TransitPrefix = %s, want %s", got.TransitPrefix, transit)
	}
	if got.TransitHost != netip.MustParseAddr("10.190.4.9") {
		t.Errorf("TransitHost = %s, want 10.190.4.9", got.TransitHost)
	}
	if got.TransitNamespace != netip.MustParseAddr("10.190.4.10") {
		t.Errorf("TransitNamespace = %s, want 10.190.4.10", got.TransitNamespace)
	}
	if got.GuestPrefix != netip.MustParsePrefix("172.31.255.0/30") {
		t.Errorf("GuestPrefix = %s, want 172.31.255.0/30", got.GuestPrefix)
	}
	if got.GuestGateway != netip.MustParseAddr("172.31.255.1") {
		t.Errorf("GuestGateway = %s, want 172.31.255.1", got.GuestGateway)
	}
	if got.GuestAddress != netip.MustParseAddr("172.31.255.2") {
		t.Errorf("GuestAddress = %s, want 172.31.255.2", got.GuestAddress)
	}
	if got.GuestMAC.String() != "ce:98:38:32:8c:60" {
		t.Errorf("GuestMAC = %s, want ce:98:38:32:8c:60", got.GuestMAC)
	}
	if got.GuestMAC[0]&1 != 0 || got.GuestMAC[0]&2 == 0 {
		t.Errorf("GuestMAC = %s, want unicast locally administered MAC", got.GuestMAC)
	}

	again, err := network.NewLayout("vm-test", transit)
	if err != nil {
		t.Fatalf("NewLayout again: %v", err)
	}
	if again.GuestMAC.String() != got.GuestMAC.String() {
		t.Errorf("GuestMAC changed: first %s, second %s", got.GuestMAC, again.GuestMAC)
	}
	other, err := network.NewLayout("vm-other", transit)
	if err != nil {
		t.Fatalf("NewLayout other VM: %v", err)
	}
	if other.GuestMAC.String() == got.GuestMAC.String() {
		t.Errorf("distinct VM IDs produced the same GuestMAC %s", got.GuestMAC)
	}
}

func TestNewLayoutRejectsInvalidTransitPrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prefix netip.Prefix
	}{
		{name: "invalid", prefix: netip.Prefix{}},
		{name: "IPv6", prefix: netip.MustParsePrefix("2001:db8::/30")},
		{name: "mapped IPv4", prefix: netip.MustParsePrefix("::ffff:10.190.0.0/126")},
		{name: "wrong size", prefix: netip.MustParsePrefix("10.190.0.0/29")},
		{name: "non-canonical", prefix: netip.MustParsePrefix("10.190.0.1/30")},
		{name: "guest link", prefix: netip.MustParsePrefix("172.31.255.0/30")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := network.NewLayout("vm-test", tt.prefix); err == nil {
				t.Fatalf("NewLayout(vm-test, %s) succeeded", tt.prefix)
			}
		})
	}
}

func TestNewLayoutRejectsUnvalidatedVMIdentity(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"-leading",
		"UPPER",
		"slash/name",
		"dot.name",
		strings.Repeat("a", 64),
	}
	transit := netip.MustParsePrefix("10.190.0.0/30")
	for _, vmID := range tests {
		if _, err := network.NewLayout(vmID, transit); err == nil {
			t.Errorf("NewLayout(%q, %s) succeeded", vmID, transit)
		}
	}
}
