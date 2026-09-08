// ABOUTME: Tests the versioned IPv4 public-destination boundary and immutable deny inputs.
// ABOUTME: Covers every special registry edge plus invalid, mapped, multicast, and local prefixes.
package network_test

import (
	"net/netip"
	"testing"

	"github.com/2389-research/observatory/internal/network"
)

func TestDestinationPolicyDeniesSpecialRegistryBoundaries(t *testing.T) {
	t.Parallel()
	policy, err := network.NewDestinationPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	blocks := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4",
	}
	for _, raw := range blocks {
		prefix := netip.MustParsePrefix(raw)
		for _, addr := range []netip.Addr{prefix.Addr(), lastAddress(prefix)} {
			if public, reason := policy.Classify(addr); public || reason != "iana_special" {
				t.Errorf("Classify(%s) = (%t, %q), want denied IANA special", addr, public, reason)
			}
		}
	}
	for _, raw := range []string{"8.8.8.8", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0", "223.255.255.255"} {
		addr := netip.MustParseAddr(raw)
		if public, reason := policy.Classify(addr); !public || reason != "public" {
			t.Errorf("Classify(%s) = (%t, %q), want public", addr, public, reason)
		}
	}
}

func TestDestinationPolicyDeniesMulticastAndCallerPrefixes(t *testing.T) {
	t.Parallel()
	extra := []netip.Prefix{
		netip.MustParsePrefix("8.8.8.9/24"),
		netip.MustParsePrefix("203.0.113.7/32"), // overlaps the fixed registry and should normalize.
	}
	policy, err := network.NewDestinationPolicy(extra)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"224.0.0.0", "239.255.255.255"} {
		if public, reason := policy.Classify(netip.MustParseAddr(raw)); public || reason != "multicast" {
			t.Errorf("Classify(%s) = (%t, %q), want multicast denial", raw, public, reason)
		}
	}
	for _, raw := range []string{"8.8.8.0", "8.8.8.255"} {
		if public, reason := policy.Classify(netip.MustParseAddr(raw)); public || reason != "configured_prefix" {
			t.Errorf("Classify(%s) = (%t, %q), want configured denial", raw, public, reason)
		}
	}

	extra[0] = netip.MustParsePrefix("9.9.9.0/24")
	denied := policy.DeniedPrefixes()
	denied[0] = netip.MustParsePrefix("8.8.8.0/24")
	if public, _ := policy.Classify(netip.MustParseAddr("9.9.9.9")); !public {
		t.Fatal("caller mutation changed policy")
	}
}

func TestDestinationPolicyRejectsInvalidInputsAndAddresses(t *testing.T) {
	t.Parallel()
	bad := [][]netip.Prefix{
		{{}},
		{netip.MustParsePrefix("2001:db8::/32")},
		{netip.MustParsePrefix("::ffff:192.0.2.0/120")},
		make([]netip.Prefix, network.MaxDestinationPolicyExtraPrefixes+1),
	}
	for _, prefixes := range bad {
		if _, err := network.NewDestinationPolicy(prefixes); err == nil {
			t.Errorf("NewDestinationPolicy(%v) succeeded", prefixes)
		}
	}
	policy, err := network.NewDestinationPolicy(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []netip.Addr{{}, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("::ffff:8.8.8.8")} {
		if public, reason := policy.Classify(addr); public || reason != "invalid_ipv4" {
			t.Errorf("Classify(%s) = (%t, %q), want invalid IPv4 denial", addr, public, reason)
		}
	}
	if public, reason := (network.DestinationPolicy{}).Classify(netip.MustParseAddr("8.8.8.8")); public || reason != "policy_uninitialized" {
		t.Errorf("zero policy Classify = (%t, %q), want fail-closed", public, reason)
	}
}

func TestDestinationPolicyVersionAndPrefixCopies(t *testing.T) {
	t.Parallel()
	if network.DestinationPolicyVersion != "iana-ipv4-special-registry-2025-10-09" {
		t.Fatalf("unexpected version %q", network.DestinationPolicyVersion)
	}
	policy, err := network.NewDestinationPolicy([]netip.Prefix{
		netip.MustParsePrefix("8.8.8.9/24"),
		netip.MustParsePrefix("8.8.8.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := policy.DeniedPrefixes()
	count := 0
	for _, prefix := range got {
		if prefix == netip.MustParsePrefix("8.8.8.0/24") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("normalized extra prefix count = %d, want 1: %v", count, got)
	}
}

func lastAddress(prefix netip.Prefix) netip.Addr {
	addr := prefix.Addr().As4()
	bits := prefix.Bits()
	value := uint32(addr[0])<<24 | uint32(addr[1])<<16 | uint32(addr[2])<<8 | uint32(addr[3])
	value |= ^uint32(0) >> bits
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}
