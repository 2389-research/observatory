// ABOUTME: Defines the versioned IPv4 public-destination boundary shared by network enforcement.
// ABOUTME: Combines IANA special-purpose space with bounded host, interface, VM, and transit prefixes.
package network

import (
	"fmt"
	"net/netip"
)

const (
	// DestinationPolicyVersion identifies the registry snapshot encoded below.
	DestinationPolicyVersion = "iana-ipv4-special-registry-2025-10-09"
	// MaxDestinationPolicyExtraPrefixes bounds host-derived policy input and rule growth.
	MaxDestinationPolicyExtraPrefixes = 256
)

// IANA source: https://www.iana.org/assignments/iana-ipv4-special-registry/
// Snapshot last updated 2025-10-09. The aggregate entries cover every address
// block in that snapshot, including the globally reachable special services.
var specialDestinationPrefixes = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.31.196.0/24",
	"192.52.193.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"192.175.48.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
)

var multicastDestinationPrefix = netip.MustParsePrefix("224.0.0.0/4")

// DestinationPolicy is an immutable classification boundary. A zero value is
// not a valid policy; callers construct one with NewDestinationPolicy.
type DestinationPolicy struct {
	extra  []netip.Prefix
	denied []netip.Prefix
	valid  bool
}

// NewDestinationPolicy adds normalized local prefixes to the fixed registry
// boundary. It rejects non-IPv4 and unbounded input rather than weakening it.
func NewDestinationPolicy(extra []netip.Prefix) (DestinationPolicy, error) {
	if len(extra) > MaxDestinationPolicyExtraPrefixes {
		return DestinationPolicy{}, fmt.Errorf("network: destination policy has %d extra prefixes, maximum is %d", len(extra), MaxDestinationPolicyExtraPrefixes)
	}
	normalized := make([]netip.Prefix, 0, len(extra))
	seen := make(map[netip.Prefix]struct{}, len(extra))
	for i, prefix := range extra {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return DestinationPolicy{}, fmt.Errorf("network: destination policy prefix %d is not unscoped IPv4", i)
		}
		prefix = prefix.Masked()
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
	}
	denied := make([]netip.Prefix, 0, len(specialDestinationPrefixes)+1+len(normalized))
	denied = append(denied, specialDestinationPrefixes...)
	denied = append(denied, multicastDestinationPrefix)
	denied = append(denied, normalized...)
	return DestinationPolicy{extra: normalized, denied: denied, valid: true}, nil
}

// Classify returns true only for an unscoped, native IPv4 public destination.
// The reason is stable policy evidence for logs and denials.
func (p DestinationPolicy) Classify(addr netip.Addr) (public bool, reason string) {
	if !p.valid {
		return false, "policy_uninitialized"
	}
	if !addr.IsValid() || !addr.Is4() || addr.Is4In6() || addr.Zone() != "" {
		return false, "invalid_ipv4"
	}
	for _, prefix := range p.extra {
		if prefix.Contains(addr) {
			return false, "configured_prefix"
		}
	}
	if multicastDestinationPrefix.Contains(addr) {
		return false, "multicast"
	}
	for _, prefix := range specialDestinationPrefixes {
		if prefix.Contains(addr) {
			return false, "iana_special"
		}
	}
	return true, "public"
}

// DeniedPrefixes returns a copy suitable for downstream nft rule generation.
func (p DestinationPolicy) DeniedPrefixes() []netip.Prefix {
	return append([]netip.Prefix(nil), p.denied...)
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(values))
	for i, value := range values {
		prefixes[i] = netip.MustParsePrefix(value)
	}
	return prefixes
}
