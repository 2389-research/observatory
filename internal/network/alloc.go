// ABOUTME: Transit-subnet allocator with host-route overlap detection (§10.1).
// ABOUTME: Reserves reusable /30s by VM owner; uses netip throughout.
package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// Route represents a single entry from `ip -json route` output.
type Route struct {
	Dst     netip.Prefix
	Dev     string
	Gateway string
}

// ipRouteEntry is the raw JSON shape produced by `ip -json route show table all`.
// The Type field is present on local, broadcast, and multicast entries; absent
// (empty string) on ordinary unicast/transit routes.
type ipRouteEntry struct {
	Dst     string `json:"dst"`
	Type    string `json:"type"`
	Dev     string `json:"dev"`
	Gateway string `json:"gateway"`
}

// ParseIPRoutes parses the JSON output of `ip -json route show table all` (or
// plain `ip -json route`) into a slice of Routes.
//
// Callers must feed `ip -json route show table all` to catch policy-routed VPN
// routes that the main table omits. On aibox03, tailscale uses table 52;
// `ip -json route` (main table only) misses those entries entirely. The blessed
// capture command is: ip -json route show table all
//
// Entries whose type field is anything other than "" or "unicast" are skipped.
// Those entries (local, broadcast, multicast) are interface addresses or
// non-forwarding entries, not transit routes, and would cause false exclusions.
//
// "default" in the dst field is converted to 0.0.0.0/0.
// Entries without a "type" field (the common case) keep parsing unchanged.
func ParseIPRoutes(jsonOut []byte) ([]Route, error) {
	var entries []ipRouteEntry
	if err := json.Unmarshal(jsonOut, &entries); err != nil {
		return nil, fmt.Errorf("parse ip route json: %w", err)
	}
	routes := make([]Route, 0, len(entries))
	for _, e := range entries {
		// Skip non-unicast entries: local, broadcast, multicast are interface
		// addresses or non-forwarding entries, not transit routes.
		if e.Type != "" && e.Type != "unicast" {
			continue
		}
		dst := e.Dst
		if dst == "default" {
			dst = "0.0.0.0/0"
		}
		// `ip route` may emit a bare host address (no CIDR suffix) for host routes.
		// Attempt prefix parse first; fall back to address parse with /32.
		var p netip.Prefix
		if pp, err := netip.ParsePrefix(dst); err == nil {
			p = pp.Masked()
		} else if addr, err2 := netip.ParseAddr(dst); err2 == nil {
			p = netip.PrefixFrom(addr, addr.BitLen())
		} else {
			return nil, fmt.Errorf("parse prefix %q: %w", e.Dst, err)
		}
		routes = append(routes, Route{Dst: p, Dev: e.Dev, Gateway: e.Gateway})
	}
	return routes, nil
}

// ErrAllPoolsOverlap is returned by NewAllocator when every provided pool
// overlaps at least one host route and no usable pool remains.
var ErrAllPoolsOverlap = errors.New("network: all pools overlap host routes; no usable pool")

// ErrPoolExhausted is returned by Acquire when all /30s in all pools have been allocated.
var ErrPoolExhausted = errors.New("network: all /30 subnets exhausted")

// Allocator caches VM leases reconstructed from provisioning manifests.
// Acquisition, restoration and release are atomic; callers release only after
// durable teardown. This cache is not a second ownership database.
type Allocator struct {
	mu         sync.Mutex
	pools      []netip.Prefix
	exclusions []string
	leases     map[string]netip.Prefix
	occupied   map[netip.Prefix]string
}

// ExcludeOwnedRoutes removes only a direct route whose prefix and interface
// match a validated provisioning manifest. Similar names and foreign routes
// remain collision evidence, including routes with a gateway.
func ExcludeOwnedRoutes(routes []Route, leases map[string]netip.Prefix) []Route {
	owned := make(map[string]netip.Prefix, len(leases))
	for vmID, p := range leases {
		owned[VethName(vmID)] = p
	}
	result := make([]Route, 0, len(routes))
	for _, r := range routes {
		if p, ok := owned[r.Dev]; ok && p == r.Dst && r.Gateway == "" {
			continue
		}
		result = append(result, r)
	}
	return result
}

// NewAllocator constructs an Allocator from the given host routes and pool prefixes.
// Pools that overlap any non-default host route are excluded and recorded.
// Returns a recovery-only allocator and ErrAllPoolsOverlap if no usable pool
// remains. That allocator can restore and release ownership but has no free pool.
//
// All pools must be plain IPv4 (Addr().Is4() == true). IPv4-in-IPv6 mapped
// form (Is4In6()) is also rejected. The internal /30 arithmetic (As4, addUint32,
// lastAddr) requires an unambiguously IPv4 address; any other form silently mis-allocates.
//
// The default route (0.0.0.0/0) is always skipped during overlap checks. Every
// host has a default route; including it in overlap detection would exclude all
// pools and make the allocator impossible to construct. §10.1's intent is catching
// LAN/VPN collisions; the overlap check covers whatever routes the caller supplies.
// Callers must feed `ip -json route show table all` because the main table misses
// policy-routed VPNs (tailscale uses table 52 on aibox03).
func NewAllocator(hostRoutes []Route, pools []netip.Prefix) (*Allocator, error) {
	var usable []netip.Prefix
	var exclusions []string

	for _, pool := range pools {
		if !pool.Addr().Is4() {
			return nil, fmt.Errorf("network: pool %s is not plain IPv4; /30 arithmetic requires plain IPv4 pools (IPv4-in-IPv6 mapped form is also rejected)", pool)
		}
	}

	for _, pool := range pools {
		overlaps := false
		for _, r := range hostRoutes {
			// Skip the default route: 0.0.0.0/0 mathematically contains every
			// address and would exclude every pool, defeating §10.1's purpose.
			if r.Dst.Bits() == 0 {
				continue
			}
			if prefixesOverlap(pool, r.Dst) {
				overlaps = true
				exclusions = append(exclusions, fmt.Sprintf("%s overlaps host route %s", pool, r.Dst))
				break
			}
		}
		if !overlaps {
			usable = append(usable, pool)
		}
	}

	a := &Allocator{
		pools:      usable,
		exclusions: exclusions,
	}
	a.leases = make(map[string]netip.Prefix)
	a.occupied = make(map[netip.Prefix]string)
	if len(usable) == 0 {
		return a, ErrAllPoolsOverlap
	}
	return a, nil
}

// Exclusions returns descriptions of pools that were excluded due to host-route overlap.
func (a *Allocator) Exclusions() []string {
	return a.exclusions
}

// Acquire returns the owner's existing prefix or reserves the first free /30.
func (a *Allocator) Acquire(vmID string) (netip.Prefix, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vmID == "" {
		return netip.Prefix{}, errors.New("network: lease owner is required")
	}
	if p, ok := a.leases[vmID]; ok {
		return p, nil
	}
	for _, pool := range a.pools {
		for addr := pool.Masked().Addr(); ; {
			p := netip.PrefixFrom(addr, 30)
			if !pool.Contains(addr) || !pool.Contains(lastAddr(p)) {
				break
			}
			if _, taken := a.occupied[p]; !taken {
				a.leases[vmID] = p
				a.occupied[p] = vmID
				return p, nil
			}
			next, overflow := addUint32(addr, 4)
			if overflow {
				break
			}
			addr = next
		}
	}
	return netip.Prefix{}, ErrPoolExhausted
}

// Restore reserves the exact manifest prefix, including prefixes outside today's
// usable pools. Existing resources keep their identity when host routes change.
func (a *Allocator) Restore(vmID string, p netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vmID == "" || !p.Addr().Is4() || p.Bits() != 30 || p != p.Masked() {
		return fmt.Errorf("network: invalid lease %q %s", vmID, p)
	}
	if owner, ok := a.occupied[p]; ok && owner != vmID {
		return fmt.Errorf("network: prefix %s belongs to %s, not %s", p, owner, vmID)
	}
	if old, ok := a.leases[vmID]; ok && old != p {
		return fmt.Errorf("network: owner %s already holds %s, not %s", vmID, old, p)
	}
	a.leases[vmID] = p
	a.occupied[p] = vmID
	return nil
}

// Release forgets the owner only after the caller proves durable teardown.
func (a *Allocator) Release(vmID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if p, ok := a.leases[vmID]; ok {
		delete(a.occupied, p)
		delete(a.leases, vmID)
	}
}

// prefixesOverlap reports whether two prefixes intersect (either contains the
// other's network address, or they are the same range).
func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

// lastAddr returns the last address in the prefix (broadcast for IPv4).
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	ones := p.Bits()
	hostBits := 32 - ones
	mask := (uint32(1) << hostBits) - 1
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	n |= mask
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// addUint32 adds delta to the IPv4 address, returning the result and whether it overflowed.
func addUint32(addr netip.Addr, delta uint32) (netip.Addr, bool) {
	a := addr.As4()
	n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	sum := n + delta
	overflow := sum < n
	return netip.AddrFrom4([4]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}), overflow
}
