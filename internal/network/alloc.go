// ABOUTME: Transit-subnet allocator with host-route overlap detection (§10.1).
// ABOUTME: Carves sequential /30s from non-overlapping pools; uses netip throughout.
package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
)

// Route represents a single entry from `ip -json route` output.
type Route struct {
	Dst netip.Prefix
}

// ipRouteEntry is the raw JSON shape produced by `ip -json route`.
type ipRouteEntry struct {
	Dst string `json:"dst"`
}

// ParseIPRoutes parses the JSON output of `ip -json route` into a slice of Routes.
// "default" in the dst field is converted to 0.0.0.0/0.
func ParseIPRoutes(jsonOut []byte) ([]Route, error) {
	var entries []ipRouteEntry
	if err := json.Unmarshal(jsonOut, &entries); err != nil {
		return nil, fmt.Errorf("parse ip route json: %w", err)
	}
	routes := make([]Route, 0, len(entries))
	for _, e := range entries {
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
		routes = append(routes, Route{Dst: p})
	}
	return routes, nil
}

// ErrAllPoolsOverlap is returned by NewAllocator when every provided pool
// overlaps at least one host route and no usable pool remains.
var ErrAllPoolsOverlap = errors.New("network: all pools overlap host routes; no usable pool")

// ErrPoolExhausted is returned by Next when all /30s in all pools have been allocated.
var ErrPoolExhausted = errors.New("network: all /30 subnets exhausted")

// Allocator hands out sequential /30 prefixes from a set of pool prefixes that
// do not conflict with host routing table entries.
type Allocator struct {
	// pools are the non-overlapping pools, in order.
	pools      []netip.Prefix
	exclusions []string
	// cursor into pools and within the current pool.
	poolIdx int
	next    netip.Addr // first address of the next /30 to hand out
}

// NewAllocator constructs an Allocator from the given host routes and pool prefixes.
// Pools that overlap any non-default host route are excluded and recorded.
// Returns ErrAllPoolsOverlap if no usable pool remains after exclusion.
//
// The default route (0.0.0.0/0) is always skipped during overlap checks. Every
// host has a default route; including it in overlap detection would exclude all
// pools and make the allocator impossible to construct, which is not the intent
// of §10.1 (catching LAN/VPN collisions).
func NewAllocator(hostRoutes []Route, pools []netip.Prefix) (*Allocator, error) {
	var usable []netip.Prefix
	var exclusions []string

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

	if len(usable) == 0 {
		return nil, ErrAllPoolsOverlap
	}

	a := &Allocator{
		pools:      usable,
		exclusions: exclusions,
	}
	a.next = usable[0].Masked().Addr()
	return a, nil
}

// Exclusions returns descriptions of pools that were excluded due to host-route overlap.
func (a *Allocator) Exclusions() []string {
	return a.exclusions
}

// Next returns the next available /30 prefix, advancing the cursor.
// Returns ErrPoolExhausted when all pools are consumed.
func (a *Allocator) Next() (netip.Prefix, error) {
	const bits = 30
	blockSize := uint32(1) << (32 - bits) // 4 addresses per /30

	for a.poolIdx < len(a.pools) {
		pool := a.pools[a.poolIdx]
		candidate, ok := netip.AddrFromSlice(a.next.AsSlice())
		if !ok {
			return netip.Prefix{}, fmt.Errorf("internal: bad cursor address")
		}
		candidate = candidate.Unmap()
		// Build the candidate prefix anchored at the cursor.
		p, err := candidate.Prefix(bits)
		if err != nil {
			return netip.Prefix{}, err
		}
		p = p.Masked()

		// Advance cursor for next call.
		nextAddr, overflow := addUint32(p.Addr(), blockSize)
		a.next = nextAddr

		// If the candidate fits in the current pool, return it.
		if pool.Contains(p.Addr()) && pool.Contains(lastAddr(p)) {
			return p, nil
		}

		// Candidate is outside the current pool; move to next pool.
		a.poolIdx++
		if a.poolIdx < len(a.pools) {
			a.next = a.pools[a.poolIdx].Masked().Addr()
		}
		_ = overflow
	}

	return netip.Prefix{}, ErrPoolExhausted
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
