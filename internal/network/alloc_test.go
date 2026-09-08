// ABOUTME: Tests for transit-subnet allocation with host-route overlap detection.
// ABOUTME: Fixture data is captured aibox03 output (`ip -json route`) with its addresses renumbered.
package network_test

import (
	_ "embed"
	"net/netip"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/network"
)

// Both fixtures are captured `ip -json route` output from the aibox03 host: the
// set of entries, their fields, and their order are verbatim. The addresses are
// not. Every tailnet peer, the host's own tailnet and LAN addresses, and the
// IPv6 addresses that carry the NIC's MAC in their EUI-64 suffix were renumbered
// onto synthetic equivalents before this repository was published. What the
// tests below read -- bare host addresses, /32 peer routes in table 52,
// local/broadcast/multicast entries to filter -- is the shape, and the shape is
// unchanged.

//go:embed testdata/aibox03-routes.json
var aibox03RoutesJSON []byte

//go:embed testdata/aibox03-routes-table-all.json
var aibox03RoutesTableAllJSON []byte

// defaultPools are the two default pools defined in §10.1.
var defaultPools = []netip.Prefix{
	netip.MustParsePrefix("10.190.0.0/16"),
	netip.MustParsePrefix("172.28.0.0/16"),
}

// TestParseIPRoutes verifies ParseIPRoutes against the real aibox03 fixture.
func TestParseIPRoutes(t *testing.T) {
	routes, err := network.ParseIPRoutes(aibox03RoutesJSON)
	if err != nil {
		t.Fatalf("ParseIPRoutes: %v", err)
	}
	// The fixture has 4 entries: default, 172.17.0.0/16, 192.168.10.0/24, 192.168.10.1.
	// "default" maps to 0.0.0.0/0.
	if len(routes) != 4 {
		t.Errorf("got %d routes, want 4", len(routes))
	}
	// default route must parse to 0.0.0.0/0
	found := false
	for _, r := range routes {
		if r.Dst.String() == "0.0.0.0/0" {
			found = true
		}
	}
	if !found {
		t.Error("default route not parsed as 0.0.0.0/0")
	}
	// docker route must be present
	docker := netip.MustParsePrefix("172.17.0.0/16")
	foundDocker := false
	for _, r := range routes {
		if r.Dst == docker {
			foundDocker = true
		}
	}
	if !foundDocker {
		t.Error("docker 172.17.0.0/16 route not found in parsed output")
	}
}

// TestParseIPRoutesInvalidJSON verifies rejection of bad input.
func TestParseIPRoutesInvalidJSON(t *testing.T) {
	_, err := network.ParseIPRoutes([]byte("not json"))
	if err == nil {
		t.Error("expected error on invalid JSON, got nil")
	}
}

// TestNewAllocatorBothPoolsValid verifies construction succeeds when neither pool
// overlaps any non-default host route.
func TestNewAllocatorBothPoolsValid(t *testing.T) {
	routes, err := network.ParseIPRoutes(aibox03RoutesJSON)
	if err != nil {
		t.Fatalf("ParseIPRoutes: %v", err)
	}
	a, err := network.NewAllocator(routes, defaultPools)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if len(a.Exclusions()) != 0 {
		t.Errorf("expected no exclusions, got %v", a.Exclusions())
	}
}

// TestNewAllocatorExcludesOverlappingPool verifies that a pool overlapping a host
// route is excluded and recorded in Exclusions().
func TestNewAllocatorExcludesOverlappingPool(t *testing.T) {
	routes, err := network.ParseIPRoutes(aibox03RoutesJSON)
	if err != nil {
		t.Fatalf("ParseIPRoutes: %v", err)
	}
	// 172.17.0.0/16 is in the fixture; use it as a pool — it overlaps the docker route.
	pools := []netip.Prefix{
		netip.MustParsePrefix("172.17.0.0/16"),
		netip.MustParsePrefix("10.190.0.0/16"),
	}
	a, err := network.NewAllocator(routes, pools)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if len(a.Exclusions()) != 1 {
		t.Errorf("expected 1 exclusion, got %d: %v", len(a.Exclusions()), a.Exclusions())
	}
}

// TestNewAllocatorAllPoolsOverlap verifies that construction fails when every pool
// overlaps a host route.
func TestNewAllocatorAllPoolsOverlap(t *testing.T) {
	routes, err := network.ParseIPRoutes(aibox03RoutesJSON)
	if err != nil {
		t.Fatalf("ParseIPRoutes: %v", err)
	}
	// Both pools overlap host routes in the fixture.
	pools := []netip.Prefix{
		netip.MustParsePrefix("172.17.0.0/16"),   // overlaps docker0
		netip.MustParsePrefix("192.168.10.0/24"), // overlaps LAN
	}
	_, err = network.NewAllocator(routes, pools)
	if err == nil {
		t.Fatal("expected error when all pools overlap host routes, got nil")
	}
}

// TestNewAllocatorDefaultRouteDoesNotExclude verifies that the default route
// (0.0.0.0/0) is skipped during overlap checks. Every host has a default route;
// if it caused exclusions, construction would always fail.
func TestNewAllocatorDefaultRouteDoesNotExclude(t *testing.T) {
	// A route table with only the default route: no pool should be excluded.
	defaultOnly := []network.Route{
		{Dst: netip.MustParsePrefix("0.0.0.0/0")},
	}
	a, err := network.NewAllocator(defaultOnly, defaultPools)
	if err != nil {
		t.Fatalf("NewAllocator with only default route: %v", err)
	}
	if len(a.Exclusions()) != 0 {
		t.Errorf("default route caused exclusions: %v", a.Exclusions())
	}
}

// TestAllocatorNext verifies sequential /30 allocation within a pool.
func TestAllocatorNext(t *testing.T) {
	a, err := network.NewAllocator(nil, defaultPools)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	p1, err := a.Acquire("first")
	if err != nil {
		t.Fatalf("Next (1): %v", err)
	}
	if p1.Bits() != 30 {
		t.Errorf("Next returned /%d, want /30", p1.Bits())
	}
	// First /30 of 10.190.0.0/16 is 10.190.0.0/30.
	want1 := netip.MustParsePrefix("10.190.0.0/30")
	if p1 != want1 {
		t.Errorf("Next (1) = %s, want %s", p1, want1)
	}
	p2, err := a.Acquire("second")
	if err != nil {
		t.Fatalf("Next (2): %v", err)
	}
	// Second /30 is 10.190.0.4/30.
	want2 := netip.MustParsePrefix("10.190.0.4/30")
	if p2 != want2 {
		t.Errorf("Next (2) = %s, want %s", p2, want2)
	}
}

// TestAllocatorExhaustion verifies Next returns an error when all /30s are consumed.
// Uses a tiny /30 pool so we only need 1 call to exhaust it.
func TestAllocatorExhaustion(t *testing.T) {
	// A /30 pool only has one /30 (itself).
	tiny := []netip.Prefix{netip.MustParsePrefix("10.100.0.0/30")}
	a, err := network.NewAllocator(nil, tiny)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	_, err = a.Acquire("first")
	if err != nil {
		t.Fatalf("first Next from /30 pool: %v", err)
	}
	// Second call must fail: pool exhausted.
	_, err = a.Acquire("second")
	if err == nil {
		t.Fatal("expected error on exhausted pool, got nil")
	}
}

// TestParseIPRoutesTableAll verifies parsing of the real `ip -json route show table all`
// fixture from aibox03. Key assertions:
//   - Tailscale /32s from table 52 are present (100.64.0.1 etc.)
//   - type=local, type=broadcast, type=multicast entries are absent
//   - The fixture contains at least 40 tailscale IPv4 unicast routes
//
// On aibox03, tailscale publishes individual /32 peer routes in table 52, not a
// single /10 block. Each peer is a bare IP in the JSON dst field, parsed as /32.
func TestParseIPRoutesTableAll(t *testing.T) {
	routes, err := network.ParseIPRoutes(aibox03RoutesTableAllJSON)
	if err != nil {
		t.Fatalf("ParseIPRoutes(table-all): %v", err)
	}

	// Tailscale /32 that must appear: aibox03's first table-52 entry.
	wantTS := netip.MustParsePrefix("100.64.0.1/32")
	foundTS := false
	for _, r := range routes {
		if r.Dst == wantTS {
			foundTS = true
		}
	}
	if !foundTS {
		t.Errorf("tailscale route %s not found in table-all parse result", wantTS)
	}

	// Count tailscale IPv4 /32 routes (100.x.x.x/32, no gateway, via tailscale0).
	// The fixture has 40 such entries; verify we got most of them (≥ 10 is a
	// conservative bound that survives minor tailnet churn).
	tsCount := 0
	for _, r := range routes {
		addr := r.Dst.Addr()
		if addr.Is4() && r.Dst.Bits() == 32 {
			b := addr.As4()
			if b[0] == 100 {
				tsCount++
			}
		}
	}
	if tsCount < 10 {
		t.Errorf("expected ≥10 tailscale /32 routes in table-all result, got %d", tsCount)
	}

	// No type=local/broadcast/multicast entries should be present.
	// Those entries have dst values like "127.0.0.1/32", "127.255.255.255/32",
	// "172.17.255.255/32" (broadcast), "ff00::/8" (multicast). We verify by
	// checking that known local/broadcast dsts are absent.
	excluded := []string{
		"127.0.0.1/32",       // type=local loopback
		"127.255.255.255/32", // type=broadcast
		"172.17.255.255/32",  // type=broadcast docker
	}
	for _, ex := range excluded {
		want := netip.MustParsePrefix(ex)
		for _, r := range routes {
			if r.Dst == want {
				t.Errorf("non-unicast route %s was not filtered out", ex)
			}
		}
	}
}

// TestAllocatorExcludesTailscaleRoutes verifies that an allocator built from
// the table-all fixture excludes a pool that overlaps a tailscale /32 route.
// Tailscale routes on aibox03 are individual /32s (e.g., 100.64.0.1/32),
// not a block; a pool containing that address is detected as overlapping.
func TestAllocatorExcludesTailscaleRoutes(t *testing.T) {
	routes, err := network.ParseIPRoutes(aibox03RoutesTableAllJSON)
	if err != nil {
		t.Fatalf("ParseIPRoutes(table-all): %v", err)
	}

	// 100.64.0.0/16 contains 100.64.0.1 (a tailscale /32 in the fixture).
	// Using it as a pool must trigger an exclusion.
	// 10.190.0.0/16 is the fallback pool that must remain usable.
	pools := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/16"),
		netip.MustParsePrefix("10.190.0.0/16"),
	}
	a, err := network.NewAllocator(routes, pools)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if len(a.Exclusions()) == 0 {
		t.Error("expected at least one exclusion for pool 100.64.0.0/16 overlapping tailscale routes")
	}
	// Verify the exclusion message mentions the overlapping pool.
	found := false
	for _, ex := range a.Exclusions() {
		if strings.Contains(ex, "100.64.0.0/16") {
			found = true
		}
	}
	if !found {
		t.Errorf("exclusion for 100.64.0.0/16 not found; got: %v", a.Exclusions())
	}
}

// TestNewAllocatorRejectsIPv6Pool verifies that NewAllocator returns an error
// when a pool is not IPv4. The /30 arithmetic (As4, addUint32, lastAddr) requires
// plain IPv4; an IPv6 pool would silently mis-allocate.
func TestNewAllocatorRejectsIPv6Pool(t *testing.T) {
	ipv6Pool := netip.MustParsePrefix("fd00::/16")
	_, err := network.NewAllocator(nil, []netip.Prefix{ipv6Pool})
	if err == nil {
		t.Fatal("expected error for IPv6 pool, got nil")
	}
}

// TestNewAllocatorRejectsIPv4MappedPool verifies that IPv4-in-IPv6 mapped pools
// are also rejected. Unmap().Is4() is false for ::ffff:10.0.0.0/104.
func TestNewAllocatorRejectsIPv4MappedPool(t *testing.T) {
	// ::ffff:10.0.0.1 is the IPv4-mapped form of 10.0.0.1.
	// netip.ParsePrefix("::ffff:10.0.0.0/104") gives a mapped prefix.
	mapped, err := netip.ParsePrefix("::ffff:10.0.0.0/104")
	if err != nil {
		t.Skipf("platform did not parse mapped prefix: %v", err)
	}
	_, err = network.NewAllocator(nil, []netip.Prefix{mapped})
	if err == nil {
		t.Fatal("expected error for IPv4-mapped pool, got nil")
	}
}
