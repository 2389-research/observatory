// ABOUTME: Tests for transit-subnet allocation with host-route overlap detection.
// ABOUTME: Fixture data is real captured output from aibox03 via `ip -json route`.
package network_test

import (
	_ "embed"
	"net/netip"
	"testing"

	"github.com/2389-research/observatory-v2/internal/network"
)

//go:embed testdata/aibox03-routes.json
var aibox03RoutesJSON []byte

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
	p1, err := a.Next()
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
	p2, err := a.Next()
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
	_, err = a.Next()
	if err != nil {
		t.Fatalf("first Next from /30 pool: %v", err)
	}
	// Second call must fail: pool exhausted.
	_, err = a.Next()
	if err == nil {
		t.Fatal("expected error on exhausted pool, got nil")
	}
}
