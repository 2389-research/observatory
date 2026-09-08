// ABOUTME: Verifies owner leases, restart restoration, and safe route exclusions.
// ABOUTME: Exercises the allocator directly, including concurrent acquisition and small pools.
package network_test

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/2389-research/observatory/internal/network"
)

func TestOwnerLeaseReuseAndRestart(t *testing.T) {
	pool := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/29")}
	a, err := network.NewAllocator(nil, pool)
	if err != nil {
		t.Fatal(err)
	}
	survivor, err := a.Acquire("survivor")
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.Acquire("survivor")
	if err != nil || again != survivor {
		t.Fatalf("same owner: %v %v", again, err)
	}
	a, err = network.NewAllocator(nil, pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Restore("survivor", survivor); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		owner := fmt.Sprintf("vm-%d", i)
		p, err := a.Acquire(owner)
		if err != nil || p == survivor {
			t.Fatalf("iteration %d: %v %v", i, p, err)
		}
		if _, err := a.Acquire("overflow"); !errors.Is(err, network.ErrPoolExhausted) {
			t.Fatalf("exhaustion: %v", err)
		}
		a.Release(owner)
	}
	if err := a.Restore("other", survivor); err == nil {
		t.Fatal("duplicate restoration accepted")
	}
	if err := a.Restore("survivor", netip.MustParsePrefix("10.0.0.4/30")); err == nil {
		t.Fatal("owner reassignment accepted")
	}
}

func TestAcquireConcurrentOwners(t *testing.T) {
	a, err := network.NewAllocator(nil, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan netip.Prefix, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, e := a.Acquire(fmt.Sprint(i))
			if e != nil {
				t.Error(e)
				return
			}
			results <- p
		}()
	}
	wg.Wait()
	close(results)
	seen := map[netip.Prefix]bool{}
	for p := range results {
		if seen[p] {
			t.Errorf("duplicate prefix %s", p)
		}
		seen[p] = true
	}
	if len(seen) != 64 {
		t.Fatalf("got %d leases", len(seen))
	}
}

func TestOwnedRoutesRequireExactManifestIdentity(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/30")
	dev := network.VethName("survivor")
	raw := fmt.Sprintf(`[{"dst":"10.0.0.0/30","dev":%q},{"dst":"10.0.0.4/30","dev":%q},{"dst":"10.0.0.0/30","dev":"tailscale0"},{"dst":"10.0.0.0/30","dev":%q,"gateway":"10.2.0.1"}]`, dev, dev, dev)
	routes, err := network.ParseIPRoutes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	filtered := network.ExcludeOwnedRoutes(routes, map[string]netip.Prefix{"survivor": cidr})
	if len(filtered) != 3 {
		t.Fatalf("retained routes: %v", filtered)
	}
	if _, err := network.NewAllocator(filtered, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}); !errors.Is(err, network.ErrAllPoolsOverlap) {
		t.Fatalf("foreign route exclusion lost: %v", err)
	}
	filtered = network.ExcludeOwnedRoutes(routes[:1], map[string]netip.Prefix{"survivor": cidr})
	if _, err := network.NewAllocator(filtered, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}); err != nil {
		t.Fatal(err)
	}
}

func TestExcludedPoolsKeepRecoveryAllocator(t *testing.T) {
	pool := netip.MustParsePrefix("10.0.0.0/29")
	a, err := network.NewAllocator([]network.Route{{Dst: pool}}, []netip.Prefix{pool})
	if !errors.Is(err, network.ErrAllPoolsOverlap) {
		t.Fatalf("expected unusable pool error: %v", err)
	}
	if a == nil {
		t.Fatal("excluded pools must retain an allocator for ownership recovery")
	}
	held := netip.MustParsePrefix("10.0.0.0/30")
	if err := a.Restore("survivor", held); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Acquire("successor"); !errors.Is(err, network.ErrPoolExhausted) {
		t.Fatalf("excluded pool allocated: %v", err)
	}
	a.Release("survivor")
	if _, err := a.Acquire("successor"); !errors.Is(err, network.ErrPoolExhausted) {
		t.Fatalf("recovery release enabled excluded pool: %v", err)
	}
}
