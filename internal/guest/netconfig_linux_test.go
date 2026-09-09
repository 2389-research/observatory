// ABOUTME: Exercises guest eth0 static configuration against a real Linux network stack.
// ABOUTME: The component case runs only in an explicitly isolated disposable container.
//go:build linux

package guest_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/guest"
)

func TestConfigureNetworkHonorsCanceledContext(t *testing.T) {
	cfg, err := guest.NewNetworkConfig("vm-test", netip.MustParsePrefix("10.190.4.8/30"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := guest.ConfigureNetwork(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("ConfigureNetwork error = %v, want context canceled", err)
	}
}

func TestConfigureNetworkRequiresDeadline(t *testing.T) {
	cfg, err := guest.NewNetworkConfig("vm-test", netip.MustParsePrefix("10.190.4.8/30"))
	if err != nil {
		t.Fatal(err)
	}
	if err := guest.ConfigureNetwork(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("ConfigureNetwork error = %v, want required deadline", err)
	}
}

func TestConfigureNetworkRealIsolatedLinux(t *testing.T) {
	if os.Getenv("VMOBS_GUEST_NETWORK_TEST") != "1" {
		t.Skip("set VMOBS_GUEST_NETWORK_TEST=1 inside a disposable isolated Linux container")
	}
	if os.Geteuid() != 0 {
		t.Skip("real network setup requires root in the disposable container")
	}

	cfg, err := guest.NewNetworkConfig("vm-test", netip.MustParsePrefix("10.190.4.8/30"))
	if err != nil {
		t.Fatal(err)
	}
	eth0, err := net.InterfaceByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	bad := cfg
	bad.MAC = "02:00:00:00:00:01"
	badCtx, badCancel := context.WithTimeout(context.Background(), 5*time.Second)
	badErr := guest.ConfigureNetwork(badCtx, bad)
	badCancel()
	if badErr == nil || !strings.Contains(badErr.Error(), "MAC") {
		t.Fatalf("mismatched MAC error = %v", badErr)
	}
	cfg.MAC = eth0.HardwareAddr.String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := guest.ConfigureNetwork(ctx, cfg); err != nil {
		t.Fatalf("ConfigureNetwork: %v", err)
	}

	addrs, err := eth0.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, addr := range addrs {
		if addr.String() == cfg.Address {
			found = true
		}
	}
	if !found || eth0.Flags&net.FlagUp == 0 {
		t.Fatalf("eth0 flags=%v addrs=%v, want up with %s", eth0.Flags, addrs, cfg.Address)
	}
	routes, err := os.ReadFile("/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(routes), "eth0\t00000000\t01FF1FAC\t") {
		t.Fatalf("default route through %s missing:\n%s", cfg.Gateway, routes)
	}
	resolver, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		t.Fatal(err)
	}
	if string(resolver) != "nameserver 172.31.255.1\n" {
		t.Fatalf("resolv.conf = %q", resolver)
	}
}
