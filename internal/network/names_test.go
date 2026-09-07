// ABOUTME: Tests for NamespaceName and VethName — must match the root helper's derivations.
// ABOUTME: The root helper sets ns="vmobs-$id" and derives veth the same sha256-digest way; see VethName.
package network_test

import (
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/network"
)

func TestNamespaceName(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"abc", "vmobs-abc"},
		{"itest-net", "vmobs-itest-net"},
		{"vm-01", "vmobs-vm-01"},
	}
	for _, tt := range tests {
		got := network.NamespaceName(tt.id)
		if got != tt.want {
			t.Errorf("NamespaceName(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestVethName(t *testing.T) {
	// Pinned literals: exact sha256-digest-derived output for fixed inputs,
	// computed once, so the derivation itself (sha256, first 10 hex chars) is
	// pinned against drift. The last case is UUID-shaped (36 chars) — the real
	// shape of production VM ids, and the case that overflowed IFNAMSIZ under
	// the old "veth-"+id scheme.
	tests := []struct {
		id   string
		want string
	}{
		{"abc", "veth-ba7816bf8f"},
		{"itest-net", "veth-4f9408328d"},
		{"vm-01", "veth-154c8e73b6"},
		{"550e8400-e29b-41d4-a716-446655440000", "veth-a3a9e1ed97"},
	}
	for _, tt := range tests {
		got := network.VethName(tt.id)
		if got != tt.want {
			t.Errorf("VethName(%q) = %q, want %q", tt.id, got, tt.want)
		}
		// Every name must fit the kernel's IFNAMSIZ limit (15 usable chars),
		// regardless of input length.
		if len(got) != 15 {
			t.Errorf("VethName(%q) = %q (len %d), want len 15", tt.id, got, len(got))
		}
		if !strings.HasPrefix(got, "veth-") {
			t.Errorf("VethName(%q) = %q, want prefix %q", tt.id, got, "veth-")
		}
	}

	// Deterministic across calls.
	const uuidA = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	if a, b := network.VethName(uuidA), network.VethName(uuidA); a != b {
		t.Errorf("VethName(%q) not deterministic: %q then %q", uuidA, a, b)
	}

	// Distinct ids must produce distinct names.
	const uuidB = "6ba7b811-9dad-11d1-80b4-00c04fd430c8"
	if a, b := network.VethName(uuidA), network.VethName(uuidB); a == b {
		t.Errorf("VethName collision: %q and %q both produced %q", uuidA, uuidB, a)
	}
}
