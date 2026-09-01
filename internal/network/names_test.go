// ABOUTME: Tests for NamespaceName and VethName — must match the root helper's derivations.
// ABOUTME: The root helper sets ns="vmobs-$id" and veth="veth-$id"; these must be character-for-character equal.
package network_test

import (
	"testing"

	"github.com/2389-research/observatory-v2/internal/network"
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
	tests := []struct {
		id   string
		want string
	}{
		{"abc", "veth-abc"},
		{"itest-net", "veth-itest-net"},
		{"vm-01", "veth-vm-01"},
	}
	for _, tt := range tests {
		got := network.VethName(tt.id)
		if got != tt.want {
			t.Errorf("VethName(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}
