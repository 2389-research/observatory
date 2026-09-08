// ABOUTME: Derives the one authoritative routed namespace and guest link layout.
// ABOUTME: Rejects invalid ownership or transit input before privileged setup.
package network

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
)

var guestLinkPrefix = netip.MustParsePrefix("172.31.255.0/30")

// MACAddress is a copyable Ethernet address. Its array representation prevents
// a caller from mutating a validated Layout through a shared slice.
type MACAddress [6]byte

func (address MACAddress) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", address[0], address[1], address[2], address[3], address[4], address[5])
}

// Layout is the complete address and guest Ethernet identity derived for one VM.
// Both transit addresses and both guest-link addresses use their corresponding
// /30 prefix when installed on an interface.
type Layout struct {
	TransitPrefix    netip.Prefix
	TransitHost      netip.Addr
	TransitNamespace netip.Addr
	GuestPrefix      netip.Prefix
	GuestGateway     netip.Addr
	GuestAddress     netip.Addr
	GuestMAC         MACAddress
}

// NewLayout validates an existing transit lease and derives every address used
// by the routed namespace. VM identity follows the privilege boundary's current
// contract: 1-63 lowercase ASCII letters, digits, or hyphens, starting with a
// letter or digit.
func NewLayout(vmID string, transit netip.Prefix) (Layout, error) {
	if !validVMID(vmID) {
		return Layout{}, fmt.Errorf("network: invalid VM id %q", vmID)
	}
	if !transit.IsValid() || !transit.Addr().Is4() || transit.Addr().Is4In6() || transit.Addr().Zone() != "" {
		return Layout{}, fmt.Errorf("network: transit prefix %s is not native unscoped IPv4", transit)
	}
	if transit.Bits() != 30 {
		return Layout{}, fmt.Errorf("network: transit prefix %s is not a /30", transit)
	}
	if transit != transit.Masked() {
		return Layout{}, fmt.Errorf("network: transit prefix %s is not canonical", transit)
	}
	if prefixesOverlap(transit, guestLinkPrefix) {
		return Layout{}, fmt.Errorf("network: transit prefix %s overlaps isolated guest link %s", transit, guestLinkPrefix)
	}

	sum := sha256.Sum256([]byte(vmID))
	var guestMAC MACAddress
	copy(guestMAC[:], sum[:6])
	guestMAC[0] = guestMAC[0]&0xfe | 0x02

	return Layout{
		TransitPrefix:    transit,
		TransitHost:      transit.Addr().Next(),
		TransitNamespace: transit.Addr().Next().Next(),
		GuestPrefix:      guestLinkPrefix,
		GuestGateway:     guestLinkPrefix.Addr().Next(),
		GuestAddress:     guestLinkPrefix.Addr().Next().Next(),
		GuestMAC:         guestMAC,
	}, nil
}

func validVMID(id string) bool {
	if len(id) == 0 || len(id) > 63 || !asciiLowerOrDigit(id[0]) {
		return false
	}
	for i := 1; i < len(id); i++ {
		if !asciiLowerOrDigit(id[i]) && id[i] != '-' {
			return false
		}
	}
	return true
}

func asciiLowerOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}
