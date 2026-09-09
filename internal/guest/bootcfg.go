// ABOUTME: BootConfig type and loader for the config device (context.json).
// ABOUTME: LoadBootConfigDir validates all required fields and version; LoadBootConfig mounts then delegates.
package guest

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/2389-research/observatory/internal/guest/proto"
	"github.com/2389-research/observatory/internal/network"
)

// GuestContextSchema is the canonical schema field value for context.json.
// The host mints the file; the guest validates this exact string on load.
const GuestContextSchema = "vmobs.guest_context.v1"

// BootConfig holds the per-boot context injected via the config device.
// The JSON schema value is GuestContextSchema; all fields are required non-empty.
type BootConfig struct {
	Schema          string        `json:"schema"`
	VMID            string        `json:"vm_id"`
	BootID          string        `json:"boot_id"`
	CapabilityToken string        `json:"capability_token"`
	ProtocolVersion int           `json:"protocol_version"`
	Network         NetworkConfig `json:"network"`
}

// NetworkConfig is the host-minted static link configuration for eth0. The
// transit prefix binds it to the allocated host layout even though the guest
// installs only the isolated guest-link address, route, and resolver.
type NetworkConfig struct {
	TransitPrefix string `json:"transit_prefix"`
	Address       string `json:"address"`
	Gateway       string `json:"gateway"`
	DNS           string `json:"dns"`
	MAC           string `json:"mac"`
}

// NewNetworkConfig derives the guest boot contract from the shared network
// layout. Callers must not construct or repeat these address constants.
func NewNetworkConfig(vmID string, transit netip.Prefix) (NetworkConfig, error) {
	layout, err := network.NewLayout(vmID, transit)
	if err != nil {
		return NetworkConfig{}, err
	}
	return NetworkConfig{
		TransitPrefix: layout.TransitPrefix.String(),
		Address:       netip.PrefixFrom(layout.GuestAddress, layout.GuestPrefix.Bits()).String(),
		Gateway:       layout.GuestGateway.String(),
		DNS:           layout.GuestGateway.String(),
		MAC:           layout.GuestMAC.String(),
	}, nil
}

// configFileName is the file inside the config device directory.
const configFileName = "context.json"

// LoadBootConfigDir reads and validates context.json from dir.
func LoadBootConfigDir(dir string) (*BootConfig, error) {
	data, err := os.ReadFile(filepath.Join(dir, configFileName))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", configFileName, err)
	}
	var cfg BootConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", configFileName, err)
	}
	if err := validateBootConfig(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validateBootConfig returns an error naming any missing or invalid field.
func validateBootConfig(cfg *BootConfig) error {
	if cfg.Schema != GuestContextSchema {
		return fmt.Errorf("boot config: schema mismatch: got %q, want %q", cfg.Schema, GuestContextSchema)
	}
	if cfg.VMID == "" {
		return fmt.Errorf("boot config: field 'vm_id' is required but empty")
	}
	if cfg.BootID == "" {
		return fmt.Errorf("boot config: field 'boot_id' is required but empty")
	}
	if cfg.CapabilityToken == "" {
		return fmt.Errorf("boot config: field 'capability_token' is required but empty")
	}
	if cfg.ProtocolVersion != proto.ProtocolVersion {
		return fmt.Errorf("boot config: protocol_version mismatch: got %d, want %d",
			cfg.ProtocolVersion, proto.ProtocolVersion)
	}
	if err := validateNetworkConfig(cfg.VMID, cfg.Network); err != nil {
		return err
	}
	return nil
}

func validateNetworkConfig(vmID string, cfg NetworkConfig) error {
	transit, err := netip.ParsePrefix(cfg.TransitPrefix)
	if err != nil {
		return fmt.Errorf("boot config: network.transit_prefix %q is invalid: %w", cfg.TransitPrefix, err)
	}
	want, err := NewNetworkConfig(vmID, transit)
	if err != nil {
		return fmt.Errorf("boot config: network.transit_prefix: %w", err)
	}
	checks := []struct {
		name      string
		got, want string
	}{
		{name: "transit_prefix", got: cfg.TransitPrefix, want: want.TransitPrefix},
		{name: "address", got: cfg.Address, want: want.Address},
		{name: "gateway", got: cfg.Gateway, want: want.Gateway},
		{name: "dns", got: cfg.DNS, want: want.DNS},
		{name: "mac", got: cfg.MAC, want: want.MAC},
	}
	for _, check := range checks {
		if check.got != check.want {
			return fmt.Errorf("boot config: network.%s mismatch: got %q, want %q", check.name, check.got, check.want)
		}
	}
	return nil
}
