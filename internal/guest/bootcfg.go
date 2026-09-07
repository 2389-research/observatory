// ABOUTME: BootConfig type and loader for the config device (context.json).
// ABOUTME: LoadBootConfigDir validates all required fields and version; LoadBootConfig mounts then delegates.
package guest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/2389-research/observatory/internal/guest/proto"
)

// GuestContextSchema is the canonical schema field value for context.json.
// The host mints the file; the guest validates this exact string on load.
const GuestContextSchema = "vmobs.guest_context.v1"

// BootConfig holds the per-boot context injected via the config device.
// The JSON schema value is GuestContextSchema; all fields are required non-empty.
// Task 6 will import this type and marshal it to produce context.json.
type BootConfig struct {
	Schema          string `json:"schema"`
	VMID            string `json:"vm_id"`
	BootID          string `json:"boot_id"`
	CapabilityToken string `json:"capability_token"`
	ProtocolVersion int    `json:"protocol_version"`
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
	return nil
}
