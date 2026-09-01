// ABOUTME: Tests for BootConfig loading: valid config, missing fields, version mismatch.
// ABOUTME: Uses real tempdir files — no mocks.
package guest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/guest"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
)

func writeContextJSON(t *testing.T, dir string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "context.json"), b, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestLoadBootConfigDirValid(t *testing.T) {
	dir := t.TempDir()
	writeContextJSON(t, dir, map[string]any{
		"schema":           "vmobs.guest_context.v1",
		"vm_id":            "vm-abc",
		"boot_id":          "boot-xyz",
		"capability_token": "tok-123",
		"protocol_version": proto.ProtocolVersion,
	})

	cfg, err := guest.LoadBootConfigDir(dir)
	if err != nil {
		t.Fatalf("LoadBootConfigDir: %v", err)
	}
	if cfg.Schema != "vmobs.guest_context.v1" {
		t.Errorf("Schema: got %q", cfg.Schema)
	}
	if cfg.VMID != "vm-abc" {
		t.Errorf("VMID: got %q", cfg.VMID)
	}
	if cfg.BootID != "boot-xyz" {
		t.Errorf("BootID: got %q", cfg.BootID)
	}
	if cfg.CapabilityToken != "tok-123" {
		t.Errorf("CapabilityToken: unexpected value (not logging)")
	}
	if cfg.ProtocolVersion != proto.ProtocolVersion {
		t.Errorf("ProtocolVersion: got %d, want %d", cfg.ProtocolVersion, proto.ProtocolVersion)
	}
}

func TestLoadBootConfigDirMissingSchema(t *testing.T) {
	dir := t.TempDir()
	writeContextJSON(t, dir, map[string]any{
		"vm_id":            "vm-abc",
		"boot_id":          "boot-xyz",
		"capability_token": "tok-123",
		"protocol_version": proto.ProtocolVersion,
	})
	_, err := guest.LoadBootConfigDir(dir)
	if err == nil {
		t.Fatal("want error for missing schema field")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("want error mentioning 'schema', got: %v", err)
	}
}

func TestLoadBootConfigDirMissingVMID(t *testing.T) {
	dir := t.TempDir()
	writeContextJSON(t, dir, map[string]any{
		"schema":           "vmobs.guest_context.v1",
		"boot_id":          "boot-xyz",
		"capability_token": "tok-123",
		"protocol_version": proto.ProtocolVersion,
	})
	_, err := guest.LoadBootConfigDir(dir)
	if err == nil {
		t.Fatal("want error for missing vm_id field")
	}
	if !strings.Contains(err.Error(), "vm_id") {
		t.Errorf("want error mentioning 'vm_id', got: %v", err)
	}
}

func TestLoadBootConfigDirMissingBootID(t *testing.T) {
	dir := t.TempDir()
	writeContextJSON(t, dir, map[string]any{
		"schema":           "vmobs.guest_context.v1",
		"vm_id":            "vm-abc",
		"capability_token": "tok-123",
		"protocol_version": proto.ProtocolVersion,
	})
	_, err := guest.LoadBootConfigDir(dir)
	if err == nil {
		t.Fatal("want error for missing boot_id field")
	}
	if !strings.Contains(err.Error(), "boot_id") {
		t.Errorf("want error mentioning 'boot_id', got: %v", err)
	}
}

func TestLoadBootConfigDirMissingToken(t *testing.T) {
	dir := t.TempDir()
	writeContextJSON(t, dir, map[string]any{
		"schema":           "vmobs.guest_context.v1",
		"vm_id":            "vm-abc",
		"boot_id":          "boot-xyz",
		"protocol_version": proto.ProtocolVersion,
	})
	_, err := guest.LoadBootConfigDir(dir)
	if err == nil {
		t.Fatal("want error for missing capability_token field")
	}
	if !strings.Contains(err.Error(), "capability_token") {
		t.Errorf("want error mentioning 'capability_token', got: %v", err)
	}
}

func TestLoadBootConfigDirVersionMismatch(t *testing.T) {
	dir := t.TempDir()
	writeContextJSON(t, dir, map[string]any{
		"schema":           "vmobs.guest_context.v1",
		"vm_id":            "vm-abc",
		"boot_id":          "boot-xyz",
		"capability_token": "tok-123",
		"protocol_version": 999,
	})
	_, err := guest.LoadBootConfigDir(dir)
	if err == nil {
		t.Fatal("want error for protocol_version mismatch")
	}
	// Error must name both values.
	if !strings.Contains(err.Error(), "999") {
		t.Errorf("want error to mention got version 999, got: %v", err)
	}
	if !strings.Contains(err.Error(), "1") {
		t.Errorf("want error to mention expected version 1, got: %v", err)
	}
}

func TestLoadBootConfigDirMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := guest.LoadBootConfigDir(dir)
	if err == nil {
		t.Fatal("want error for missing context.json")
	}
}

// TestLoadBootConfigDirWrongSchema verifies that a schema value other than the
// canonical const is rejected, and the error names both the got and want values.
func TestLoadBootConfigDirWrongSchema(t *testing.T) {
	dir := t.TempDir()
	writeContextJSON(t, dir, map[string]any{
		"schema":           "vmobs.guest_context.v2",
		"vm_id":            "vm-abc",
		"boot_id":          "boot-xyz",
		"capability_token": "tok-123",
		"protocol_version": proto.ProtocolVersion,
	})
	_, err := guest.LoadBootConfigDir(dir)
	if err == nil {
		t.Fatal("want error for wrong schema value")
	}
	if !strings.Contains(err.Error(), "vmobs.guest_context.v2") {
		t.Errorf("want error to mention got value 'vmobs.guest_context.v2', got: %v", err)
	}
	if !strings.Contains(err.Error(), guest.GuestContextSchema) {
		t.Errorf("want error to mention want value %q, got: %v", guest.GuestContextSchema, err)
	}
}
