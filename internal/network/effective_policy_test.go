// ABOUTME: Exercises strict, bounded loading of host-owned network policy files.
// ABOUTME: Pins fail-closed profile behavior and the initial public-web allowance.
package network_test

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/network"
	"golang.org/x/sys/unix"
)

func TestLoadEffectivePolicyParsesTransportPublicWeb(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePolicy(t, dir, network.TransportPublicWebPolicyID, `{
  "schema_version": 1,
  "id": "transport-public-web",
  "profile": "transport",
  "dns_upstream": "8.8.8.8",
  "allowed_tcp_ports": [80, 443],
  "extra_deny_prefixes": ["198.51.100.7/24"]
}`)

	got, err := network.LoadEffectivePolicy(dir, network.TransportPublicWebPolicyID)
	if err != nil {
		t.Fatalf("LoadEffectivePolicy: %v", err)
	}
	if got.ID() != network.TransportPublicWebPolicyID || got.Profile() != network.ProfileTransport {
		t.Errorf("identity = (%q, %q), want (%q, %q)", got.ID(), got.Profile(), network.TransportPublicWebPolicyID, network.ProfileTransport)
	}
	if got.DNSUpstream() != netip.MustParseAddr("8.8.8.8") {
		t.Errorf("DNSUpstream = %s, want 8.8.8.8", got.DNSUpstream())
	}
	ports := got.TCPPorts()
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Errorf("TCPPorts = %v, want [80 443]", ports)
	}
	ports[0] = 22
	if got.TCPPorts()[0] != 80 {
		t.Errorf("caller mutation changed effective ports to %v", got.TCPPorts())
	}
	if public, reason := got.Destinations().Classify(netip.MustParseAddr("198.51.100.8")); public || reason != "configured_prefix" {
		t.Errorf("configured extra deny classified as (%t, %q)", public, reason)
	}
	if public, reason := got.Destinations().Classify(got.DNSUpstream()); !public || reason != "public" {
		t.Errorf("DNS upstream classified as (%t, %q), want public", public, reason)
	}
	denied := got.Destinations().DeniedPrefixes()
	denied[0] = netip.MustParsePrefix("8.8.8.0/24")
	if public, reason := got.Destinations().Classify(netip.MustParseAddr("8.8.8.8")); !public || reason != "public" {
		t.Errorf("caller mutation changed effective destination policy to (%t, %q)", public, reason)
	}
}

func TestValidateEffectivePolicyAllowsOnlyExplicitProfileContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file network.PolicyFile
		want error
	}{
		{
			name: "offline",
			file: network.PolicyFile{SchemaVersion: 1, ID: network.OfflinePolicyID, Profile: network.ProfileOffline},
		},
		{
			name: "offline upstream",
			file: network.PolicyFile{SchemaVersion: 1, ID: network.OfflinePolicyID, Profile: network.ProfileOffline, DNSUpstream: "8.8.8.8"},
			want: network.ErrInvalidPolicy,
		},
		{
			name: "offline port",
			file: network.PolicyFile{SchemaVersion: 1, ID: network.OfflinePolicyID, Profile: network.ProfileOffline, AllowedTCPPorts: []uint16{80}},
			want: network.ErrInvalidPolicy,
		},
		{
			name: "transport missing explicit upstream",
			file: network.PolicyFile{SchemaVersion: 1, ID: network.TransportPublicWebPolicyID, Profile: network.ProfileTransport, AllowedTCPPorts: []uint16{80, 443}},
			want: network.ErrInvalidPolicy,
		},
		{
			name: "transport private upstream",
			file: network.PolicyFile{SchemaVersion: 1, ID: network.TransportPublicWebPolicyID, Profile: network.ProfileTransport, DNSUpstream: "192.168.1.1", AllowedTCPPorts: []uint16{80, 443}},
			want: network.ErrInvalidPolicy,
		},
		{
			name: "transport expanded ports",
			file: network.PolicyFile{SchemaVersion: 1, ID: network.TransportPublicWebPolicyID, Profile: network.ProfileTransport, DNSUpstream: "8.8.8.8", AllowedTCPPorts: []uint16{80, 443, 8443}},
			want: network.ErrInvalidPolicy,
		},
		{
			name: "unsupported transport id",
			file: network.PolicyFile{SchemaVersion: 1, ID: "transport-other", Profile: network.ProfileTransport, DNSUpstream: "8.8.8.8", AllowedTCPPorts: []uint16{80, 443}},
			want: network.ErrUnsupportedPolicy,
		},
		{
			name: "inspection unavailable",
			file: network.PolicyFile{SchemaVersion: 1, ID: "http-inspect", Profile: network.ProfileHTTPInspect},
			want: network.ErrProfileUnavailable,
		},
		{
			name: "unknown profile",
			file: network.PolicyFile{SchemaVersion: 1, ID: "unknown", Profile: "anything"},
			want: network.ErrUnsupportedProfile,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := network.ValidateEffectivePolicy(tt.file)
			if tt.want == nil && err != nil {
				t.Fatalf("ValidateEffectivePolicy: %v", err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("ValidateEffectivePolicy error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestValidateEffectivePolicyBoundsExtraPrefixes(t *testing.T) {
	t.Parallel()

	prefixes := make([]string, network.MaxDestinationPolicyExtraPrefixes+1)
	for i := range prefixes {
		prefixes[i] = "8.8.8.8/32"
	}
	_, err := network.ValidateEffectivePolicy(network.PolicyFile{
		SchemaVersion:     1,
		ID:                network.TransportPublicWebPolicyID,
		Profile:           network.ProfileTransport,
		DNSUpstream:       "8.8.8.8",
		AllowedTCPPorts:   []uint16{80, 443},
		ExtraDenyPrefixes: prefixes,
	})
	if !errors.Is(err, network.ErrInvalidPolicy) {
		t.Fatalf("ValidateEffectivePolicy error = %v, want invalid policy", err)
	}
}

func TestLoadEffectivePolicyRejectsUnsafeStrictAndOversizedFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	valid := `{"schema_version":1,"id":"offline","profile":"offline","dns_upstream":"","allowed_tcp_ports":[],"extra_deny_prefixes":[]}`
	tests := []struct {
		name string
		id   string
		body string
		want error
	}{
		{name: "unsafe id", id: "../offline", body: valid, want: network.ErrInvalidPolicyID},
		{name: "unknown field", id: "offline", body: strings.TrimSuffix(valid, "}") + `,"surprise":true}`, want: network.ErrInvalidPolicy},
		{name: "trailing document", id: "offline", body: valid + `{}`, want: network.ErrInvalidPolicy},
		{name: "id mismatch", id: "offline", body: strings.Replace(valid, `"id":"offline"`, `"id":"transport-public-web"`, 1), want: network.ErrInvalidPolicy},
		{name: "oversized", id: "offline", body: valid + strings.Repeat(" ", network.MaxPolicyFileBytes), want: network.ErrPolicyTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.id == "../offline" {
				if _, err := network.LoadEffectivePolicy(dir, tt.id); !errors.Is(err, tt.want) {
					t.Fatalf("LoadEffectivePolicy error = %v, want %v", err, tt.want)
				}
				return
			}
			writePolicy(t, dir, tt.id, tt.body)
			if _, err := network.LoadEffectivePolicy(dir, tt.id); !errors.Is(err, tt.want) {
				t.Fatalf("LoadEffectivePolicy error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestLoadEffectivePolicyRejectsSymlinkAndFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{"schema_version":1,"id":"offline","profile":"offline"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "offline.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := network.LoadEffectivePolicy(dir, "offline"); !errors.Is(err, network.ErrInvalidPolicy) {
		t.Fatalf("symlink error = %v, want invalid policy", err)
	}

	fifoID := "offline-fifo"
	if err := unix.Mkfifo(filepath.Join(dir, fifoID+".json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := network.LoadEffectivePolicy(dir, fifoID); !errors.Is(err, network.ErrInvalidPolicy) {
		t.Fatalf("FIFO error = %v, want invalid policy", err)
	}
}

func writePolicy(t *testing.T, dir, id, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, id+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadEffectivePolicyFileUsesPinnedBytesFromStart(t *testing.T) {
	directory := t.TempDir()
	writePolicy(t, directory, "offline", `{"schema_version":1,"id":"offline","profile":"offline","dns_upstream":"","allowed_tcp_ports":[],"extra_deny_prefixes":[]}`)
	path := filepath.Join(directory, "offline.json")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(8, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".pinned"); err != nil {
		t.Fatal(err)
	}
	writePolicy(t, directory, "offline", `{"schema_version":999}`)
	policy, err := network.LoadEffectivePolicyFile(file, "offline")
	if err != nil {
		t.Fatal(err)
	}
	if policy.Profile() != network.ProfileOffline {
		t.Fatal("pinned policy identity changed")
	}
	offset, err := file.Seek(0, 1)
	if err != nil || offset != 8 {
		t.Fatal("loader changed caller file position", offset, err)
	}
}
