// ABOUTME: Loads strict bounded host-owned network policy files by safe policy ID.
// ABOUTME: Validates one fail-closed profile contract into enforcement-ready values.
package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	PolicySchemaVersion        = 1
	MaxPolicyFileBytes         = 64 * 1024
	TransportPublicWebPolicyID = "transport-public-web"
	OfflinePolicyID            = "offline"
)

// Profile names the network behavior a policy may enable.
type Profile string

const (
	ProfileOffline     Profile = "offline"
	ProfileTransport   Profile = "transport"
	ProfileHTTPInspect Profile = "http_inspect"
)

var (
	ErrInvalidPolicy      = errors.New("network: invalid policy")
	ErrInvalidPolicyID    = errors.New("network: invalid policy id")
	ErrPolicyTooLarge     = errors.New("network: policy file too large")
	ErrUnsupportedPolicy  = errors.New("network: unsupported policy")
	ErrUnsupportedProfile = errors.New("network: unsupported profile")
	ErrProfileUnavailable = errors.New("network: profile unavailable")
)

// PolicyFile is schema version 1 of <policy-directory>/<id>.json. Every field
// is explicit; the loader rejects unknown fields and trailing JSON values.
type PolicyFile struct {
	SchemaVersion     int      `json:"schema_version"`
	ID                string   `json:"id"`
	Profile           Profile  `json:"profile"`
	DNSUpstream       string   `json:"dns_upstream"`
	AllowedTCPPorts   []uint16 `json:"allowed_tcp_ports"`
	ExtraDenyPrefixes []string `json:"extra_deny_prefixes"`
}

// EffectivePolicy contains only validated values used by enforcement. Slices
// are newly allocated by validation, and Destinations owns its prefix copies.
type EffectivePolicy struct {
	id              string
	profile         Profile
	dnsUpstream     netip.Addr
	destinations    DestinationPolicy
	allowedTCPPorts []uint16
}

// ID returns the validated policy identity.
func (policy EffectivePolicy) ID() string { return policy.id }

// Profile returns the validated network profile.
func (policy EffectivePolicy) Profile() Profile { return policy.profile }

// DNSUpstream returns the explicit validated resolver address. It is invalid
// for an offline policy, which has no resolver allowance.
func (policy EffectivePolicy) DNSUpstream() netip.Addr { return policy.dnsUpstream }

// Destinations returns the immutable validated destination classifier.
func (policy EffectivePolicy) Destinations() DestinationPolicy { return policy.destinations }

// TCPPorts returns a copy of the exact validated transport allowance.
func (policy EffectivePolicy) TCPPorts() []uint16 {
	return append([]uint16(nil), policy.allowedTCPPorts...)
}

// LoadEffectivePolicy reads <directory>/<id>.json with a fixed byte bound,
// strict fields, one JSON document, and an exact requested/file ID match.
func LoadEffectivePolicy(directory, id string) (EffectivePolicy, error) {
	if !validPolicyID(id) {
		return EffectivePolicy{}, fmt.Errorf("%w: %q", ErrInvalidPolicyID, id)
	}
	if directory == "" {
		return EffectivePolicy{}, fmt.Errorf("%w: policy directory is required", ErrInvalidPolicy)
	}

	path := filepath.Join(directory, id+".json")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return EffectivePolicy{}, fmt.Errorf("%w: policy %q is a symbolic link", ErrInvalidPolicy, id)
		}
		return EffectivePolicy{}, fmt.Errorf("network: open policy %q: %w", id, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return EffectivePolicy{}, fmt.Errorf("network: open policy %q: invalid file descriptor", id)
	}
	defer file.Close()
	return LoadEffectivePolicyFile(file, id)
}

// LoadEffectivePolicyFile decodes one already-open regular file from offset zero.
// It neither closes the descriptor nor changes its position. Privileged callers
// can verify ownership on this same descriptor before any policy bytes are read.
func LoadEffectivePolicyFile(file *os.File, id string) (EffectivePolicy, error) {
	if !validPolicyID(id) {
		return EffectivePolicy{}, fmt.Errorf("%w: %q", ErrInvalidPolicyID, id)
	}
	if file == nil {
		return EffectivePolicy{}, fmt.Errorf("%w: missing policy descriptor", ErrInvalidPolicy)
	}
	info, err := file.Stat()
	if err != nil {
		return EffectivePolicy{}, fmt.Errorf("network: stat policy %q: %w", id, err)
	}
	if !info.Mode().IsRegular() {
		return EffectivePolicy{}, fmt.Errorf("%w: policy %q is not a regular file", ErrInvalidPolicy, id)
	}
	if info.Size() > MaxPolicyFileBytes {
		return EffectivePolicy{}, fmt.Errorf("%w: policy %q has %d bytes, maximum is %d", ErrPolicyTooLarge, id, info.Size(), MaxPolicyFileBytes)
	}
	body, err := io.ReadAll(io.NewSectionReader(file, 0, MaxPolicyFileBytes+1))
	if err != nil {
		return EffectivePolicy{}, fmt.Errorf("network: read policy %q: %w", id, err)
	}
	if len(body) > MaxPolicyFileBytes {
		return EffectivePolicy{}, fmt.Errorf("%w: policy %q exceeds %d bytes", ErrPolicyTooLarge, id, MaxPolicyFileBytes)
	}

	var policy PolicyFile
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return EffectivePolicy{}, fmt.Errorf("%w: decode policy %q: %v", ErrInvalidPolicy, id, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return EffectivePolicy{}, fmt.Errorf("%w: policy %q contains more than one JSON value", ErrInvalidPolicy, id)
		}
		return EffectivePolicy{}, fmt.Errorf("%w: trailing data in policy %q: %v", ErrInvalidPolicy, id, err)
	}
	if policy.ID != id {
		return EffectivePolicy{}, fmt.Errorf("%w: requested id %q does not match file id %q", ErrInvalidPolicy, id, policy.ID)
	}
	return ValidateEffectivePolicy(policy)
}

// ValidateEffectivePolicy is the sole profile-to-allowance validator. It does
// not select a DNS resolver or broaden a port set when the file omits them.
func ValidateEffectivePolicy(policy PolicyFile) (EffectivePolicy, error) {
	if policy.SchemaVersion != PolicySchemaVersion {
		return EffectivePolicy{}, fmt.Errorf("%w: schema_version must be %d", ErrInvalidPolicy, PolicySchemaVersion)
	}
	if !validPolicyID(policy.ID) {
		return EffectivePolicy{}, fmt.Errorf("%w: %q", ErrInvalidPolicyID, policy.ID)
	}

	if len(policy.ExtraDenyPrefixes) > MaxDestinationPolicyExtraPrefixes {
		return EffectivePolicy{}, fmt.Errorf("%w: %d extra deny prefixes exceeds maximum %d", ErrInvalidPolicy, len(policy.ExtraDenyPrefixes), MaxDestinationPolicyExtraPrefixes)
	}
	prefixes := make([]netip.Prefix, len(policy.ExtraDenyPrefixes))
	for i, raw := range policy.ExtraDenyPrefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return EffectivePolicy{}, fmt.Errorf("%w: extra_deny_prefixes[%d] is not native unscoped IPv4", ErrInvalidPolicy, i)
		}
		prefixes[i] = prefix.Masked()
	}
	destinations, err := NewDestinationPolicy(prefixes)
	if err != nil {
		return EffectivePolicy{}, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}

	effective := EffectivePolicy{id: policy.ID, profile: policy.Profile, destinations: destinations}
	switch policy.Profile {
	case ProfileOffline:
		if policy.ID != OfflinePolicyID {
			return EffectivePolicy{}, fmt.Errorf("%w: offline policy id %q", ErrUnsupportedPolicy, policy.ID)
		}
		if policy.DNSUpstream != "" || len(policy.AllowedTCPPorts) != 0 {
			return EffectivePolicy{}, fmt.Errorf("%w: offline policy cannot configure DNS or TCP ports", ErrInvalidPolicy)
		}
		return effective, nil
	case ProfileTransport:
		if policy.ID != TransportPublicWebPolicyID {
			return EffectivePolicy{}, fmt.Errorf("%w: transport policy id %q", ErrUnsupportedPolicy, policy.ID)
		}
		upstream, parseErr := netip.ParseAddr(policy.DNSUpstream)
		if parseErr != nil || !upstream.Is4() || upstream.Is4In6() || upstream.Zone() != "" {
			return EffectivePolicy{}, fmt.Errorf("%w: transport dns_upstream must be an explicit native IPv4 address", ErrInvalidPolicy)
		}
		if public, reason := destinations.Classify(upstream); !public {
			return EffectivePolicy{}, fmt.Errorf("%w: dns_upstream %s is denied (%s)", ErrInvalidPolicy, upstream, reason)
		}
		if len(policy.AllowedTCPPorts) != 2 || policy.AllowedTCPPorts[0] != 80 || policy.AllowedTCPPorts[1] != 443 {
			return EffectivePolicy{}, fmt.Errorf("%w: %s allowed_tcp_ports must be [80, 443]", ErrInvalidPolicy, TransportPublicWebPolicyID)
		}
		effective.dnsUpstream = upstream
		effective.allowedTCPPorts = append([]uint16(nil), policy.AllowedTCPPorts...)
		return effective, nil
	case ProfileHTTPInspect:
		return EffectivePolicy{}, fmt.Errorf("%w: %s proxy path is not implemented", ErrProfileUnavailable, ProfileHTTPInspect)
	default:
		return EffectivePolicy{}, fmt.Errorf("%w: %q", ErrUnsupportedProfile, policy.Profile)
	}
}

func validPolicyID(id string) bool {
	return validVMID(id)
}
