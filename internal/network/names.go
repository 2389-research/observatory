// ABOUTME: Derives the network-namespace and veth names from a VM id.
// ABOUTME: Must match the root helper's derivations character-for-character (ns="vmobs-$id"; veth is a sha256-digest form — see VethName).
package network

import (
	"crypto/sha256"
	"encoding/hex"
)

// NamespaceName returns the network namespace name for the given VM id.
// The root helper uses: ns="vmobs-$id"
//
// The root helper validates id against a charset of [a-z0-9-] (first char
// [a-z0-9]) and a length of at most 63 characters, matching privd's
// ValidVMID. Callers must enforce that constraint; this function is not the
// enforcer and does not validate its input.
func NamespaceName(id string) string {
	return "vmobs-" + id
}

// VethName returns the host-side veth interface name for the given VM id.
//
// Real VM ids are UUIDs (36 chars); "veth-" plus the raw id would be 41
// characters, over the kernel's IFNAMSIZ limit (15 usable chars, not
// counting the trailing NUL) — the kernel rejects it outright. So the name
// is "veth-" plus the first 10 hex characters of sha256(id): exactly 15
// characters, deterministic, independent of id length. 10 hex chars is a
// 40-bit digest space, which is fine for the ≤64 concurrent network slots
// this host supports (birthday-bound collision odds stay negligible far
// past that count).
//
// The root helper derives the same name:
//
//	veth="veth-$(printf '%s' "$id" | sha256sum | cut -c1-10)"
//
// The root helper validates id against the constraints documented on
// NamespaceName. Callers must enforce that constraint; this function is not
// the enforcer and does not validate its input.
func VethName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return "veth-" + hex.EncodeToString(sum[:])[:10]
}
