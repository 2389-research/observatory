// ABOUTME: Derives the network-namespace and veth names from a VM id.
// ABOUTME: Must match the root helper's derivations character-for-character (ns="vmobs-$id", veth="veth-$id").
package network

// NamespaceName returns the network namespace name for the given VM id.
// The root helper uses: ns="vmobs-$id"
//
// The root helper validates id against ^[a-z0-9][a-z0-9-]{0,23}$ before invoking
// this function. Callers must enforce that constraint; this function is not the
// enforcer and does not validate its input.
func NamespaceName(id string) string {
	return "vmobs-" + id
}

// VethName returns the host-side veth interface name for the given VM id.
// The root helper uses: ip link add "veth-$id" type veth peer name eth-up netns "$ns"
//
// The root helper validates id against ^[a-z0-9][a-z0-9-]{0,23}$ before invoking
// this function. Callers must enforce that constraint; this function is not the
// enforcer and does not validate its input.
func VethName(id string) string {
	return "veth-" + id
}
