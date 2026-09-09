// ABOUTME: Builds deterministic nftables programs for one validated routed VM boundary.
// ABOUTME: Keeps namespace traffic closed until readiness and limits host hooks to owned traffic.
package network

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	namespaceGatewayTable = "vmobs_gateway"
	namespaceIngressTable = "vmobs_gateway_ingress"
	// NamespaceNFLogGroup is local to each VM namespace, so it can be reused there.
	NamespaceNFLogGroup uint16 = 100
	// MinHostNFLogGroup separates durable host ownership from low externally managed groups.
	MinHostNFLogGroup uint16 = 1024
)

func IsHostNFLogGroup(group uint16) bool { return group >= MinHostNFLogGroup }

// GatewayRuleConfig contains only host-validated values. Interface names are
// derived here rather than accepted from a request or policy file.
type GatewayRuleConfig struct {
	VMID             string
	Layout           Layout
	Policy           EffectivePolicy
	HostDenyPrefixes []netip.Prefix
	Ready            bool
	HostNFLogGroup   uint16
}

// NFTTable identifies one owned nftables object without relying on an implied
// family at cleanup time.
type NFTTable struct {
	Family string
	Name   string
}

// GatewayRules contains complete nft input for an already isolated namespace
// and for the host. Every table identity is returned so lifecycle code can
// remove only this VM's resources.
type GatewayRules struct {
	NamespaceIngressTable NFTTable
	NamespaceFilterTable  NFTTable
	NamespaceNATTable     NFTTable
	HostFilterTable       NFTTable
	HostNATTable          NFTTable
	NamespaceScript       string
	HostScript            string
}

// BuildGatewayRules validates the layout and effective policy again at the
// privileged boundary, then renders complete rulesets without accepting nft
// fragments, interface overrides, or guest-controlled paths.
func BuildGatewayRules(config GatewayRuleConfig) (GatewayRules, error) {
	if !IsHostNFLogGroup(config.HostNFLogGroup) {
		return GatewayRules{}, fmt.Errorf("network: owned host NFLOG group required")
	}
	expected, err := NewLayout(config.VMID, config.Layout.TransitPrefix)
	if err != nil {
		return GatewayRules{}, fmt.Errorf("network: gateway layout: %w", err)
	}
	if config.Layout != expected {
		return GatewayRules{}, fmt.Errorf("network: gateway layout does not match VM and transit prefix")
	}
	if err := validateGatewayPolicy(config.Policy); err != nil {
		return GatewayRules{}, err
	}

	denied, err := gatewayDeniedPrefixes(config.Policy, config.Layout, config.HostDenyPrefixes)
	if err != nil {
		return GatewayRules{}, err
	}
	if config.Policy.Profile() == ProfileTransport {
		for _, prefix := range denied {
			if prefix.Contains(config.Policy.DNSUpstream()) {
				return GatewayRules{}, fmt.Errorf("%w: DNS upstream %s is denied by the effective host boundary", ErrInvalidPolicy, config.Policy.DNSUpstream())
			}
		}
	}
	hostTable, hostNATTable := gatewayHostTableNames(config.VMID)
	rules := GatewayRules{
		NamespaceIngressTable: NFTTable{Family: "netdev", Name: namespaceIngressTable},
		NamespaceFilterTable:  NFTTable{Family: "inet", Name: namespaceGatewayTable},
		NamespaceNATTable:     NFTTable{Family: "ip", Name: "vmobs_gateway_nat"},
		HostFilterTable:       NFTTable{Family: "inet", Name: hostTable},
		HostNATTable:          NFTTable{Family: "ip", Name: hostNATTable},
	}
	rules.NamespaceScript = buildNamespaceRules(config, denied)
	rules.HostScript = buildHostRules(config, denied, hostTable, hostNATTable)
	return rules, nil
}

func validateGatewayPolicy(policy EffectivePolicy) error {
	ports := policy.TCPPorts()
	destinations := policy.Destinations()
	if len(destinations.DeniedPrefixes()) == 0 {
		return fmt.Errorf("%w: destination policy is uninitialized", ErrInvalidPolicy)
	}
	switch policy.Profile() {
	case ProfileOffline:
		if policy.ID() != OfflinePolicyID || policy.DNSUpstream().IsValid() || len(ports) != 0 {
			return fmt.Errorf("%w: inconsistent offline effective policy", ErrInvalidPolicy)
		}
	case ProfileTransport:
		if policy.ID() != TransportPublicWebPolicyID || len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
			return fmt.Errorf("%w: inconsistent transport effective policy", ErrInvalidPolicy)
		}
		if public, _ := destinations.Classify(policy.DNSUpstream()); !public {
			return fmt.Errorf("%w: transport DNS upstream is not public", ErrInvalidPolicy)
		}
	case ProfileHTTPInspect:
		return fmt.Errorf("%w: %s proxy path is not implemented", ErrProfileUnavailable, ProfileHTTPInspect)
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedProfile, policy.Profile())
	}
	return nil
}

func gatewayDeniedPrefixes(policy EffectivePolicy, layout Layout, host []netip.Prefix) ([]netip.Prefix, error) {
	if len(host) == 0 {
		return nil, fmt.Errorf("network: gateway host deny inventory is required")
	}
	all := append(policy.Destinations().DeniedPrefixes(), layout.TransitPrefix, layout.GuestPrefix)
	all = append(all, host...)
	if len(all) > MaxDestinationPolicyExtraPrefixes {
		return nil, fmt.Errorf("network: gateway deny prefixes has %d entries, maximum is %d", len(all), MaxDestinationPolicyExtraPrefixes)
	}

	unique := make(map[netip.Prefix]struct{}, len(all))
	for i, prefix := range all {
		if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return nil, fmt.Errorf("network: gateway deny prefix %d is not native unscoped IPv4", i)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("network: gateway deny prefix %d is a default route", i)
		}
		unique[prefix] = struct{}{}
	}
	result := make([]netip.Prefix, 0, len(unique))
	for prefix := range unique {
		result = append(result, prefix)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Addr().Compare(result[j].Addr()) < 0 ||
			result[i].Addr() == result[j].Addr() && result[i].Bits() < result[j].Bits()
	})
	compact := make([]netip.Prefix, 0, len(result))
	for _, prefix := range result {
		contained := false
		for _, existing := range compact {
			if existing.Bits() <= prefix.Bits() && existing.Contains(prefix.Addr()) {
				contained = true
				break
			}
		}
		if !contained {
			compact = append(compact, prefix)
		}
	}
	return compact, nil
}

func gatewayHostTableNames(vmID string) (string, string) {
	digest := sha256.Sum256([]byte(vmID))
	suffix := hex.EncodeToString(digest[:6])
	return "vmobs_" + suffix, "vmobs_nat_" + suffix
}

func buildNamespaceRules(config GatewayRuleConfig, denied []netip.Prefix) string {
	layout := config.Layout
	mac := layout.GuestMAC.String()
	var script strings.Builder
	fmt.Fprintf(&script, `table netdev %s {
  counter denied { }
  chain deny {
    counter name denied
    limit rate 10/second burst 20 packets log group %d prefix "vmobs namespace ingress denied "
    drop
  }
  chain ingress {
    type filter hook ingress device "tap0" priority -500; policy drop;
    ether saddr != %s jump deny
    ether type ip ip saddr != %s jump deny
    ether type ip6 jump deny
    ether type arp arp saddr ether %s arp saddr ip %s arp daddr ip %s arp operation { request, reply } accept
    ether type arp jump deny
    ether type ip accept
    jump deny
  }
}
`, namespaceIngressTable, NamespaceNFLogGroup, mac, layout.GuestAddress, mac, layout.GuestAddress, layout.GuestGateway)

	fmt.Fprintf(&script, `table inet %s {
  set denied_destinations {
    type ipv4_addr
    flags interval
    elements = { %s }
  }
  counter denied { }
  counter accepted { }
  counter observed { }
  chain deny {
    counter name denied
    limit rate 10/second burst 20 packets log group %d prefix "vmobs namespace denied "
    drop
  }
  chain input {
    type filter hook input priority filter; policy drop;
`, namespaceGatewayTable, nftPrefixSet(denied), NamespaceNFLogGroup)
	if config.Ready && config.Policy.Profile() == ProfileTransport {
		fmt.Fprintf(&script, "    iifname \"tap0\" ip saddr %s udp dport 53 counter name accepted accept\n", layout.GuestAddress)
		fmt.Fprintf(&script, "    iifname \"tap0\" ip saddr %s tcp dport 53 counter name accepted accept\n", layout.GuestAddress)
		fmt.Fprintf(&script, "    iifname \"eth-up\" ip saddr %s ip daddr %s meta l4proto { tcp, udp } th sport 53 ct state established ct direction reply counter name accepted accept\n", config.Policy.DNSUpstream(), layout.TransitNamespace)
	}
	script.WriteString("    jump deny\n  }\n  chain output {\n    type filter hook output priority filter; policy drop;\n")
	if config.Ready && config.Policy.Profile() == ProfileTransport {
		fmt.Fprintf(&script, "    oifname \"eth-up\" ip saddr %s ip daddr %s udp dport 53 counter name accepted accept\n", layout.TransitNamespace, config.Policy.DNSUpstream())
		fmt.Fprintf(&script, "    oifname \"eth-up\" ip saddr %s ip daddr %s tcp dport 53 counter name accepted accept\n", layout.TransitNamespace, config.Policy.DNSUpstream())
		fmt.Fprintf(&script, "    oifname \"tap0\" ip saddr %s ip daddr %s meta l4proto { tcp, udp } th sport 53 ct state established counter name accepted accept\n", layout.GuestGateway, layout.GuestAddress)
	}
	script.WriteString("    jump deny\n  }\n  chain forward {\n    type filter hook forward priority filter; policy drop;\n    ct bytes > 0 counter name observed\n    iifname \"tap0\" ip daddr @denied_destinations jump deny\n    iifname \"tap0\" fib daddr type { local, broadcast, multicast } jump deny\n")
	if config.Ready && config.Policy.Profile() == ProfileTransport {
		fmt.Fprintf(&script, "    iifname \"tap0\" oifname \"eth-up\" ip saddr %s tcp dport { %s } ct state new,established counter name accepted accept\n", layout.GuestAddress, nftPorts(config.Policy.TCPPorts()))
		fmt.Fprintf(&script, "    oifname \"tap0\" ip daddr %s ct state established,related ct direction reply counter name accepted accept\n", layout.GuestAddress)
	}
	script.WriteString("    jump deny\n  }\n}\n")

	fmt.Fprintf(&script, `table ip vmobs_gateway_nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
`)
	if config.Ready && config.Policy.Profile() == ProfileTransport {
		fmt.Fprintf(&script, "    ip saddr %s oifname \"eth-up\" snat to %s\n", layout.GuestAddress, layout.TransitNamespace)
	}
	script.WriteString("  }\n}\n")
	return script.String()
}

func buildHostRules(config GatewayRuleConfig, denied []netip.Prefix, table, natTable string) string {
	layout := config.Layout
	veth := VethName(config.VMID)
	var script strings.Builder
	fmt.Fprintf(&script, `table inet %s {
  set denied_destinations {
    type ipv4_addr
    flags interval
    elements = { %s }
  }
  counter denied { }
  counter accepted { }
  chain deny {
    counter name denied
    limit rate 10/second burst 20 packets log group %d prefix "vmobs host denied "
    drop
  }
  chain forward {
    type filter hook forward priority -90; policy accept;
    iifname "%s" meta nfproto ipv6 jump deny
    iifname "%s" ip saddr != %s jump deny
    iifname "%s" ip daddr @denied_destinations jump deny
    iifname "%s" fib daddr type { local, broadcast, multicast } jump deny
    iifname "%s" oifname "veth-*" jump deny
`, table, nftPrefixSet(denied), config.HostNFLogGroup, veth, veth, layout.TransitNamespace, veth, veth, veth)
	if config.Ready && config.Policy.Profile() == ProfileTransport {
		fmt.Fprintf(&script, "    iifname \"%s\" ip daddr %s meta l4proto { tcp, udp } th dport 53 ct state new,established counter name accepted accept\n", veth, config.Policy.DNSUpstream())
		fmt.Fprintf(&script, "    iifname \"%s\" tcp dport { %s } ct state new,established counter name accepted accept\n", veth, nftPorts(config.Policy.TCPPorts()))
		fmt.Fprintf(&script, "    oifname \"%s\" ip daddr %s ct state established,related ct direction reply counter name accepted accept\n", veth, layout.TransitNamespace)
	}
	fmt.Fprintf(&script, "    iifname \"%s\" jump deny\n    oifname \"%s\" jump deny\n  }\n  chain input {\n    type filter hook input priority -90; policy accept;\n    iifname \"%s\" jump deny\n  }\n}\n", veth, veth, veth)

	fmt.Fprintf(&script, `table ip %s {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
`, natTable)
	if config.Ready && config.Policy.Profile() == ProfileTransport {
		fmt.Fprintf(&script, "    iifname \"%s\" ip saddr %s masquerade\n", veth, layout.TransitNamespace)
	}
	script.WriteString("  }\n}\n")
	return script.String()
}

func nftPrefixSet(prefixes []netip.Prefix) string {
	values := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		values[i] = prefix.String()
	}
	return strings.Join(values, ", ")
}

func nftPorts(ports []uint16) string {
	values := make([]string, len(ports))
	for i, port := range ports {
		values[i] = fmt.Sprintf("%d", port)
	}
	return strings.Join(values, ", ")
}
