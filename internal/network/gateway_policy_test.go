// ABOUTME: Specifies the fail-closed nftables programs for each routed VM boundary.
// ABOUTME: Checks validation, rule order, narrow host scope, and deterministic output.
package network_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/network"
)

func TestBuildGatewayRulesTransportReady(t *testing.T) {
	input := gatewayInput(t, network.ProfileTransport, true)
	first, err := network.BuildGatewayRules(input)
	if err != nil {
		t.Fatalf("BuildGatewayRules: %v", err)
	}
	second, err := network.BuildGatewayRules(input)
	if err != nil {
		t.Fatalf("BuildGatewayRules again: %v", err)
	}
	if first != second {
		t.Fatal("BuildGatewayRules is not deterministic")
	}

	if first.NamespaceIngressTable != (network.NFTTable{Family: "netdev", Name: "vmobs_gateway_ingress"}) {
		t.Errorf("NamespaceIngressTable = %#v", first.NamespaceIngressTable)
	}
	if first.NamespaceFilterTable != (network.NFTTable{Family: "inet", Name: "vmobs_gateway"}) {
		t.Errorf("NamespaceFilterTable = %#v", first.NamespaceFilterTable)
	}
	if first.NamespaceNATTable != (network.NFTTable{Family: "ip", Name: "vmobs_gateway_nat"}) {
		t.Errorf("NamespaceNATTable = %#v", first.NamespaceNATTable)
	}
	if first.HostFilterTable.Name == "" || first.HostFilterTable.Name == "vmobs_host" || first.HostFilterTable.Family != "inet" {
		t.Errorf("HostFilterTable = %#v, want a per-VM inet name", first.HostFilterTable)
	}
	if first.HostNATTable.Name == "" || first.HostNATTable.Name == first.HostFilterTable.Name || first.HostNATTable.Family != "ip" {
		t.Errorf("HostNATTable = %#v", first.HostNATTable)
	}

	ns := first.NamespaceScript
	mac := input.Layout.GuestMAC.String()
	assertContains(t, ns,
		`table netdev vmobs_gateway_ingress`,
		`counter observed { }`,
		`hook ingress device "tap0" priority -500; policy drop;`,
		`ether saddr != `+mac+` jump deny`,
		`ip saddr != 172.31.255.2 jump deny`,
		`ether type ip6 jump deny`,
		`arp saddr ether `+mac+` arp saddr ip 172.31.255.2 arp daddr ip 172.31.255.1 arp operation { request, reply } accept`,
		`iifname "tap0" ip saddr 172.31.255.2 udp dport 53`,
		`iifname "tap0" ip saddr 172.31.255.2 tcp dport 53`,
		`iifname "eth-up" ip saddr 9.9.9.9 ip daddr 10.190.0.2 meta l4proto { tcp, udp } th sport 53 ct state established ct direction reply`,
		`oifname "eth-up" ip saddr 10.190.0.2 ip daddr 9.9.9.9 udp dport 53`,
		`oifname "eth-up" ip saddr 10.190.0.2 ip daddr 9.9.9.9 tcp dport 53`,
		`iifname "tap0" oifname "eth-up" ip saddr 172.31.255.2 tcp dport { 80, 443 }`,
		`oifname "tap0" ip daddr 172.31.255.2 ct state established,related ct direction reply`,
		`ip saddr 172.31.255.2 oifname "eth-up" snat to 10.190.0.2`,
	)
	assertOrder(t, ns,
		`ether saddr != `+mac+` jump deny`,
		`ct state established,related`,
	)
	assertOrder(t, ns,
		`ip daddr @denied_destinations jump deny`,
		`ct state established,related`,
	)
	assertOrder(t, ns, `ct bytes > 0 counter name observed`, `tcp dport { 80, 443 }`)
	assertDenyOrder(t, ns)

	host := first.HostScript
	veth := network.VethName(input.VMID)
	assertContains(t, host,
		`hook forward priority -90; policy accept;`,
		`hook input priority -90; policy accept;`,
		`iifname "`+veth+`" jump deny`,
		`iifname "`+veth+`" meta nfproto ipv6 jump deny`,
		`iifname "`+veth+`" ip saddr != 10.190.0.2 jump deny`,
		`iifname "`+veth+`" ip daddr @denied_destinations jump deny`,
		`iifname "`+veth+`" fib daddr type { local, broadcast, multicast } jump deny`,
		`iifname "`+veth+`" oifname "veth-*" jump deny`,
		`iifname "`+veth+`" ip daddr 9.9.9.9 meta l4proto { tcp, udp } th dport 53`,
		`iifname "`+veth+`" tcp dport { 80, 443 }`,
		`oifname "`+veth+`" ip daddr 10.190.0.2 ct state established,related ct direction reply`,
		`iifname "`+veth+`" ip saddr 10.190.0.2 masquerade`,
	)
	assertOrder(t, host,
		`ip daddr @denied_destinations jump deny`,
		`ct state established,related`,
	)
	assertDenyOrder(t, host)
	if strings.Contains(host, "ct bytes") || strings.Contains(host, "ct packets") {
		t.Fatal("host program enables host-wide conntrack accounting")
	}
	if strings.Contains(host, "hook output") {
		t.Fatal("host program installs a host output hook")
	}
}

func TestBuildGatewayRulesUsesOwnedHostNFLogGroup(t *testing.T) {
	input := gatewayInput(t, network.ProfileOffline, false)
	input.HostNFLogGroup = 1024
	first, err := network.BuildGatewayRules(input)
	if err != nil {
		t.Fatal(err)
	}
	input.HostNFLogGroup = 1025
	second, err := network.BuildGatewayRules(input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first.HostScript, "log group 1024 ") || !strings.Contains(second.HostScript, "log group 1025 ") {
		t.Fatal("host rules do not use each VM's owned NFLOG group")
	}
	if first.NamespaceScript != second.NamespaceScript || !strings.Contains(first.NamespaceScript, "log group 100 ") {
		t.Fatal("namespace-local group changed with host allocation")
	}
	for _, group := range []uint16{0, network.NamespaceNFLogGroup} {
		input.HostNFLogGroup = group
		if _, err := network.BuildGatewayRules(input); err == nil {
			t.Fatalf("unowned host NFLOG group %d accepted", group)
		}
	}
}

func TestBuildGatewayRulesReadinessAndProfilesStayClosed(t *testing.T) {
	for _, tt := range []struct {
		name    string
		profile network.Profile
		ready   bool
	}{
		{name: "transport before readiness", profile: network.ProfileTransport, ready: false},
		{name: "offline even when ready", profile: network.ProfileOffline, ready: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := network.BuildGatewayRules(gatewayInput(t, tt.profile, tt.ready))
			if err != nil {
				t.Fatalf("BuildGatewayRules: %v", err)
			}
			for _, forbidden := range []string{"tcp dport { 80, 443 }", "dport 53", "snat to", "masquerade", "counter name accepted accept"} {
				if strings.Contains(rules.NamespaceScript, forbidden) || strings.Contains(rules.HostScript, forbidden) {
					t.Errorf("closed policy contains %q", forbidden)
				}
			}
			assertContains(t, rules.NamespaceScript, `hook input priority filter; policy drop;`, `hook forward priority filter; policy drop;`)
			assertContains(t, rules.NamespaceScript, `ct bytes > 0 counter name observed`)
		})
	}
}

func TestBuildGatewayRulesRejectsUntrustedOrInconsistentValues(t *testing.T) {
	valid := gatewayInput(t, network.ProfileTransport, true)
	tests := map[string]func(*network.GatewayRuleConfig){
		"invalid VM id": func(input *network.GatewayRuleConfig) { input.VMID = `x"; flush ruleset` },
		"mismatched layout": func(input *network.GatewayRuleConfig) {
			input.Layout.GuestAddress = netip.MustParseAddr("172.31.255.3")
		},
		"zero policy": func(input *network.GatewayRuleConfig) { input.Policy = network.EffectivePolicy{} },
		"invalid host prefix": func(input *network.GatewayRuleConfig) {
			input.HostDenyPrefixes = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
		},
		"missing host inventory": func(input *network.GatewayRuleConfig) {
			input.HostDenyPrefixes = nil
		},
		"DNS upstream denied by host inventory": func(input *network.GatewayRuleConfig) {
			input.HostDenyPrefixes = []netip.Prefix{netip.MustParsePrefix("9.9.9.9/32")}
		},
		"default host prefix": func(input *network.GatewayRuleConfig) {
			input.HostDenyPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		},
		"too many host prefixes": func(input *network.GatewayRuleConfig) {
			input.HostDenyPrefixes = make([]netip.Prefix, network.MaxDestinationPolicyExtraPrefixes)
			for i := range input.HostDenyPrefixes {
				input.HostDenyPrefixes[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{11, 0, byte(i), 1}), 32)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := valid
			input.HostDenyPrefixes = append([]netip.Prefix(nil), valid.HostDenyPrefixes...)
			mutate(&input)
			if _, err := network.BuildGatewayRules(input); err == nil {
				t.Fatal("BuildGatewayRules succeeded")
			}
		})
	}
}

func TestBuildGatewayRulesNormalizesHostPrefixes(t *testing.T) {
	input := gatewayInput(t, network.ProfileTransport, true)
	input.HostDenyPrefixes = []netip.Prefix{
		netip.MustParsePrefix("11.22.33.99/24"),
		netip.MustParsePrefix("8.8.0.0/16"),
		netip.MustParsePrefix("11.22.33.0/24"),
	}
	rules, err := network.BuildGatewayRules(input)
	if err != nil {
		t.Fatalf("BuildGatewayRules: %v", err)
	}
	if strings.Count(rules.HostScript, "11.22.33.0/24") != 1 {
		t.Fatalf("host rules do not deduplicate prefixes:\n%s", rules.HostScript)
	}
	assertOrder(t, rules.HostScript, "8.8.0.0/16", "11.22.33.0/24")
}

func gatewayInput(t *testing.T, profile network.Profile, ready bool) network.GatewayRuleConfig {
	t.Helper()
	layout, err := network.NewLayout("vm-alpha", netip.MustParsePrefix("10.190.0.0/30"))
	if err != nil {
		t.Fatalf("NewLayout: %v", err)
	}
	file := network.PolicyFile{SchemaVersion: network.PolicySchemaVersion, ID: network.OfflinePolicyID, Profile: network.ProfileOffline}
	if profile == network.ProfileTransport {
		file = network.PolicyFile{
			SchemaVersion:   network.PolicySchemaVersion,
			ID:              network.TransportPublicWebPolicyID,
			Profile:         network.ProfileTransport,
			DNSUpstream:     "9.9.9.9",
			AllowedTCPPorts: []uint16{80, 443},
		}
	}
	policy, err := network.ValidateEffectivePolicy(file)
	if err != nil {
		t.Fatalf("ValidateEffectivePolicy: %v", err)
	}
	return network.GatewayRuleConfig{
		VMID:             "vm-alpha",
		HostNFLogGroup:   1024,
		Layout:           layout,
		Policy:           policy,
		HostDenyPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
		Ready:            ready,
	}
}

func assertContains(t *testing.T, text string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(text, value) {
			t.Errorf("missing %q in:\n%s", value, text)
		}
	}
}

func assertOrder(t *testing.T, text string, values ...string) {
	t.Helper()
	previous := -1
	for _, value := range values {
		index := strings.Index(text, value)
		if index < 0 {
			t.Fatalf("missing %q in:\n%s", value, text)
		}
		if index <= previous {
			t.Fatalf("%q appears out of order in:\n%s", value, text)
		}
		previous = index
	}
}

func assertDenyOrder(t *testing.T, script string) {
	t.Helper()
	assertOrder(t, script, `counter name denied`, `limit rate 10/second burst 20 packets log group `, `drop`)
}
