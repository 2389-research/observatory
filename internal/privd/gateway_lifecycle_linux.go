// ABOUTME: Installs a closed routed topology bound to a durable gateway generation.
// ABOUTME: Refuses unknown ownership and proves kernel resource removal before lease release.
//go:build linux

package privd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/2389-research/observatory/internal/network"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func (r *RealOps) ipPath() string {
	if r.cfg.IPPath != "" {
		return r.cfg.IPPath
	}
	return "ip"
}
func (r *RealOps) nftPath() string {
	if r.cfg.NftPath != "" {
		return r.cfg.NftPath
	}
	return "nft"
}
func (r *RealOps) inNamespace(id string, argv ...string) []string {
	return append([]string{r.ipPath(), "netns", "exec", network.NamespaceName(id)}, argv...)
}

// PrepareNetworkEntry validates policy before the server persists mutation authority.
// A future activation unit must acquire real resolver/observer handles bound to this
// generation; this unit exposes no request boolean or operation that opens egress.
func (r *RealOps) PrepareNetworkEntry(ctx context.Context, entry *VMEntry, req AllocateNetworkReq) error {
	if entry.VMID != req.VMID || entry.NetCIDR != req.CIDR {
		return fmt.Errorf("privd: network ownership/request mismatch")
	}
	if _, err := uuid.Parse(req.GuestBootID); err != nil {
		return fmt.Errorf("privd: valid guest boot binding required")
	}
	prefix, err := netip.ParsePrefix(req.CIDR)
	if err != nil {
		return err
	}
	if _, err = network.NewLayout(req.VMID, prefix); err != nil {
		return err
	}
	policy, digest, err := r.loadNetworkPolicy(req.PolicyID)
	if err != nil {
		return err
	}
	if string(policy.Profile()) != req.Profile {
		return fmt.Errorf("privd: requested profile differs from trusted policy")
	}
	// Offline is the only complete lifecycle. Transport needs the managed resolver,
	// privileged observer acquisition and durable ready publication in the next unit.
	if policy.Profile() != network.ProfileOffline {
		return fmt.Errorf("%w: resolver and observer acquisition are not installed", network.ErrProfileUnavailable)
	}
	if err := r.checkHostTransitOverlap(ctx, prefix); err != nil {
		return err
	}
	boot, _, err := hostIdentity()
	if err != nil {
		return err
	}
	entry.NetworkHostBootID = boot
	var generation [16]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return err
	}
	entry.NetworkGuestBootID = req.GuestBootID
	entry.NetworkProfile = req.Profile
	entry.NetworkPolicyID = req.PolicyID
	entry.NetworkPolicyDigest = digest
	entry.NetworkPolicyVersion = network.PolicySchemaVersion
	entry.GatewayGeneration = hex.EncodeToString(generation[:])
	return nil
}

// checkHostTransitOverlap samples every IPv4 routing table and interface before
// a new connected route can divert unrelated host traffic into the owned veth.
func (r *RealOps) checkHostTransitOverlap(ctx context.Context, transit netip.Prefix) error {
	routes, err := r.commandOutput(ctx, []string{r.ipPath(), "-j", "-4", "route", "show", "table", "all"}, "")
	if err != nil {
		return err
	}
	addresses, err := r.commandOutput(ctx, []string{r.ipPath(), "-j", "-4", "address", "show"}, "")
	if err != nil {
		return err
	}
	return validateHostTransitInventory(transit, routes, addresses)
}

func validateHostTransitInventory(transit netip.Prefix, routeData, addressData []byte) error {
	const maxEntries = 4096
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(routeData, &entries); err != nil {
		return fmt.Errorf("privd: parse host routes: %w", err)
	}
	if entries == nil || len(entries) > maxEntries {
		return fmt.Errorf("privd: invalid or oversized host route inventory")
	}
	kinds := make([]string, len(entries))
	for i, entry := range entries {
		if entry == nil {
			return fmt.Errorf("privd: invalid host route entry")
		}
		if raw, ok := entry["type"]; ok {
			if string(raw) == "null" {
				return fmt.Errorf("privd: invalid host route type")
			}
			if err := json.Unmarshal(raw, &kinds[i]); err != nil {
				return fmt.Errorf("privd: parse host route type: %w", err)
			}
		}
		// ParseIPRoutes normally skips non-unicast entries for allocator discovery.
		// At this authority boundary every route type protects its destination; remove
		// only that filtering input and reuse the shared prefix/host-address parser.
		delete(entry, "type")
	}
	normalized, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	routes, err := network.ParseIPRoutes(normalized)
	if err != nil {
		return err
	}
	for i, route := range routes {
		if !route.Dst.Addr().Is4() || route.Dst.Addr().Is4In6() {
			return fmt.Errorf("privd: non-IPv4 host route in IPv4 inventory")
		}
		if route.Dst.Bits() == 0 && (kinds[i] == "" || kinds[i] == "unicast") {
			continue
		}
		if transit.Overlaps(route.Dst) {
			return fmt.Errorf("privd: transit %s overlaps host route %s", transit, route.Dst)
		}
	}
	var interfaces []struct {
		Addresses *[]struct {
			Family string `json:"family"`
			Local  string `json:"local"`
			Bits   *int   `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(addressData, &interfaces); err != nil {
		return fmt.Errorf("privd: parse host addresses: %w", err)
	}
	if interfaces == nil || len(interfaces) > maxEntries {
		return fmt.Errorf("privd: invalid or oversized host address inventory")
	}
	count := len(entries)
	for _, iface := range interfaces {
		if iface.Addresses == nil {
			return fmt.Errorf("privd: missing host interface address inventory")
		}
		count += len(*iface.Addresses)
		if count > maxEntries {
			return fmt.Errorf("privd: host inventory exceeds prefix bound")
		}
		for _, address := range *iface.Addresses {
			ip, err := netip.ParseAddr(address.Local)
			if err != nil || !ip.Is4() || ip.Is4In6() || address.Family != "inet" || address.Bits == nil || *address.Bits < 0 || *address.Bits > 32 {
				return fmt.Errorf("privd: invalid IPv4 host address entry")
			}
			prefix := netip.PrefixFrom(ip, *address.Bits).Masked()
			if transit.Overlaps(prefix) {
				return fmt.Errorf("privd: transit %s overlaps host interface prefix %s", transit, prefix)
			}
		}
	}
	return nil
}

// loadNetworkPolicy anchors lookup to an open root-owned directory. Neither the
// configured directory nor the policy may be writable by another uid/group.
func (r *RealOps) loadNetworkPolicy(id string) (network.EffectivePolicy, string, error) {
	var zero network.EffectivePolicy
	if !filepath.IsAbs(r.cfg.PolicyDirectory) {
		return zero, "", fmt.Errorf("privd: absolute trusted policy directory required")
	}
	dir, err := os.Open(r.cfg.PolicyDirectory)
	if err != nil {
		return zero, "", err
	}
	defer dir.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		return zero, "", err
	}
	if st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return zero, "", fmt.Errorf("privd: policy directory must be root-owned and not group/world writable")
	}
	if !ValidVMID(id) {
		return zero, "", network.ErrInvalidPolicyID
	}
	policyFD, err := unix.Openat(int(dir.Fd()), id+".json", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return zero, "", err
	}
	file := os.NewFile(uintptr(policyFD), id+".json")
	defer file.Close()
	if err := unix.Fstat(policyFD, &st); err != nil {
		return zero, "", err
	}
	if st.Uid != 0 || st.Mode&0022 != 0 || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return zero, "", fmt.Errorf("privd: policy file must be root-owned regular and not group/world writable")
	}
	policy, err := network.LoadEffectivePolicyFile(file, id)
	if err != nil {
		return zero, "", err
	}
	body, err := json.Marshal(struct {
		ID      string
		Profile network.Profile
		DNS     string
		Ports   []uint16
		Denied  []netip.Prefix
	}{policy.ID(), policy.Profile(), policy.DNSUpstream().String(), policy.TCPPorts(), policy.Destinations().DeniedPrefixes()})
	if err != nil {
		return zero, "", err
	}
	sum := sha256.Sum256(body)
	return policy, hex.EncodeToString(sum[:]), nil
}

func (r *RealOps) boundNetwork(entry VMEntry, req AllocateNetworkReq) (network.Layout, network.EffectivePolicy, error) {
	var layout network.Layout
	var policy network.EffectivePolicy
	if entry.VMID != req.VMID || entry.NetCIDR != req.CIDR || entry.NetworkGuestBootID != req.GuestBootID || entry.NetworkProfile != req.Profile || entry.NetworkPolicyID != req.PolicyID || entry.NetworkPolicyVersion != network.PolicySchemaVersion || len(entry.GatewayGeneration) != 32 || entry.NetworkGuestBootID == "" {
		return layout, policy, fmt.Errorf("privd: gateway binding mismatch or unprepared ownership")
	}
	if _, err := hex.DecodeString(entry.GatewayGeneration); err != nil {
		return layout, policy, err
	}
	prefix, err := netip.ParsePrefix(req.CIDR)
	if err != nil {
		return layout, policy, err
	}
	layout, err = network.NewLayout(req.VMID, prefix)
	if err != nil {
		return layout, policy, err
	}
	policy, digest, err := r.loadNetworkPolicy(req.PolicyID)
	if err != nil {
		return layout, policy, err
	}
	if digest != entry.NetworkPolicyDigest || string(policy.Profile()) != entry.NetworkProfile {
		return layout, policy, fmt.Errorf("privd: trusted policy changed since allocation")
	}
	if policy.Profile() != network.ProfileOffline {
		return layout, policy, fmt.Errorf("%w: resolver and observer acquisition are not installed", network.ErrProfileUnavailable)
	}
	return layout, policy, nil
}

func (r *RealOps) gatewayRules(entry VMEntry, layout network.Layout, policy network.EffectivePolicy) (network.GatewayRules, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return network.GatewayRules{}, err
	}
	prefixes := []netip.Prefix{layout.TransitPrefix, layout.GuestPrefix}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return network.GatewayRules{}, err
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return network.GatewayRules{}, err
			}
			if prefix.Addr().Is4() {
				prefixes = append(prefixes, prefix.Masked())
			}
		}
	}
	rules, err := network.BuildGatewayRules(network.GatewayRuleConfig{VMID: entry.VMID, Layout: layout, Policy: policy, HostDenyPrefixes: prefixes, Ready: false})
	if err != nil {
		return rules, err
	}
	for _, table := range []network.NFTTable{rules.NamespaceIngressTable, rules.NamespaceFilterTable, rules.NamespaceNATTable} {
		rules.NamespaceScript = markTable(rules.NamespaceScript, table, entry)
	}
	for _, table := range []network.NFTTable{rules.HostFilterTable, rules.HostNATTable} {
		rules.HostScript = markTable(rules.HostScript, table, entry)
	}
	return rules, nil
}
func gatewayMarker(entry VMEntry) string { return "vmobs:" + entry.GatewayGeneration }
func markTable(script string, table network.NFTTable, entry VMEntry) string {
	start := "table " + table.Family + " " + table.Name + " {\n"
	return strings.Replace(script, start, start+"  comment \""+gatewayMarker(entry)+"\"\n", 1)
}

// AllocateNetworkOwnedContext creates down links, installs closed rules, then
// addresses, owned-interface forwarding and routes. It never rebuilds a remnant.
func (r *RealOps) AllocateNetworkOwnedContext(ctx context.Context, entry *VMEntry, req AllocateNetworkReq) error {
	layout, policy, err := r.boundNetwork(*entry, req)
	if err != nil {
		return err
	}
	exists, err := r.netnsExists(ctx, entry.VMID)
	if err != nil {
		return err
	}
	if exists {
		return r.ProbeNetworkContext(ctx, *entry, req)
	}

	if entry.NetworkNamespaceInode != 0 || entry.NetworkTopologyDigest != "" {
		return fmt.Errorf("privd: owned namespace disappeared; release required")
	}
	rules, err := r.gatewayRules(*entry, layout, policy)
	if err != nil {
		return err
	}
	hostLinks, err := r.commandOutput(ctx, []string{r.ipPath(), "-j", "link", "show"}, "")
	if err != nil {
		return err
	}
	var links []struct {
		Name string `json:"ifname"`
	}
	if err := json.Unmarshal(hostLinks, &links); err != nil {
		return err
	}
	for _, link := range links {
		if link.Name == network.VethName(entry.VMID) {
			return fmt.Errorf("privd: host veth name collision")
		}
	}
	for _, table := range []network.NFTTable{rules.HostFilterTable, rules.HostNATTable} {
		found, _, err := r.table(ctx, "", table)
		if err != nil {
			return err
		}
		if found {
			return fmt.Errorf("privd: host nft table collision")
		}
	}
	if err := r.checkHostTransitOverlap(ctx, layout.TransitPrefix); err != nil {
		return err
	}
	if err := r.runCmd(ctx, []string{r.ipPath(), "netns", "add", network.NamespaceName(entry.VMID)}); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Stat("/run/netns/"+network.NamespaceName(entry.VMID), &st); err != nil {
		return err
	}
	entry.NetworkNamespaceDevice = uint64(st.Dev)
	entry.NetworkNamespaceInode = st.Ino
	// Mark the namespace before creating any link. If this first marker cannot
	// be installed, retain the claim rather than later deleting an unmarked name.
	ownershipScript := markTable("table "+rules.NamespaceFilterTable.Family+" "+rules.NamespaceFilterTable.Name+" {\n}\n", rules.NamespaceFilterTable, *entry)
	if _, err := r.commandOutput(ctx, r.inNamespace(entry.VMID, r.nftPath(), "-f", "-"), ownershipScript); err != nil {
		return err
	}
	nsIP := func(args ...string) []string {
		return r.inNamespace(entry.VMID, append([]string{r.ipPath()}, args...)...)
	}
	commands := [][]string{
		nsIP("tuntap", "add", "dev", "tap0", "mode", "tap"),
		{r.ipPath(), "link", "add", network.VethName(entry.VMID), "type", "veth", "peer", "name", "eth-up", "netns", network.NamespaceName(entry.VMID)},
		{r.ipPath(), "link", "set", "dev", network.VethName(entry.VMID), "alias", gatewayMarker(*entry)},
		nsIP("link", "set", "dev", "eth-up", "alias", gatewayMarker(*entry)),
	}
	if err := r.runAll(ctx, commands); err != nil {
		return err
	}
	if _, err := r.commandOutput(ctx, r.inNamespace(entry.VMID, r.nftPath(), "-f", "-"), rules.NamespaceScript); err != nil {
		return err
	}
	if _, err := r.commandOutput(ctx, []string{r.nftPath(), "-f", "-"}, rules.HostScript); err != nil {
		return err
	}
	commands = [][]string{
		{r.ipPath(), "address", "add", layout.TransitHost.String() + "/30", "dev", network.VethName(entry.VMID)},
		nsIP("address", "add", layout.TransitNamespace.String()+"/30", "dev", "eth-up"),
		nsIP("address", "add", layout.GuestGateway.String()+"/30", "dev", "tap0"),
	}
	if err := r.runAll(ctx, commands); err != nil {
		return err
	}
	if err := enableOwnedForwarding(ctx, "", network.VethName(entry.VMID)); err != nil {
		return err
	}
	if err := enableOwnedForwarding(ctx, network.NamespaceName(entry.VMID), "tap0", "eth-up"); err != nil {
		return err
	}
	commands = [][]string{
		{r.ipPath(), "link", "set", "dev", network.VethName(entry.VMID), "up"},
		nsIP("link", "set", "dev", "lo", "up"), nsIP("link", "set", "dev", "tap0", "up"), nsIP("link", "set", "dev", "eth-up", "up"),
		nsIP("route", "add", "default", "via", layout.TransitHost.String(), "dev", "eth-up"),
	}
	if err := r.runAll(ctx, commands); err != nil {
		return err
	}
	entry.NetworkTopologyDigest, err = r.topologyDigest(ctx, *entry)
	return err
}

// ProbeNetworkContext is read-only even for an incomplete or missing topology.
// Repeated allocations and the launch barrier may verify this immutable binding;
// neither is authorized to repair or replace the kernel resources they inspect.
func (r *RealOps) ProbeNetworkContext(ctx context.Context, entry VMEntry, req AllocateNetworkReq) error {
	if _, _, err := r.boundNetwork(entry, req); err != nil {
		return err
	}
	if entry.NetworkTopologyDigest == "" {
		return fmt.Errorf("privd: incomplete gateway requires explicit release")
	}
	if err := r.proveNamespace(entry); err != nil {
		return err
	}
	digest, err := r.topologyDigest(ctx, entry)
	if err != nil {
		return err
	}
	if digest != entry.NetworkTopologyDigest {
		return fmt.Errorf("privd: owned topology changed; refusing live rebuild")
	}
	return nil
}

// enableOwnedForwarding retires its locked OS thread if namespace restore fails.
// No unrelated Go work can subsequently run in the guest network namespace.
func enableOwnedForwarding(ctx context.Context, namespace string, names ...string) error {
	result := make(chan error, 1)
	go func() { result <- forwardInNamespace(ctx, namespace, names) }()
	return <-result
}

func forwardInNamespace(ctx context.Context, namespace string, names []string) (result error) {
	runtime.LockOSThread()
	restored := true
	defer func() {
		if restored {
			runtime.UnlockOSThread()
		}
	}()
	if namespace != "" {
		current, err := os.Open("/proc/self/task/" + fmt.Sprint(unix.Gettid()) + "/ns/net")
		if err != nil {
			return err
		}
		defer current.Close()
		target, err := os.Open("/run/netns/" + namespace)
		if err != nil {
			return err
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			return err
		}
		restored = false
		defer func() {
			err := unix.Setns(int(current.Fd()), unix.CLONE_NEWNET)
			restored = err == nil
			result = errors.Join(result, err)
		}()
	}
	for _, name := range names {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return err
		}
		if err := network.EnableIPv4Forwarding(ctx, iface.Index); err != nil {
			return err
		}
	}
	return nil
}

func (r *RealOps) proveNamespace(entry VMEntry) error {
	boot, _, err := hostIdentity()
	if err != nil {
		return err
	}
	if entry.NetworkHostBootID == "" || entry.NetworkHostBootID != boot {
		return fmt.Errorf("privd: namespace belongs to a different or unknown host boot")
	}
	var st unix.Stat_t
	if err := unix.Stat("/run/netns/"+network.NamespaceName(entry.VMID), &st); err != nil {
		return err
	}
	if entry.NetworkNamespaceInode == 0 || st.Ino != entry.NetworkNamespaceInode || uint64(st.Dev) != entry.NetworkNamespaceDevice {
		return fmt.Errorf("privd: namespace kernel ownership mismatch")
	}
	return nil
}

// commandOutput bounds both command output streams; oversized inventory is an error.
func (r *RealOps) commandOutput(ctx context.Context, argv []string, stdin string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is built from validated identities and fixed commands.
	cmd.Stdin = strings.NewReader(stdin)
	output := &gatewayOutput{limit: 4 * 1024 * 1024}
	stderr := &gatewayOutput{limit: 512}
	cmd.Stdout = output
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("privd: %s: %w: %s", argv[0], err, stderr.String())
	}
	if output.overflow || stderr.overflow {
		return nil, fmt.Errorf("privd: gateway command output exceeds bound")
	}
	return output.Bytes(), nil
}

type gatewayOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *gatewayOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.buffer.Len()
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

func (b *gatewayOutput) Bytes() []byte  { return b.buffer.Bytes() }
func (b *gatewayOutput) String() string { return b.buffer.String() }

var _ io.Writer = (*gatewayOutput)(nil)

func (r *RealOps) table(ctx context.Context, namespace string, table network.NFTTable) (bool, string, error) {
	argv := []string{r.nftPath(), "-j", "list", "tables"}
	if namespace != "" {
		argv = r.inNamespace(namespace, argv...)
	}
	data, err := r.commandOutput(ctx, argv, "")
	if err != nil {
		return false, "", err
	}
	var doc struct {
		NFTables []struct {
			Table *struct {
				Family  string `json:"family"`
				Name    string `json:"name"`
				Comment string `json:"comment"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return false, "", err
	}
	for _, object := range doc.NFTables {
		if object.Table != nil && object.Table.Family == table.Family && object.Table.Name == table.Name {
			return true, object.Table.Comment, nil
		}
	}
	return false, "", nil
}

func gatewayTables(entry VMEntry) (network.GatewayRules, error) {
	prefix, err := netip.ParsePrefix(entry.NetCIDR)
	if err != nil {
		return network.GatewayRules{}, err
	}
	layout, err := network.NewLayout(entry.VMID, prefix)
	if err != nil {
		return network.GatewayRules{}, err
	}
	policy, err := network.ValidateEffectivePolicy(network.PolicyFile{SchemaVersion: 1, ID: "offline", Profile: network.ProfileOffline})
	if err != nil {
		return network.GatewayRules{}, err
	}
	return network.BuildGatewayRules(network.GatewayRuleConfig{VMID: entry.VMID, Layout: layout, Policy: policy, HostDenyPrefixes: []netip.Prefix{layout.TransitPrefix}})
}

func (r *RealOps) topologyDigest(ctx context.Context, entry VMEntry) (string, error) {
	if err := r.proveNamespace(entry); err != nil {
		return "", err
	}
	rules, err := gatewayTables(entry)
	if err != nil {
		return "", err
	}
	var snapshots []json.RawMessage
	for _, object := range []struct {
		namespace string
		table     network.NFTTable
	}{{"", rules.HostFilterTable}, {"", rules.HostNATTable}, {entry.VMID, rules.NamespaceIngressTable}, {entry.VMID, rules.NamespaceFilterTable}, {entry.VMID, rules.NamespaceNATTable}} {
		argv := []string{r.nftPath(), "-j", "list", "table", object.table.Family, object.table.Name}
		if object.namespace != "" {
			argv = r.inNamespace(object.namespace, argv...)
		}
		data, err := r.commandOutput(ctx, argv, "")
		if err != nil {
			return "", err
		}
		var document any
		if err := json.Unmarshal(data, &document); err != nil {
			return "", err
		}
		normalizeNFT(document)
		normalized, err := json.Marshal(document)
		if err != nil {
			return "", err
		}
		snapshots = append(snapshots, normalized)
	}
	for _, object := range []struct{ namespace, name string }{{"", network.VethName(entry.VMID)}, {entry.VMID, "eth-up"}, {entry.VMID, "tap0"}} {
		argv := []string{r.ipPath(), "-j", "address", "show", "dev", object.name}
		if object.namespace != "" {
			argv = r.inNamespace(object.namespace, argv...)
		}
		data, err := r.commandOutput(ctx, argv, "")
		if err != nil {
			return "", err
		}
		var links []map[string]any
		if err := json.Unmarshal(data, &links); err != nil {
			return "", err
		}
		if len(links) != 1 {
			return "", fmt.Errorf("privd: expected one owned interface")
		}
		link := links[0]
		// Carrier state changes when the VMM opens TAP; configured state must not.
		delete(link, "operstate")
		delete(link, "linkmode")
		delete(link, "txqlen")
		if flags, ok := link["flags"].([]any); ok {
			up := false
			for _, flag := range flags {
				if flag == "UP" {
					up = true
				}
			}
			link["flags"] = up
		}
		if addresses, ok := link["addr_info"].([]any); ok {
			var v4 []any
			for _, address := range addresses {
				if a, ok := address.(map[string]any); ok && a["family"] == "inet" {
					v4 = append(v4, a)
				}
			}
			link["addr_info"] = v4
		}
		normalized, err := json.Marshal(link)
		if err != nil {
			return "", err
		}
		snapshots = append(snapshots, normalized)
		argv = []string{"cat", "/proc/sys/net/ipv4/conf/" + object.name + "/forwarding"}
		if object.namespace != "" {
			argv = r.inNamespace(object.namespace, argv...)
		}
		data, err = r.commandOutput(ctx, argv, "")
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(string(data)) != "1" {
			return "", fmt.Errorf("privd: owned interface forwarding is disabled")
		}
	}
	data, err := r.commandOutput(ctx, r.inNamespace(entry.VMID, r.ipPath(), "-j", "-4", "route", "show", "table", "all"), "")
	if err != nil {
		return "", err
	}
	var routes any
	if err := json.Unmarshal(data, &routes); err != nil {
		return "", err
	}
	normalized, err := json.Marshal(routes)
	if err != nil {
		return "", err
	}
	snapshots = append(snapshots, normalized)
	data, err = json.Marshal(snapshots)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
func normalizeNFT(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "handle" || key == "packets" || key == "bytes" || key == "metainfo" {
				delete(v, key)
			} else {
				normalizeNFT(child)
			}
		}
	case []any:
		for _, child := range v {
			normalizeNFT(child)
		}
	}
}

// ReleaseNetworkContext keeps the lease on every unknown or surviving resource.
func (r *RealOps) ReleaseNetworkContext(ctx context.Context, entry VMEntry) error {
	if entry.PID != 0 {
		return fmt.Errorf("privd: VM must be released before its network")
	}
	if len(entry.GatewayGeneration) != 32 {
		return fmt.Errorf("privd: network generation ownership missing")
	}
	rules, err := gatewayTables(entry)
	if err != nil {
		return err
	}
	exists, err := r.netnsExists(ctx, entry.VMID)
	if err != nil {
		return err
	}
	if exists {
		if err := r.proveNamespace(entry); err != nil {
			return err
		}
		for _, table := range []network.NFTTable{rules.NamespaceFilterTable, rules.NamespaceIngressTable, rules.NamespaceNATTable} {
			found, comment, err := r.table(ctx, entry.VMID, table)
			if err != nil {
				return err
			}
			if !found && table == rules.NamespaceFilterTable {
				return fmt.Errorf("privd: namespace generation marker missing")
			}
			if found && comment != gatewayMarker(entry) {
				return fmt.Errorf("privd: namespace nft ownership mismatch")
			}
		}
	}
	// Prove every host resource before any deletion. A name alone never grants ownership.
	for _, table := range []network.NFTTable{rules.HostFilterTable, rules.HostNATTable} {
		found, comment, err := r.table(ctx, "", table)
		if err != nil {
			return err
		}
		if found && comment != gatewayMarker(entry) {
			return fmt.Errorf("privd: host nft ownership mismatch")
		}
	}
	data, err := r.commandOutput(ctx, []string{r.ipPath(), "-j", "link", "show"}, "")
	if err != nil {
		return err
	}
	var links []struct {
		Name  string `json:"ifname"`
		Alias string `json:"ifalias"`
	}
	if err := json.Unmarshal(data, &links); err != nil {
		return err
	}
	vethExists := false
	for _, link := range links {
		if link.Name == network.VethName(entry.VMID) {
			if link.Alias != gatewayMarker(entry) {
				return fmt.Errorf("privd: host veth ownership mismatch")
			}
			vethExists = true
		}
	}
	var cleanupErr error
	// Close the owned interface before removing its enforcement.
	if vethExists {
		if err := r.runCmd(ctx, []string{r.ipPath(), "link", "del", network.VethName(entry.VMID)}); err != nil {
			return err
		}
	}
	if exists {
		if err := r.runCmd(ctx, []string{r.ipPath(), "netns", "del", network.NamespaceName(entry.VMID)}); err != nil {
			return err
		}
	}
	for _, table := range []network.NFTTable{rules.HostFilterTable, rules.HostNATTable} {
		found, _, err := r.table(ctx, "", table)
		if err != nil {
			return err
		}
		if found {
			cleanupErr = errors.Join(cleanupErr, r.runCmd(ctx, []string{r.nftPath(), "delete", "table", table.Family, table.Name}))
		}
	}
	exists, err = r.netnsExists(ctx, entry.VMID)
	if err != nil {
		return errors.Join(cleanupErr, err)
	}
	if exists {
		return errors.Join(cleanupErr, fmt.Errorf("privd: namespace survives teardown"))
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return errors.Join(cleanupErr, err)
	}
	for _, iface := range interfaces {
		if iface.Name == network.VethName(entry.VMID) {
			return errors.Join(cleanupErr, fmt.Errorf("privd: host veth survives teardown"))
		}
	}
	for _, table := range []network.NFTTable{rules.HostFilterTable, rules.HostNATTable} {
		found, _, err := r.table(ctx, "", table)
		if err != nil {
			return errors.Join(cleanupErr, err)
		}
		if found {
			return errors.Join(cleanupErr, fmt.Errorf("privd: host nft table survives teardown"))
		}
	}
	return cleanupErr
}
