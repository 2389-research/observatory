// ABOUTME: Tests exact observer binding metadata before accepting privileged descriptors.
// ABOUTME: Rejects ambiguous identities and closes all caller-owned resources.
package privd

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func validObserverMetadata() (AcquireNetworkObserversReq, *NetworkObserverBundle) {
	req := AcquireNetworkObserversReq{VMID: "observer-test", GuestBootID: "b28581fb-7b8b-499a-8671-8bf54d159839"}
	return req, &NetworkObserverBundle{Binding: NetworkObserverBinding{VMID: req.VMID, GuestBootID: req.GuestBootID, HostBootID: "a28581fb-7b8b-499a-8671-8bf54d159839", GatewayGeneration: strings.Repeat("a", 32), NamespaceDevice: "4", NamespaceInode: "4026532448", PolicyID: "offline", PolicyDigest: strings.Repeat("b", 64), Profile: "offline", AcquisitionID: "c28581fb-7b8b-499a-8671-8bf54d159839"}, Sockets: []ObserverSocket{{Kind: "conntrack", Boundary: "namespace_gateway", PortID: 11, SnapshotSequence: 1}, {Kind: "nflog", Boundary: "namespace_gateway", PortID: 12, Group: 100}, {Kind: "nflog", Boundary: "host_veth", PortID: 13, Group: 1024}}}
}
func TestObserverMetadataRequiresExactBoundScope(t *testing.T) {
	req, b := validObserverMetadata()
	if err := validateObserverMetadata(req, b); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*NetworkObserverBundle){"vm": func(b *NetworkObserverBundle) { b.Binding.VMID = "other" }, "boot": func(b *NetworkObserverBundle) { b.Binding.GuestBootID = b.Binding.HostBootID }, "uuid": func(b *NetworkObserverBundle) { b.Binding.AcquisitionID = "bad" }, "digest": func(b *NetworkObserverBundle) { b.Binding.PolicyDigest = "bad" }, "generation": func(b *NetworkObserverBundle) { b.Binding.GatewayGeneration = "bad" }, "inode": func(b *NetworkObserverBundle) { b.Binding.NamespaceInode = "04026532448" }, "device": func(b *NetworkObserverBundle) { b.Binding.NamespaceDevice = "-1" }, "profile": func(b *NetworkObserverBundle) { b.Binding.Profile = "unknown" }, "count": func(b *NetworkObserverBundle) { b.Sockets = b.Sockets[:2] }, "order": func(b *NetworkObserverBundle) { b.Sockets[0], b.Sockets[1] = b.Sockets[1], b.Sockets[0] }, "hostgroup": func(b *NetworkObserverBundle) { b.Sockets[2].Group = 100 }, "namespacegroup": func(b *NetworkObserverBundle) { b.Sockets[1].Group = 101 }, "dump": func(b *NetworkObserverBundle) { b.Sockets[0].SnapshotSequence = 0 }, "port": func(b *NetworkObserverBundle) { b.Sockets[0].PortID = 0 }, "nflogdump": func(b *NetworkObserverBundle) { b.Sockets[1].SnapshotSequence = 1 }} {
		t.Run(name, func(t *testing.T) {
			_, b := validObserverMetadata()
			change(b)
			if err := validateObserverMetadata(req, b); err == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
}
func TestObserverStrictJSON(t *testing.T) {
	for _, raw := range []string{`{"vm_id":"a","guest_boot_id":"b","namespace":"/run/netns/x"}`, `{"vm_id":"a","vm_id":"b","guest_boot_id":"c"}`, `{"VM_ID":"a","guest_boot_id":"b"}`, `{"vm_id":"a","VM_ID":"b","guest_boot_id":"c"}`, `{"vm_id":"a"} {}`, `null`} {
		var req AcquireNetworkObserversReq
		if err := decodeObserverJSON([]byte(raw), &req); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	var req AcquireNetworkObserversReq
	if err := decodeObserverJSON([]byte(`{"vm_id":"a","guest_boot_id":"b"}`), &req); err != nil {
		t.Fatal(err)
	}
}
func TestObserverBundleCloseIsIdempotent(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "bundle")
	if err != nil {
		t.Fatal(err)
	}
	bundle := &NetworkObserverBundle{Files: []*os.File{file, nil}}
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("closed")); err == nil {
		t.Fatal("file remained open")
	}
	if err := bundle.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "Files") || strings.Contains(string(body), "files") {
		t.Fatalf("descriptor objects serialized %s", body)
	}
}
