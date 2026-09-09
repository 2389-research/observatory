// ABOUTME: Checks launch refusal for unbound allocations and copied Firecracker resources.
// ABOUTME: Uses real files and the real isolated gateway when explicitly enabled.
//go:build linux

package privd

import (
	"context"
	"fmt"
	"github.com/2389-research/observatory/internal/network"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestStartVMRequiresCompletedNetwork(t *testing.T) {
	ops, _ := stageOps(t, t.TempDir())
	entry := VMEntry{VMID: "binding"}
	_, err := ops.StartVM(&entry, StartVMReq{VMID: entry.VMID})
	if err == nil || !strings.Contains(err.Error(), "network allocation") {
		t.Fatalf("missing completed network: %v", err)
	}
	if entry.StartAttempted {
		t.Fatal("launch attempted")
	}
}

func TestCopiedFirecrackerBinding(t *testing.T) {
	entry := VMEntry{VMID: "binding", NetCIDR: "10.99.0.0/30"}
	valid := bindingConfig(t, entry)
	cases := map[string]string{"valid": valid, "tap": strings.Replace(valid, "tap0", "tap1", 1), "mac": strings.Replace(valid, bindingMAC(t, entry), "02:00:00:00:00:01", 1), "cid": strings.Replace(valid, `"guest_cid":3`, `"guest_cid":4`, 1), "vsock": strings.Replace(valid, "v.sock", "../v.sock", 1), "kernel": strings.Replace(valid, "vmlinux", "../vmlinux", 1), "drive": strings.Replace(valid, "rootfs.ext4", "../rootfs.ext4", 1), "extra-path": strings.Replace(valid, `"boot_args"`, `"initrd_path":"secret","boot_args"`, 1), "extra-nic": strings.Replace(valid, `"network-interfaces":[`, `"network-interfaces":[{"host_dev_name":"tap1"},`, 1), "trailing": valid + ` {}`, "oversized": strings.Repeat(" ", 1024*1024) + valid}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			file := stageOne(t, dir, "fc-config.json", []byte(body))
			src, err := os.Open(dir + "/fc-config.json")
			if err != nil {
				t.Fatal(err)
			}
			defer src.Close()
			dst, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer dst.Close()
			err = copyBoundConfigContext(context.Background(), src, dst, file, os.Getuid(), os.Getgid(), entry, StartVMReq{CID: 3})
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted mismatched configuration")
			}
		})
	}
}

func bindingMAC(t *testing.T, entry VMEntry) string {
	t.Helper()
	layout, err := network.NewLayout(entry.VMID, netip.MustParsePrefix(entry.NetCIDR))
	if err != nil {
		t.Fatal(err)
	}
	return layout.GuestMAC.String()
}

// startStagedForTest isolates staging/exec filesystem tests from network allocation.
// Public StartVM refusal and actual network proof have separate tests below.
func startStagedForTest(t *testing.T, ops *RealOps, entry *VMEntry, req StartVMReq) (StartVMResp, error) {
	t.Helper()
	root, err := ops.stageVMContext(context.Background(), *entry, req)
	if err != nil {
		return StartVMResp{}, err
	}
	defer root.Close()
	return ops.execStagedVMContext(context.Background(), entry, req, root)
}

func bindingConfig(t *testing.T, entry VMEntry) string {
	valid := `{"boot-source":{"kernel_image_path":"vmlinux","boot_args":"console=ttyS0"},"drives":[{"drive_id":"rootfs","path_on_host":"rootfs.ext4","is_root_device":true,"is_read_only":false},{"drive_id":"config","path_on_host":"config.ext4","is_root_device":false,"is_read_only":true},{"drive_id":"workspace","path_on_host":"workspace.ext4","is_root_device":false,"is_read_only":false}],"machine-config":{"vcpu_count":1,"mem_size_mib":512},"vsock":{"guest_cid":3,"uds_path":"v.sock"},"network-interfaces":[{"iface_id":"eth0","host_dev_name":"tap0","guest_mac":"MAC"}]}`
	return strings.ReplaceAll(valid, "MAC", bindingMAC(t, entry))
}

func TestStartVMClosedGatewayBinding(t *testing.T) {
	if os.Getenv("VMOBS_GATEWAY_LIFECYCLE") != "1" {
		t.Skip("requires opted-in isolated Linux container")
	}
	ops, _ := stageOps(t, t.TempDir())
	ops.cfg.PolicyDirectory = t.TempDir()
	if err := os.WriteFile(ops.cfg.PolicyDirectory+"/offline.json", []byte(`{"schema_version":1,"id":"offline","profile":"offline","dns_upstream":"","allowed_tcp_ports":[],"extra_deny_prefixes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	entry := VMEntry{VMID: "start-binding", NetCIDR: "10.99.0.40/30", UID: os.Getuid(), GID: os.Getgid()}
	allocation := AllocateNetworkReq{VMID: entry.VMID, CIDR: entry.NetCIDR, Profile: "offline", PolicyID: "offline", GuestBootID: "b28581fb-7b8b-499a-8671-8bf54d159839"}
	ctx := context.Background()
	if err := ops.PrepareNetworkEntry(ctx, &entry, allocation); err != nil {
		t.Fatal(err)
	}
	if err := ops.AllocateNetworkOwnedContext(ctx, &entry, allocation); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ops.ReleaseNetwork(entry); err != nil {
			t.Error(err)
		}
	})
	entry.NetworkComplete = true
	// A real executable marker records whether the jailer boundary was crossed.
	marker := t.TempDir() + "/executed"
	ops.cfg.JailerPath = t.TempDir() + "/jailer"
	if err := os.WriteFile(ops.cfg.JailerPath, []byte("#!/bin/sh\ntouch '"+marker+"'\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	request := StartVMReq{VMID: entry.VMID, UID: entry.UID, GID: entry.GID, CID: 3}
	for name, change := range map[string]func(*VMEntry){"incomplete": func(e *VMEntry) { e.NetworkComplete = false }, "stale-boot": func(e *VMEntry) { e.NetworkHostBootID = "stale" }, "generation": func(e *VMEntry) { e.GatewayGeneration = strings.Repeat("0", 32) }, "policy": func(e *VMEntry) { e.NetworkPolicyDigest = "stale" }, "topology": func(e *VMEntry) { e.NetworkTopologyDigest = "stale" }} {
		t.Run(name, func(t *testing.T) {
			bad := entry
			change(&bad)
			if _, err := ops.StartVM(&bad, request); err == nil {
				t.Fatal("accepted stale allocation")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("jailer executed", err)
			}
		})
	}
	for _, variant := range []string{"mac", "tap", "cid", "path", "valid"} {
		t.Run(variant, func(t *testing.T) {
			body := bindingConfig(t, entry)
			switch variant {
			case "mac":
				body = strings.Replace(body, bindingMAC(t, entry), "02:00:00:00:00:01", 1)
			case "tap":
				body = strings.Replace(body, "tap0", "tap1", 1)
			case "cid":
				body = strings.Replace(body, `"guest_cid":3`, `"guest_cid":4`, 1)
			case "path":
				body = strings.Replace(body, "v.sock", "../v.sock", 1)
			}
			request.Files = []StagedFile{stageOne(t, ops.cfg.StageRoot+"/"+entry.VMID, "fc-config.json", []byte(body))}
			trial := entry
			_, err := ops.StartVM(&trial, request)
			if err == nil {
				t.Fatal("test executable must return failure")
			}
			_, statErr := os.Stat(marker)
			if variant == "valid" {
				if statErr != nil || !trial.StartAttempted {
					t.Fatalf("valid configuration never reached jailer: %v, %v", err, statErr)
				}
			} else if !os.IsNotExist(statErr) || trial.StartAttempted {
				t.Fatalf("mismatch reached jailer: %v", err)
			}
			if err := os.RemoveAll(ops.cfg.JailBase + "/firecracker/" + entry.VMID); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := ops.runCmd(ctx, []string{"ip", "netns", "exec", "vmobs-" + entry.VMID, "ip", "address", "del", "172.31.255.1/30", "dev", "tap0"}); err != nil {
		t.Fatal(err)
	}
	damaged := entry
	if _, err := ops.StartVM(&damaged, request); err == nil {
		t.Fatal("accepted actual topology damage")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("damaged topology reached jailer")
	}
	if err := ops.ProbeNetworkContext(ctx, entry, allocation); err == nil {
		t.Fatal("launch repaired damaged topology")
	}

}

func TestCopiedConfigDescriptorSurvivesPathReplacement(t *testing.T) {
	entry := VMEntry{VMID: "binding", NetCIDR: "10.99.0.0/30"}
	for _, valid := range []bool{false, true} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			body := bindingConfig(t, entry)
			replacement := strings.Replace(body, "tap0", "tap1", 1)
			if !valid {
				body, replacement = replacement, body
			}
			sourceDir := t.TempDir()
			staged := stageOne(t, sourceDir, "fc-config.json", []byte(body))
			source, err := os.Open(sourceDir + "/fc-config.json")
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			targetDir := t.TempDir()
			target, err := os.Open(targetDir)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			err = copyValidatedContext(context.Background(), source, target, staged, os.Getuid(), os.Getgid(), func(fd *os.File) error {
				if err := os.Rename(targetDir+"/fc-config.json", targetDir+"/pinned"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(targetDir+"/fc-config.json", []byte(replacement), 0600); err != nil {
					t.Fatal(err)
				}
				return validateCopiedConfig(fd, entry, StartVMReq{CID: 3})
			})
			if (err == nil) != valid {
				t.Fatalf("validation followed replacement name: valid=%v err=%v", valid, err)
			}
		})
	}
}
