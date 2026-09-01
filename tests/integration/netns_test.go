// ABOUTME: Root-gated integration test for vmobs-root-helper net-setup/net-teardown.
// ABOUTME: Requires VMOBS_FIXTURE=1 and the helper installed by scripts/aibox03/setup.

//go:build linux

package integration_test

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"

	"github.com/2389-research/observatory-v2/internal/network"
)

const (
	helperPath = "/usr/local/sbin/vmobs-root-helper"
	testID     = "itest-net"
	testCIDR   = "10.190.0.0/30"
)

// TestNetNSSetupTeardown exercises net-setup and net-teardown via the root helper.
// It skips if VMOBS_FIXTURE=1 is not set or the helper binary is absent.
func TestNetNSSetupTeardown(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 to run root-gated network integration tests")
	}
	if _, err := os.Stat(helperPath); os.IsNotExist(err) {
		t.Skipf("root helper not installed at %s; run scripts/aibox03/setup to install it", helperPath)
	}

	// Teardown on cleanup regardless of assertion failures.
	t.Cleanup(func() {
		cmd := exec.Command("sudo", helperPath, "net-teardown", testID)
		// Ignore teardown errors — the namespace may already be gone.
		_ = cmd.Run()
	})

	// net-setup
	setupCmd := exec.Command("sudo", helperPath, "net-setup", testID, testCIDR)
	setupCmd.Stdout = os.Stdout
	setupCmd.Stderr = os.Stderr
	if err := setupCmd.Run(); err != nil {
		t.Fatalf("net-setup failed: %v", err)
	}

	// Assert 1: /var/run/netns/vmobs-itest-net must exist (no root needed).
	nsPath := fmt.Sprintf("/var/run/netns/%s", network.NamespaceName(testID))
	if _, err := os.Stat(nsPath); err != nil {
		t.Errorf("network namespace path %s: %v", nsPath, err)
	}

	// Assert 2: host-side veth link must exist (readable via /sys/class/net, no root).
	vethName := network.VethName(testID)
	sysPath := fmt.Sprintf("/sys/class/net/%s", vethName)
	if _, err := os.Stat(sysPath); err != nil {
		t.Errorf("host veth %s not found at %s: %v", vethName, sysPath, err)
	}
	// Double-check via net.InterfaceByName, which also needs no privilege.
	if _, err := net.InterfaceByName(vethName); err != nil {
		t.Errorf("net.InterfaceByName(%q): %v", vethName, err)
	}

	// net-teardown
	teardownCmd := exec.Command("sudo", helperPath, "net-teardown", testID)
	teardownCmd.Stdout = os.Stdout
	teardownCmd.Stderr = os.Stderr
	if err := teardownCmd.Run(); err != nil {
		t.Fatalf("net-teardown failed: %v", err)
	}

	// Assert 3: namespace must be gone after teardown.
	if _, err := os.Stat(nsPath); !os.IsNotExist(err) {
		t.Errorf("namespace path %s still exists after teardown (err: %v)", nsPath, err)
	}

	// Assert 4: veth must be gone after teardown.
	if _, err := os.Stat(sysPath); !os.IsNotExist(err) {
		t.Errorf("veth %s still exists after teardown (err: %v)", sysPath, err)
	}
}
