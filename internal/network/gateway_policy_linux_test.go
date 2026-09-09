//go:build linux

// ABOUTME: Sends generated namespace and host programs through the real nft parser.
// ABOUTME: Runs only in an explicitly isolated, privileged Linux test environment.
package network_test

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/2389-research/observatory/internal/network"
)

func TestGatewayRulesPassRealNftCheck(t *testing.T) {
	if os.Getenv("VMOBS_REAL_NFT_CHECK") != "1" {
		t.Skip("set VMOBS_REAL_NFT_CHECK=1 inside a disposable privileged Linux network namespace")
	}
	rules, err := network.BuildGatewayRules(gatewayInput(t, network.ProfileTransport, true))
	if err != nil {
		t.Fatalf("BuildGatewayRules: %v", err)
	}
	for name, script := range map[string]string{
		"namespace": rules.NamespaceScript,
		"host":      rules.HostScript,
	} {
		t.Run(name, func(t *testing.T) {
			command := exec.Command("nft", "-c", "-f", "-")
			command.Stdin = bytes.NewBufferString(script)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("nft -c: %v\n%s\nprogram:\n%s", err, output, script)
			}
		})
	}
}
