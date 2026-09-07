// ABOUTME: Live smoke test against a running vmobs-privd daemon on the real socket.
// ABOUTME: Skips cleanly when the socket is absent (daemon not yet installed).

//go:build linux

package privd_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/privd"
)

const privdSockPath = "/run/vmobs/privd.sock"

// TestPrivdLiveSmoke connects to the real privd socket, allocates a network entry,
// then releases it. Skips when the socket is absent (daemon not installed yet).
// To install the daemon, run: scripts/aibox03/setup.sh
func TestPrivdLiveSmoke(t *testing.T) {
	if _, err := os.Stat(privdSockPath); errors.Is(err, os.ErrNotExist) {
		t.Skipf("privd socket absent (%s): install daemon via scripts/aibox03/setup.sh", privdSockPath)
	}

	c := &privd.Client{SocketPath: privdSockPath}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const smokeID = "privd-smoke"
	const smokeCIDR = "10.199.99.0/30"

	t.Run("allocate_network", func(t *testing.T) {
		err := c.AllocateNetwork(ctx, privd.AllocateNetworkReq{
			VMID: smokeID,
			CIDR: smokeCIDR,
		})
		if err != nil {
			t.Fatalf("AllocateNetwork: %v", err)
		}
	})

	t.Run("release_network", func(t *testing.T) {
		err := c.ReleaseNetwork(ctx, privd.ReleaseNetworkReq{VMID: smokeID})
		if err != nil {
			t.Fatalf("ReleaseNetwork: %v", err)
		}
	})
}
