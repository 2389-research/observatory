// ABOUTME: Served-daemon proof that the doctor sees the guest channel: a real
// ABOUTME: privd socket and stage root make GET /host/status report guest_channel pass.

//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// wirePreflightHostStatus is the slice of GET /host/status this test reads:
// the preflight report the daemon wires into the response.
type wirePreflightHostStatus struct {
	Preflight *struct {
		Overall string `json:"overall"`
		Checks  []struct {
			ID       string   `json:"id"`
			Status   string   `json:"status"`
			Summary  string   `json:"summary"`
			Evidence []string `json:"evidence"`
		} `json:"checks"`
	} `json:"preflight"`
}

// A daemon configured with a reachable privd socket and an existing stage root
// must report guest_channel pass. Before the wiring fix the daemon built the
// doctor's config without either field, so this check reported "not configured"
// on every host and the jailer adapter refused every launch with 501.
func TestServeReportsGuestChannelPassWhenPrivdReachable(t *testing.T) {
	// A unix socket path must fit in sun_path (108 bytes); t.TempDir() embeds the
	// test name and can overrun it, so the socket lives in a short /tmp dir.
	sockDir, err := os.MkdirTemp("/tmp", "pfw")
	if err != nil {
		t.Fatalf("make socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "privd.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen on %s: %v", sockPath, err)
	}
	t.Cleanup(func() { ln.Close() })
	// Drain accepted connections: the check connects and closes without sending
	// a request, so the listener only has to exist and accept.
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			conn.Close()
		}
	}()

	runtimeDir := t.TempDir()
	cfg := testConfig(t, "127.0.0.1:0")
	cfg.Paths.Runtime = runtimeDir
	cfg.Paths.PrivilegedSocket = sockPath
	if err := os.MkdirAll(cfg.Paths.StageRoot(), 0o755); err != nil {
		t.Fatalf("create stage root: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, cfg, quietLogger(), func(addr string) { addrCh <- addr })
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		t.Fatalf("serve exited before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("daemon never became ready")
	}

	resp, err := http.Get("http://" + addr + "/api/v1/host/status")
	if err != nil {
		t.Fatalf("GET /host/status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /host/status: status %d", resp.StatusCode)
	}
	var status wirePreflightHostStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode host status: %v", err)
	}
	if status.Preflight == nil {
		t.Fatal("host status carries no preflight block; the daemon did not wire the doctor")
	}

	found := false
	for _, c := range status.Preflight.Checks {
		if c.ID != "guest_channel" {
			continue
		}
		found = true
		if c.Status != "pass" {
			t.Errorf("guest_channel status = %q, want %q: summary=%q evidence=%v",
				c.Status, "pass", c.Summary, c.Evidence)
		}
		// The evidence must name the socket this test is listening on, so a pass
		// says which socket the doctor dialed rather than merely that one worked.
		sockNamed := false
		for _, e := range c.Evidence {
			if strings.Contains(e, sockPath) {
				sockNamed = true
			}
		}
		if !sockNamed {
			t.Errorf("guest_channel evidence %v does not name the configured socket %q",
				c.Evidence, sockPath)
		}
	}
	if !found {
		t.Error("no guest_channel check in the preflight report")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("serve returned %v on graceful shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not shut down")
	}
}
