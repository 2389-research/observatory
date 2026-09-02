// ABOUTME: Pins the daemon's preflight config wiring: the doctor must be handed
// ABOUTME: the same privd socket and stage root the jailer adapter launches with.
package main

import (
	"errors"
	"testing"

	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/lock"
)

// exampleConfigPath is the shipped host config. config.Load applies no default
// to any paths.* key, so the example is the only place the operator-facing
// values for privileged_socket and runtime live.
const exampleConfigPath = "../../docs/examples/host-config.yaml"

// preflightConfig must carry every field the doctor needs. The two that matter
// most are PrivdSocket and StageRoot: without them guest_channel reports
// "not configured" and every launch is refused 501 on a healthy host.
func TestPreflightConfigCarriesGuestChannelFields(t *testing.T) {
	cfg := &config.Config{
		Server: config.Server{Mode: "loopback_only"},
		Auth:   config.Auth{RequireAuthentication: true},
		Storage: config.Storage{
			Database: "/var/lib/vmobs/state/events.sqlite",
		},
		Paths: config.Paths{
			Runtime:          "/srv/vmobs",
			PrivilegedSocket: "/x/privd.sock",
		},
	}
	pfLock := &lock.Lock{Schema: "vmobs.runtime-lock/1"}
	pfLockErr := errors.New("lock load failed")

	got := preflightConfig(cfg, pfLock, pfLockErr)

	if got.PrivdSocket != "/x/privd.sock" {
		t.Errorf("PrivdSocket = %q, want %q", got.PrivdSocket, "/x/privd.sock")
	}
	if got.StageRoot != "/srv/vmobs/stage" {
		t.Errorf("StageRoot = %q, want %q", got.StageRoot, "/srv/vmobs/stage")
	}
	if got.StageRoot != cfg.Paths.StageRoot() {
		t.Errorf("StageRoot = %q, want the config derivation %q", got.StageRoot, cfg.Paths.StageRoot())
	}
	// The extraction must not silently drop a field the literal used to set.
	if got.DataDir != "/var/lib/vmobs/state" {
		t.Errorf("DataDir = %q, want %q", got.DataDir, "/var/lib/vmobs/state")
	}
	if got.APIMode != "loopback_only" {
		t.Errorf("APIMode = %q, want %q", got.APIMode, "loopback_only")
	}
	if !got.RequireAuth {
		t.Error("RequireAuth = false, want true")
	}
	if got.Lock != pfLock {
		t.Errorf("Lock = %v, want the lock passed in", got.Lock)
	}
	if !errors.Is(got.LockErr, pfLockErr) {
		t.Errorf("LockErr = %v, want %v", got.LockErr, pfLockErr)
	}
}

// config.Load supplies no default for paths.privileged_socket or paths.runtime,
// so the shipped example is the only place those two operator-facing values are
// written down. This guards exactly that: both reach the doctor non-empty, so an
// edit that empties either one fails here instead of reappearing as a red gate.
// Non-empty does not mean reachable: whether the example's paths match the
// installed privd unit's --stage-root is a separate question this assertion
// cannot answer.
func TestPreflightConfigFromExampleConfigHasGuestChannelPaths(t *testing.T) {
	cfg, err := config.Load(exampleConfigPath)
	if err != nil {
		t.Fatalf("load %s: %v", exampleConfigPath, err)
	}
	pf := preflightConfig(cfg, nil, nil)
	if pf.PrivdSocket == "" {
		t.Error("PrivdSocket is empty for the shipped example config; guest_channel would report not_configured")
	}
	if pf.StageRoot == "" {
		t.Error("StageRoot is empty for the shipped example config; guest_channel would report not_configured")
	}
}
