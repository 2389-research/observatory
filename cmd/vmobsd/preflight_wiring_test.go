// ABOUTME: Pins the daemon's preflight config wiring: the doctor must be handed
// ABOUTME: the same privd socket and stage root the jailer adapter launches with.
package main

import (
	"testing"

	"github.com/2389-research/observatory/internal/config"
	"github.com/2389-research/observatory/internal/runtime"
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
		Runtime: config.Runtime{LockFile: "/srv/vmobs/runtime.lock.json"},
	}

	got := preflightConfig(cfg)

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
	// The doctor reads the lock itself, so it must be pointed at the file a
	// launch stages from. Hand it a different path — or none — and fc_binaries
	// answers for a file nothing boots from.
	if got.LockPath != cfg.Runtime.LockFile {
		t.Errorf("LockPath = %q, want the jailer's %q", got.LockPath, cfg.Runtime.LockFile)
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
	pf := preflightConfig(cfg)
	if pf.PrivdSocket == "" {
		t.Error("PrivdSocket is empty for the shipped example config; guest_channel would report not_configured")
	}
	if pf.StageRoot == "" {
		t.Error("StageRoot is empty for the shipped example config; guest_channel would report not_configured")
	}
}

// TestManagerConfigStagesFromTheJailersLockFile: /host/status publishes what a
// launch would stage, and the manager is where the API reads it. The jailer
// adapter stages from cfg.Runtime.LockFile (runtime_linux.go), re-reading it on
// every launch; a manager pointed at a different path — or at none — answers
// for a file nothing boots from, with every unit test still green, because the
// wiring is the only place the two are joined.
func TestManagerConfigStagesFromTheJailersLockFile(t *testing.T) {
	cfg := &config.Config{
		Server:  config.Server{Mode: "loopback_only"},
		Storage: config.Storage{Database: "/var/lib/vmobs/state/events.sqlite"},
		Paths:   config.Paths{Runtime: "/srv/vmobs"},
		Runtime: config.Runtime{LockFile: "/srv/vmobs/runtime.lock.json"},
	}

	got := managerConfig(cfg, nil, runtime.HostResources{}, nil, nil)

	if got.LockPath != cfg.Runtime.LockFile {
		t.Errorf("ManagerConfig.LockPath = %q, want the jailer's %q", got.LockPath, cfg.Runtime.LockFile)
	}
}

// A daemon with no lock configured hands the manager no path rather than a
// default one, so /host/status omits the images block instead of reporting an
// error about a file the operator never asked for.
func TestManagerConfigWithoutALockHasNoPath(t *testing.T) {
	cfg := &config.Config{Storage: config.Storage{Database: "/x/events.sqlite"}}
	if got := managerConfig(cfg, nil, runtime.HostResources{}, nil, nil); got.LockPath != "" {
		t.Errorf("ManagerConfig.LockPath = %q with no lock configured, want empty", got.LockPath)
	}
}
