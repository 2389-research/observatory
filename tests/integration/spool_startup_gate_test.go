// ABOUTME: Exercises real daemon startup and importer polling before any VM launch.
// ABOUTME: Pins fresh spool creation and preservation of existing spool contents.

//go:build linux

package integration_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/config"
	"github.com/2389-research/observatory/internal/store"
)

func TestSpoolStartupGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 inside scripts/vmobs-gate")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)
	repoRoot := findRepoRoot(t)
	daemonBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd")
	runnerBin := buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner")
	for _, existing := range []bool{false, true} {
		name := "fresh"
		if existing {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			root := filepath.Join(stateDir, "spool")
			marker := filepath.Join(root, "retained-data")
			if existing {
				if err := os.MkdirAll(root, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(root, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(marker, []byte("keep this data"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			d := startDaemon(t, repoRoot, daemonBin, runnerBin, "spool-"+name,
				withStateDir(stateDir), func(o *daemonOptions) { o.telemetryAttention = true })
			cfg, err := config.Load(d.configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.AgentInterface.AttentionTriggers["telemetry_degraded"] {
				t.Fatal("telemetry attention is disabled")
			}
			info, err := os.Stat(root)
			if err != nil || !info.IsDir() {
				t.Fatalf("daemon ready without spool directory: %v", err)
			}
			if existing {
				if info.Mode().Perm() != 0o750 {
					t.Errorf("existing spool mode = %o, want 750", info.Mode().Perm())
				}
				data, err := os.ReadFile(marker)
				if err != nil || string(data) != "keep this data" {
					t.Fatalf("existing spool data changed: %q, %v", data, err)
				}
			}
			deadline := time.Now().Add(15 * time.Second)
			for {
				code, health := d.apiGetCode(t, "/telemetry/import")
				if code != 200 || health["state"] == "degraded" {
					t.Fatalf("empty spool import failed: HTTP %d, %v", code, health)
				}
				lastSuccess, _ := health["last_success_at"].(string)
				if health["state"] == "healthy" && lastSuccess != "" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no successful import cycle: %v", health)
				}
				time.Sleep(100 * time.Millisecond)
			}
			st, err := store.Open(filepath.Join(stateDir, "vmobs.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			items, err := st.ListAttention(t.Context(), store.AttentionQuery{IncludeAcked: true, Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range items {
				if item.TriggerClass == "telemetry_degraded" {
					t.Errorf("startup raised telemetry attention: %+v", item)
				}
			}
		})
	}
}
