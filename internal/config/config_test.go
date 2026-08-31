// ABOUTME: Tests host-config loading: the shipped example must parse, unknown
// ABOUTME: fields fail, and phase-1 safety constraints are enforced with teaching errors.
package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/config"
)

const minimalConfig = `config_version: 1
server:
  listen: "127.0.0.1:0"
  mode: loopback_only
storage:
  database: "/tmp/vmobs-test/events.sqlite"
  sqlite_journal_mode: WAL
  sqlite_synchronous: FULL
  logical_writers: 1
`

func load(t *testing.T, yaml string) (*config.Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return config.Load(path)
}

func TestExampleConfigParsesAndValidates(t *testing.T) {
	cfg, err := config.Load("../../docs/examples/host-config.yaml")
	if err != nil {
		t.Fatalf("the shipped example must load: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:8787" || cfg.Server.Mode != "loopback_only" {
		t.Errorf("server = %+v", cfg.Server)
	}
	if cfg.Storage.Database != "/var/lib/vmobs/vmobs.sqlite" {
		t.Errorf("database = %q", cfg.Storage.Database)
	}
	if !cfg.AgentInterface.AttentionTriggers["lifecycle_failed"] {
		t.Error("attention trigger lifecycle_failed should parse true")
	}
	if cfg.AgentInterface.AttentionNotifyHook != nil {
		t.Errorf("notify hook should parse null, got %v", *cfg.AgentInterface.AttentionNotifyHook)
	}
	if cfg.Observation.MaxRunnerSpoolBytes != 536870912 {
		t.Errorf("spool bytes = %d", cfg.Observation.MaxRunnerSpoolBytes)
	}
}

func TestMinimalConfigValidates(t *testing.T) {
	cfg, err := load(t, minimalConfig)
	if err != nil {
		t.Fatalf("minimal config: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:0" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := load(t, minimalConfig+"surprise_section:\n  x: 1\n")
	if err == nil || !strings.Contains(err.Error(), "surprise_section") {
		t.Errorf("unknown field: err = %v", err)
	}
}

func TestValidationTeaches(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		mention string
	}{
		{
			"wrong config version",
			func(c string) string { return strings.Replace(c, "config_version: 1", "config_version: 2", 1) },
			"config_version",
		},
		{
			"non-loopback listen",
			func(c string) string { return strings.Replace(c, "127.0.0.1:0", "0.0.0.0:8787", 1) },
			"loopback",
		},
		{
			"hostname listen",
			func(c string) string { return strings.Replace(c, "127.0.0.1:0", "localhost:8787", 1) },
			"127.0.0.1",
		},
		{
			"unsupported mode",
			func(c string) string { return strings.Replace(c, "loopback_only", "public", 1) },
			"loopback_only",
		},
		{
			"wrong journal mode",
			func(c string) string {
				return strings.Replace(c, "sqlite_journal_mode: WAL", "sqlite_journal_mode: DELETE", 1)
			},
			"WAL",
		},
		{
			"missing database",
			func(c string) string {
				return strings.Replace(c, `database: "/tmp/vmobs-test/events.sqlite"`, `database: ""`, 1)
			},
			"database",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := load(t, tc.mutate(minimalConfig))
			if err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.mention) {
				t.Errorf("error should mention %q: %v", tc.mention, err)
			}
		})
	}
}
