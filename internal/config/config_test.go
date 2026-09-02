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

func TestAuthAndModeValidation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *config.Config)
		wantErr string // substring; "" = valid
	}{
		{"example is valid", func(c *config.Config) {}, ""},
		{"trust_forwarded_identity refused", func(c *config.Config) { c.Server.TrustForwardedIdentity = true }, "trust_forwarded_identity"},
		{"auth mode must be local_operator", func(c *config.Config) {
			c.Auth.RequireAuthentication = true
			c.Auth.CredentialStore = "/tmp/auth"
			c.Auth.CSRFProtection = true
			c.Auth.SessionCookieHTTPOnly = true
			c.Auth.SessionCookieSameSite = "strict"
			c.Auth.Mode = "reverse_proxy"
		}, "auth.mode"},
		{"auth on requires credential store", func(c *config.Config) {
			c.Auth.RequireAuthentication = true
			c.Auth.CSRFProtection = true
			c.Auth.SessionCookieHTTPOnly = true
			c.Auth.SessionCookieSameSite = "strict"
			c.Auth.CredentialStore = ""
		}, "credential_store"},
		{"auth on requires csrf", func(c *config.Config) {
			c.Auth.RequireAuthentication = true
			c.Auth.CredentialStore = "/tmp/auth"
			c.Auth.SessionCookieHTTPOnly = true
			c.Auth.SessionCookieSameSite = "strict"
			c.Auth.CSRFProtection = false
		}, "csrf_protection"},
		{"auth on requires httponly", func(c *config.Config) {
			c.Auth.RequireAuthentication = true
			c.Auth.CredentialStore = "/tmp/auth"
			c.Auth.CSRFProtection = true
			c.Auth.SessionCookieSameSite = "strict"
			c.Auth.SessionCookieHTTPOnly = false
		}, "session_cookie_http_only"},
		{"samesite none refused", func(c *config.Config) {
			c.Auth.RequireAuthentication = true
			c.Auth.CredentialStore = "/tmp/auth"
			c.Auth.CSRFProtection = true
			c.Auth.SessionCookieHTTPOnly = true
			c.Auth.SessionCookieSameSite = "none"
		}, "session_cookie_same_site"},
		{"negative ttl refused", func(c *config.Config) { c.Auth.SessionTTLMinutes = -1 }, "session_ttl_minutes"},
		{"https mode needs cert", func(c *config.Config) { c.Server.Mode = "https"; c.Server.TLSKeyFile = "k.pem" }, "tls_cert_file"},
		{"https mode needs key", func(c *config.Config) { c.Server.Mode = "https"; c.Server.TLSCertFile = "c.pem" }, "tls_key_file"},
		{"https forces auth", func(c *config.Config) {
			c.Server.Mode = "https"
			c.Server.TLSCertFile, c.Server.TLSKeyFile = "c.pem", "k.pem"
			c.Server.PublicOrigin = "https://vmobs.example:8787"
			c.Auth.SessionCookieSecure = true
			c.Auth.RequireAuthentication = false
		}, "require_authentication"},
		{"https forces secure cookies", func(c *config.Config) {
			c.Server.Mode = "https"
			c.Server.TLSCertFile, c.Server.TLSKeyFile = "c.pem", "k.pem"
			c.Server.PublicOrigin = "https://vmobs.example:8787"
			c.Auth.SessionCookieSecure = false
		}, "session_cookie_secure"},
		{"https needs https origin", func(c *config.Config) {
			c.Server.Mode = "https"
			c.Server.TLSCertFile, c.Server.TLSKeyFile = "c.pem", "k.pem"
			c.Auth.SessionCookieSecure = true
			// PublicOrigin stays http://...
		}, "public_origin"},
		{"https allows non-loopback listen", func(c *config.Config) {
			c.Server.Mode = "https"
			c.Server.TLSCertFile, c.Server.TLSKeyFile = "c.pem", "k.pem"
			c.Server.PublicOrigin = "https://vmobs.example:8787"
			c.Auth.RequireAuthentication = true
			c.Auth.CredentialStore = "/tmp/auth"
			c.Auth.CSRFProtection = true
			c.Auth.SessionCookieHTTPOnly = true
			c.Auth.SessionCookieSameSite = "strict"
			c.Auth.SessionCookieSecure = true
			c.Server.Listen = "0.0.0.0:8787"
		}, ""},
		{"loopback mode refuses tls files", func(c *config.Config) { c.Server.TLSCertFile = "c.pem" }, "tls_cert_file"},
		{"unknown mode refused", func(c *config.Config) { c.Server.Mode = "tailscale" }, "server.mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.Load("../../docs/examples/host-config.yaml")
			if err != nil {
				t.Fatalf("loading example config: %v", err)
			}
			tc.mutate(cfg)
			err = cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Errorf("expected valid, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error should contain %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestSessionTTLDefault(t *testing.T) {
	const minimalWithAuth = `config_version: 1
server:
  listen: "127.0.0.1:0"
  mode: loopback_only
auth:
  mode: local_operator
  require_authentication: true
  credential_store: "/tmp/auth"
  csrf_protection: true
  session_cookie_http_only: true
  session_cookie_same_site: strict
storage:
  database: "/tmp/vmobs-test/events.sqlite"
  sqlite_journal_mode: WAL
  sqlite_synchronous: FULL
  logical_writers: 1
`
	cfg, err := load(t, minimalWithAuth)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Auth.SessionTTLMinutes != 720 {
		t.Errorf("expected SessionTTLMinutes=720 when omitted, got %d", cfg.Auth.SessionTTLMinutes)
	}
}

// TestRuntimeLockFileDefault verifies that omitting the runtime: section
// results in LockFile defaulting to "runtime.lock.json". An absent key must
// not be conflated with an explicit empty string.
func TestRuntimeLockFileDefault(t *testing.T) {
	cfg, err := load(t, minimalConfig)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Runtime.LockFile != "runtime.lock.json" {
		t.Errorf("expected default LockFile=%q, got %q", "runtime.lock.json", cfg.Runtime.LockFile)
	}
}

// TestRuntimeLockFileExplicitEmpty verifies that lock_file: "" in YAML means
// "explicitly no lock" — verification is skipped. The explicit empty value must
// survive Load unchanged (not get overwritten by the default).
func TestRuntimeLockFileExplicitEmpty(t *testing.T) {
	const withEmptyLock = minimalConfig + "runtime:\n  lock_file: \"\"\n"
	cfg, err := load(t, withEmptyLock)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Runtime.LockFile != "" {
		t.Errorf("explicit lock_file: \"\" must survive as empty; got %q", cfg.Runtime.LockFile)
	}
}

// TestRuntimeLockFileExplicit verifies that an explicit lock_file path is preserved.
func TestRuntimeLockFileExplicit(t *testing.T) {
	const withRuntime = minimalConfig + `runtime:
  lock_file: "/etc/vmobs/runtime.lock.json"
`
	cfg, err := load(t, withRuntime)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Runtime.LockFile != "/etc/vmobs/runtime.lock.json" {
		t.Errorf("expected LockFile=%q, got %q", "/etc/vmobs/runtime.lock.json", cfg.Runtime.LockFile)
	}
}

// TestRuntimeModeDefault verifies that omitting runtime.mode defaults to "unavailable".
func TestRuntimeModeDefault(t *testing.T) {
	cfg, err := load(t, minimalConfig)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Runtime.Mode != "unavailable" {
		t.Errorf("default Mode: want %q, got %q", "unavailable", cfg.Runtime.Mode)
	}
}

// TestRuntimeModeFirecrackerAccepted verifies that "firecracker" is accepted.
func TestRuntimeModeFirecrackerAccepted(t *testing.T) {
	const withMode = minimalConfig + `runtime:
  mode: firecracker
`
	cfg, err := load(t, withMode)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Runtime.Mode != "firecracker" {
		t.Errorf("Mode: want %q, got %q", "firecracker", cfg.Runtime.Mode)
	}
}

// TestRuntimeModeUnknownRejected verifies that an unknown mode names the field in the error.
func TestRuntimeModeUnknownRejected(t *testing.T) {
	const withBadMode = minimalConfig + `runtime:
  mode: kvm_direct
`
	_, err := load(t, withBadMode)
	if err == nil {
		t.Fatal("expected error for unknown runtime.mode, got nil")
	}
	if !strings.Contains(err.Error(), "runtime.mode") {
		t.Errorf("error should mention runtime.mode, got: %v", err)
	}
}

// TestRuntimeJailDefaults verifies JailUIDBase, JailGID, CIDBase default values.
func TestRuntimeJailDefaults(t *testing.T) {
	cfg, err := load(t, minimalConfig)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Runtime.JailUIDBase != 20000 {
		t.Errorf("JailUIDBase: want 20000, got %d", cfg.Runtime.JailUIDBase)
	}
	if cfg.Runtime.JailGID != 36000 {
		t.Errorf("JailGID: want 36000, got %d", cfg.Runtime.JailGID)
	}
	if cfg.Runtime.CIDBase != 3 {
		t.Errorf("CIDBase: want 3, got %d", cfg.Runtime.CIDBase)
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

// The runtime-derived paths have no dedicated config key: they hang off
// Paths.Runtime. Both the jailer adapter and the preflight doctor read them, so
// the derivation lives in one place and this test pins it.
func TestPathsRuntimeDerivations(t *testing.T) {
	cases := []struct {
		name          string
		runtime       string
		wantStageRoot string
		wantJailBase  string
	}{
		{"aibox03 runtime root", "/srv/vmobs", "/srv/vmobs/stage", "/srv/vmobs/jail"},
		{"trailing slash cleaned", "/srv/vmobs/", "/srv/vmobs/stage", "/srv/vmobs/jail"},
		{"relative root", "runtime", "runtime/stage", "runtime/jail"},
		// An unset runtime root derives nothing: a relative "stage"/"jail" would
		// let guest_channel pass against the daemon's working directory.
		{"empty root", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := config.Paths{Runtime: tc.runtime}
			if got := p.StageRoot(); got != tc.wantStageRoot {
				t.Errorf("StageRoot() = %q, want %q", got, tc.wantStageRoot)
			}
			if got := p.JailBase(); got != tc.wantJailBase {
				t.Errorf("JailBase() = %q, want %q", got, tc.wantJailBase)
			}
		})
	}
}
