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
// results in LockFile defaulting to "runtime.lock.json".
func TestRuntimeLockFileDefault(t *testing.T) {
	cfg, err := load(t, minimalConfig)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Runtime.LockFile != "runtime.lock.json" {
		t.Errorf("expected default LockFile=%q, got %q", "runtime.lock.json", cfg.Runtime.LockFile)
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
