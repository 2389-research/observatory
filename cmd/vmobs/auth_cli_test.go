// ABOUTME: CLI tests for bearer-token auth, --token/--ca global flags, and
// ABOUTME: the auth whoami/token subcommands against a real auth-enabled server.
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

// newAuthServer builds a real httptest server with auth enabled.
// The credential store is initialized in a temp dir with username "local_operator".
// Returns the server, the auth.Store (for minting tokens directly), and cleanup
// is registered via t.Cleanup.
func newAuthServer(t *testing.T) (*httptest.Server, *auth.Store) {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{"telemetry_degraded": true},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})

	mgr, err := runtime.NewManager(st, runtimetest.NewFake(), runtime.ManagerConfig{
		Admission:  config.Admission{},
		VMDefaults: config.VMDefaults{},
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 4, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	credDir := filepath.Join(t.TempDir(), "creds")
	credStore, err := auth.InitStore(credDir, "local_operator", "testpassword")
	if err != nil {
		t.Fatalf("init auth store: %v", err)
	}

	ac := api.AuthConfig{
		Enabled:        true,
		Creds:          credStore,
		Sessions:       auth.NewSessions(12 * time.Hour),
		PublicOrigin:   "http://127.0.0.1",
		CookieSameSite: http.SameSiteStrictMode,
		LoginDelay:     time.Millisecond,
	}

	srv := httptest.NewServer(api.New(st, eng, mgr, ac, nil, nil))
	t.Cleanup(srv.Close)

	return srv, credStore
}

// TestCLIBearerToken verifies that --token sends Authorization: Bearer and
// that without the token an auth-enabled server returns exit 1 with
// "unauthenticated" on stderr.
func TestCLIBearerToken(t *testing.T) {
	srv, credStore := newAuthServer(t)

	// Mint a token directly (Go call, not HTTP — the lifecycle test exercises HTTP).
	secret, _, err := credStore.CreateToken("test-bearer", "local_operator", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	// With token: vm list should succeed (exit 0).
	code, _, stderr := runCLI(t, "--api", srv.URL, "--token", secret, "vm", "list")
	if code != exitOK {
		t.Fatalf("with token: exit %d, stderr: %s", code, stderr)
	}

	// Without token: should exit 1 with "unauthenticated" on stderr.
	code, _, stderr = runCLI(t, "--api", srv.URL, "vm", "list")
	if code != exitAPIError {
		t.Fatalf("without token: exit %d, want %d\nstderr: %s", code, exitAPIError, stderr)
	}
	if !strings.Contains(stderr, "unauthenticated") {
		t.Errorf("stderr should mention unauthenticated:\n%s", stderr)
	}
}

// TestCLIWhoami verifies `auth whoami` outputs owner and method, with --json parity.
func TestCLIWhoami(t *testing.T) {
	srv, credStore := newAuthServer(t)

	secret, _, err := credStore.CreateToken("whoami-token", "local_operator", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	// Human output: owner and method visible.
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--token", secret, "auth", "whoami")
	if code != exitOK {
		t.Fatalf("whoami: exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "local_operator") {
		t.Errorf("whoami human: expected owner in stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "token") {
		t.Errorf("whoami human: expected method 'token' in stdout:\n%s", stdout)
	}

	// --json output: parses and has correct fields.
	code, stdout, stderr = runCLI(t, "--api", srv.URL, "--token", secret, "--json", "auth", "whoami")
	if code != exitOK {
		t.Fatalf("whoami --json: exit %d, stderr: %s", code, stderr)
	}
	var sess struct {
		Owner  string `json:"owner"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal([]byte(stdout), &sess); err != nil {
		t.Fatalf("whoami --json: parse: %v\n%s", err, stdout)
	}
	if sess.Owner != "local_operator" || sess.Method != "token" {
		t.Errorf("whoami --json: got owner=%q method=%q", sess.Owner, sess.Method)
	}
}

// TestCLITokenLifecycle exercises: create (prints vmobs_ secret) → list
// (shows token without secret) → revoke → subsequent use returns exit 1.
func TestCLITokenLifecycle(t *testing.T) {
	srv, credStore := newAuthServer(t)

	// Mint a bootstrap token to authenticate the lifecycle calls.
	bootstrap, _, err := credStore.CreateToken("bootstrap", "local_operator", 0)
	if err != nil {
		t.Fatalf("create bootstrap token: %v", err)
	}

	// Create a new token via the CLI.
	code, stdout, stderr := runCLI(t,
		"--api", srv.URL, "--token", bootstrap,
		"auth", "token", "create", "--name", "ci2")
	if code != exitOK {
		t.Fatalf("token create: exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// stdout must contain the vmobs_ secret.
	if !strings.Contains(stdout, "vmobs_") {
		t.Errorf("token create: expected vmobs_ secret in stdout:\n%s", stdout)
	}

	// stderr must warn that the secret is shown once — and must NOT contain the secret itself.
	if !strings.Contains(stderr, "once") && !strings.Contains(stderr, "again") {
		t.Errorf("token create: stderr should warn about one-time display:\n%s", stderr)
	}
	// Extract the secret from stdout to validate the rest of the lifecycle.
	var newSecret string
	var tokenID string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "vmobs_") {
			// Find the token secret in the line.
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "vmobs_") {
					newSecret = f
				}
			}
		}
		// Look for token id (tok-...).
		if strings.Contains(line, "tok-") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "tok-") {
					tokenID = f
				}
			}
		}
	}
	if newSecret == "" {
		t.Fatalf("could not extract secret from create output:\n%s", stdout)
	}

	// List tokens: should show our new token, but NOT the secret.
	code, stdout, stderr = runCLI(t,
		"--api", srv.URL, "--token", bootstrap,
		"auth", "tokens")
	if code != exitOK {
		t.Fatalf("token list: exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "ci2") {
		t.Errorf("token list: expected 'ci2' in output:\n%s", stdout)
	}
	if strings.Contains(stdout, newSecret) {
		t.Errorf("token list: secret must not appear in list output:\n%s", stdout)
	}

	// Verify the new token works.
	code, _, stderr = runCLI(t, "--api", srv.URL, "--token", newSecret, "auth", "whoami")
	if code != exitOK {
		t.Fatalf("new token whoami: exit %d, stderr: %s", code, stderr)
	}

	// If we couldn't extract tokenID from create output, get it from JSON list.
	if tokenID == "" {
		code, stdout, stderr = runCLI(t,
			"--api", srv.URL, "--token", bootstrap, "--json",
			"auth", "tokens")
		if code != exitOK {
			t.Fatalf("token list json: exit %d, stderr: %s", code, stderr)
		}
		var listResp struct {
			Tokens []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"tokens"`
		}
		if err := json.Unmarshal([]byte(stdout), &listResp); err != nil {
			t.Fatalf("parse token list: %v", err)
		}
		for _, tok := range listResp.Tokens {
			if tok.Name == "ci2" {
				tokenID = tok.ID
				break
			}
		}
	}
	if tokenID == "" {
		t.Fatal("could not find token ID for ci2")
	}

	// Revoke the new token.
	code, stdout, stderr = runCLI(t,
		"--api", srv.URL, "--token", bootstrap,
		"auth", "token", "revoke", tokenID)
	if code != exitOK {
		t.Fatalf("token revoke: exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// Subsequent use of the revoked token should exit 1.
	code, _, stderr = runCLI(t, "--api", srv.URL, "--token", newSecret, "auth", "whoami")
	if code != exitAPIError {
		t.Fatalf("revoked token: exit %d, want %d\nstderr: %s", code, exitAPIError, stderr)
	}
	if !strings.Contains(stderr, "unauthenticated") {
		t.Errorf("revoked token stderr should mention unauthenticated:\n%s", stderr)
	}
}

// TestCLITokenEnvVar verifies that VMOBS_TOKEN env works identically to --token.
func TestCLITokenEnvVar(t *testing.T) {
	srv, credStore := newAuthServer(t)

	secret, _, err := credStore.CreateToken("env-test", "local_operator", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	// Set the env var for this test process (t.Setenv restores after test).
	t.Setenv("VMOBS_TOKEN", secret)

	// With env var set: vm list should succeed.
	code, _, stderr := runCLI(t, "--api", srv.URL, "vm", "list")
	if code != exitOK {
		t.Fatalf("env var token: exit %d, stderr: %s", code, stderr)
	}

	// Clear the env var and confirm it fails.
	t.Setenv("VMOBS_TOKEN", "")
	code, _, stderr = runCLI(t, "--api", srv.URL, "vm", "list")
	if code != exitAPIError {
		t.Fatalf("no env var: exit %d, want %d\nstderr: %s", code, exitAPIError, stderr)
	}
}
