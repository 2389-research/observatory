// ABOUTME: End-to-end smoke tests for the daemon: config in, loopback bind,
// ABOUTME: real store, /meta answering; non-loopback refused even past config.
package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/config"
)

// shutdownWait bounds how long a test waits for serve to return after the
// context is cancelled. It must exceed serve's own shutdown budget (main.go),
// or a hung shutdown and a merely slow one report the same way -- and a guard
// equal to the budget is a coin flip between them.
const shutdownWait = 30 * time.Second

func testConfig(t *testing.T, listen string) *config.Config {
	t.Helper()
	return &config.Config{
		ConfigVersion: 1,
		Server:        config.Server{Listen: listen, Mode: "loopback_only"},
		Storage: config.Storage{
			Database:          filepath.Join(t.TempDir(), "state", "events.sqlite"),
			SQLiteJournalMode: "WAL",
			SQLiteSynchronous: "FULL",
			LogicalWriters:    1,
		},
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestServeAnswersMetaOverLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, testConfig(t, "127.0.0.1:0"), quietLogger(), func(addr string) { addrCh <- addr })
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		t.Fatalf("serve exited before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("daemon never became ready")
	}

	resp, err := http.Get("http://" + addr + "/api/v1/meta")
	if err != nil {
		t.Fatalf("GET /meta: %v", err)
	}
	defer resp.Body.Close()
	var meta struct {
		Service string `json:"service"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode meta: %v", err)
	}
	if resp.StatusCode != http.StatusOK || meta.Service != "vmobsd" {
		t.Errorf("meta: status %d, service %q", resp.StatusCode, meta.Service)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("serve returned %v on graceful shutdown", err)
		}
	case <-time.After(shutdownWait):
		t.Fatal("daemon did not shut down")
	}
}

// A config object that skipped Validate (or a future bug there) still must not
// get a non-loopback socket: serve re-checks the address it actually bound.
func TestServeRefusesNonLoopbackBind(t *testing.T) {
	err := serve(context.Background(), testConfig(t, "0.0.0.0:0"), quietLogger(), func(string) {
		t.Error("ready called for a non-loopback bind")
	})
	if err == nil {
		t.Fatal("serve accepted a non-loopback listen address")
	}
}

// testConfigWithAuth returns a config with auth.require_authentication enabled
// and credential_store pointing at the given directory.
func testConfigWithAuth(t *testing.T, credDir string) *config.Config {
	t.Helper()
	cfg := testConfig(t, "127.0.0.1:0")
	cfg.Auth = config.Auth{
		RequireAuthentication: true,
		CredentialStore:       credDir,
	}
	return cfg
}

// TestInitAuthCreatesStoreAndToken verifies the happy path: a valid password
// via reader produces a credential store that accepts VerifyPassword and
// VerifyToken, and stdout contains the expected operator and token lines.
func TestInitAuthCreatesStoreAndToken(t *testing.T) {
	dir := t.TempDir()
	credDir := filepath.Join(dir, "creds")
	cfg := testConfigWithAuth(t, credDir)

	var stdout, stderr strings.Builder
	password := "correct-horse-battery-staple"
	err := runInitAuth(cfg, "local_operator", "initial", strings.NewReader(password+"\n"), &stdout, &stderr)
	if err != nil {
		t.Fatalf("runInitAuth: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "operator: local_operator") {
		t.Errorf("stdout missing operator line; got: %q", out)
	}
	if !strings.Contains(out, "token: vmobs_") {
		t.Errorf("stdout missing token line; got: %q", out)
	}

	// Extract the token secret from stdout.
	var tokenSecret string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "token: ") {
			tokenSecret = strings.TrimPrefix(line, "token: ")
		}
	}
	if tokenSecret == "" {
		t.Fatal("could not extract token secret from stdout")
	}

	// Verify the store is usable.
	st, err := auth.OpenStore(credDir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	if _, err := st.VerifyPassword("local_operator", password); err != nil {
		t.Errorf("VerifyPassword: %v", err)
	}
	if _, err := st.VerifyToken(tokenSecret); err != nil {
		t.Errorf("VerifyToken: %v", err)
	}
}

// TestInitAuthRefusesReinit verifies that a second call to runInitAuth on an
// already-initialized store returns an error mentioning "already initialized"
// and does not corrupt the original credentials.
func TestInitAuthRefusesReinit(t *testing.T) {
	dir := t.TempDir()
	credDir := filepath.Join(dir, "creds")
	cfg := testConfigWithAuth(t, credDir)
	password := "correct-horse-battery-staple"

	if err := runInitAuth(cfg, "local_operator", "initial", strings.NewReader(password+"\n"), io.Discard, io.Discard); err != nil {
		t.Fatalf("first runInitAuth: %v", err)
	}

	err := runInitAuth(cfg, "local_operator", "initial", strings.NewReader(password+"\n"), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("second runInitAuth succeeded; expected error")
	}
	if !strings.Contains(err.Error(), "already initialized") {
		t.Errorf("error does not mention 'already initialized': %v", err)
	}

	// Original password still verifies.
	st, err := auth.OpenStore(credDir)
	if err != nil {
		t.Fatalf("OpenStore after reinit attempt: %v", err)
	}
	if _, err := st.VerifyPassword("local_operator", password); err != nil {
		t.Errorf("VerifyPassword after failed reinit: %v", err)
	}
}

// TestInitAuthRequiresPassword verifies that missing passwords and short
// passwords are both rejected with clear errors.
func TestInitAuthRequiresPassword(t *testing.T) {
	dir := t.TempDir()
	credDir := filepath.Join(dir, "creds")
	cfg := testConfigWithAuth(t, credDir)

	t.Run("nil reader and no env", func(t *testing.T) {
		t.Setenv("VMOBSD_OPERATOR_PASSWORD", "")
		err := runInitAuth(cfg, "local_operator", "initial", nil, io.Discard, io.Discard)
		if err == nil {
			t.Fatal("expected error for missing password")
		}
		if !strings.Contains(err.Error(), "-password-stdin") || !strings.Contains(err.Error(), "VMOBSD_OPERATOR_PASSWORD") {
			t.Errorf("error does not name both sources: %v", err)
		}
	})

	t.Run("short password", func(t *testing.T) {
		err := runInitAuth(cfg, "local_operator", "initial", strings.NewReader("short\n"), io.Discard, io.Discard)
		if err == nil {
			t.Fatal("expected error for short password")
		}
		// The error may come from runInitAuth or from InitStore; either way it
		// surfaces to the caller.
		if !strings.Contains(err.Error(), "8") && !strings.Contains(err.Error(), "short") && !strings.Contains(err.Error(), "password") {
			t.Errorf("error does not describe minimum length requirement: %v", err)
		}
	})
}

// TestServeRefusesUninitializedAuth pins the existing behavior from Task 7:
// serve must refuse to start when auth is enabled but the credential store has
// not been initialized, and the error must mention "init-auth".
func TestServeRefusesUninitializedAuth(t *testing.T) {
	credDir := filepath.Join(t.TempDir(), "creds") // does not exist
	cfg := testConfigWithAuth(t, credDir)

	err := serve(context.Background(), cfg, quietLogger(), func(string) {
		t.Error("ready called for uninitialized auth store")
	})
	if err == nil {
		t.Fatal("serve accepted an uninitialized auth store")
	}
	if !strings.Contains(err.Error(), "init-auth") {
		t.Errorf("error does not mention init-auth: %v", err)
	}
}

// TestAuthConfigCarriesThePublicOriginWithAuthOff: a WebSocket upgrade is
// accepted only when its Origin equals AuthConfig.PublicOrigin, and that gate
// runs whether or not authentication does -- it is cross-site defence, not
// authentication, and it matters more when there is no credential behind it.
//
// Built with auth off, the config's public_origin never reached the gate: the
// field was populated only inside the auth-enabled branch. The shipped default
// config has require_authentication: false, so on the appliance every terminal
// upgrade was refused, for every VM and every Origin, with:
//
//	403 {"cause":"public_origin_unset"}
//
// while /etc/vmobs/config.yaml named a public origin two lines from the listen
// address. Measured on aibox03 2026-09-06 against a running, healthy VM.
func TestAuthConfigCarriesThePublicOriginWithAuthOff(t *testing.T) {
	cfg := testConfig(t, "127.0.0.1:0")
	cfg.Server.PublicOrigin = "http://127.0.0.1:8787"

	ac, err := authConfig(cfg)
	if err != nil {
		t.Fatalf("authConfig: %v", err)
	}
	if ac.Enabled {
		t.Fatal("auth reports enabled although the config does not require it")
	}
	if ac.PublicOrigin != cfg.Server.PublicOrigin {
		t.Errorf("PublicOrigin = %q, want %q; the terminal upgrade gate reads this field and refuses every Origin when it is empty",
			ac.PublicOrigin, cfg.Server.PublicOrigin)
	}
}
