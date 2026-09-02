// ABOUTME: Startup integration tests for runtime.lock.json verification:
// ABOUTME: hash mismatch at startup refuses serve; absent lock file continues.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/lock"
)

// writeLockFile serializes l to dir/runtime.lock.json and returns the path.
func writeLockFile(t *testing.T, dir string, l *lock.Lock) string {
	t.Helper()
	data, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal lock: %v", err)
	}
	path := filepath.Join(dir, "runtime.lock.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write lock file: %v", err)
	}
	return path
}

// sha256hex returns the hex SHA-256 of data.
func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// testConfigWithLock returns a minimal loopback config that points at lockPath.
func testConfigWithLock(t *testing.T, lockPath string) *config.Config {
	t.Helper()
	cfg := testConfig(t, "127.0.0.1:0")
	cfg.Runtime = config.Runtime{LockFile: lockPath}
	return cfg
}

// TestServeRefusesHashMismatch verifies that serve() refuses to start when the
// runtime lock names a binary whose on-disk hash does not match the pinned hash.
// The error must mention the subject name (AT-002 at startup level).
func TestServeRefusesHashMismatch(t *testing.T) {
	dir := t.TempDir()

	// Create a real binary file.
	fcContent := []byte("fake-firecracker-content")
	fcPath := filepath.Join(dir, "firecracker")
	if err := os.WriteFile(fcPath, fcContent, 0o755); err != nil {
		t.Fatalf("write fc binary: %v", err)
	}

	jlContent := []byte("fake-jailer-content")
	jlPath := filepath.Join(dir, "jailer")
	if err := os.WriteFile(jlPath, jlContent, 0o755); err != nil {
		t.Fatalf("write jl binary: %v", err)
	}

	// Lock with a wrong hash for firecracker.
	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		Firecracker: lock.FirecrackerEntry{
			SHA256:      "badhash-definitely-wrong",
			InstallPath: fcPath,
		},
		Jailer: lock.JailerEntry{
			SHA256:      sha256hex(jlContent),
			InstallPath: jlPath,
		},
	}
	lockPath := writeLockFile(t, dir, l)

	cfg := testConfigWithLock(t, lockPath)
	err := serve(context.Background(), cfg, quietLogger(), func(string) {
		t.Error("ready called despite hash mismatch")
	})

	if err == nil {
		t.Fatal("serve accepted a lock with a hash mismatch; expected error")
	}
	// Error must mention the mismatch subject.
	if !strings.Contains(strings.ToLower(err.Error()), "firecracker") {
		t.Errorf("error should name the mismatched subject; got: %v", err)
	}
}

// TestServeAbsentLockContinues verifies that when cfg.Runtime.LockFile names a
// file that does not exist, serve continues (does not refuse to start).
// The exact log line is "runtime lock absent; launches will be refused by preflight".
func TestServeAbsentLockContinues(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "nonexistent.lock.json")

	cfg := testConfigWithLock(t, lockPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, cfg, quietLogger(), func(addr string) { addrCh <- addr })
	}()

	select {
	case addr := <-addrCh:
		// Good: daemon became ready despite absent lock.
		_ = addr
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("serve returned error on shutdown: %v", err)
			}
		case <-time.After(shutdownWait):
			t.Error("daemon did not shut down")
		}
	case err := <-errCh:
		t.Fatalf("serve refused to start with absent lock; expected continue, got: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("daemon never became ready")
	}
}

// TestServeEmptyLockFilePathSkipsVerification verifies that when
// cfg.Runtime.LockFile is "" (explicitly disabled), serve continues without
// any lock verification.
func TestServeEmptyLockFilePathSkipsVerification(t *testing.T) {
	cfg := testConfig(t, "127.0.0.1:0")
	// cfg.Runtime.LockFile is "" (zero value = disabled).

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, cfg, quietLogger(), func(addr string) { addrCh <- addr })
	}()

	select {
	case addr := <-addrCh:
		_ = addr
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("serve error on shutdown: %v", err)
			}
		case <-time.After(shutdownWait):
			t.Error("daemon did not shut down")
		}
	case err := <-errCh:
		t.Fatalf("serve refused to start with empty lock path: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("daemon never became ready")
	}
}

// TestServeBothMismatchesListed verifies that when two binaries both have wrong
// hashes, the startup error mentions both subjects.
func TestServeBothMismatchesListed(t *testing.T) {
	dir := t.TempDir()

	fcPath := filepath.Join(dir, "firecracker")
	if err := os.WriteFile(fcPath, []byte("fake-fc"), 0o755); err != nil {
		t.Fatalf("write fc: %v", err)
	}
	jlPath := filepath.Join(dir, "jailer")
	if err := os.WriteFile(jlPath, []byte("fake-jl"), 0o755); err != nil {
		t.Fatalf("write jl: %v", err)
	}

	l := &lock.Lock{
		Schema: "vmobs.runtime_lock.v1",
		Firecracker: lock.FirecrackerEntry{
			SHA256:      "wronghash1",
			InstallPath: fcPath,
		},
		Jailer: lock.JailerEntry{
			SHA256:      "wronghash2",
			InstallPath: jlPath,
		},
	}
	lockPath := writeLockFile(t, dir, l)
	cfg := testConfigWithLock(t, lockPath)

	err := serve(context.Background(), cfg, quietLogger(), func(string) {
		t.Error("ready called despite hash mismatches")
	})
	if err == nil {
		t.Fatal("expected error for both mismatches, got nil")
	}
	errStr := strings.ToLower(err.Error())
	if !strings.Contains(errStr, "firecracker") {
		t.Errorf("error does not mention firecracker: %v", err)
	}
	if !strings.Contains(errStr, "jailer") {
		t.Errorf("error does not mention jailer: %v", err)
	}
}
