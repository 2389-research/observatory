// ABOUTME: Verifies daemon startup rejects an unusable spool root before serving.
// ABOUTME: Uses the real filesystem and startup path without runtime substitutes.
package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeRejectsBlockedSpoolRoot(t *testing.T) {
	cfg := testConfig(t, "127.0.0.1:0")
	cfg.Runtime.Mode = "firecracker"
	cfg.Paths.State = t.TempDir()
	root := filepath.Join(cfg.Paths.State, "spool")
	if err := os.WriteFile(root, []byte("keep this data"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := serve(ctx, cfg, quietLogger(), func(string) {
		t.Error("daemon served with an unusable spool root")
	})
	if err == nil || !strings.Contains(err.Error(), "create spool root") || !strings.Contains(err.Error(), root) {
		t.Fatalf("startup error = %v, want create spool root error naming %s", err, root)
	}
	data, err := os.ReadFile(root)
	if err != nil || string(data) != "keep this data" {
		t.Fatalf("blocked spool data changed: %q, %v", data, err)
	}
}
