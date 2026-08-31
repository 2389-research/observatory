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
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/config"
)

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
	case <-time.After(10 * time.Second):
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
