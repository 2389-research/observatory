// ABOUTME: vmobsd: the control-plane daemon. Loads host config, opens the
// ABOUTME: event store, serves /api/v1 on a loopback socket until auth exists.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

func main() {
	configPath := flag.String("config", "", "path to host config YAML (required)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: vmobsd -config /path/to/config.yaml")
		os.Exit(1)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("config rejected", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := serve(ctx, cfg, logger, func(addr string) {
		logger.Info("serving", "addr", addr, "api", "/api/v1", "version", api.Version)
	}); err != nil {
		logger.Error("daemon failed", "error", err)
		os.Exit(1)
	}
}

// serve runs the daemon until ctx is canceled. ready is called once with the
// bound address. The loopback check runs against the address actually bound,
// not just the configured string: config validation is not the last line.
func serve(ctx context.Context, cfg *config.Config, logger *slog.Logger, ready func(addr string)) error {
	if err := os.MkdirAll(filepath.Dir(cfg.Storage.Database), 0o755); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	st, err := store.Open(cfg.Storage.Database)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	diag, err := st.Diagnostics(ctx)
	if err != nil {
		return fmt.Errorf("verify storage settings: %w", err)
	}
	if diag.JournalMode != "wal" || diag.Synchronous != "full" {
		return fmt.Errorf("storage came up journal=%s synchronous=%s, config promises WAL/FULL", diag.JournalMode, diag.Synchronous)
	}
	logger.Info("store open", "database", cfg.Storage.Database, "journal_mode", diag.JournalMode, "synchronous", diag.Synchronous)

	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Server.Listen, err)
	}
	if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
		ln.Close()
		return fmt.Errorf("bound %s which is not loopback; refusing to serve without an authentication boundary", ln.Addr())
	}

	eng := situation.New(st, situation.Config{
		Triggers:                  cfg.AgentInterface.AttentionTriggers,
		QueueMaxItems:             cfg.AgentInterface.AttentionQueueMaxItems,
		CollapseDuplicates:        cfg.AgentInterface.AttentionCollapseDuplicates,
		SituationMaxResponseBytes: cfg.AgentInterface.SituationMaxResponseBytes,
	})
	srv := &http.Server{
		Handler:           api.New(st, eng),
		ReadHeaderTimeout: 5 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	ready(ln.Addr().String())

	select {
	case err := <-serveErr:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}
