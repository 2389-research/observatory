// ABOUTME: vmobsd: the control-plane daemon. Loads host config, opens the
// ABOUTME: event store, serves /api/v1 on loopback or TLS depending on mode.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

func main() {
	// Subcommand dispatch before global flag parsing so init-auth gets its own
	// FlagSet and does not pollute the serve flag set.
	if len(os.Args) > 1 && os.Args[1] == "init-auth" {
		fs := flag.NewFlagSet("init-auth", flag.ExitOnError)
		cfgPath := fs.String("config", "", "path to host config YAML (required)")
		username := fs.String("username", "local_operator", "operator username")
		tokenName := fs.String("token-name", "initial", "name for the minted token")
		useStdin := fs.Bool("password-stdin", false, "read password from stdin (first line)")
		fs.Usage = func() {
			fmt.Fprintln(os.Stderr, "usage: vmobsd init-auth -config PATH [-username local_operator] [-token-name initial] [-password-stdin]")
			fs.PrintDefaults()
		}
		if err := fs.Parse(os.Args[2:]); err != nil {
			// ExitOnError handles this.
			os.Exit(3)
		}
		if *cfgPath == "" {
			fs.Usage()
			os.Exit(3)
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "config rejected: %v\n", err)
			os.Exit(1)
		}
		var passwordSrc io.Reader
		if *useStdin {
			passwordSrc = os.Stdin
		}
		if err := runInitAuth(cfg, *username, *tokenName, passwordSrc, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintf(os.Stderr, "init-auth: %v\n", err)
			os.Exit(1)
		}
		return
	}

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

// runInitAuth creates the credential store at cfg.Auth.CredentialStore, mints
// one token, and prints two lines to stdout: "operator: <username>" and
// "token: <secret>". All other output goes to stderr. It is extracted for
// testability — no exec required.
//
// Password resolution: passwordSrc non-nil means the caller passed
// -password-stdin; read the first line and trim one trailing newline (LF or
// CRLF). When passwordSrc is nil, fall back to the VMOBSD_OPERATOR_PASSWORD
// environment variable. Both absent → error naming both sources. Minimum
// password length is 8 bytes.
func runInitAuth(cfg *config.Config, username, tokenName string, passwordSrc io.Reader, stdout, stderr io.Writer) error {
	// Resolve password.
	var password string
	if passwordSrc != nil {
		scanner := bufio.NewScanner(passwordSrc)
		if scanner.Scan() {
			password = scanner.Text() // Text() already strips the trailing newline.
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read password from stdin: %w", err)
		}
	} else {
		password = os.Getenv("VMOBSD_OPERATOR_PASSWORD")
		if password == "" {
			return fmt.Errorf("no password supplied: provide -password-stdin or set VMOBSD_OPERATOR_PASSWORD")
		}
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 bytes (got %d)", len(password))
	}

	credDir := cfg.Auth.CredentialStore
	fmt.Fprintf(stderr, "initializing credential store at %s\n", credDir)

	st, err := auth.InitStore(credDir, username, password)
	if err != nil {
		if errors.Is(err, auth.ErrAlreadyInitialized) || strings.Contains(err.Error(), "already initialized") {
			return fmt.Errorf("credential store already initialized at %s: %w", credDir, err)
		}
		return fmt.Errorf("init credential store: %w", err)
	}

	secret, _, err := st.CreateToken(tokenName, username, 0)
	if err != nil {
		return fmt.Errorf("create initial token: %w", err)
	}

	fmt.Fprintf(stdout, "operator: %s\n", username)
	fmt.Fprintf(stdout, "token: %s\n", secret)
	return nil
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
	// Loopback-only mode: enforce loopback even if config validation was
	// bypassed (defense in depth). HTTPS mode legitimately binds non-loopback —
	// config validation already required auth+TLS there.
	if cfg.Server.Mode != "https" {
		if tcp, ok := ln.Addr().(*net.TCPAddr); !ok || !tcp.IP.IsLoopback() {
			ln.Close()
			return fmt.Errorf("bound %s which is not loopback; refusing to serve without an authentication boundary", ln.Addr())
		}
	}

	eng := situation.New(st, situation.Config{
		Triggers:                  cfg.AgentInterface.AttentionTriggers,
		QueueMaxItems:             cfg.AgentInterface.AttentionQueueMaxItems,
		CollapseDuplicates:        cfg.AgentInterface.AttentionCollapseDuplicates,
		SituationMaxResponseBytes: cfg.AgentInterface.SituationMaxResponseBytes,
	})

	// Templates: missing directory = empty registry (a host with no approved
	// templates is a truthful state; this is not an error on a dev host).
	tpls, err := runtime.LoadTemplates(cfg.Paths.ApprovedTemplates)
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}

	// Probe host resources from the database directory; that directory must
	// exist (we just called MkdirAll above). On macOS /var/lib/vmobs will not
	// exist, but the temp dir created by MkdirAll works fine for dev runs.
	host, err := runtime.ProbeHost(filepath.Dir(cfg.Storage.Database))
	if err != nil {
		return fmt.Errorf("probe host resources: %w", err)
	}
	logger.Info("host probed", "memory_mib", host.TotalMemoryMiB, "cpus", host.CPUCores, "disk_free_mib", host.StateDiskFreeMiB)

	rt := runtime.ForHost()
	mgr, err := runtime.NewManager(st, rt, runtime.ManagerConfig{
		Admission:  cfg.Admission,
		VMDefaults: cfg.VMDefaults,
		Templates:  tpls,
		Host:       host,
	})
	if err != nil {
		return fmt.Errorf("create lifecycle manager: %w", err)
	}
	defer mgr.Close()

	// Build auth config. When auth is off (dev mode), the API injects a
	// local_operator/none identity on every request.
	// P5 Task 13 enables auth in the smoke config; see the marker comment in
	// docs/examples/host-config.yaml.
	ac := api.AuthConfig{Enabled: false}
	if cfg.AuthEnabled() {
		credStore, err := auth.OpenStore(cfg.Auth.CredentialStore)
		if err != nil {
			return fmt.Errorf("auth.require_authentication is true but the credential store at %s is not initialized (run: vmobsd init-auth -config ...): %w", cfg.Auth.CredentialStore, err)
		}
		sameSite := http.SameSiteStrictMode
		if cfg.Auth.SessionCookieSameSite == "lax" {
			sameSite = http.SameSiteLaxMode
		}
		ac = api.AuthConfig{
			Enabled:        true,
			Creds:          credStore,
			Sessions:       auth.NewSessions(time.Duration(cfg.Auth.SessionTTLMinutes) * time.Minute),
			PublicOrigin:   cfg.Server.PublicOrigin,
			CookieSameSite: sameSite,
			CookieSecure:   cfg.Auth.SessionCookieSecure,
			LoginDelay:     500 * time.Millisecond,
		}
	}

	srv := &http.Server{
		Handler:           api.New(st, eng, mgr, ac),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	serveErr := make(chan error, 1)
	switch cfg.Server.Mode {
	case "https":
		go func() { serveErr <- srv.ServeTLS(ln, cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile) }()
	default: // loopback_only — bound-address check already ran above
		go func() { serveErr <- srv.Serve(ln) }()
	}
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
