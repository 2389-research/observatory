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
	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/jailer"
	"github.com/2389-research/observatory-v2/internal/lock"
	"github.com/2389-research/observatory-v2/internal/preflight"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/spool"
	"github.com/2389-research/observatory-v2/internal/store"
	"github.com/2389-research/observatory-v2/internal/terminal"
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

// verifyRuntimeLock loads and verifies binary hashes from the runtime lock file.
// When the lock file is absent, it logs one line and returns nil (launches will
// be refused by the preflight step). When present but invalid, it returns an
// error listing every mismatch. Empty lockPath skips verification entirely.
func verifyRuntimeLock(lockPath string, logger *slog.Logger) error {
	if lockPath == "" {
		return nil
	}
	if _, err := os.Stat(lockPath); errors.Is(err, os.ErrNotExist) {
		logger.Warn("runtime lock absent; launches will be refused by preflight")
		return nil
	}
	l, err := lock.Load(lockPath)
	if err != nil {
		return fmt.Errorf("runtime lock: %w", err)
	}
	mismatches := l.VerifyBinaries()
	if len(mismatches) == 0 {
		return nil
	}
	var msgs []string
	for _, m := range mismatches {
		msgs = append(msgs, fmt.Sprintf("%s: want %s got %s", m.Subject, m.Want, m.Got))
	}
	return fmt.Errorf("runtime lock verification failed: %s", strings.Join(msgs, "; "))
}

// managerConfig builds the lifecycle manager's config from the daemon config.
// Lock must be the same lock preflight was handed: the doctor reports on the
// pins and /host/status publishes the images they name, and a host where those
// two disagree is describing a system nobody is running.
func managerConfig(cfg *config.Config, tpls map[string]runtime.Template, host runtime.HostResources, pfLock *lock.Lock) runtime.ManagerConfig {
	return runtime.ManagerConfig{
		Admission:  cfg.Admission,
		VMDefaults: cfg.VMDefaults,
		Templates:  tpls,
		Host:       host,
		Lock:       pfLock,
	}
}

// preflightConfig builds the doctor's config from the daemon config. PrivdSocket
// and StageRoot must come from the same fields the jailer adapter launches with,
// or the doctor reports a host it never looked at.
func preflightConfig(cfg *config.Config, pfLock *lock.Lock, pfLockErr error) preflight.Config {
	return preflight.Config{
		Lock:        pfLock,
		LockErr:     pfLockErr,
		DataDir:     filepath.Dir(cfg.Storage.Database),
		APIMode:     cfg.Server.Mode,
		RequireAuth: cfg.Auth.RequireAuthentication,
		PrivdSocket: cfg.Paths.PrivilegedSocket,
		StageRoot:   cfg.Paths.StageRoot(),
	}
}

// serve runs the daemon until ctx is canceled. ready is called once with the
// bound address. The loopback check runs against the address actually bound,
// not just the configured string: config validation is not the last line.
func serve(ctx context.Context, cfg *config.Config, logger *slog.Logger, ready func(addr string)) error {
	if err := verifyRuntimeLock(cfg.Runtime.LockFile, logger); err != nil {
		return err
	}
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

	// Construct preflight runner. Load the lock again (verifyRuntimeLock already
	// ran above, so if we reach here a mismatch is already fatal; this re-load
	// is for the preflight config, not for binary verification).
	var pfLock *lock.Lock
	var pfLockErr error
	if cfg.Runtime.LockFile != "" {
		pfLock, pfLockErr = lock.Load(cfg.Runtime.LockFile)
		if pfLockErr != nil {
			logger.Warn("preflight: lock load error", "error", pfLockErr)
			// pfLock stays nil; pfLockErr is passed to the runner.
		}
	}
	pfRunner := preflight.New(preflightConfig(cfg, pfLock, pfLockErr))

	// Run preflight once at startup; log a summary. This does not block serving.
	{
		startupReport := pfRunner.Run(ctx)
		logger.Info("preflight complete", "overall", startupReport.Overall, "summary", startupReport.Summary())
	}

	// The preflight hook re-runs on demand (?refresh=1) or returns the last result.
	// For M0 we always re-run (cheap <1s checks); caching is future work.
	// refresh ignored in M0: no caching yet; every call re-runs.
	pfFunc := api.PreflightFunc(func(pCtx context.Context, _ bool) preflight.Report {
		return pfRunner.Run(pCtx)
	})

	// Build runtime adapter and wire the importer based on runtime.mode.
	var rt runtime.Runtime
	var adapterFindings []jailer.Finding
	var spoolRoot string

	switch cfg.Runtime.Mode {
	case "firecracker":
		adapter, buildErr := buildFirecrackerRuntime(cfg, pfFunc)
		if buildErr != nil {
			return fmt.Errorf("build firecracker runtime: %w", buildErr)
		}
		// Reconcile adapter at startup: classify all known VM jail dirs.
		// Must happen before the manager is created so findings are available
		// when we call mgr.NotifyVMMExit after manager construction.
		if jAdapter, ok := adapter.(*jailer.Adapter); ok {
			adapterFindings, err = jAdapter.Reconcile(ctx)
			if err != nil {
				return fmt.Errorf("adapter reconcile at startup: %w", err)
			}
			logger.Info("adapter reconcile complete", "findings", len(adapterFindings))
		}
		rt = adapter
		spoolRoot = filepath.Join(cfg.Paths.State, "spool")
	default:
		// "unavailable": keep the existing ForHost path unchanged.
		rt = runtime.ForHost(func() string {
			report := pfRunner.Run(ctx)
			return report.Summary()
		})
	}

	mgr, err := runtime.NewManager(st, rt, managerConfig(cfg, tpls, host, pfLock))
	if err != nil {
		return fmt.Errorf("create lifecycle manager: %w", err)
	}
	defer mgr.Close()

	// Map adapter findings to manager: vmm_gone and ambiguous outcomes mean the
	// VMM is gone or unverifiable — notify the manager so it can record the
	// specific reason (supplementing manager.Reconcile's generic controller_restart reason).
	for _, f := range adapterFindings {
		switch f.Outcome {
		case "vmm_gone", "ambiguous":
			// Reconcile names no boot: it stats the runner that is live now, so
			// its finding is about whatever boot the VM is on.
			if notifyErr := mgr.NotifyVMMExit(ctx, f.VMID, "", "reconcile: "+f.Detail, false); notifyErr != nil {
				logger.Warn("NotifyVMMExit for adapter finding failed", "vm_id", f.VMID, "outcome", f.Outcome, "err", notifyErr)
			}
		}
		// "adopted": VMM is alive and runner is running — no action.
	}

	// Start the spool importer goroutine when a spool root is configured.
	// The onImported callback routes vm.vmm_exited envelopes to NotifyVMMExit.
	if spoolRoot != "" {
		onImported := func(env *events.Envelope) {
			if env.Kind != "vm.vmm_exited" {
				return
			}
			vmID := ""
			if env.VMID != nil {
				vmID = *env.VMID
			}
			if vmID == "" {
				// vm_id in data (host-stream pattern: VMID column is NULL,
				// linkage lives in data.vm_id per the one-vm_id-semantic deviation).
				if v, ok := env.Data["vm_id"].(string); ok {
					vmID = v
				}
			}
			if vmID == "" {
				return
			}
			// The boot this exit was observed on. A vmm_exited crosses the spool
			// and can arrive after the VM has started again, so the boot it names
			// is what tells a live VM from one whose VMM is gone.
			bootID := ""
			if env.BootID != nil {
				bootID = *env.BootID
			}
			graceful := false
			if g, ok := env.Data["graceful"].(bool); ok {
				graceful = g
			}
			reason := "vmm_exited"
			if by, ok := env.Data["exit_observed_by"].(string); ok {
				reason = "vmm_exited observed by " + by
			}
			if notifyErr := mgr.NotifyVMMExit(ctx, vmID, bootID, reason, graceful); notifyErr != nil {
				logger.Warn("NotifyVMMExit from importer failed", "vm_id", vmID, "err", notifyErr)
			}
		}
		imp := spool.NewImporter(st, spoolRoot, 5*time.Second, onImported)
		go func() {
			if runErr := imp.Run(ctx); runErr != nil && !errors.Is(runErr, context.Canceled) {
				logger.Warn("spool importer exited", "err", runErr)
			}
		}()
		logger.Info("spool importer started", "root", spoolRoot)
	}

	// Build auth config. When auth is off (dev mode, loopback only), the API
	// injects a local_operator/none identity on every request. The smoke test
	// runs with require_authentication: true; the example config shows the
	// dev-default (false, loopback only).
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

	// The registry dials each VM's runner control socket under the state dir.
	// It is wired in every mode: on a host that cannot launch VMs there is no
	// socket to dial, and a terminal request fails saying exactly that, which
	// beats a 501 that blames the build.
	termReg := terminal.NewRegistry(terminal.Options{
		MaxReplayBytesPerSession: cfg.Terminal.MaxReplayBytesPerSession,
		MaxInflightBrowserBytes:  cfg.Terminal.MaxInflightBrowserBytes,
		WriterLease:              time.Duration(cfg.Terminal.WriterLeaseSeconds) * time.Second,
		Dial:                     terminal.UnixDialer(cfg.Paths.State),
	})

	srv := &http.Server{
		Handler:           api.New(st, eng, mgr, ac, pfFunc, termReg),
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
	// This budget is sized against net/http's own reclaim clock, not against how
	// long a handler runs. Shutdown will not close a connection sitting in
	// StateNew — accepted, no request byte read — until closeIdleConns releases
	// it (net/http/server.go, issue 22682):
	//
	//	if st == StateNew && unixSec < time.Now().Unix()-5 {
	//
	// Three details put that clock out of a 5s budget's reach. It starts when the
	// connection was accepted, not when shutdown began. unixSec compares whole
	// seconds, so the grace runs 5–6s rather than 5s. And Shutdown only re-checks
	// on an interval that ramps to shutdownPollIntervalMax (500ms), so it can
	// miss a reclaim it did not cause. Worst case the connection clears ~6.5s
	// after it was accepted, and any client holding an idle but never used pooled
	// connection at SIGTERM — a browser pre-connect, any pooled Go client — leaves
	// one behind.
	// A 5s budget was structurally unable to win that race and turned ordinary
	// shutdowns into "context deadline exceeded".
	//
	// 10s clears 6.5s with margin and stays far inside systemd's default 90s
	// TimeoutStopSec. ReadHeaderTimeout above also reaps such a connection at 5s
	// today, but it is a separate knob on a separate clock: raise it and only the
	// grace above is left, so the budget is sized against the grace. Do not tidy
	// this back down to match it.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	return nil
}
