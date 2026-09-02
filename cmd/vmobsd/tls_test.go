// ABOUTME: TLS/https mode tests: self-signed cert helper, TestServeHTTPS (real
// ABOUTME: HTTPS + bearer auth), shutdown against parked connections, loopback.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/auth"
	"github.com/2389-research/observatory-v2/internal/config"
)

// writeSelfSigned generates a P-256 ECDSA key and a self-signed x509
// certificate for 127.0.0.1 with 1h validity. Returns the paths to the PEM
// files and the raw cert PEM bytes (for use as a trusted root in test clients).
func writeSelfSigned(t *testing.T, dir string) (certPath, keyPath string, certPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vmobsd-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certPath = filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert.pem: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key.pem: %v", err)
	}

	return certPath, keyPath, certPEM
}

// httpsConfig returns a config.Config for mode:https bound to 127.0.0.1:0
// with a fully initialized auth section, self-signed TLS files, and the DB
// placed under dir. The credential store is initialized and a bearer token is
// minted; the token secret and a ready-to-use *auth.Store are returned for use
// in test requests.
func httpsConfig(t *testing.T, dir string) (*config.Config, string) {
	t.Helper()

	certPath, keyPath, _ := writeSelfSigned(t, dir)

	credDir := filepath.Join(dir, "creds")
	st, err := auth.InitStore(credDir, "local_operator", "password123456")
	if err != nil {
		t.Fatalf("InitStore: %v", err)
	}
	secret, _, err := st.CreateToken("t12", "local_operator", 0)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}

	cfg := &config.Config{
		ConfigVersion: 1,
		Server: config.Server{
			Listen:       "127.0.0.1:0",
			Mode:         "https",
			TLSCertFile:  certPath,
			TLSKeyFile:   keyPath,
			PublicOrigin: "https://127.0.0.1",
		},
		Auth: config.Auth{
			Mode:                  "local_operator",
			RequireAuthentication: true,
			CredentialStore:       credDir,
			CSRFProtection:        true,
			SessionCookieHTTPOnly: true,
			SessionCookieSameSite: "strict",
			SessionCookieSecure:   true,
			SessionTTLMinutes:     720,
		},
		Storage: config.Storage{
			Database:          filepath.Join(dir, "state", "events.sqlite"),
			SQLiteJournalMode: "WAL",
			SQLiteSynchronous: "FULL",
			LogicalWriters:    1,
		},
	}

	return cfg, secret
}

// drainAndClose reads a response body to EOF, then closes it.
//
// Closing an unread body releases the caller before net/http's read loop has
// put the connection back in the client's idle pool. A second request issued
// inside that window finds the pool empty, queues a dial, and is then handed
// the original connection anyway — leaving the freshly dialed connection
// parked in the pool having never carried a request. The server counts such a
// connection as http.StateNew, and Server.Shutdown refuses to close a
// StateNew connection until net/http's hardcoded five-second grace expires,
// which outlasts serve's own five-second shutdown budget. Reading to EOF
// orders the pool return ahead of Close, so no spare connection is dialed.
func drainAndClose(t *testing.T, resp *http.Response) {
	t.Helper()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Errorf("drain response body: %v", err)
	}
	resp.Body.Close()
}

// TestServeHTTPS verifies the https server mode end-to-end:
// (1) GET /api/v1/meta over HTTPS (no auth needed) → 200
// (2) GET /api/v1/vms with bearer token → 200
// (3) plain HTTP request to the TLS listener → not 2xx (cleartext on TLS port)
func TestServeHTTPS(t *testing.T) {
	dir := t.TempDir()
	cfg, secret := httpsConfig(t, dir)

	// Capture the cert PEM for the custom TLS client root pool.
	certPEMBytes, err := os.ReadFile(cfg.Server.TLSCertFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEMBytes) {
		t.Fatal("failed to parse test certificate into pool")
	}

	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: roots,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, cfg, quietLogger(), func(addr string) { addrCh <- addr })
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		t.Fatalf("serve exited before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("daemon never became ready")
	}

	// (1) HTTPS GET /meta → 200 (no auth required on meta).
	metaURL := fmt.Sprintf("https://%s/api/v1/meta", addr)
	resp, err := tlsClient.Get(metaURL)
	if err != nil {
		t.Fatalf("GET /meta: %v", err)
	}
	drainAndClose(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /meta: want 200, got %d", resp.StatusCode)
	}

	// (2) Bearer GET /vms → 200.
	vmsURL := fmt.Sprintf("https://%s/api/v1/vms", addr)
	req, err := http.NewRequest(http.MethodGet, vmsURL, nil)
	if err != nil {
		t.Fatalf("build /vms request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err = tlsClient.Do(req)
	if err != nil {
		t.Fatalf("GET /vms: %v", err)
	}
	drainAndClose(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /vms with bearer: want 200, got %d", resp.StatusCode)
	}

	// (3) Plain HTTP to the TLS listener must not succeed (2xx).
	plainURL := fmt.Sprintf("http://%s/api/v1/meta", addr)
	plainResp, plainErr := http.DefaultClient.Get(plainURL)
	if plainErr == nil {
		plainResp.Body.Close()
		if plainResp.StatusCode >= 200 && plainResp.StatusCode < 300 {
			t.Errorf("plain HTTP to TLS listener: want non-2xx or error, got %d", plainResp.StatusCode)
		}
		// Non-2xx is acceptable (Go returns "Client sent an HTTP request to an HTTPS server").
	}
	// transport error is also acceptable — either way the cleartext request did not succeed.

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

// TestShutdownOutlastsParkedConnection pins serve's shutdown budget against
// net/http's reclaim clocks rather than against handler latency.
//
// A connection the server has accepted but read no request byte from sits in
// http.StateNew, and Server.Shutdown will not close one: closeIdleConns skips
// it until its StateNew grace expires, up to ~6.5s after the connection
// appeared. Two connections are parked because a connection can wait in
// StateNew at two different points inside (*conn).serve:
//
//   - raw: TCP established, no ClientHello, so the server waits in the TLS
//     handshake under tlsHandshakeTimeout().
//   - parked: handshake finished, no request, so the server waits in
//     readRequest under ReadHeaderTimeout. This is the shape a browser
//     pre-connect or any pooled client leaves behind at SIGTERM.
//
// Both those deadlines are 5s here and both start before the shutdown budget
// does, and Shutdown's poll interval has ramped to its 500ms cap by then, so a
// 5s budget cannot observe either reclaim in time.
//
// Dialing raw first makes its acceptance provable: the accept queue is FIFO, so
// a completed handshake on the later connection means the earlier one has been
// accepted and tracked.
func TestShutdownOutlastsParkedConnection(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := httpsConfig(t, dir)

	certPEMBytes, err := os.ReadFile(cfg.Server.TLSCertFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEMBytes) {
		t.Fatal("failed to parse test certificate into pool")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, cfg, quietLogger(), func(addr string) { addrCh <- addr })
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		t.Fatalf("serve exited before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("daemon never became ready")
	}

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("park pre-handshake connection: %v", err)
	}
	defer raw.Close()

	parked, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("park post-handshake connection: %v", err)
	}
	defer parked.Close()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("serve returned %v shutting down with parked connections", err)
		}
	case <-time.After(shutdownWait):
		t.Fatal("daemon did not shut down")
	}
}

// TestLoopbackModeStillRefusesNonLoopback pins the loopback_only defense in
// depth: Validate rejects a non-loopback listen address, and serve's own
// bound-address check catches any config that slips through Validate.
func TestLoopbackModeStillRefusesNonLoopback(t *testing.T) {
	t.Run("validate_rejects_nonloopback_listen", func(t *testing.T) {
		cfg := testConfig(t, "0.0.0.0:0")
		// config_version required; testConfig sets Mode:loopback_only and listen 0.0.0.0:0
		// Validate should reject this.
		if err := cfg.Validate(); err == nil {
			t.Fatal("Validate: expected error for non-loopback listen in loopback_only mode")
		}
	})

	t.Run("serve_rejects_nonloopback_bind", func(t *testing.T) {
		// Same defense in depth as TestServeRefusesNonLoopbackBind.
		err := serve(context.Background(), testConfig(t, "0.0.0.0:0"), quietLogger(), func(string) {
			t.Error("ready called for non-loopback bind")
		})
		if err == nil {
			t.Fatal("serve accepted non-loopback bind in loopback_only mode")
		}
	})

	t.Run("loopback_bind_serves_fine", func(t *testing.T) {
		// Pin that the loopback_only path itself still works normally.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		addrCh := make(chan string, 1)
		errCh := make(chan error, 1)
		go func() {
			errCh <- serve(ctx, testConfig(t, "127.0.0.1:0"), quietLogger(), func(addr string) { addrCh <- addr })
		}()

		select {
		case <-addrCh:
			// ready called — loopback serve is up
		case err := <-errCh:
			t.Fatalf("loopback serve exited before ready: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("daemon never became ready")
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
	})
}
