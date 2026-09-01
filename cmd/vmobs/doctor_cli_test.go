// ABOUTME: CLI tests for `vmobs doctor`: human table, --json parity, exit codes,
// ABOUTME: and preflight-absent handling. Uses real HTTP against an httptest server.
package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/preflight"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/situation"
	"github.com/2389-research/observatory-v2/internal/store"
)

// newDoctorServer builds a test server with the preflight hook wired.
// The hook always returns a fresh report from the given runner.
func newDoctorServer(t *testing.T, pfRunner *preflight.Runner) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{"capacity_exhausted": true},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})
	fake := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fake, runtime.ManagerConfig{
		Admission: config.Admission{CPUOvercommitRatio: 4.0, MaxParallelProvisions: 2},
		VMDefaults: config.VMDefaults{
			MemoryMiB: 512, VCPUCount: 1, RootDiskMiB: 4096, WorkspaceDiskMiB: 8192,
		},
		Templates: map[string]runtime.Template{},
		Host:      runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })

	pf := api.PreflightFunc(func(_ context.Context, _ bool) preflight.Report {
		return pfRunner.Run(t.Context())
	})
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}, pf))
	t.Cleanup(srv.Close)
	return srv
}

// newDoctorServerNoPF builds a test server WITHOUT the preflight hook wired,
// to test the "no preflight block" path.
func newDoctorServerNoPF(t *testing.T) *httptest.Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "events.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	eng := situation.New(st, situation.Config{
		Triggers:                  map[string]bool{},
		QueueMaxItems:             500,
		CollapseDuplicates:        true,
		SituationMaxResponseBytes: 65536,
	})
	fake := runtimetest.NewFake()
	mgr, err := runtime.NewManager(st, fake, runtime.ManagerConfig{
		Admission:  config.Admission{CPUOvercommitRatio: 4.0},
		VMDefaults: config.VMDefaults{MemoryMiB: 512, VCPUCount: 1, RootDiskMiB: 4096, WorkspaceDiskMiB: 8192},
		Templates:  map[string]runtime.Template{},
		Host:       runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}, nil))
	t.Cleanup(srv.Close)
	return srv
}

// TestDoctorNoPreflight: when the preflight hook is nil, doctor explains that
// and exits non-zero (exitAPIError).
func TestDoctorNoPreflight(t *testing.T) {
	srv := newDoctorServerNoPF(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "doctor")
	if code == exitOK {
		t.Error("doctor with no preflight block should not exit 0")
	}
	if !strings.Contains(stderr, "preflight") {
		t.Errorf("doctor stderr should mention preflight: %q", stderr)
	}
}

// TestDoctorJSONShape: --json emits the preflight JSON; top-level fields present.
func TestDoctorJSONShape(t *testing.T) {
	pfRunner := preflight.New(preflight.Config{
		DataDir:     t.TempDir(),
		APIMode:     "loopback_only",
		RequireAuth: false,
	})
	srv := newDoctorServer(t, pfRunner)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "doctor")
	// code is exitAPIError if overall=fail (expected on macOS where arch_kvm fails)
	// or exitOK if somehow overall=pass. We just need it to not be exitTransport.
	if code == exitTransport {
		t.Fatalf("doctor --json transport failure: %s", stderr)
	}
	if code == exitUsage {
		t.Fatalf("doctor usage error: %s", stderr)
	}

	var pf map[string]any
	if err := json.Unmarshal([]byte(stdout), &pf); err != nil {
		t.Fatalf("--json output not valid JSON: %v\n%s", err, stdout)
	}
	for _, field := range []string{"ran_at", "overall", "checks"} {
		if _, ok := pf[field]; !ok {
			t.Errorf("--json missing field %q", field)
		}
	}
}

// TestDoctorHumanTable: human output includes a header line and all 9 check IDs.
func TestDoctorHumanTable(t *testing.T) {
	pfRunner := preflight.New(preflight.Config{
		DataDir:     t.TempDir(),
		APIMode:     "loopback_only",
		RequireAuth: false,
	})
	srv := newDoctorServer(t, pfRunner)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "doctor")
	if code == exitTransport {
		t.Fatalf("doctor transport failure: %s", stderr)
	}

	// Human table must show all 9 check IDs.
	expectedIDs := []string{
		"arch_kvm", "fc_binaries", "kernel_tuple", "cgroup_v2",
		"net_prereqs", "resources", "dir_permissions", "api_binding", "guest_channel",
	}
	for _, id := range expectedIDs {
		if !strings.Contains(stdout, id) {
			t.Errorf("human table missing check id %q\n%s", id, stdout)
		}
	}

	// Header line present.
	if !strings.Contains(stdout, "preflight") {
		t.Errorf("human output missing 'preflight' header:\n%s", stdout)
	}
}

// TestDoctorExitOneOnFail: when overall=fail the exit code is 1 (exitAPIError).
// On macOS arch_kvm always fails, guaranteeing this path.
func TestDoctorExitOneOnFail(t *testing.T) {
	pfRunner := preflight.New(preflight.Config{
		DataDir: t.TempDir(),
		// No lock → fc_binaries fails. Plus arch_kvm fails on macOS.
		// That guarantees overall=fail.
	})
	report := pfRunner.Run(t.Context())
	if report.Overall != preflight.StatusFail {
		t.Skip("cannot force overall=fail in this environment; skipping exit-1 assertion")
	}

	srv := newDoctorServer(t, pfRunner)
	code, _, stderr := runCLI(t, "--api", srv.URL, "doctor")
	if code != exitAPIError {
		t.Errorf("doctor with overall=fail: exit %d, want %d (stderr: %s)", code, exitAPIError, stderr)
	}
}

// TestDoctorJSONExitCodeFromOverall: --json mode also exits 1 on fail.
func TestDoctorJSONExitCodeFromOverall(t *testing.T) {
	pfRunner := preflight.New(preflight.Config{
		DataDir: t.TempDir(),
	})
	report := pfRunner.Run(t.Context())
	if report.Overall != preflight.StatusFail {
		t.Skip("cannot force overall=fail in this environment")
	}

	srv := newDoctorServer(t, pfRunner)
	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "doctor")
	if code != exitAPIError {
		t.Errorf("doctor --json with overall=fail: exit %d, want %d", code, exitAPIError)
	}
	// Body must still be valid JSON.
	var pf map[string]any
	if err := json.Unmarshal([]byte(stdout), &pf); err != nil {
		t.Errorf("--json exit-1 output not valid JSON: %v\n%s", err, stdout)
	}
}
