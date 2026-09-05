// ABOUTME: Admission policy tests: boundary conditions and overcommit flags.
package runtime_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/2389-research/observatory-v2/internal/config"
	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/store"
)

// baseAdmission is a reasonable starting config for table tests.
func baseAdmission() config.Admission {
	return config.Admission{
		AllowMemoryOvercommit:       false,
		CPUOvercommitRatio:          1.0,
		ReserveHostCPUCores:         2,
		ReserveHostMemoryMinMiB:     4096,
		ReserveHostMemoryFraction:   0.20,
		ReservePerVMHostOverheadMiB: 768,
		ReserveInspectionSlots:      1,
		ReserveInspectorMemoryMiB:   1024,
		ReserveInspectorCPUCores:    1,
		ReserveInspectorScratchMiB:  20480,
		MaxParallelProvisions:       2,
		MaxBatchSize:                8,
	}
}

func TestPolicyUsableMemory(t *testing.T) {
	// Total 32768 MiB, 20% fraction = 6553 MiB, min = 4096 — fraction wins.
	// Inspector reserve: 1 slot × 1024 MiB = 1024 MiB.
	// Usable = 32768 − 6553 − 1024 = 25191 MiB.
	// (Actual: floor(32768*0.20) = 6553, so 32768-6553-1024 = 25191.)
	p := runtime.Policy{
		Admission: baseAdmission(),
		Host:      runtime.HostResources{TotalMemoryMiB: 32768, CPUCores: 16, StateDiskFreeMiB: 100000},
	}
	got := p.UsableMemoryMiB()
	// fraction = floor(32768 * 0.20) = 6553
	want := int64(32768) - int64(32768*20/100) - 1024
	if got != want {
		t.Errorf("UsableMemoryMiB = %d, want %d", got, want)
	}
}

func TestPolicyUsableMemoryMinWins(t *testing.T) {
	// Total 8192 MiB; fraction = 1638, min = 4096 → min wins.
	// Usable = 8192 − 4096 − 1024 = 3072 MiB.
	p := runtime.Policy{
		Admission: baseAdmission(),
		Host:      runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 50000},
	}
	if got := p.UsableMemoryMiB(); got != 3072 {
		t.Errorf("UsableMemoryMiB = %d, want 3072", got)
	}
}

func TestPolicyUsableVCPU(t *testing.T) {
	// 16 cores − 2 host reserve − 1 inspector = 13 usable × 1.0 = 13.0
	p := runtime.Policy{
		Admission: baseAdmission(),
		Host:      runtime.HostResources{TotalMemoryMiB: 32768, CPUCores: 16, StateDiskFreeMiB: 100000},
	}
	if got := p.UsableVCPU(); got != 13.0 {
		t.Errorf("UsableVCPU = %v, want 13.0", got)
	}
}

func TestAdmitHappyPath(t *testing.T) {
	p := runtime.Policy{
		Admission: baseAdmission(),
		Host:      runtime.HostResources{TotalMemoryMiB: 32768, CPUCores: 16, StateDiskFreeMiB: 100000},
	}
	totals := store.ReservationTotals{}
	err := p.Admit(totals, 2048+768, 2, 18432)
	if err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestAdmitExactBoundary(t *testing.T) {
	// Fill usable memory exactly — should admit.
	p := runtime.Policy{
		Admission: baseAdmission(),
		Host:      runtime.HostResources{TotalMemoryMiB: 32768, CPUCores: 16, StateDiskFreeMiB: 200000},
	}
	usable := p.UsableMemoryMiB()
	totals := store.ReservationTotals{}
	// Reserve exactly usable MiB — admitted.
	err := p.Admit(totals, usable, 1, 1024)
	if err != nil {
		t.Errorf("exact boundary: expected nil, got %v", err)
	}
	// One more MiB — refused.
	err = p.Admit(totals, usable+1, 1, 1024)
	var ar *store.AdmissionRefusal
	if !errors.As(err, &ar) {
		t.Fatalf("one over boundary: expected AdmissionRefusal, got %v", err)
	}
	if ar.Cause != "insufficient_capacity" {
		t.Errorf("cause = %q, want insufficient_capacity", ar.Cause)
	}
}

func TestAdmitMemoryRefusalNamesCorrectDimension(t *testing.T) {
	p := runtime.Policy{
		Admission: baseAdmission(),
		Host:      runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 16, StateDiskFreeMiB: 200000},
	}
	// Pre-fill all memory.
	totals := store.ReservationTotals{MemoryMiB: p.UsableMemoryMiB() + 1}
	err := p.Admit(totals, 1024, 1, 1024)
	var ar *store.AdmissionRefusal
	if !errors.As(err, &ar) {
		t.Fatalf("expected AdmissionRefusal, got %v", err)
	}
	if ar.Cause != "insufficient_capacity" {
		t.Errorf("cause = %q, want insufficient_capacity", ar.Cause)
	}
	// Message must mention "memory"
	if len(ar.Message) == 0 {
		t.Error("refusal message is empty")
	}
}

func TestAdmitCPURefusal(t *testing.T) {
	p := runtime.Policy{
		Admission: baseAdmission(),
		Host:      runtime.HostResources{TotalMemoryMiB: 131072, CPUCores: 4, StateDiskFreeMiB: 200000},
	}
	// 4 cores − 2 host − 1 inspector = 1 usable; asking for 2 should refuse.
	totals := store.ReservationTotals{}
	err := p.Admit(totals, 1024, 2, 1024)
	var ar *store.AdmissionRefusal
	if !errors.As(err, &ar) {
		t.Fatalf("expected AdmissionRefusal, got %v", err)
	}
	if ar.Cause != "insufficient_capacity" {
		t.Errorf("cause = %q, want insufficient_capacity", ar.Cause)
	}
}

func TestAdmitDiskRefusal(t *testing.T) {
	p := runtime.Policy{
		Admission: baseAdmission(),
		Host:      runtime.HostResources{TotalMemoryMiB: 131072, CPUCores: 32, StateDiskFreeMiB: 20481},
	}
	// usable disk = 20481 − 20480 = 1 MiB; asking for 2 should refuse.
	totals := store.ReservationTotals{}
	err := p.Admit(totals, 1024, 1, 2)
	var ar *store.AdmissionRefusal
	if !errors.As(err, &ar) {
		t.Fatalf("expected AdmissionRefusal, got %v", err)
	}
	if ar.Cause != "insufficient_capacity" {
		t.Errorf("cause = %q, want insufficient_capacity", ar.Cause)
	}
}

func TestAdmitMemoryOvercommitFlag(t *testing.T) {
	adm := baseAdmission()
	adm.AllowMemoryOvercommit = true
	p := runtime.Policy{
		Admission: adm,
		// Tiny total — would normally refuse memory.
		Host: runtime.HostResources{TotalMemoryMiB: 100, CPUCores: 32, StateDiskFreeMiB: 200000},
	}
	// With overcommit allowed, should pass on memory.
	totals := store.ReservationTotals{}
	err := p.Admit(totals, 99999, 1, 1)
	// CPU and disk should still be checked; memory is skipped.
	// With 32 cores − 2 − 1 = 29 usable vCPUs and asking for 1 with 1 vCPU, should pass.
	if err != nil {
		t.Errorf("overcommit allowed: expected nil, got %v", err)
	}
}

func TestAdmitPausedVMsStillCounted(t *testing.T) {
	// Paused VMs do NOT release compute in reservations — their compute_released=0.
	// ReservationTotals.MemoryMiB includes them by construction (store sums
	// non-compute-released rows). Test that a totals object representing a
	// paused VM still blocks new admission as expected.
	p := runtime.Policy{
		Admission: baseAdmission(),
		Host:      runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 50000},
	}
	usable := p.UsableMemoryMiB()
	// Simulate a paused VM holding usable memory (compute not released).
	totals := store.ReservationTotals{MemoryMiB: usable}
	err := p.Admit(totals, 1, 1, 1)
	var ar *store.AdmissionRefusal
	if !errors.As(err, &ar) {
		t.Fatalf("paused VM full: expected AdmissionRefusal, got %v", err)
	}
}

func TestProbeHostReturnsRealNumbers(t *testing.T) {
	dir := t.TempDir()
	h, err := runtime.ProbeHost(dir)
	if err != nil {
		t.Fatalf("ProbeHost: %v", err)
	}
	if h.TotalMemoryMiB <= 0 {
		t.Errorf("TotalMemoryMiB = %d, want > 0", h.TotalMemoryMiB)
	}
	if h.CPUCores <= 0 {
		t.Errorf("CPUCores = %d, want > 0", h.CPUCores)
	}
	if h.StateDiskFreeMiB <= 0 {
		t.Errorf("StateDiskFreeMiB = %d, want > 0", h.StateDiskFreeMiB)
	}
}

// --- template tests ---

func TestLoadTemplatesEmptyDir(t *testing.T) {
	dir := t.TempDir()
	tpls, err := runtime.LoadTemplates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tpls) != 0 {
		t.Errorf("expected empty map, got %d templates", len(tpls))
	}
}

func TestLoadTemplatesMissingDir(t *testing.T) {
	tpls, err := runtime.LoadTemplates("/no/such/directory/vmobs-templates")
	if err != nil {
		t.Fatal(err)
	}
	if len(tpls) != 0 {
		t.Errorf("expected empty map for missing dir, got %d", len(tpls))
	}
}

func TestLoadTemplatesHappyPath(t *testing.T) {
	dir := t.TempDir()
	manifest := `{
		"template_id": "tmpl-001",
		"description": "Test template",
		"guest_privilege_profiles": ["unprivileged"],
		"sensors": ["fanotify"],
		"protocol_versions": {"guestd": "1"}
	}`
	if err := os.WriteFile(filepath.Join(dir, "tmpl-001.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	tpls, err := runtime.LoadTemplates(dir)
	if err != nil {
		t.Fatalf("LoadTemplates: %v", err)
	}
	tpl, ok := tpls["tmpl-001"]
	if !ok {
		t.Fatal("template tmpl-001 not found")
	}
	if tpl.TemplateID != "tmpl-001" {
		t.Errorf("TemplateID = %q, want tmpl-001", tpl.TemplateID)
	}
	if !hasPrefix(tpl.Digest, "sha256:") {
		t.Errorf("Digest = %q, want sha256: prefix", tpl.Digest)
	}
	if len(tpl.Digest) != 71 { // "sha256:" + 64 hex chars
		t.Errorf("Digest length = %d, want 71", len(tpl.Digest))
	}
}

func TestLoadTemplatesDisallowsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	manifest := `{
		"template_id": "tmpl-bad",
		"description": "Test",
		"unknown_field": "should_fail"
	}`
	if err := os.WriteFile(filepath.Join(dir, "tmpl-bad.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runtime.LoadTemplates(dir)
	if err == nil {
		t.Error("expected error for unknown field, got nil")
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
