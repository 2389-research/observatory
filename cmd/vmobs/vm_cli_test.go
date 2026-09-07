// ABOUTME: CLI tests for vm/operation/template/host subcommands: --json parity,
// ABOUTME: human rendering, typed exit codes against a real daemon surface.
package main

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/api"
	"github.com/2389-research/observatory/internal/config"
	"github.com/2389-research/observatory/internal/runtime"
	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"github.com/2389-research/observatory/internal/situation"
	"github.com/2389-research/observatory/internal/store"
)

var cliTestTemplate = runtime.Template{
	TemplateID:  "test-small-v1",
	Description: "small test VM",
	Digest:      "sha256:aabbcc0011223344",
}

// newVMServer builds a server with one template, 8 GiB host, and a fake runtime.
// Used for VM-related CLI tests.
func newVMServer(t *testing.T) *httptest.Server {
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
		Admission: config.Admission{
			CPUOvercommitRatio:    4.0,
			MaxParallelProvisions: 2,
		},
		VMDefaults: config.VMDefaults{
			MemoryMiB:        512,
			VCPUCount:        1,
			RootDiskMiB:      4096,
			WorkspaceDiskMiB: 8192,
		},
		Templates: map[string]runtime.Template{cliTestTemplate.TemplateID: cliTestTemplate},
		Host:      runtime.HostResources{TotalMemoryMiB: 8192, CPUCores: 8, StateDiskFreeMiB: 100 * 1024},
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	t.Cleanup(func() { mgr.Close() })
	srv := httptest.NewServer(api.New(st, eng, mgr, api.AuthConfig{Enabled: false}, nil, nil))
	t.Cleanup(srv.Close)
	return srv
}

// --- vm list ---

func TestVMListEmpty(t *testing.T) {
	srv := newVMServer(t)
	code, stdout, _ := runCLI(t, "--api", srv.URL, "vm", "list")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "no VMs") {
		t.Errorf("empty list output should mention no VMs:\n%s", stdout)
	}
}

func TestVMListJSON(t *testing.T) {
	srv := newVMServer(t)
	// Create a VM first so the list is non-empty.
	createCode, createOut, _ := runCLI(t, "--api", srv.URL, "--json", "vm", "create",
		"--template", cliTestTemplate.TemplateID, "list-vm")
	if createCode != exitOK {
		t.Fatalf("create exit %d\nout: %s", createCode, createOut)
	}

	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "vm", "list")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var resp struct {
		VMs []map[string]any `json:"vms"`
	}
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if len(resp.VMs) != 1 {
		t.Errorf("vms = %d, want 1", len(resp.VMs))
	}
}

func TestVMListHuman(t *testing.T) {
	srv := newVMServer(t)
	runCLI(t, "--api", srv.URL, "vm", "create", "--template", cliTestTemplate.TemplateID, "human-list-vm")

	code, stdout, _ := runCLI(t, "--api", srv.URL, "vm", "list")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "human-list-vm") {
		t.Errorf("human list output missing vm name:\n%s", stdout)
	}
	if !strings.Contains(stdout, cliTestTemplate.TemplateID) {
		t.Errorf("human list missing template id:\n%s", stdout)
	}
}

// --- vm create ---

func TestVMCreateJSON(t *testing.T) {
	srv := newVMServer(t)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "--json", "vm", "create",
		"--template", cliTestTemplate.TemplateID, "my-vm")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	vm, _ := resp["vm"].(map[string]any)
	if vm["vm_id"] == nil {
		t.Error("create response missing vm.vm_id")
	}
	if vm["name"] != "my-vm" {
		t.Errorf("vm.name = %v, want my-vm", vm["name"])
	}
	op, _ := resp["operation"].(map[string]any)
	opID, _ := op["operation_id"].(string)
	if !strings.HasPrefix(opID, "op-") {
		t.Errorf("operation_id = %q, want op- prefix", opID)
	}
}

func TestVMCreateHuman(t *testing.T) {
	srv := newVMServer(t)
	code, stdout, stderr := runCLI(t, "--api", srv.URL, "vm", "create",
		"--template", cliTestTemplate.TemplateID, "human-vm")
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	// Human output: "created <vm-id>  <op-id> (state)"
	if !strings.Contains(stdout, "created") {
		t.Errorf("human create output missing 'created':\n%s", stdout)
	}
	if !strings.Contains(stdout, "op-") {
		t.Errorf("human create output missing operation id:\n%s", stdout)
	}
}

func TestVMCreateMissingTemplate(t *testing.T) {
	srv := newVMServer(t)
	// Missing --template flag → exitUsage.
	code, _, _ := runCLI(t, "--api", srv.URL, "vm", "create", "bad-vm")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

func TestVMCreateUnknownTemplate(t *testing.T) {
	srv := newVMServer(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "vm", "create",
		"--template", "no-such-template", "bad-vm")
	if code != exitAPIError {
		t.Errorf("exit %d, want %d", code, exitAPIError)
	}
	if !strings.Contains(stderr, "template_unknown") {
		t.Errorf("stderr should show template_unknown:\n%s", stderr)
	}
}

// --- vm get ---

func TestVMGetNotFound(t *testing.T) {
	srv := newVMServer(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "vm", "get",
		"00000000-dead-beef-0000-000000000001")
	if code != exitAPIError {
		t.Fatalf("exit %d, want %d", code, exitAPIError)
	}
	if !strings.Contains(stderr, "not_found") {
		t.Errorf("stderr should show not_found:\n%s", stderr)
	}
}

func TestVMGetJSON(t *testing.T) {
	srv := newVMServer(t)
	code, out, _ := runCLI(t, "--api", srv.URL, "--json", "vm", "create",
		"--template", cliTestTemplate.TemplateID, "get-test-vm")
	if code != exitOK {
		t.Fatalf("create: exit %d\n%s", code, out)
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	vmID := created["vm"].(map[string]any)["vm_id"].(string)

	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "vm", "get", vmID)
	if code != exitOK {
		t.Fatalf("get: exit %d\n%s", code, stdout)
	}
	var vm map[string]any
	if err := json.Unmarshal([]byte(stdout), &vm); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if vm["vm_id"] != vmID {
		t.Errorf("vm_id = %v, want %q", vm["vm_id"], vmID)
	}
}

func TestVMGetHuman(t *testing.T) {
	srv := newVMServer(t)
	code, out, _ := runCLI(t, "--api", srv.URL, "--json", "vm", "create",
		"--template", cliTestTemplate.TemplateID, "human-get-vm")
	if code != exitOK {
		t.Fatalf("create: exit %d", code)
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	vmID := created["vm"].(map[string]any)["vm_id"].(string)

	code, stdout, _ := runCLI(t, "--api", srv.URL, "vm", "get", vmID)
	if code != exitOK {
		t.Fatalf("get: exit %d", code)
	}
	if !strings.Contains(stdout, "human-get-vm") {
		t.Errorf("human vm get missing name:\n%s", stdout)
	}
	if !strings.Contains(stdout, vmID) {
		t.Errorf("human vm get missing vm_id:\n%s", stdout)
	}
}

// --- operation get ---

func TestOperationGetNotFound(t *testing.T) {
	srv := newVMServer(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "operation", "get", "op-999999")
	if code != exitAPIError {
		t.Fatalf("exit %d, want %d", code, exitAPIError)
	}
	if !strings.Contains(stderr, "not_found") {
		t.Errorf("stderr should show not_found:\n%s", stderr)
	}
}

func TestOperationGetJSON(t *testing.T) {
	srv := newVMServer(t)
	code, out, _ := runCLI(t, "--api", srv.URL, "--json", "vm", "create",
		"--template", cliTestTemplate.TemplateID, "op-get-vm")
	if code != exitOK {
		t.Fatalf("create: exit %d", code)
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	opID := created["operation"].(map[string]any)["operation_id"].(string)

	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "operation", "get", opID)
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	var op map[string]any
	if err := json.Unmarshal([]byte(stdout), &op); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if op["operation_id"] != opID {
		t.Errorf("operation_id = %v, want %q", op["operation_id"], opID)
	}
	if op["kind"] != "vm.create" {
		t.Errorf("kind = %v, want vm.create", op["kind"])
	}
}

func TestOperationGetMalformedID(t *testing.T) {
	srv := newVMServer(t)
	code, _, stderr := runCLI(t, "--api", srv.URL, "operation", "get", "not-an-op")
	if code != exitAPIError {
		t.Fatalf("exit %d, want %d\nstderr: %s", code, exitAPIError, stderr)
	}
	if !strings.Contains(stderr, "malformed_request") {
		t.Errorf("stderr should show malformed_request:\n%s", stderr)
	}
}

// --- template list ---

func TestTemplateListEmpty(t *testing.T) {
	srv, _ := newServer(t) // uses empty template registry
	code, stdout, _ := runCLI(t, "--api", srv.URL, "template", "list")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, "no approved templates") {
		t.Errorf("empty template list should say no approved templates:\n%s", stdout)
	}
}

func TestTemplateListJSON(t *testing.T) {
	srv := newVMServer(t)
	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "template", "list")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var resp struct {
		Templates []map[string]any `json:"templates"`
	}
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if len(resp.Templates) != 1 {
		t.Fatalf("templates = %d, want 1", len(resp.Templates))
	}
	if resp.Templates[0]["template_id"] != cliTestTemplate.TemplateID {
		t.Errorf("template_id = %v, want %q", resp.Templates[0]["template_id"], cliTestTemplate.TemplateID)
	}
}

func TestTemplateListHuman(t *testing.T) {
	srv := newVMServer(t)
	code, stdout, _ := runCLI(t, "--api", srv.URL, "template", "list")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout, cliTestTemplate.TemplateID) {
		t.Errorf("template list missing template ID:\n%s", stdout)
	}
	if !strings.Contains(stdout, cliTestTemplate.Description) {
		t.Errorf("template list missing description:\n%s", stdout)
	}
}

// --- host status ---

func TestHostStatusHuman(t *testing.T) {
	srv := newVMServer(t)
	code, stdout, _ := runCLI(t, "--api", srv.URL, "host", "status")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "runtime: available") {
		t.Errorf("host status missing runtime line:\n%s", stdout)
	}
	if !strings.Contains(stdout, "memory:") {
		t.Errorf("host status missing memory line:\n%s", stdout)
	}
}

func TestHostStatusJSON(t *testing.T) {
	srv := newVMServer(t)
	code, stdout, _ := runCLI(t, "--api", srv.URL, "--json", "host", "status")
	if code != exitOK {
		t.Fatalf("exit %d\n%s", code, stdout)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, stdout)
	}
	if got["capacity"] == nil || got["runtime"] == nil {
		t.Error("host/status JSON missing capacity or runtime")
	}
}

// --- dispatch edge cases ---

func TestVMUnknownSubcommand(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "vm", "explode")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

func TestOperationNoSubcommand(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "operation")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}

func TestHostNoSubcommand(t *testing.T) {
	srv, _ := newServer(t)
	code, _, _ := runCLI(t, "--api", srv.URL, "host")
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
}
