// ABOUTME: Names the per-VM files the gate rescues before teardown deletes them,
// ABOUTME: kept build-tag-free so the token-exclusion rule is testable off Linux.

package integration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// postmortemFile names one file to rescue and what it is called under the
// post-mortem directory. An optional file may be absent without that counting as
// a copy failure.
type postmortemFile struct {
	src      string
	dst      string
	optional bool
}

// vmRunnerFiles names the per-VM artifacts worth rescuing: the runner's stderr and
// the phase file the stop path polls. Both live in <StateDir>/vms/<vmID>
// (internal/jailer/launch.go), which is inside t.TempDir() and which privd's
// release deletes on stop or delete -- so they must be copied while the VM exists.
//
// The capability token is that directory's third file and is never named here:
// SPEC §15.3 keeps it out of logs and evidence, and the post-mortem directory
// outlives the run under /tmp.
//
// Returns nil when the VM's state dir is already gone, which is the normal case
// for every VM a green subtest cleaned up. Callers use that to stay quiet.
func vmRunnerFiles(stateDir, vmID string) []postmortemFile {
	dir := filepath.Join(stateDir, "vms", vmID)
	if _, err := os.Stat(dir); err != nil {
		return nil
	}
	return []postmortemFile{
		{src: filepath.Join(dir, "runner.log"), dst: "vm-" + vmID + "-runner.log"},
		{src: filepath.Join(dir, "runner-state.json"), dst: "vm-" + vmID + "-runner-state.json"},
	}
}

func TestVMRunnerFilesNamesRunnerArtifactsAndNeverTheToken(t *testing.T) {
	stateDir := t.TempDir()
	const vmID = "vm-01J000000000000000000000"
	vmDir := filepath.Join(stateDir, "vms", vmID)
	if err := os.MkdirAll(vmDir, 0o700); err != nil {
		t.Fatalf("mkdir vm dir: %v", err)
	}
	// The real layout: the token sits beside the two artifacts we do want.
	for name, content := range map[string]string{
		"runner.log":        "runner stderr\n",
		"runner-state.json": `{"phase":"vmm_exited"}`,
		"token":             "deadbeefdeadbeefdeadbeefdeadbeef",
	} {
		if err := os.WriteFile(filepath.Join(vmDir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	files := vmRunnerFiles(stateDir, vmID)
	if len(files) != 2 {
		t.Fatalf("vmRunnerFiles returned %d file(s), want 2: %+v", len(files), files)
	}
	wantSrc := map[string]string{
		filepath.Join(vmDir, "runner.log"):        "vm-" + vmID + "-runner.log",
		filepath.Join(vmDir, "runner-state.json"): "vm-" + vmID + "-runner-state.json",
	}
	for _, f := range files {
		dst, ok := wantSrc[f.src]
		if !ok {
			t.Errorf("vmRunnerFiles named unexpected source %q", f.src)
			continue
		}
		if f.dst != dst {
			t.Errorf("source %q: dst = %q, want %q", f.src, f.dst, dst)
		}
		// Not optional: these two exist for every VM that ever launched, so a
		// missing one is worth the log line savePostmortem writes for it.
		if f.optional {
			t.Errorf("source %q is marked optional; a missing runner artifact should be reported, not passed over", f.src)
		}
		delete(wantSrc, f.src)
		// §15.3: the capability token must never reach the post-mortem directory,
		// which outlives the run under /tmp.
		if strings.Contains(f.src, "token") || strings.Contains(f.dst, "token") {
			t.Errorf("vmRunnerFiles named the capability token: src=%q dst=%q", f.src, f.dst)
		}
	}
	for src := range wantSrc {
		t.Errorf("vmRunnerFiles did not name %q", src)
	}
}

func TestVMRunnerFilesSkipsAReleasedVM(t *testing.T) {
	stateDir := t.TempDir()
	// No vms/<id> directory: the normal case once a VM has been released. Naming
	// files here would make every green teardown log a rescue that saved nothing.
	if files := vmRunnerFiles(stateDir, "vm-gone"); files != nil {
		t.Fatalf("vmRunnerFiles = %+v for a released VM, want nil", files)
	}
}
