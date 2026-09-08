// ABOUTME: Exercises Compose startup, policy loss and a real VM on a Linux KVM host.
// ABOUTME: Opt in with VMOBS_COMPOSE_LIVE=1 and VMOBS_IMAGE; uses disposable volumes.
package deploy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestComposeLive requires exclusive use of the vmobs-jailer profile and port
// 8787. It refuses an occupied host instead of disturbing an existing appliance.
// No reboot is needed: unloading the unused policy reproduces its loss at boot.
func TestComposeLive(t *testing.T) {
	if os.Getenv("VMOBS_COMPOSE_LIVE") != "1" {
		t.Skip("set VMOBS_COMPOSE_LIVE=1 and VMOBS_IMAGE on an idle Linux Docker/KVM host")
	}
	if runtime.GOOS != "linux" || os.Getenv("VMOBS_IMAGE") == "" {
		t.Fatal("requires Linux and an explicit VMOBS_IMAGE built from this checkout")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	name := fmt.Sprintf("vmobs-compose-test-%d", os.Getpid())
	for key, value := range map[string]string{
		"VMOBS_CONTAINER_NAME": name, "VMOBS_STATE_VOLUME": name + "-state",
		"VMOBS_RUNTIME_VOLUME": name + "-runtime", "VMOBS_APPARMOR_PROFILE": "vmobs-jailer",
	} {
		t.Setenv(key, value)
	}
	env := os.Environ()
	docker := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, "docker", args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	mustDocker := func(args ...string) string {
		t.Helper()
		out, err := docker(args...)
		if err != nil {
			t.Fatalf("docker %v: %v\n%s", args, err, out)
		}
		return out
	}
	for _, id := range strings.Fields(mustDocker("ps", "-q")) {
		if strings.TrimSpace(mustDocker("inspect", "--format", "{{.AppArmorProfile}}", id)) == "vmobs-jailer" {
			t.Fatal("vmobs-jailer is in use; stop its appliance before this test")
		}
	}
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:8787", time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("port 8787 is in use; refusing to disturb its service")
	}
	if _, err := os.Stat("/etc/apparmor.d/vmobs-jailer"); !os.IsNotExist(err) {
		t.Fatal("this fresh-install test requires no host /etc/apparmor.d/vmobs-jailer file; it will not remove one")
	}
	composeFile, err := filepath.Abs(composePath)
	if err != nil {
		t.Fatal(err)
	}
	base := []string{"compose", "-p", name, "-f", composeFile}
	compose := func(args ...string) string { return mustDocker(append(append([]string{}, base...), args...)...) }
	// Preserve logs before teardown; volumes belong only to this test invocation.
	defer func() {
		// A test timeout must not prevent cleanup of its VMs and volumes.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		cleanup := func(args ...string) (string, error) {
			cmd := exec.CommandContext(cleanupCtx, "docker", append(append([]string{}, base...), args...)...)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			return string(out), err
		}
		logs, _ := cleanup("logs", "--no-color")
		t.Logf("Compose logs:\n%s", logs)
		out, cleanupErr := cleanup("down", "--volumes", "--timeout", "10")
		if cleanupErr != nil {
			t.Errorf("Compose cleanup: %v\n%s", cleanupErr, out)
		}
	}()
	profiles := func() string {
		return compose("run", "--rm", "--no-deps", "--entrypoint", "cat", "apparmor", "/sys/kernel/security/apparmor/profiles")
	}
	unload := func() {
		if strings.Contains(profiles(), "vmobs-jailer (enforce)") {
			compose("run", "--rm", "--no-deps", "apparmor", "--remove", "--skip-cache", "/etc/apparmor.d/vmobs-jailer")
		}
		if strings.Contains(profiles(), "vmobs-jailer (") {
			t.Fatal("profile remains loaded before the fresh startup")
		}
	}
	unload()

	// A real parser refusal must block the dependent service, even if Docker
	// creates its container before the dependency has finished.
	failureFile := filepath.Join(t.TempDir(), "failure.yaml")
	if err := os.WriteFile(failureFile, []byte("services:\n  apparmor:\n    command: [--replace, --skip-cache, /missing-profile]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	failureArgs := append(append([]string{}, base...), "-f", failureFile, "up", "-d", "--no-build")
	if out, err := docker(failureArgs...); err == nil {
		t.Fatalf("Compose started despite missing policy:\n%s", out)
	} else {
		t.Logf("expected parser failure blocked startup:\n%s", out)
	}
	if out, err := docker("inspect", "--format", "{{.State.Running}}", name); err == nil && strings.TrimSpace(out) == "true" {
		t.Fatal("appliance ran despite failed policy load")
	}
	compose("up", "-d", "--no-build")
	// Forced deletion can wait for both VMM death and privileged cleanup.
	client := &http.Client{Timeout: 60 * time.Second}
	request := func(method, route, body string) (map[string]any, error) {
		req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:8787/api/v1"+route, bytes.NewBufferString(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("%s %s: %s", method, route, data)
		}
		var result map[string]any
		if len(data) > 0 {
			err = json.Unmarshal(data, &result)
		}
		return result, err
	}
	await := func(route, key, want string) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		var last any
		for time.Now().Before(deadline) {
			result, err := request("GET", route, "")
			last = result
			if err != nil {
				last = err
			} else if key == "" || result[key] == want {
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("waiting for %s %s=%s: %v", route, key, want, last)
	}
	await("/meta", "", "")
	if got := strings.TrimSpace(mustDocker("exec", name, "cat", "/proc/self/attr/current")); got != "vmobs-jailer (enforce)" {
		t.Fatalf("runtime profile = %q", got)
	}
	createVM := func() string {
		t.Helper()
		vm, err := request("POST", "/vms", `{"name":"compose-proof","template_id":"standard","vcpu_count":1,"memory_mib":512,"root_disk_mib":2048,"workspace_disk_mib":1024}`)
		if err != nil {
			t.Fatal(err)
		}
		created, ok := vm["vm"].(map[string]any)
		if !ok {
			t.Fatalf("create returned no vm object: %v", vm)
		}
		id, ok := created["vm_id"].(string)
		if !ok || id == "" {
			t.Fatalf("create returned no vm_id: %v", vm)
		}
		await("/vms/"+id, "observed_state", "running")
		t.Logf("real VM %s reached running under vmobs-jailer", id)
		return id
	}
	resources := func(id string, present bool) {
		t.Helper()
		check := `for resource do test -e "$resource" || exit 1; done`
		if !present {
			check = `for resource do test ! -e "$resource" && test ! -L "$resource" || exit 1; done`
		}
		mustDocker("exec", name, "sh", "-c", check, "check-vm-resources",
			"/srv/vmobs/jail/firecracker/"+id,
			"/srv/vmobs/jail/firecracker/"+id+"/root",
			"/srv/vmobs/stage/"+id,
			"/var/lib/vmobs/vms/"+id+"/manifest.json")
	}
	deleteVM := func(id string) {
		t.Helper()
		if _, err := request("DELETE", "/vms/"+id+"?force=true", ""); err != nil {
			t.Fatal(err)
		}
		await("/vms/"+id, "observed_state", "deleted")
		resources(id, false)
	}
	readManifest := func(id string) map[string]any {
		t.Helper()
		data := mustDocker("exec", name, "cat", "/var/lib/vmobs/vms/"+id+"/manifest.json")
		var manifest map[string]any
		if err := json.Unmarshal([]byte(data), &manifest); err != nil {
			t.Fatal(err)
		}
		return manifest
	}
	capacity := func() map[string]any {
		t.Helper()
		status, err := request("GET", "/host/status", "")
		if err != nil {
			t.Fatal(err)
		}
		result, ok := status["capacity"].(map[string]any)
		if !ok {
			t.Fatalf("host status lacks capacity: %v", status)
		}
		return result
	}
	baseline := capacity()
	assertReservationsReleased := func() {
		t.Helper()
		got := capacity()
		for _, key := range []string{"reserved_memory_mib", "reserved_vcpu", "reserved_disk_mib"} {
			if baseline[key] == nil || got[key] != baseline[key] {
				t.Errorf("%s after deletion = %v, initial = %v", key, got[key], baseline[key])
			}
		}
	}
	id := createVM()
	resources(id, true)
	predecessor := readManifest(id)
	ledgerPath := "/srv/vmobs/privd/" + id + ".json"
	ownership := mustDocker("exec", name, "cat", ledgerPath)
	if mode := strings.TrimSpace(mustDocker("exec", name, "stat", "-c", "%u:%g:%a", "/srv/vmobs/privd")); mode != "0:0:700" {
		t.Fatalf("privileged ledger ownership/mode = %s", mode)
	}
	if out, err := docker("exec", "--user", "2389:2389", name, "cat", ledgerPath); err == nil || !strings.Contains(out, "Permission denied") {
		t.Fatalf("unprivileged daemon must not read ownership ledger: %v: %s", err, out)
	}

	// Docker ends the VMM and clears /run. Persistent ownership must still
	// authorize cleanup of the chroot and manifest on the surviving volumes.
	compose("restart", "--timeout", "10", "vmobs")
	await("/meta", "", "")
	await("/vms/"+id, "observed_state", "failed")
	resources(id, true)
	if got := mustDocker("exec", name, "cat", ledgerPath); got != ownership {
		t.Fatalf("restart changed privileged ownership: before=%s after=%s", ownership, got)
	}
	t.Logf("VM %s failed after container restart with its chroot, stage and manifest still present", id)
	deleteVM(id)
	assertReservationsReleased()

	// The next VM should reuse the released slot. Retrying the predecessor's
	// deletion must preserve the new process even though its UID/CID are reused.
	successorID := createVM()
	resources(successorID, true)
	successor := readManifest(successorID)
	for _, key := range []string{"slot", "uid", "cid"} {
		if predecessor[key] == nil || successor[key] != predecessor[key] {
			t.Fatalf("successor did not reuse released %s: predecessor=%v successor=%v", key, predecessor[key], successor[key])
		}
	}
	pid, ok := successor["vmm_pid"].(float64)
	start, startOK := successor["vmm_starttime"].(string)
	if !ok || pid <= 0 || !startOK || start == "" {
		t.Fatalf("successor manifest lacks VMM identity: %v", successor)
	}
	assertSuccessorAlive := func() {
		t.Helper()
		stat := mustDocker("exec", name, "cat", fmt.Sprintf("/proc/%.0f/stat", pid))
		// Fields after comm start at field 3; starttime is field 22. Read the
		// kernel directly so a stale API state cannot hide a killed successor.
		end := strings.LastIndex(stat, ")")
		fields := strings.Fields(stat[end+1:])
		if end < 0 || len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" || fields[19] != start {
			t.Fatalf("successor VMM identity is no longer live: %s", stat)
		}
	}
	assertSuccessorAlive()
	deleteVM(id)
	assertSuccessorAlive()
	resources(successorID, true)
	await("/vms/"+successorID, "observed_state", "running")
	deleteVM(successorID)
	assertReservationsReleased()

	// Keep the exited setup container: a later up must rerun it rather than
	// trust yesterday's exit zero after the kernel has lost its policy.
	compose("stop", "vmobs")
	unload()
	compose("up", "-d", "--no-build")
	await("/meta", "", "")
	if !strings.Contains(profiles(), "vmobs-jailer (enforce)") {
		t.Fatal("Compose did not reload policy")
	}
	compose("up", "-d", "--no-build")
	await("/meta", "", "")
	if _, err := os.Stat("/etc/apparmor.d/vmobs-jailer"); !os.IsNotExist(err) {
		t.Fatal("startup installed a host policy file")
	}
	t.Log("PASS: failed loader blocks startup; confined VM lifecycle; restart orphan reclamation; successor survives delete retry; profile-loss recovery; repeat up; no host policy file")
}
