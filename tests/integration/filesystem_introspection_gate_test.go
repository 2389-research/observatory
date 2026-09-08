// ABOUTME: Verifies root and workspace mutation evidence from the actual pinned guest image.
// ABOUTME: Runs through a real terminal, runner spool and API in the Docker/KVM gate.
//go:build linux

package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/lock"
)

func TestFilesystemIntrospectionGate(t *testing.T) {
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("run through scripts/vmobs-gate with the pinned guest image")
	}
	gateSkipChecks(t)
	m1aSkipChecks(t)
	// Runner sockets include a VM UUID; testing.T's long generated path can
	// exceed Linux's sockaddr_un limit before the guest test starts.
	stateDir, err := os.MkdirTemp("", "vmobs-fs-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	opts := []daemonOption{withStateDir(stateDir), withRequiredAuth(m1bOperator, m1bPassword)}
	if os.Getenv("VMOBS_GUEST_SENSOR_TESTS") == "1" && os.Getenv("VMOBS_PROCESS_SENSOR_TESTS") == "1" {
		t.Fatal("select one supplemental guest test executable per fixture")
	}
	if os.Getenv("VMOBS_GUEST_SENSOR_TESTS") == "1" {
		fixtureLock := guestSensorTestImage(t, findRepoRoot(t), "fswatch")
		opts = append(opts, func(o *daemonOptions) { o.lockFile = fixtureLock })
	}
	if os.Getenv("VMOBS_PROCESS_SENSOR_TESTS") == "1" {
		fixtureLock := guestSensorTestImage(t, findRepoRoot(t), "procwatch")
		opts = append(opts, func(o *daemonOptions) { o.lockFile = fixtureLock })
	}
	d := startDaemon(t, findRepoRoot(t),
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobsd"),
		buildBinary(t, "github.com/2389-research/observatory/cmd/vmobs-runner"),
		"filesystem-introspection", opts...)
	status, body := d.apiPost(t, "/vms", map[string]any{
		"name": "filesystem-introspection", "template_id": "standard",
		"vcpu_count": 1, "memory_mib": 512,
		"root_disk_mib": 2048, "workspace_disk_mib": 64,
	})
	if status != http.StatusCreated {
		t.Fatalf("create guest: status=%d body=%v", status, body)
	}
	id := stringField(mapField(body, "vm"), "vm_id")
	d.trackVMID(id)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	for {
		vm := d.apiGet(t, "/vms/"+id)
		if stringField(vm, "observed_state") == "running" {
			break
		}
		if stringField(vm, "observed_state") == "failed" {
			logs, err := filepath.Glob(filepath.Join(d.stateDir, "failed", "*"+id+"*", "runner.log"))
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range logs {
				f, err := os.Open(name)
				if err != nil {
					t.Fatal(err)
				}
				log, err := io.ReadAll(io.LimitReader(f, 16*1024))
				_ = f.Close()
				if err != nil {
					t.Fatal(err)
				}
				assertNoToken(t, log)
				t.Logf("failed runner: %s", log)
			}
			op := d.apiGet(t, "/operations/"+stringField(mapField(body, "operation"), "operation_id"))
			page := d.apiGet(t, "/events?vm_id="+id+"&kind=vm.state_changed&tail=true")
			t.Fatalf("guest launch failed before capture check: vm=%v operation=%v events=%v", vm, op, page)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
	term := d.openTerm(t, d.createTerminal(t, id).ID, "filesystem-guest")
	term.takeWriter()
	output := term.runGuest(`while read device mount rest; do if [ "$mount" = /workspace ]; then printf 'workspace-mounted=%s\n' "$device"; fi; done < /proc/mounts`, m1bCommandTimeout)
	if !strings.Contains(strings.ReplaceAll(output, "\r", ""), "\nworkspace-mounted=/dev/vdc\n") {
		t.Fatalf("workspace disk is not mounted in guest: %s", tailOf(output, 1000))
	}
	bootID := waitFilesystemCoverage(t, d, id)
	for _, root := range []string{"/root", "/workspace"} {
		t.Run(root, func(t *testing.T) {
			name := "introspection-" + strings.TrimPrefix(root, "/")
			file := root + "/" + name
			term.runGuest("printf 'observed data' > "+file+"; chmod 640 "+file+"; mv "+file+" "+file+"-renamed; rm "+file+"-renamed", m1bCommandTimeout)
			deadline := time.Now().Add(30 * time.Second)
			seen := map[string]bool{}
			for time.Now().Before(deadline) {
				page := d.apiGet(t, "/events?vm_id="+id+"&boot_id="+bootID+"&family=fs&tail=true&limit=1000")
				for _, raw := range page["events"].([]any) {
					event := raw.(map[string]any)
					if stringField(event, "vm_id") != id || stringField(event, "boot_id") != bootID {
						t.Fatalf("event crossed VM/boot scope: %v", event)
					}
					data, err := json.Marshal(event["data"])
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(data), name) {
						if stringField(event, "provenance") != "guest_reported" {
							t.Fatalf("guest mutation has wrong provenance: %v", event)
						}
						if stringField(event, "kind") == "fs.create" && stringField(mapField(event, "quality"), "path_resolution") != "inferred" {
							t.Fatalf("live fixture parent failed path resolution: %v", event)
						}
						seen[stringField(event, "kind")] = true
					}
				}
				if seen["fs.create"] && seen["fs.modify"] && seen["fs.close_write"] && seen["fs.rename"] && seen["fs.delete"] && seen["fs.metadata"] {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Fatalf("missing durable mutation evidence for %s: %v", root, seen)
		})
	}
	if os.Getenv("VMOBS_GUEST_SENSOR_TESTS") == "1" {
		// Root has enough inodes for a complete fanotify queue plus one file;
		// the deliberately small workspace fixture cannot hold that pressure test.
		output := term.runGuest("VMOBS_FANOTIFY_TEST_ROOT=/root /usr/local/bin/vmobs-fswatch.test -test.v -test.timeout=90s; result=$?; printf '\\nfixture-result=%s\\n' \"$result\"", 2*time.Minute)
		output = strings.ReplaceAll(output, "\r", "")
		t.Logf("guest sensor tests: %s", tailOf(output, 16000))
		if !strings.Contains(output, "\nfixture-result=0\n") || strings.Contains(output, "--- SKIP:") {
			t.Fatal("guest filesystem sensor tests failed or skipped")
		}
	}
	if os.Getenv("VMOBS_PROCESS_CAPTURE_TESTS") == "1" {
		t.Run("process_capture", func(t *testing.T) { verifyGuestProcessCapture(t, d, term, id, bootID) })
	}
	if os.Getenv("VMOBS_PROCESS_SENSOR_TESTS") == "1" {
		output := term.runGuest("VMOBS_PROCWATCH_INTEGRATION=1 /usr/local/bin/vmobs-procwatch.test -test.v -test.timeout=90s; result=$?; printf '\\nprocess-fixture-result=%s\\n' \"$result\"", 2*time.Minute)
		output = strings.ReplaceAll(output, "\r", "")
		t.Logf("guest process sensor tests: %s", tailOf(output, 16000))
		if !strings.Contains(output, "\nprocess-fixture-result=0\n") || strings.Contains(output, "--- SKIP:") {
			t.Fatal("guest process sensor tests failed or skipped")
		}
	}
	if reviewRoot := os.Getenv("VMOBS_BROWSER_REVIEW_DIR"); reviewRoot != "" {
		term.close()
		waitFilesystemBrowserReview(t, d, id, reviewRoot)
	}
}

func verifyGuestProcessCapture(t *testing.T, d *m1aDaemon, term *gateTerm, id, bootID string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var coverage map[string]any
	for {
		coverage = d.apiGet(t, "/vms/"+id+"/coverage")
		ready := false
		for _, raw := range coverage["collectors"].([]any) {
			collector := raw.(map[string]any)
			if stringField(collector, "id") == "process" && stringField(collector, "state") == "healthy" && stringField(collector, "last_success_at") != "" {
				ready = true
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("guestd did not start healthy process capture: %v", coverage)
		}
		time.Sleep(100 * time.Millisecond)
	}
	term.runGuest(`/bin/sh -c 'exit 0' vmobs-process-proof`, m1bCommandTimeout)
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		page := d.apiGet(t, "/events?vm_id="+id+"&boot_id="+bootID+"&kind=proc.exec&tail=true&limit=1000")
		for _, raw := range page["events"].([]any) {
			event := raw.(map[string]any)
			data := mapField(event, "data")
			args, _ := data["argv_display"].([]any)
			if len(args) != 4 || args[3] != "vmobs-process-proof" {
				continue
			}
			process := mapField(data, "process")
			if stringField(event, "vm_id") != id || stringField(event, "boot_id") != bootID || stringField(process, "boot_id") != bootID || stringField(event, "sensor") != "process" || stringField(event, "provenance") != "guest_reported" || stringField(mapField(event, "quality"), "attribution") != "exact" || stringField(event, "process_key") == "" {
				t.Fatalf("durable process evidence lost identity: %v", event)
			}
			t.Logf("guestd command reached durable API: event=%s process=%s", stringField(event, "event_id"), stringField(event, "process_key"))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("terminal command did not reach durable process API")
}

func waitFilesystemCoverage(t *testing.T, d *m1aDaemon, id string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last map[string]any
	for time.Now().Before(deadline) {
		last = d.apiGet(t, "/vms/"+id+"/coverage")
		boot := stringField(last, "boot_id")
		if boot != "" && stringField(mapField(last, "channel"), "state") == "healthy" {
			for _, raw := range last["collectors"].([]any) {
				collector := raw.(map[string]any)
				if stringField(collector, "id") != "filesystem" || stringField(collector, "state") != "healthy" {
					continue
				}
				scope, err := json.Marshal(collector["scope"])
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(scope), "/workspace") || stringField(collector, "last_success_at") == "" {
					t.Fatalf("healthy filesystem coverage omitted workspace/success evidence: %v", collector)
				}
				if collector["observed_dropped"] == nil || collector["unknown_loss_intervals"] == nil || len(collector["limitations"].([]any)) == 0 {
					t.Fatalf("filesystem coverage omitted quality evidence: %v", collector)
				}
				return boot
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no healthy boot-scoped filesystem coverage: %v", last)
	return ""
}

// waitFilesystemBrowserReview keeps this real fixture alive for an external
// browser check. Its marker releases the fixture; it does not assert UI success.
func waitFilesystemBrowserReview(t *testing.T, d *m1aDaemon, id, root string) {
	t.Helper()
	dir, err := os.MkdirTemp(root, "filesystem-browser-")
	if err != nil {
		t.Fatal(err)
	}
	ready, err := json.Marshal(map[string]string{
		"url":   strings.TrimSuffix(d.baseURL, "/api/v1") + "/ui/?vm=" + id,
		"vm_id": id, "root_image_sha256": d.lk.RootImage.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ready.json"), ready, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("browser review fixture: %s; create review.complete to release", dir)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	for {
		if _, err := os.Stat(filepath.Join(dir, "review.complete")); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("browser review did not release fixture before deadline")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// guestSensorTestImage inserts the Linux test executable into a disposable
// trusted rootfs copy. debugfs operates in userspace; no guest disk is mounted on
// the host, and the shipped template never contains the test executable.
func guestSensorTestImage(t *testing.T, repoRoot, sensor string) string {
	t.Helper()
	if sensor != "fswatch" && sensor != "procwatch" {
		t.Fatal("unrecognized guest sensor fixture")
	}
	dir := t.TempDir()
	executable := "vmobs-" + sensor + ".test"
	binary := filepath.Join(dir, executable)
	cmd := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", binary, "./internal/guest/"+sensor)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile guest sensor tests: %v\n%s", err, out)
	}
	lk, err := lock.Load(filepath.Join(repoRoot, "runtime.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	rootfs := filepath.Join(dir, "rootfs.ext4")
	if err := copyFile(filepath.Join(repoRoot, lk.RootImage.Path), rootfs, 0600); err != nil {
		t.Fatal(err)
	}
	for _, request := range []string{
		"write " + binary + " /usr/local/bin/" + executable,
		"set_inode_field /usr/local/bin/" + executable + " mode 0100755",
	} {
		cmd := exec.CommandContext(t.Context(), "debugfs", "-w", "-R", request, rootfs)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("prepare trusted fixture rootfs: %v\n%s", err, out)
		}
	}
	f, err := os.Open(rootfs)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	lk.RootImage.Path = "rootfs.ext4"
	lk.RootImage.SHA256 = fmt.Sprintf("%x", h.Sum(nil))
	lk.RootImage.URL = ""
	if err := copyFile(filepath.Join(repoRoot, lk.GuestKernel.VmlinuxPath), filepath.Join(dir, "vmlinux"), 0600); err != nil {
		t.Fatal(err)
	}
	lk.GuestKernel.VmlinuxPath = "vmlinux"
	data, err := json.Marshal(lk)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "runtime.lock.json")
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	return name
}
