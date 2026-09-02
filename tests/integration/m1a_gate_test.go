// ABOUTME: M1a gate test: real Firecracker runtime slice — privd, jailer, runner, guestd.
// ABOUTME: Requires VMOBS_FIXTURE=1 and scripts/aibox03/setup.sh (incl. vmobs-privd) to have run.

//go:build linux

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// m1aPrivdSock is the socket path installed by scripts/aibox03/setup.sh.
const m1aPrivdSock = "/run/vmobs/privd.sock"

// m1aRuntimeRoot is the primary gate daemon's Paths.Runtime. It must be exactly
// /srv/vmobs: the daemon derives StageRoot = Paths.Runtime + "/stage" and
// JailBase = Paths.Runtime + "/jail" (config.Paths.StageRoot/JailBase), and
// JailBase is load-bearing — the runner's --uds flag and the stop path both build
// <JailBase>/firecracker/<id>/root/v.sock from it (internal/jailer/launch.go:179,196;
// internal/jailer/stop.go:368) and dial it host-side. privd creates the real chroot
// under ITS OWN --jail-base, which the installed unit sets to /srv/vmobs/jail
// (scripts/aibox03/vmobs-privd.service); its --stage-root is /srv/vmobs/stage. So
// /srv/vmobs is the only Paths.Runtime that satisfies both derivations against the
// installed privd.
const m1aRuntimeRoot = "/srv/vmobs"

// m1aStageBaseDir is the installed privd's stage root. The test stages each VM's boot
// files here, one subdir per vm_id. Derived from m1aRuntimeRoot — one source of truth —
// rather than a second independent literal that could drift from it.
const m1aStageBaseDir = m1aRuntimeRoot + "/stage"

// m1aJailBase is where privd puts jail chroot dirs (from --jail-base in the service
// unit). This is NOT path-configurable per test — it is privd's fixed server-side
// value. Also derived from m1aRuntimeRoot: since Paths.Runtime = /srv/vmobs, the
// primary daemon's own JailBase derivation lands on this exact path too — that
// equality is what lets the runner's v.sock dial succeed against privd's real chroot.
const m1aJailBase = m1aRuntimeRoot + "/jail"

// m1aPrivdLabel is checked in vmobsd's AT-001 refusal body.
// The jailer adapter names the failing preflight check ID: "guest_channel".
const m1aPrivdLabel = "guest_channel"

// m1aBadPrivdSocket is the AT-001 daemon's privileged_socket: a path that cannot
// exist, so the guest_channel dial must fail. The refusal body has to name it —
// that is the proof the daemon actually reached out and was refused.
const m1aBadPrivdSocket = "/nonexistent/privd.sock"

// m1aPrivdDialFailure is the guest_channel dial-branch summary
// (internal/preflight/checks_linux.go). AT-001 requires this branch and not the
// not_configured branch: a daemon that never learned its socket path would fail
// too, but it would prove nothing about privd being unreachable.
const m1aPrivdDialFailure = "cannot reach privd socket"

// m1aPrivdNotConfigured is the exact prefix of the guest_channel
// not_configured-branch summary (internal/preflight/checks_linux.go). Its
// presence in an AT-001 refusal means the daemon never dialed anything, so the
// subtest would be vacuous. Matching the full branch wording rather than a bare
// "not configured" keeps an unrelated phrase elsewhere in the message from
// reddening the gate for the wrong cause.
const m1aPrivdNotConfigured = "guest_channel not configured"

// gateRootDiskMiB and gateWorkspaceDiskMiB are the per-VM disk reservation every
// gate VM asks for. Admission charges root+workspace against UsableDiskMiB
// (internal/runtime/admission.go), so this pair sets how many gate VMs fit on the
// host at once.
//
// Derived from what a running gate VM actually costs on the state disk:
//
//	stage dir <Runtime>/stage/<vm_id>/:
//	  vmlinux         549 MiB  (PLAN.md, L0 Task 6: Linux 6.1.186 build on aibox03)
//	  rootfs.ext4    1024 MiB  (images/rootfs/build.sh: mkfs.ext4 ... 1G, exactly)
//	  config.ext4       1 MiB  (configDiskMiB, internal/jailer/launch.go)
//	  workspace.ext4   64 MiB  (this pair's workspace figure, which does size the file)
//	jail chroot <Runtime>/jail/firecracker/<vm_id>/root/:
//	  the same four files again -- privd copies every staged file in
//	  (CopyFromPinnedFd, internal/privd/vmops.go)
//	                 ---------
//	                  3276 MiB
//
// 4096 covers that with room for the per-VM state dir and for a dense copy of a
// sparse source. RootDiskMiB sizes nothing at launch -- the guest's root disk is
// the fixed 1 GiB rootfs.ext4 -- so it is purely this admission figure.
//
// Run 5 asked for 8192+64 = 8256 MiB. Six of those exactly fill aibox03's 52474 MiB
// of usable disk, and the run needs six reservations alive at AT-009, so a single VM
// stranded by an earlier subtest turned straight into insufficient_capacity. 4160
// MiB per VM fits twelve.
const (
	gateRootDiskMiB      = 4096
	gateWorkspaceDiskMiB = 64
)

// m1aGateEnv is the guard env — the same one TestM0Boot uses.
// We inherit the full set of gateSkipChecks from boot_test.go via the shared package.
// The M1a gate adds its own prerequisite probes on top.

// m1aSkipChecks runs M1a-specific prerequisite checks beyond the base gate checks.
// Call AFTER gateSkipChecks.
func m1aSkipChecks(t *testing.T) {
	t.Helper()
	// vmobs-privd socket installed by setup.sh.
	if _, err := os.Stat(m1aPrivdSock); os.IsNotExist(err) {
		t.Skipf("privd socket absent at %s; run scripts/aibox03/setup.sh to install vmobs-privd", m1aPrivdSock)
	}
	// Stage dir and jail base are created and owned by the operator by setup.sh.
	// Both derive from m1aRuntimeRoot (one source of truth) and are checked once
	// here; startDaemon relies on this check instead of repeating it.
	for _, d := range []string{m1aStageBaseDir, m1aJailBase} {
		if _, err := os.Stat(d); os.IsNotExist(err) {
			t.Skipf("dir absent at %s; run scripts/aibox03/setup.sh to create it", d)
		}
	}
}

// m1aDaemon holds a running vmobsd instance started by the gate test.
type m1aDaemon struct {
	addr       string
	baseURL    string
	httpClient *http.Client
	cmd        *exec.Cmd
	configPath string
	stateDir   string
	runtimeDir string
	cancel     context.CancelFunc
	// label names this daemon in log lines and is the post-mortem subdirectory,
	// so a rescue triggered from a VM teardown lands beside the daemon's own logs.
	label string

	// vmMu guards createdVMs, the vm_ids this daemon has created via POST /vms.
	// Tracked centrally (trackVMID) so t.Cleanup can best-effort remove each VM's
	// stage dir: /srv/vmobs is the shared production layout, so cleanup can no longer
	// blanket-RemoveAll a private per-test runtime dir the way the old layout did.
	vmMu       sync.Mutex
	createdVMs []string
}

// trackVMID records vmID as created by this daemon so t.Cleanup can best-effort
// remove its stage dir afterward. Safe for concurrent callers.
func (d *m1aDaemon) trackVMID(vmID string) {
	d.vmMu.Lock()
	defer d.vmMu.Unlock()
	d.createdVMs = append(d.createdVMs, vmID)
}

// startDaemon starts vmobsd with runtime.mode=firecracker and returns a handle.
// It polls /api/v1/meta until the daemon answers, then returns.
// The daemon and all its dirs are cleaned up in t.Cleanup.
func startDaemon(t *testing.T, repoRoot, daemonBin, runnerBin, label string) *m1aDaemon {
	t.Helper()

	// Paths.Runtime is the fixed production layout, not a per-test subdir: it must
	// equal /srv/vmobs exactly so the daemon's JailBase derivation (Paths.Runtime +
	// "/jail") matches privd's real --jail-base. See the m1aRuntimeRoot doc comment.
	runtimeDir := m1aRuntimeRoot

	// /srv/vmobs/stage and /srv/vmobs/jail are provisioned by scripts/aibox03/setup.sh,
	// not by this test: /srv/vmobs/jail is root:root 0755 (traversable, not writable by
	// this test's uid), and MkdirAll-ing the stage dir here would risk it silently
	// diverging from the production layout. m1aSkipChecks already verified both exist
	// before this function runs, so there is no second Stat here.

	stateDir := filepath.Join(t.TempDir(), "state")

	templatesDir := filepath.Join(stateDir, "templates")
	for _, d := range []string{
		stateDir,
		filepath.Join(stateDir, "spool"),
		templatesDir,
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("startDaemon %s: mkdir %s: %v", label, d, err)
		}
	}

	// Write the "standard" template the gate's POST /vms calls request.
	// kernel_image and root_image must be paths that exist on aibox03 (/srv/vmobs).
	// Field names match internal/runtime/templates.go:Template exactly; DisallowUnknownFields
	// will reject any stray field, so match the struct precisely.
	const standardTemplateJSON = `{
	"template_id": "standard",
	"description": "Standard M1a gate VM template",
	"kernel_image": "/srv/vmobs/images/vmlinux",
	"root_image": "/srv/vmobs/images/rootfs.img",
	"guest_privilege_profiles": ["unprivileged"],
	"sensors": ["fanotify"],
	"protocol_versions": {"guestd": "1"}
}`
	if err := os.WriteFile(filepath.Join(templatesDir, "standard.json"), []byte(standardTemplateJSON), 0o644); err != nil {
		t.Fatalf("startDaemon %s: write standard.json: %v", label, err)
	}

	// Find a free loopback port.
	port := findFreePort(t)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)

	dbPath := filepath.Join(stateDir, "vmobs.db")

	// Write a minimal config file.
	configPath := filepath.Join(t.TempDir(), "vmobsd.yaml")
	lockPath := filepath.Join(repoRoot, "runtime.lock.json")

	// runner binary must live beside daemonBin for T12's "resolve runner beside daemon".
	// We copy the runner binary into the daemon's dir so os.Executable's sibling check passes.
	daemonDir := filepath.Dir(daemonBin)
	runnerTarget := filepath.Join(daemonDir, "vmobs-runner")
	if err := copyFile(runnerBin, runnerTarget, 0o755); err != nil {
		t.Fatalf("startDaemon %s: install runner beside daemon: %v", label, err)
	}
	t.Cleanup(func() { _ = os.Remove(runnerTarget) })

	cfgContent := fmt.Sprintf(`config_version: 1
server:
  listen: %q
  public_origin: %q
  mode: loopback_only
auth:
  mode: local_operator
  require_authentication: false
  credential_store: %q
  csrf_protection: true
  session_cookie_http_only: true
  session_cookie_same_site: strict
  session_cookie_secure: false
  session_ttl_minutes: 720
paths:
  state: %q
  runtime: %q
  approved_templates: %q
  runtime_lock: %q
  privileged_socket: %q
runtime:
  mode: firecracker
  lock_file: %q
  jail_uid_base: 20000
  jail_gid: 36000
  cid_base: 3
admission:
  allow_memory_overcommit: false
  cpu_overcommit_ratio: 4.0
  reserve_host_cpu_cores: 0
  reserve_host_memory_min_mib: 0
  reserve_host_memory_fraction: 0.0
  reserve_per_vm_host_overhead_mib: 0
  reserve_inspection_slots: 0
  reserve_inspector_memory_mib: 0
  reserve_inspector_cpu_cores: 0
  reserve_inspector_scratch_mib: 0
  max_parallel_provisions: 4
  max_batch_size: 8
  default_batch_reservation: atomic_reservation
  default_batch_on_failure: keep_successful
vm_defaults:
  vcpu_count: 1
  memory_mib: 512
  root_disk_mib: %d
  workspace_disk_mib: %d
  guest_privilege: unprivileged
  network_profile: transport
  network_policy_id: ""
  disk_allocation: ""
  max_terminal_sessions: 0
  stop_grace_seconds: 30
network:
  ipv4_only_guest_boundary: false
  drop_guest_ipv6_on_host: false
  deny_cross_vm: false
  deny_host_and_special_use_destinations: false
  policy_directory: ""
  proxy_per_vm: false
  proxy_ca_per_vm: false
  proxy_upstream_tls_verify: false
  proxy_failure: ""
  raw_pcap_default: false
observation:
  filesystem_reads_default: false
  required_by_default: false
  failure_action_default: ""
  heartbeat_interval_seconds: 0
  heartbeat_timeout_seconds: 0
  max_frame_bytes: 0
  max_guest_pending_bytes: 0
  max_runner_spool_bytes: 0
  host_emergency_reserve_bytes: 0
  spool_ack_barrier: ""
  source_deduplication: ""
terminal:
  max_replay_bytes_per_session: 0
  max_wire_chunk_bytes: 0
  max_inflight_browser_bytes: 0
  writer_lease_seconds: 0
  record_input: false
  persist_output_default: false
  automatic_clipboard_write: false
  automatic_download: false
capture:
  http_headers_default: ""
  http_bodies_default: ""
  max_header_bytes: 0
  max_body_preview_bytes: 0
  max_file_preview_bytes: 0
  redact_before_persistence: false
  allow_unredacted_proxy_flow_dump: false
agent_interface:
  situation_max_response_bytes: 0
  attention_queue_max_items: 0
  attention_collapse_duplicates: false
  run_goal_max_bytes: 0
  guest_result_max_bytes: 0
  report_tail_max_bytes: 0
storage:
  database: %q
  sqlite_journal_mode: WAL
  sqlite_synchronous: FULL
  logical_writers: 1
  event_retention_days: 0
  artifact_retention_days: 0
  raw_disk_export_requires_separate_authorization: false
  untrusted_host_kernel_mounts: ""
performance_targets:
  reference_concurrent_vms: 0
  terminal_echo_p95_ms: 0
  event_visibility_p95_ms: 0
  steady_metadata_events_per_second: 0
`,
		listenAddr,
		"http://"+listenAddr,
		filepath.Join(stateDir, "auth"),
		stateDir,
		runtimeDir,
		filepath.Join(stateDir, "templates"),
		lockPath,
		m1aPrivdSock,
		lockPath,
		gateRootDiskMiB,
		gateWorkspaceDiskMiB,
		dbPath,
	)

	if err := os.WriteFile(configPath, []byte(cfgContent), 0o600); err != nil {
		t.Fatalf("startDaemon %s: write config: %v", label, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	stdoutPath := filepath.Join(t.TempDir(), label+"-stdout.log")
	stderrPath := filepath.Join(t.TempDir(), label+"-stderr.log")
	stdoutF, err := os.Create(stdoutPath)
	if err != nil {
		cancel()
		t.Fatalf("startDaemon %s: create stdout log: %v", label, err)
	}
	stderrF, err := os.Create(stderrPath)
	if err != nil {
		stdoutF.Close()
		cancel()
		t.Fatalf("startDaemon %s: create stderr log: %v", label, err)
	}

	cmd := exec.CommandContext(ctx, daemonBin, "-config", configPath)
	cmd.Stdout = stdoutF
	cmd.Stderr = stderrF
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// The handle is built before Start so the post-mortem cleanup registered just
	// after it can read the tracked VM list. Building it later would force that
	// cleanup to be registered later too, and the registration order here is
	// load-bearing: cleanups run last-added-first-called.
	d := &m1aDaemon{
		addr:    listenAddr,
		baseURL: "http://" + listenAddr + "/api/v1",
		// This client must outlive every budget the daemon gives itself, so it is
		// tied to those budgets rather than re-derived from the runtime's timeouts.
		// A gate client that gives up first converts a slow-but-legal operation into
		// a gate failure and blames the wrong component: the daemon is doing exactly
		// what it is supposed to, the test reports a timeout, and nothing in the
		// evidence says which of the two ran out. Lifecycle mutations stopped riding
		// r.Context() (internal/api/vms.go), so giving up here costs this test the
		// answer, not the VM -- which is precisely why the answer must not be lost.
		//
		//	stop, force_stop, delete, create   Manager.OperationContext:
		//	                                   stop_grace_seconds + operationSlack
		//	                                   = 30 + 120                      150s
		//	start                              Manager.launchBudget            240s
		//
		// 300s clears the larger of the two. Both constants live in
		// internal/runtime/manager.go with their derivations; re-derive this whenever
		// either moves, or whenever stop_grace_seconds does.
		httpClient: &http.Client{Timeout: 300 * time.Second},
		cmd:        cmd,
		configPath: configPath,
		stateDir:   stateDir,
		runtimeDir: runtimeDir,
		cancel:     cancel,
		label:      label,
	}

	if err := cmd.Start(); err != nil {
		stdoutF.Close()
		stderrF.Close()
		cancel()
		t.Fatalf("startDaemon %s: start vmobsd: %v", label, err)
	}

	t.Cleanup(func() {
		cancel()
		// Give the daemon a moment to shut down gracefully.
		done := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
			<-done
		}
		stdoutF.Close()
		stderrF.Close()
		// The daemon has stopped writing and the files are closed, so what is on
		// disk now is the whole record — and it lives under t.TempDir(), which Go
		// removes as this test ends. Rescue it before that happens.
		if t.Failed() {
			files := []postmortemFile{
				{src: stdoutPath, dst: filepath.Base(stdoutPath)},
				{src: stderrPath, dst: filepath.Base(stderrPath)},
				{src: dbPath, dst: filepath.Base(dbPath)},
				// The WAL and shared-memory sidecars exist only while the DB is open or
				// after an unclean exit; their absence is normal, not a copy failure.
				{src: dbPath + "-wal", dst: filepath.Base(dbPath) + "-wal", optional: true},
				{src: dbPath + "-shm", dst: filepath.Base(dbPath) + "-shm", optional: true},
			}
			// Any VM still holding a state dir at this point failed to release: the
			// teardown above rescues and deletes each VM it can reach, so what survives
			// to here is a leak, and its runner log is the record of why.
			d.vmMu.Lock()
			ids := append([]string(nil), d.createdVMs...)
			d.vmMu.Unlock()
			for _, id := range ids {
				files = append(files, vmRunnerFiles(stateDir, id)...)
			}
			savePostmortem(t, label, files)
		}
	})

	// Best-effort per-VM stage cleanup: /srv/vmobs is the shared production layout,
	// so unlike the old test-private runtime dir this cannot blanket-RemoveAll it.
	// Instead remove exactly the stage subdirs this daemon's run created, tracked via
	// trackVMID wherever POST /vms succeeds. Never remove /srv/vmobs/jail here: privd
	// owns that lifecycle via ReleaseVM, and a jail dir surviving past this point is a
	// leak to report, not hide.
	t.Cleanup(func() {
		d.vmMu.Lock()
		ids := append([]string(nil), d.createdVMs...)
		d.vmMu.Unlock()
		for _, id := range ids {
			_ = os.RemoveAll(filepath.Join(m1aStageBaseDir, id))
		}
	})

	// Best-effort VM teardown. Registered last on purpose: t.Cleanup runs in
	// last-added-first-called order (testing.go's runCleanup pops off the end),
	// so this runs BEFORE the stage-dir removal and before the daemon is killed —
	// i.e. while the daemon is still up and can serve the request. privd owns the
	// VM lifecycle (firecracker process, runner, netns, veth pair, jail dir) and
	// the daemon is the only thing that asks privd to release it, so killing
	// vmobsd with VMs still live strands all of that on the host; every red run so
	// far has needed manual cleanup with the root helper. A VM that will not
	// delete is a leak for AT-018 to catch — log it, never fail the run here.
	t.Cleanup(func() {
		d.vmMu.Lock()
		ids := append([]string(nil), d.createdVMs...)
		d.vmMu.Unlock()

		// One deadline for the whole loop. Every request below is built with
		// teardownCtx, so this 60s cap binds before the client's own 90s timeout and a
		// daemon that accepts connections but never answers costs 60s in total rather
		// than 90s per id. Uncapped, ten ids would outrun go test's own timeout, whose
		// panic aborts the binary before the remaining cleanups run -- losing the
		// post-mortem for exactly the failure that most needs it.
		teardownCtx, cancelTeardown := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancelTeardown()

		for i, id := range ids {
			if teardownCtx.Err() != nil {
				t.Logf("teardown %s: deadline expired after %d/%d vm(s); not deleted: %v",
					label, i, len(ids), ids[i:])
				return
			}
			// Rescue the runner's log and state file before the DELETE takes the VM's
			// state dir with it. Only when the run has already failed: a green run has
			// nothing to explain, and vmRunnerFiles is silent about VMs already gone.
			if t.Failed() {
				if files := vmRunnerFiles(d.stateDir, id); len(files) > 0 {
					savePostmortem(t, label, files)
				}
			}
			logVMStateBeforeTeardown(teardownCtx, t, d, label, id)

			req, err := http.NewRequestWithContext(teardownCtx, http.MethodDelete, d.baseURL+"/vms/"+id+"?force=true", nil)
			if err != nil {
				t.Logf("teardown %s: DELETE vm %s: new request: %v", label, id, err)
				continue
			}
			resp, err := d.httpClient.Do(req)
			if err != nil {
				t.Logf("teardown %s: DELETE vm %s: %v", label, id, err)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Logf("teardown %s: DELETE vm %s: got %d: %s", label, id, resp.StatusCode, body)
			}
		}
	})

	// Poll until the daemon responds to /meta.
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := d.httpClient.Get(d.baseURL + "/meta")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Logf("daemon stdout: %s", readFileTail(stdoutPath, 80))
			t.Logf("daemon stderr: %s", readFileTail(stderrPath, 80))
			t.Fatalf("startDaemon %s: daemon did not become ready within 30s (last err: %v)", label, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	return d
}

// logVMStateBeforeTeardown records a VM's observed state and revision before the
// teardown loop force-deletes it. Cleanups run last-added-first-called, so the
// teardown runs before the post-mortem capture and the rescued DB shows
// post-teardown vms rows rather than the state at failure; events and operations
// are append-only, so only the row state needs rescuing here. Best-effort — every
// failure logs and returns so the teardown continues.
func logVMStateBeforeTeardown(ctx context.Context, t *testing.T, d *m1aDaemon, label, id string) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.baseURL+"/vms/"+id, nil)
	if err != nil {
		t.Logf("teardown %s: pre-delete GET vm %s: new request: %v", label, id, err)
		return
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		t.Logf("teardown %s: pre-delete GET vm %s: %v", label, id, err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var vm map[string]any
	if err := json.Unmarshal(body, &vm); err != nil {
		t.Logf("teardown %s: pre-delete GET vm %s: got %d, unparseable body: %s",
			label, id, resp.StatusCode, body)
		return
	}
	t.Logf("teardown %s: pre-delete vm %s: status=%d observed_state=%v revision=%v",
		label, id, resp.StatusCode, vm["observed_state"], vm["revision"])
}

// apiGet performs a GET request and returns the parsed body.
func (d *m1aDaemon) apiGet(t *testing.T, path string) map[string]any {
	t.Helper()
	resp, err := d.httpClient.Get(d.baseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("GET %s: unmarshal body: %v\nbody=%s", path, err, body)
	}
	return result
}

// apiGetCode performs a GET and returns status code + body.
func (d *m1aDaemon) apiGetCode(t *testing.T, path string) (int, map[string]any) {
	t.Helper()
	resp, err := d.httpClient.Get(d.baseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("GET %s: unmarshal: %v\nbody=%s", path, err, body)
	}
	return resp.StatusCode, result
}

// apiPost performs a POST request and returns status code + parsed body.
func (d *m1aDaemon) apiPost(t *testing.T, path string, reqBody any) (int, map[string]any) {
	t.Helper()
	data, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("POST %s: marshal: %v", path, err)
	}
	resp, err := d.httpClient.Post(d.baseURL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("POST %s: unmarshal: %v\nbody=%s", path, err, respBody)
	}
	return resp.StatusCode, result
}

// apiPostErr performs a POST request and returns status code, parsed body, or
// an error instead of calling t.Fatalf. Unlike apiPost, it is safe to call
// from a goroutine other than the test goroutine (Go forbids FailNow off it).
func (d *m1aDaemon) apiPostErr(path string, reqBody any) (int, map[string]any, error) {
	data, err := json.Marshal(reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("POST %s: marshal: %w", path, err)
	}
	resp, err := d.httpClient.Post(d.baseURL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return 0, nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, nil, fmt.Errorf("POST %s: unmarshal: %w\nbody=%s", path, err, respBody)
	}
	return resp.StatusCode, result, nil
}

// apiDelete performs a DELETE request and returns status code + parsed body.
func (d *m1aDaemon) apiDelete(t *testing.T, path string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, d.baseURL+path, nil)
	if err != nil {
		t.Fatalf("DELETE %s: new request: %v", path, err)
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("DELETE %s: unmarshal: %v\nbody=%s", path, err, respBody)
	}
	return resp.StatusCode, result
}

// waitVMState polls GET /vms/{id} until observed_state matches want or ctx expires.
func (d *m1aDaemon) waitVMState(ctx context.Context, t *testing.T, vmID, want string) {
	t.Helper()
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("waitVMState %s: timed out waiting for state=%q (ctx: %v)", vmID, want, ctx.Err())
		default:
		}
		vm := d.apiGet(t, "/vms/"+vmID)
		if got, _ := vm["observed_state"].(string); got == want {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// waitEventKind polls GET /events?vm_id=<id>&kind=<kind> until at least one event
// appears or ctx expires. Returns the first matching event.
func (d *m1aDaemon) waitEventKind(ctx context.Context, t *testing.T, vmID, kind string) map[string]any {
	t.Helper()
	for {
		select {
		case <-ctx.Done():
			t.Errorf("waitEventKind %s kind=%q: timed out", vmID, kind)
			return nil
		default:
		}
		result := d.apiGet(t, "/events?vm_id="+vmID+"&kind="+kind)
		evts, _ := result["events"].([]any)
		if len(evts) > 0 {
			if m, ok := evts[0].(map[string]any); ok {
				return m
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// findFreePort returns a free loopback TCP port by binding and immediately closing.
func findFreePort(t *testing.T) int {
	t.Helper()
	l, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	addr := &syscall.SockaddrInet4{Port: 0, Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(l, addr); err != nil {
		syscall.Close(l)
		t.Fatalf("bind: %v", err)
	}
	sa, err := syscall.Getsockname(l)
	if err != nil {
		syscall.Close(l)
		t.Fatalf("getsockname: %v", err)
	}
	syscall.Close(l)
	return sa.(*syscall.SockaddrInet4).Port
}

// copyFile copies src to dst with mode.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src %s: %w", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create dst %s: %w", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return out.Close()
}

// savePostmortem copies files that would not survive the run -- a failed daemon's
// logs and state DB, a VM's runner log -- out of t.TempDir(), which Go deletes as
// the test ends, into a directory that survives, and names that directory in the
// test log so the path shows up in the run output. The pid keeps concurrent or
// repeated runs from overwriting each other. Callers may call it more than once
// for the same label; the files accumulate in one directory.
// Best-effort throughout: a copy error is reported, never fatal.
func savePostmortem(t *testing.T, label string, files []postmortemFile) {
	t.Helper()
	if len(files) == 0 {
		return
	}
	dir := filepath.Join("/tmp", fmt.Sprintf("m1a-gate-postmortem-%d", os.Getpid()), label)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Logf("postmortem %s: mkdir %s: %v", label, dir, err)
		return
	}
	var saved []string
	for _, f := range files {
		if _, err := os.Stat(f.src); err != nil {
			if !f.optional {
				t.Logf("postmortem %s: %s: %v", label, f.src, err)
			}
			continue
		}
		if err := copyFile(f.src, filepath.Join(dir, f.dst), 0o644); err != nil {
			t.Logf("postmortem %s: %v", label, err)
			continue
		}
		saved = append(saved, f.dst)
	}
	// Only claim what actually landed. A summary line that says "saved" after every
	// copy failed is the kind of vacuous evidence this gate exists to catch.
	if len(saved) == 0 {
		t.Logf("postmortem for %s: nothing saved to %s", label, dir)
		return
	}
	t.Logf("postmortem for %s: saved %d file(s) to %s: %s",
		label, len(saved), dir, strings.Join(saved, ", "))
}

// readFileTail returns the last n lines of a file as a string, for log dumps.
func readFileTail(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(read error: %v)", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// createVMErr posts POST /vms with minimal params and reports failure through
// its return value instead of t.Fatalf, so it is safe to call from a goroutine
// other than the test goroutine (Go forbids FailNow off it). apiPostErr and
// trackVMID are both goroutine-safe. createVM wraps this for the sequential
// call sites and fails t on error.
func (d *m1aDaemon) createVMErr(name string) (string, error) {
	status, body, err := d.apiPostErr("/vms", map[string]any{
		"name":               name,
		"template_id":        "standard",
		"vcpu_count":         1,
		"memory_mib":         512,
		"root_disk_mib":      gateRootDiskMiB,
		"workspace_disk_mib": gateWorkspaceDiskMiB,
	})
	if err != nil {
		return "", fmt.Errorf("createVM %s: %w", name, err)
	}
	if status != http.StatusCreated {
		return "", fmt.Errorf("createVM %s: expected 201, got %d: %v", name, status, body)
	}
	vm, _ := body["vm"].(map[string]any)
	vmID, _ := vm["vm_id"].(string)
	if vmID == "" {
		return "", fmt.Errorf("createVM %s: no vm_id in response: %v", name, body)
	}
	d.trackVMID(vmID)
	return vmID, nil
}

// createVM posts POST /vms with minimal params and returns the vm_id.
func (d *m1aDaemon) createVM(t *testing.T, name string) string {
	t.Helper()
	vmID, err := d.createVMErr(name)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return vmID
}

// disposeSubtestVMs registers a cleanup that force-deletes every VM created after
// this call. Call it as a subtest's first statement, before anything that can
// abort: t.Cleanup still runs after a t.Fatalf, so the subtest's reservations are
// freed however it exits, and t.Run waits for the cleanup before the next subtest
// starts. In live run 5 at011 aborted between its stop and its delete; vmA's disk
// reservation was still held two subtests later, and AT-009's third create came
// back 409 insufficient_capacity ("need 8256 MiB, only 2938 MiB free"), taking
// at018 and at007 down with it -- three red subtests from one abort.
//
// Only for VMs whose life ends with the subtest. A VM a later subtest still needs
// -- gate-a and gate-b, created by two_real_vms and used by at011 -- stays on the
// daemon's own teardown instead.
func (d *m1aDaemon) disposeSubtestVMs(t *testing.T) {
	t.Helper()
	d.vmMu.Lock()
	mark := len(d.createdVMs)
	d.vmMu.Unlock()
	t.Cleanup(func() {
		d.vmMu.Lock()
		ids := append([]string(nil), d.createdVMs[mark:]...)
		d.vmMu.Unlock()
		// One deadline for the whole loop, for the reason the daemon teardown gives:
		// a wedged daemon costs disposeVM its full per-VM timeout, and six of those in
		// one cleanup can outrun go test's own timeout, whose panic aborts the binary
		// before the remaining cleanups run.
		deadline := time.Now().Add(90 * time.Second)
		for i, id := range ids {
			if time.Now().After(deadline) {
				t.Logf("dispose: deadline expired after %d/%d vm(s); not deleted: %v", i, len(ids), ids[i:])
				return
			}
			d.disposeVM(t, id)
		}
	})
}

// disposeVM force-deletes one VM, rescuing its runner artifacts first when the test
// has already failed. Deleting an already-deleted VM answers 200 (Manager.Delete
// returns the row unchanged), so it is safe to call after the subtest deleted the
// VM itself, and after this the daemon teardown may call it again.
//
// Best-effort: every failure is logged, none fails the test. A VM that will not
// delete is a leak for AT-018 to catch, not for teardown to hide.
func (d *m1aDaemon) disposeVM(t *testing.T, vmID string) {
	t.Helper()
	if vmID == "" {
		return
	}
	if t.Failed() {
		savePostmortem(t, d.label, vmRunnerFiles(d.stateDir, vmID))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, d.baseURL+"/vms/"+vmID+"?force=true", nil)
	if err != nil {
		t.Logf("dispose vm %s: new request: %v", vmID, err)
		return
	}
	resp, err := d.httpClient.Do(req)
	if err != nil {
		t.Logf("dispose vm %s: %v", vmID, err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Logf("dispose vm %s: got %d: %s", vmID, resp.StatusCode, body)
	}
}

// stopVM posts the stop action for a VM.
func (d *m1aDaemon) stopVM(t *testing.T, vmID string) {
	t.Helper()
	vm := d.apiGet(t, "/vms/"+vmID)
	rev, _ := vm["revision"].(string)
	status, body := d.apiPost(t, "/vms/"+vmID+"/actions", map[string]any{
		"action":            "stop",
		"expected_revision": rev,
	})
	if status != http.StatusOK {
		t.Fatalf("stopVM %s: expected 200, got %d: %v", vmID, status, body)
	}
}

// deleteVM sends DELETE /vms/{id}.
func (d *m1aDaemon) deleteVM(t *testing.T, vmID string) {
	t.Helper()
	status, body := d.apiDelete(t, "/vms/"+vmID)
	if status != http.StatusOK {
		t.Fatalf("deleteVM %s: expected 200, got %d: %v", vmID, status, body)
	}
}

// countDirEntries counts entries in dir. A missing directory is zero entries; a
// directory that cannot be read is a failure, not a zero.
//
// The distinction is the whole point. These counters are compared against
// themselves before and after a workload, so "could not read" answering 0 reads
// exactly like "nothing leaked" — on both sides. privd recreates
// <JailBase>/firecracker with os.MkdirAll(root, 0o750) as root
// (internal/privd/vmops.go), so one removal is all it takes for the headline
// leak observable to go permanently blind while still reporting success.
func countDirEntries(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("leak observable %s is unreadable: %v — a count that cannot read its directory would report 0, which is indistinguishable from no leak", dir, err)
	}
	return len(entries)
}

// netnsCount counts entries in /var/run/netns (a missing directory is zero).
func netnsCount(t *testing.T) int {
	t.Helper()
	return countDirEntries(t, "/var/run/netns")
}

// vethCount counts network interfaces whose name starts with "veth-".
func vethCount(t *testing.T) int {
	t.Helper()
	out, err := exec.Command("ip", "-j", "link", "show").Output()
	if err != nil {
		t.Fatalf("leak observable veth: ip -j link show: %v — a count that cannot list links would report 0, which is indistinguishable from no leak", err)
	}
	var links []map[string]any
	if err := json.Unmarshal(out, &links); err != nil {
		t.Fatalf("leak observable veth: parse ip -j link show output: %v", err)
	}
	count := 0
	for _, l := range links {
		name, _ := l["ifname"].(string)
		if strings.HasPrefix(name, "veth-") {
			count++
		}
	}
	return count
}

// jailDirEntries counts subdirectories under /srv/vmobs/jail/firecracker.
func jailDirEntries(t *testing.T) int {
	t.Helper()
	return countDirEntries(t, filepath.Join(m1aJailBase, "firecracker"))
}

// firecrackerProcCount counts running firecracker processes via /proc.
func firecrackerProcCount(t *testing.T) int {
	t.Helper()
	count, unreadable, err := countFirecrackerProcs("/proc")
	if err != nil {
		t.Fatalf("leak observable firecracker processes: %v — a count that cannot read /proc would report 0, which is indistinguishable from no leak", err)
	}
	if unreadable > 0 {
		// Not fatal: a host normally carries a few processes whose /proc entries
		// this user may not read. Logged because "fc_procs=0, unreadable=<large>"
		// is a blind count, and the run's log should say so rather than imply zero.
		t.Logf("firecrackerProcCount: %d pid(s) unreadable; count=%d is a floor, not a total", unreadable, count)
	}
	return count
}

// stateDirEntries counts entries in stateDir/vms (number of VM state dirs).
func stateDirEntries(t *testing.T, stateDir string) int {
	t.Helper()
	return countDirEntries(t, filepath.Join(stateDir, "vms"))
}

// stageDirEntries counts entries in runtimeDir/stage (number of staged VM dirs).
func stageDirEntries(t *testing.T, runtimeDir string) int {
	t.Helper()
	return countDirEntries(t, filepath.Join(runtimeDir, "stage"))
}

// m1aBaseline captures the host baseline for AT-018 leak detection.
type m1aBaseline struct {
	NetnsCount      int
	VethCount       int
	JailEntries     int
	FcProcCount     int
	StateDirEntries int
	StageDirEntries int
}

// captureBaseline captures all AT-018 observables.
func captureBaseline(t *testing.T, stateDir, runtimeDir string) m1aBaseline {
	t.Helper()
	return m1aBaseline{
		NetnsCount:      netnsCount(t),
		VethCount:       vethCount(t),
		JailEntries:     jailDirEntries(t),
		FcProcCount:     firecrackerProcCount(t),
		StateDirEntries: stateDirEntries(t, stateDir),
		StageDirEntries: stageDirEntries(t, runtimeDir),
	}
}

// evidenceSubtest appends one subtest's evidence to sb after asserting the text
// contains no vsock auth token (§15.3). All evidence writes go through here so
// no call site can forget the scan.
func evidenceSubtest(t *testing.T, sb *strings.Builder, name, text string) {
	t.Helper()
	assertNoToken(t, []byte(text))
	fmt.Fprintf(sb, "\n## Subtest: %s\n", name)
	fmt.Fprintln(sb, text)
}

// ---------------------------------------------------------------------------
// TestM1aGate — the M1a acceptance gate, 8 ordered subtests.
// ---------------------------------------------------------------------------

// TestM1aGate is the M1a gate: real Firecracker VMs via the installed vmobs-privd.
// Guard: VMOBS_FIXTURE=1 (same as TestM0Boot), plus privd socket and stage dir present.
// Evidence is captured into tests/integration/evidence/m1a-gate-<hostname>.txt.
//
// Path reconciliation (verified at runtime, not guessed):
//   - Paths.Runtime = /srv/vmobs (m1aRuntimeRoot) — the exact production path, not a
//     per-test subdir.
//   - StageRoot (T12 derivation) = Paths.Runtime + "/stage" = /srv/vmobs/stage, which
//     is privd's own --stage-root — every start_vm StageDir resolves under it ✓
//   - JailBase (T12 derivation) = Paths.Runtime + "/jail" = /srv/vmobs/jail, which is
//     privd's own --jail-base. JailBase is load-bearing, not config-only: the runner's
//     --uds flag and the stop path both build <JailBase>/firecracker/<id>/root/v.sock
//     from it (internal/jailer/launch.go:179,196; internal/jailer/stop.go:368) and
//     dial it host-side — it must equal the chroot privd actually creates ✓
//   - /srv/vmobs is therefore the only Paths.Runtime that satisfies both derivations
//     against the installed privd.
func TestM1aGate(t *testing.T) {
	// Guard env check with an honest M1a message — the M0 message in gateSkipChecks
	// says "root-gated" which is wrong for M1a (M1a must NOT run as root). The env var
	// is the same (VMOBS_FIXTURE=1) for parity with M0; only the skip text changes.
	if os.Getenv("VMOBS_FIXTURE") != "1" {
		t.Skip("set VMOBS_FIXTURE=1 to run the M1a real-runtime gate (requires installed vmobs-privd; must NOT run as root)")
	}
	// Run the shared prerequisite probes (helper binary, firecracker, vmobs-fixture
	// group). The env check inside gateSkipChecks is now a no-op because the env is set.
	gateSkipChecks(t)
	m1aSkipChecks(t)

	if os.Getuid() == 0 {
		t.Fatal("M1a gate must not run as root; privileged ops flow through privd socket only")
	}

	repoRoot := findRepoRoot(t)

	// Build vmobsd and vmobs-runner binaries (one build, shared by all subtests).
	daemonBin := buildBinary(t, "github.com/2389-research/observatory-v2/cmd/vmobsd")
	runnerBin := buildBinary(t, "github.com/2389-research/observatory-v2/cmd/vmobs-runner")

	// Start the primary daemon (runtime.mode=firecracker).
	daemon := startDaemon(t, repoRoot, daemonBin, runnerBin, "m1a-primary")

	hostname, _ := os.Hostname()
	var evidence strings.Builder
	fmt.Fprintf(&evidence, "# M1a gate evidence\n")
	fmt.Fprintf(&evidence, "# hostname: %s\n", hostname)
	fmt.Fprintf(&evidence, "# date: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&evidence, "# pid: %d\n", os.Getpid())
	fmt.Fprintf(&evidence, "# paths.runtime: %s\n", daemon.runtimeDir)
	fmt.Fprintf(&evidence, "# paths.state: %s\n", daemon.stateDir)

	// ── Subtest 1: Doctor pass ─────────────────────────────────────────────────
	// GET /host/status → preflight.overall = "pass"
	t.Run("doctor_pass", func(t *testing.T) {
		status, body := daemon.apiGetCode(t, "/host/status")
		if status != http.StatusOK {
			t.Fatalf("GET /host/status: expected 200, got %d: %v", status, body)
		}
		pf, _ := body["preflight"].(map[string]any)
		if pf == nil {
			t.Fatal("GET /host/status: no preflight block in response")
		}
		overall, _ := pf["overall"].(string)
		if overall != "pass" {
			t.Errorf("preflight.overall = %q, want %q — gate is honestly red; fix the host, not the test", overall, "pass")
			checksRaw, _ := pf["checks"].([]any)
			for _, c := range checksRaw {
				cm, _ := c.(map[string]any)
				t.Logf("  check: %v", cm)
			}
		}
		rt, _ := body["runtime"].(map[string]any)
		rtAvail, _ := rt["available"].(bool)
		if !rtAvail {
			t.Errorf("runtime.available = false, reason: %v", rt["reason"])
		}
		evidenceSubtest(t, &evidence, "1_doctor_pass", fmt.Sprintf(
			"GET /host/status: status=%d overall=%q runtime.available=%v",
			status, overall, rtAvail,
		))
	})

	// ── Subtest 2: AT-001 refusal ──────────────────────────────────────────────
	// Second daemon with nonexistent privd socket → POST /vms refused with typed
	// error naming "guest_channel" in its cause or details.
	t.Run("at001_privd_refusal", func(t *testing.T) {
		// Build dirs for the bad daemon without calling startDaemon (which uses the
		// real privd socket — we want a daemon that uses /nonexistent/privd.sock).
		badStateDir := filepath.Join(t.TempDir(), "bad-state")
		// This daemon never reaches privd (its socket points at /nonexistent), so the
		// /srv/vmobs prefix is irrelevant — any writable dir works. t.TempDir() auto-
		// cleans, so no manual RemoveAll is needed.
		badRuntimeDir := filepath.Join(t.TempDir(), "runtime")
		badTemplatesDir := filepath.Join(badStateDir, "templates")
		for _, d := range []string{
			badStateDir,
			filepath.Join(badStateDir, "spool"),
			badRuntimeDir,
			filepath.Join(badRuntimeDir, "stage"),
			filepath.Join(badRuntimeDir, "jail"),
			badTemplatesDir,
		} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatalf("AT-001: mkdir %s: %v", d, err)
			}
		}

		// Provision the same "standard" template into the bad daemon so its
		// POST /vms refusal is caused only by the dead privd socket, not a
		// missing template. (manager.go checks runtime availability before
		// template lookup, so provisioning is belt-and-suspenders — but it
		// keeps both daemons identically configured except for the socket path.)
		const badStandardTemplateJSON = `{
	"template_id": "standard",
	"description": "Standard M1a gate VM template",
	"kernel_image": "/srv/vmobs/images/vmlinux",
	"root_image": "/srv/vmobs/images/rootfs.img",
	"guest_privilege_profiles": ["unprivileged"],
	"sensors": ["fanotify"],
	"protocol_versions": {"guestd": "1"}
}`
		if err := os.WriteFile(filepath.Join(badTemplatesDir, "standard.json"), []byte(badStandardTemplateJSON), 0o644); err != nil {
			t.Fatalf("AT-001: write standard.json: %v", err)
		}

		// vmobs-runner is already beside daemonBin (installed by startDaemon above).
		// The bad daemon uses the same daemonBin directory; no additional copy needed.
		// The bad daemon will fail at preflight before ever reaching runner invocation.

		badListenPort := findFreePort(t)
		badListenAddr := fmt.Sprintf("127.0.0.1:%d", badListenPort)
		badLockPath := filepath.Join(repoRoot, "runtime.lock.json")
		badDB := filepath.Join(badStateDir, "bad-vmobs.db")

		badCfgPath := filepath.Join(t.TempDir(), "bad-vmobsd.yaml")
		badCfgContent := fmt.Sprintf(`config_version: 1
server:
  listen: %q
  public_origin: %q
  mode: loopback_only
auth:
  mode: local_operator
  require_authentication: false
  credential_store: %q
  csrf_protection: true
  session_cookie_http_only: true
  session_cookie_same_site: strict
  session_cookie_secure: false
  session_ttl_minutes: 720
paths:
  state: %q
  runtime: %q
  approved_templates: %q
  runtime_lock: %q
  privileged_socket: %q
runtime:
  mode: firecracker
  lock_file: %q
  jail_uid_base: 20000
  jail_gid: 36000
  cid_base: 3
admission:
  allow_memory_overcommit: false
  cpu_overcommit_ratio: 4.0
  reserve_host_cpu_cores: 0
  reserve_host_memory_min_mib: 0
  reserve_host_memory_fraction: 0.0
  reserve_per_vm_host_overhead_mib: 0
  reserve_inspection_slots: 0
  reserve_inspector_memory_mib: 0
  reserve_inspector_cpu_cores: 0
  reserve_inspector_scratch_mib: 0
  max_parallel_provisions: 4
  max_batch_size: 8
  default_batch_reservation: atomic_reservation
  default_batch_on_failure: keep_successful
vm_defaults:
  vcpu_count: 1
  memory_mib: 512
  root_disk_mib: %d
  workspace_disk_mib: %d
  guest_privilege: unprivileged
  network_profile: transport
  network_policy_id: ""
  disk_allocation: ""
  max_terminal_sessions: 0
  stop_grace_seconds: 30
network:
  ipv4_only_guest_boundary: false
  drop_guest_ipv6_on_host: false
  deny_cross_vm: false
  deny_host_and_special_use_destinations: false
  policy_directory: ""
  proxy_per_vm: false
  proxy_ca_per_vm: false
  proxy_upstream_tls_verify: false
  proxy_failure: ""
  raw_pcap_default: false
observation:
  filesystem_reads_default: false
  required_by_default: false
  failure_action_default: ""
  heartbeat_interval_seconds: 0
  heartbeat_timeout_seconds: 0
  max_frame_bytes: 0
  max_guest_pending_bytes: 0
  max_runner_spool_bytes: 0
  host_emergency_reserve_bytes: 0
  spool_ack_barrier: ""
  source_deduplication: ""
terminal:
  max_replay_bytes_per_session: 0
  max_wire_chunk_bytes: 0
  max_inflight_browser_bytes: 0
  writer_lease_seconds: 0
  record_input: false
  persist_output_default: false
  automatic_clipboard_write: false
  automatic_download: false
capture:
  http_headers_default: ""
  http_bodies_default: ""
  max_header_bytes: 0
  max_body_preview_bytes: 0
  max_file_preview_bytes: 0
  redact_before_persistence: false
  allow_unredacted_proxy_flow_dump: false
agent_interface:
  situation_max_response_bytes: 0
  attention_queue_max_items: 0
  attention_collapse_duplicates: false
  run_goal_max_bytes: 0
  guest_result_max_bytes: 0
  report_tail_max_bytes: 0
storage:
  database: %q
  sqlite_journal_mode: WAL
  sqlite_synchronous: FULL
  logical_writers: 1
  event_retention_days: 0
  artifact_retention_days: 0
  raw_disk_export_requires_separate_authorization: false
  untrusted_host_kernel_mounts: ""
performance_targets:
  reference_concurrent_vms: 0
  terminal_echo_p95_ms: 0
  event_visibility_p95_ms: 0
  steady_metadata_events_per_second: 0
`,
			badListenAddr,
			"http://"+badListenAddr,
			filepath.Join(badStateDir, "auth"),
			badStateDir,
			badRuntimeDir,
			filepath.Join(badStateDir, "templates"),
			badLockPath,
			m1aBadPrivdSocket,
			badLockPath,
			gateRootDiskMiB,
			gateWorkspaceDiskMiB,
			badDB,
		)
		if err := os.WriteFile(badCfgPath, []byte(badCfgContent), 0o600); err != nil {
			t.Fatalf("write bad config: %v", err)
		}

		badCtx, badCancel := context.WithCancel(context.Background())
		t.Cleanup(badCancel)

		stdoutPath := filepath.Join(t.TempDir(), "bad-stdout.log")
		stderrPath := filepath.Join(t.TempDir(), "bad-stderr.log")
		stdoutF, _ := os.Create(stdoutPath)
		stderrF, _ := os.Create(stderrPath)
		t.Cleanup(func() { stdoutF.Close(); stderrF.Close() })

		badCmd := exec.CommandContext(badCtx, daemonBin, "-config", badCfgPath)
		badCmd.Stdout = stdoutF
		badCmd.Stderr = stderrF
		badCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := badCmd.Start(); err != nil {
			t.Fatalf("start bad daemon: %v", err)
		}
		t.Cleanup(func() {
			badCancel()
			done := make(chan struct{})
			go func() { _ = badCmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				if badCmd.Process != nil {
					_ = syscall.Kill(-badCmd.Process.Pid, syscall.SIGKILL)
				}
				<-done
			}
		})

		// Poll until bad daemon is up.
		badClient := &http.Client{Timeout: 10 * time.Second}
		badBase := "http://" + badListenAddr + "/api/v1"
		deadline := time.Now().Add(30 * time.Second)
		for {
			resp, err := badClient.Get(badBase + "/meta")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("bad daemon did not start within 30s")
			}
			time.Sleep(200 * time.Millisecond)
		}

		// POST /vms must fail with 501 missing_capability / cause runtime_unavailable.
		// The reason must name the unreachable socket the daemon actually dialed.
		resp, err := badClient.Post(badBase+"/vms", "application/json",
			bytes.NewBufferString(fmt.Sprintf(
				`{"name":"at001-test","template_id":"standard","vcpu_count":1,"memory_mib":512,"root_disk_mib":%d,"workspace_disk_mib":%d}`,
				gateRootDiskMiB, gateWorkspaceDiskMiB)))
		if err != nil {
			t.Fatalf("POST /vms on bad daemon: %v", err)
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		var errBody map[string]any
		if err := json.Unmarshal(respBody, &errBody); err != nil {
			t.Fatalf("unmarshal AT-001 error body: %v\nbody=%s", err, respBody)
		}

		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("AT-001: expected 501, got %d: %s", resp.StatusCode, respBody)
		}
		cause, _ := errBody["cause"].(string)
		if cause != "runtime_unavailable" {
			t.Errorf("AT-001: cause = %q, want %q", cause, "runtime_unavailable")
		}
		// The reason must name guest_channel.
		msg, _ := errBody["message"].(string)
		details, _ := errBody["details"].(map[string]any)
		reason, _ := details["reason"].(string)
		guestChannelFound := strings.Contains(msg, m1aPrivdLabel) || strings.Contains(reason, m1aPrivdLabel)
		if !guestChannelFound {
			t.Errorf("AT-001: neither message %q nor details.reason %q contains %q",
				msg, reason, m1aPrivdLabel)
		}

		// The refusal must come from the dial branch: the daemon read its config,
		// reached for the socket, and was refused. A refusal that only says
		// "guest_channel" would also be produced by a daemon that never dialed at
		// all, which is what shipped before the preflight wiring fix.
		dialFailureFound := strings.Contains(msg, m1aPrivdDialFailure) || strings.Contains(reason, m1aPrivdDialFailure)
		if !dialFailureFound {
			t.Errorf("AT-001: neither message %q nor details.reason %q contains %q; the daemon did not dial privd",
				msg, reason, m1aPrivdDialFailure)
		}
		socketNamed := strings.Contains(msg, m1aBadPrivdSocket) || strings.Contains(reason, m1aBadPrivdSocket)
		if !socketNamed {
			t.Errorf("AT-001: neither message %q nor details.reason %q names the configured socket %q",
				msg, reason, m1aBadPrivdSocket)
		}
		notConfiguredFound := strings.Contains(msg, m1aPrivdNotConfigured) || strings.Contains(reason, m1aPrivdNotConfigured)
		if notConfiguredFound {
			t.Errorf("AT-001: refusal says %q (message %q, details.reason %q); the daemon never received its privd socket and stage root",
				m1aPrivdNotConfigured, msg, reason)
		}

		// Token must not appear anywhere in the error body.
		assertNoToken(t, respBody)

		badCancel() // shut the bad daemon down promptly

		evidenceSubtest(t, &evidence, "2_at001_privd_refusal", fmt.Sprintf(
			"POST /vms on bad-privd daemon: status=%d cause=%q message=%q details.reason=%q "+
				"guest_channel_found=%v dial_failure_found=%v socket_named=%v not_configured_found=%v",
			resp.StatusCode, cause, msg, reason,
			guestChannelFound, dialFailureFound, socketNamed, notConfiguredFound,
		))
	})

	// ── Subtest 3: Two real VMs ────────────────────────────────────────────────
	// Create A and B; both reach running; independence asserted. POST /vms is the
	// create/start request (SPEC §14): it launches the VM, so there is no separate
	// start action to issue.
	var vmAID, vmBID string
	t.Run("two_real_vms", func(t *testing.T) {
		// No disposeSubtestVMs here on purpose: both VMs are meant to outlive this
		// subtest. at011 owns vmA's disposal; vmB stays live to the end of the run so
		// at011 can show A's stop left it alone, and the daemon teardown disposes it.
		vmAID = daemon.createVM(t, "gate-a")
		vmBID = daemon.createVM(t, "gate-b")

		// Wait for both to reach running.
		runCtx, runCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer runCancel()
		daemon.waitVMState(runCtx, t, vmAID, "running")
		daemon.waitVMState(runCtx, t, vmBID, "running")

		// Read manifests to check uid/cid independence.
		mA, errA := readM1aManifest(daemon.stateDir, vmAID)
		mB, errB := readM1aManifest(daemon.stateDir, vmBID)
		if errA != nil {
			t.Errorf("read manifest for vmA: %v", errA)
		}
		if errB != nil {
			t.Errorf("read manifest for vmB: %v", errB)
		}
		if errA == nil && errB == nil {
			if mA.UID == mB.UID {
				t.Errorf("vmA and vmB share uid %d (identity isolation failure)", mA.UID)
			}
			if mA.CID == mB.CID {
				t.Errorf("vmA and vmB share cid %d (isolation failure)", mA.CID)
			}
		}

		// Both must have separate network namespaces.
		nsA := "vmobs-" + vmAID
		nsB := "vmobs-" + vmBID
		// Use 'ip netns list' to check presence.
		nsOut, err := exec.Command("ip", "netns", "list").Output()
		if err != nil {
			t.Logf("ip netns list: %v", err)
		}
		nsStr := string(nsOut)
		if !strings.Contains(nsStr, nsA) {
			t.Errorf("netns %s not found in: %s", nsA, nsStr)
		}
		if !strings.Contains(nsStr, nsB) {
			t.Errorf("netns %s not found in: %s", nsB, nsStr)
		}

		// Both must have guest.channel_established events.
		chanCtx, chanCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer chanCancel()
		_ = daemon.waitEventKind(chanCtx, t, vmAID, "guest.channel_established")
		_ = daemon.waitEventKind(chanCtx, t, vmBID, "guest.channel_established")

		uidAStr := "uid=N/A"
		cidAStr := "cid=N/A"
		uidBStr := "uid=N/A"
		cidBStr := "cid=N/A"
		if errA == nil {
			uidAStr = fmt.Sprintf("uid=%d", mA.UID)
			cidAStr = fmt.Sprintf("cid=%d", mA.CID)
		}
		if errB == nil {
			uidBStr = fmt.Sprintf("uid=%d", mB.UID)
			cidBStr = fmt.Sprintf("cid=%d", mB.CID)
		}

		evidenceSubtest(t, &evidence, "3_two_real_vms", fmt.Sprintf(
			"vmA=%s %s %s netns=%s channel_established=true\nvmB=%s %s %s netns=%s channel_established=true",
			vmAID, uidAStr, cidAStr, nsA,
			vmBID, uidBStr, cidBStr, nsB,
		))
	})

	// ── Subtest 4: AT-011 — graceful stop A while B lives ─────────────────────
	t.Run("at011_graceful_stop", func(t *testing.T) {
		if vmAID == "" || vmBID == "" {
			t.Skip("skipping: prior subtest did not produce vmAID/vmBID")
		}

		// vmA's life ends in this subtest. Register its disposal before the first
		// assertion so an abort below cannot leave its reservation held for the rest
		// of the run. vmB is deliberately not disposed here.
		t.Cleanup(func() { daemon.disposeVM(t, vmAID) })

		// Stop A gracefully.
		daemon.stopVM(t, vmAID)

		stoppedCtx, stoppedCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stoppedCancel()
		daemon.waitVMState(stoppedCtx, t, vmAID, "stopped")

		// Find the stop operation to check graceful outcome.
		// The stop outcome lives in vm.state_changed event's reason field.
		// Look for a vm.state_changed event for vmA with reason=graceful_stop.
		events := daemon.apiGet(t, "/events?vm_id="+vmAID+"&kind=vm.state_changed")
		evts, _ := events["events"].([]any)
		gracefulFound := false
		for _, e := range evts {
			em, _ := e.(map[string]any)
			data, _ := em["data"].(map[string]any)
			reason, _ := data["reason"].(string)
			to, _ := data["to"].(string)
			if to == "stopped" && reason == "graceful_stop" {
				gracefulFound = true
				break
			}
		}
		if !gracefulFound {
			t.Errorf("AT-011: no vm.state_changed event with reason=graceful_stop found for vmA after stop")
		}

		// Record the stop completion time AFTER waitVMState confirms stopped.
		// Everything after this is "after A's stop."
		aStopTime := time.Now()

		// (a) B must still be running immediately after A's stop completed.
		vmB := daemon.apiGet(t, "/vms/"+vmBID)
		bState, _ := vmB["observed_state"].(string)
		if bState != "running" {
			t.Errorf("AT-011: vmB state = %q, want running after vmA stop", bState)
		}

		// (b) Assert B's vm.state_changed stream has no departure-from-running event
		// with host_received_at after aStopTime. A departure event would mean B was
		// interrupted by A's stop — which the product must prevent.
		// Deviation: the brief asked for "ping-driven events after A's stop time" but
		// no runner ping event kind exists in the registry (verified). State-change
		// absence is the product's actual record of interruptions. (Filed: I2 deviation.)
		bStateChanges := daemon.apiGet(t, "/events?vm_id="+vmBID+"&kind=vm.state_changed")
		bEvts, _ := bStateChanges["events"].([]any)
		for _, e := range bEvts {
			em, _ := e.(map[string]any)
			data, _ := em["data"].(map[string]any)
			from, _ := data["from"].(string)
			hostRecvStr, _ := em["host_received_at"].(string)
			if from != "running" {
				continue
			}
			if hostRecvStr == "" {
				continue
			}
			evtTime, err := time.Parse(time.RFC3339Nano, hostRecvStr)
			if err != nil {
				continue
			}
			if evtTime.After(aStopTime) {
				t.Errorf("AT-011: vmB left running state at %s (after aStopTime %s) — B was interrupted by A's stop",
					hostRecvStr, aStopTime.UTC().Format(time.RFC3339Nano))
			}
		}

		// Delete A.
		daemon.deleteVM(t, vmAID)

		// Verify B is still running after A is fully deleted.
		vmBAfter := daemon.apiGet(t, "/vms/"+vmBID)
		bStateAfter, _ := vmBAfter["observed_state"].(string)
		if bStateAfter != "running" {
			t.Errorf("AT-011: vmB state = %q after vmA delete, want running", bStateAfter)
		}

		evidenceSubtest(t, &evidence, "4_at011_graceful_stop", fmt.Sprintf(
			"vmA stopped graceful_stop=%v; vmB state after vmA stop=%q; vmB state after vmA delete=%q; aStopTime=%s; vmB no state departure after stop=verified",
			gracefulFound, bState, bStateAfter, aStopTime.UTC().Format(time.RFC3339),
		))
	})

	// ── Subtest 5: AT-006 — idempotent replay + conflict ──────────────────────
	t.Run("at006_idempotency", func(t *testing.T) {
		daemon.disposeSubtestVMs(t)
		iKey := fmt.Sprintf("m1a-gate-at006-%d", os.Getpid())
		status1, body1 := daemon.apiPost(t, "/vms", map[string]any{
			"name":               "idem-test",
			"template_id":        "standard",
			"vcpu_count":         1,
			"memory_mib":         512,
			"root_disk_mib":      gateRootDiskMiB,
			"workspace_disk_mib": gateWorkspaceDiskMiB,
			"idempotency_key":    iKey,
		})
		if status1 != http.StatusCreated {
			t.Fatalf("AT-006 first create: expected 201, got %d: %v", status1, body1)
		}
		vm1, _ := body1["vm"].(map[string]any)
		id1, _ := vm1["vm_id"].(string)
		daemon.trackVMID(id1)
		_, isReplay1 := body1["is_replay"]

		// Same idempotency key → replay (same VM, is_replay: true).
		status2, body2 := daemon.apiPost(t, "/vms", map[string]any{
			"name":               "idem-test",
			"template_id":        "standard",
			"vcpu_count":         1,
			"memory_mib":         512,
			"root_disk_mib":      gateRootDiskMiB,
			"workspace_disk_mib": gateWorkspaceDiskMiB,
			"idempotency_key":    iKey,
		})
		if status2 != http.StatusCreated {
			t.Errorf("AT-006 replay: expected 201, got %d: %v", status2, body2)
		}
		vm2, _ := body2["vm"].(map[string]any)
		id2, _ := vm2["vm_id"].(string)
		isReplay2, _ := body2["is_replay"].(bool)
		if id1 != id2 {
			t.Errorf("AT-006: replay returned different vm_id: %q vs %q", id1, id2)
		}
		if !isReplay2 {
			t.Errorf("AT-006: replay response missing is_replay:true")
		}

		// Same key, different payload → conflict.
		status3, body3 := daemon.apiPost(t, "/vms", map[string]any{
			"name":               "idem-test-DIFFERENT",
			"template_id":        "standard",
			"vcpu_count":         2,
			"memory_mib":         512,
			"root_disk_mib":      gateRootDiskMiB,
			"workspace_disk_mib": gateWorkspaceDiskMiB,
			"idempotency_key":    iKey,
		})
		if status3 != http.StatusConflict {
			t.Errorf("AT-006 conflict: expected 409, got %d: %v", status3, body3)
		}
		cause3, _ := body3["cause"].(string)
		if cause3 != "idempotency_key_reused" {
			t.Errorf("AT-006 conflict: cause = %q, want idempotency_key_reused", cause3)
		}

		// Clean up the idempotency test VM.
		_, _ = daemon.apiDelete(t, "/vms/"+id1)

		evidenceSubtest(t, &evidence, "5_at006_idempotency", fmt.Sprintf(
			"first_create=%d vm_id=%s is_replay1=%v replay=%d vm_id=%s is_replay=%v conflict=%d cause=%q",
			status1, id1, isReplay1, status2, id2, isReplay2, status3, cause3,
		))
	})

	// ── Subtest 6: AT-009 — four VMs with established channels ────────────────
	t.Run("at009_four_concurrent_vms", func(t *testing.T) {
		// Creation IS the simultaneous launch AT-009 requires: POST /vms is the
		// create/start request (SPEC §14) and drives the VM all the way to running,
		// so four concurrent creates are four concurrent launches. One goroutine
		// issues each. t.Fatalf/t.FailNow must never run off the test goroutine (Go
		// forbids FailNow there), so createVMErr reports failure through its return
		// value instead of failing t directly. Once the WaitGroup completes, the
		// test goroutine reports every failed create by name and fails once.
		daemon.disposeSubtestVMs(t)
		var vmIDs [4]string
		createErrs := make([]error, len(vmIDs))
		var createWG sync.WaitGroup
		for i := range vmIDs {
			createWG.Add(1)
			go func(i int) {
				defer createWG.Done()
				vmIDs[i], createErrs[i] = daemon.createVMErr(fmt.Sprintf("at009-%d", i))
			}(i)
		}
		createWG.Wait()
		createFailed := false
		for i, err := range createErrs {
			if err != nil {
				createFailed = true
				t.Errorf("AT-009: simultaneous create of at009-%d failed: %v", i, err)
			}
		}
		if createFailed {
			t.FailNow()
		}
		// Wait for all four to reach running.
		runCtx, runCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer runCancel()
		for _, id := range vmIDs {
			daemon.waitVMState(runCtx, t, id, "running")
		}
		// Wait for all four to have guest.channel_established.
		chanCtx, chanCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer chanCancel()
		for _, id := range vmIDs {
			_ = daemon.waitEventKind(chanCtx, t, id, "guest.channel_established")
		}

		// AT-009 simultaneity assertion: re-read all four states in one pass and
		// require all are running at this point, before any stop begins.
		for _, id := range vmIDs {
			vm := daemon.apiGet(t, "/vms/"+id)
			state, _ := vm["observed_state"].(string)
			if state != "running" {
				t.Errorf("AT-009: vm %s state = %q, want running (simultaneity check)", id, state)
			}
		}

		// Stop and delete all four.
		for _, id := range vmIDs {
			daemon.stopVM(t, id)
		}
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer stopCancel()
		for _, id := range vmIDs {
			daemon.waitVMState(stopCtx, t, id, "stopped")
		}
		for _, id := range vmIDs {
			daemon.deleteVM(t, id)
		}

		evidenceSubtest(t, &evidence, "6_at009_four_concurrent_vms", fmt.Sprintf(
			"four VMs %v: created concurrently (four simultaneous POST /vms launches); "+
				"all reached running with channel_established; all stopped and deleted",
			vmIDs,
		))
	})

	// ── Subtest 7: AT-018 — resource leak check ────────────────────────────────
	t.Run("at018_no_resource_leaks", func(t *testing.T) {
		daemon.disposeSubtestVMs(t)
		baseline := captureBaseline(t, daemon.stateDir, daemon.runtimeDir)

		for cycle := 0; cycle < 5; cycle++ {
			id := daemon.createVM(t, fmt.Sprintf("at018-cycle-%d", cycle))

			runCtx, runCancel := context.WithTimeout(context.Background(), 3*time.Minute)
			daemon.waitVMState(runCtx, t, id, "running")
			runCancel()

			daemon.stopVM(t, id)
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			daemon.waitVMState(stopCtx, t, id, "stopped")
			stopCancel()

			daemon.deleteVM(t, id)

			// Poll until state dir entry count drops back to baseline.StateDirEntries,
			// confirming the VM's state dir was cleaned up before the next cycle begins.
			// Deadline: 30s per cycle (well within aibox03's expected teardown time).
			cyclePollDeadline := time.Now().Add(30 * time.Second)
			for stateDirEntries(t, daemon.stateDir) != baseline.StateDirEntries {
				if time.Now().After(cyclePollDeadline) {
					t.Fatalf("AT-018 cycle %d: state dir did not return to baseline within 30s", cycle)
				}
				time.Sleep(200 * time.Millisecond)
			}
		}

		// One force-delete cycle. The five cycles above all take the graceful path,
		// which is why this subtest stayed green next to the 1.7 GB jail chroot that
		// live gate run 4 leaked: only DELETE ?force=true drives ForceStop, where the
		// release raced the SIGKILL. Skip the stop entirely so the VM is killed while
		// running, exactly as run 4 did.
		{
			id := daemon.createVM(t, "at018-force-delete")

			runCtx, runCancel := context.WithTimeout(context.Background(), 3*time.Minute)
			daemon.waitVMState(runCtx, t, id, "running")
			runCancel()

			status, body := daemon.apiDelete(t, "/vms/"+id+"?force=true")
			if status != http.StatusOK {
				t.Fatalf("AT-018 force-delete: expected 200, got %d: %v", status, body)
			}

			delCtx, delCancel := context.WithTimeout(context.Background(), 2*time.Minute)
			daemon.waitVMState(delCtx, t, id, "deleted")
			delCancel()

			cyclePollDeadline := time.Now().Add(30 * time.Second)
			for stateDirEntries(t, daemon.stateDir) != baseline.StateDirEntries {
				if time.Now().After(cyclePollDeadline) {
					t.Fatalf("AT-018 force-delete cycle: state dir did not return to baseline within 30s")
				}
				time.Sleep(200 * time.Millisecond)
			}
		}

		// Poll all six observables until they match baseline or a 60s deadline expires.
		// Hard-assert equality after — timeout is a failure, not a pass.
		recaptureDeadline := time.Now().Add(60 * time.Second)
		var after m1aBaseline
		for {
			after = captureBaseline(t, daemon.stateDir, daemon.runtimeDir)
			if after == baseline {
				break
			}
			if time.Now().After(recaptureDeadline) {
				// Let the assertions below produce the specific failure message.
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		if after.NetnsCount != baseline.NetnsCount {
			t.Errorf("AT-018: netns count: baseline=%d after=%d (leaked %d)",
				baseline.NetnsCount, after.NetnsCount, after.NetnsCount-baseline.NetnsCount)
		}
		if after.VethCount != baseline.VethCount {
			t.Errorf("AT-018: veth count: baseline=%d after=%d (leaked %d)",
				baseline.VethCount, after.VethCount, after.VethCount-baseline.VethCount)
		}
		if after.JailEntries != baseline.JailEntries {
			t.Errorf("AT-018: jail dir entries: baseline=%d after=%d (leaked %d)",
				baseline.JailEntries, after.JailEntries, after.JailEntries-baseline.JailEntries)
		}
		if after.FcProcCount != baseline.FcProcCount {
			t.Errorf("AT-018: firecracker process count: baseline=%d after=%d (leaked %d)",
				baseline.FcProcCount, after.FcProcCount, after.FcProcCount-baseline.FcProcCount)
		}
		if after.StateDirEntries != baseline.StateDirEntries {
			t.Errorf("AT-018: state dir entries: baseline=%d after=%d (leaked %d)",
				baseline.StateDirEntries, after.StateDirEntries, after.StateDirEntries-baseline.StateDirEntries)
		}
		if after.StageDirEntries != baseline.StageDirEntries {
			t.Errorf("AT-018: stage dir entries: baseline=%d after=%d (leaked %d)",
				baseline.StageDirEntries, after.StageDirEntries, after.StageDirEntries-baseline.StageDirEntries)
		}

		evidenceSubtest(t, &evidence, "7_at018_resource_leaks", fmt.Sprintf(
			"baseline: netns=%d veth=%d jail=%d fc_procs=%d state_entries=%d stage_entries=%d\n"+
				"after 5 graceful cycles + 1 force-delete: netns=%d veth=%d jail=%d fc_procs=%d state_entries=%d stage_entries=%d\n"+
				"delta: netns=%+d veth=%+d jail=%+d fc_procs=%+d state=%+d stage=%+d",
			baseline.NetnsCount, baseline.VethCount, baseline.JailEntries,
			baseline.FcProcCount, baseline.StateDirEntries, baseline.StageDirEntries,
			after.NetnsCount, after.VethCount, after.JailEntries,
			after.FcProcCount, after.StateDirEntries, after.StageDirEntries,
			after.NetnsCount-baseline.NetnsCount,
			after.VethCount-baseline.VethCount,
			after.JailEntries-baseline.JailEntries,
			after.FcProcCount-baseline.FcProcCount,
			after.StateDirEntries-baseline.StateDirEntries,
			after.StageDirEntries-baseline.StageDirEntries,
		))
	})

	// ── Subtest 8: AT-007 — running not before channel_established ────────────
	// For one VM: its running-transition timestamp must NOT be earlier than its
	// guest.channel_established event timestamp. Both from the API.
	t.Run("at007_ordering", func(t *testing.T) {
		daemon.disposeSubtestVMs(t)
		vmID := daemon.createVM(t, "at007-order")

		runCtx, runCancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer runCancel()
		daemon.waitVMState(runCtx, t, vmID, "running")

		chanCtx, chanCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer chanCancel()
		chanEvt := daemon.waitEventKind(chanCtx, t, vmID, "guest.channel_established")

		// Get the running-transition timestamp from vm.state_changed events.
		// The Envelope serializes host_received_at (not "occurred_at" — that field
		// does not exist). Both timestamps use the Timestamp format: RFC3339 with
		// microsecond precision (parseable by time.RFC3339Nano).
		stateEvents := daemon.apiGet(t, "/events?vm_id="+vmID+"&kind=vm.state_changed")
		evts, _ := stateEvents["events"].([]any)
		var runningAt string
		for _, e := range evts {
			em, _ := e.(map[string]any)
			data, _ := em["data"].(map[string]any)
			to, _ := data["to"].(string)
			if to == "running" {
				runningAt, _ = em["host_received_at"].(string)
				break
			}
		}

		var chanAt string
		if chanEvt != nil {
			chanAt, _ = chanEvt["host_received_at"].(string)
		}

		// Missing timestamps are test failures — a vacuous guard would hide real
		// product bugs. Both fields must be present and parseable.
		if runningAt == "" {
			t.Fatalf("AT-007: no vm.state_changed event with to=running found (or host_received_at missing)")
		}
		if chanAt == "" {
			t.Fatalf("AT-007: no guest.channel_established event found (or host_received_at missing)")
		}

		// Parse both and assert running >= channel_established.
		tRunning, errR := time.Parse(time.RFC3339Nano, runningAt)
		tChan, errC := time.Parse(time.RFC3339Nano, chanAt)
		if errR != nil {
			t.Fatalf("AT-007: parse running host_received_at %q: %v", runningAt, errR)
		}
		if errC != nil {
			t.Fatalf("AT-007: parse channel_established host_received_at %q: %v", chanAt, errC)
		}
		runningNotBeforeChannel := !tRunning.Before(tChan)
		if !runningNotBeforeChannel {
			t.Errorf("AT-007 VIOLATION: running transition (%s) is EARLIER than channel_established (%s)",
				runningAt, chanAt)
		}

		// Deviation note: seeding/baseline comparison is M4 scope.
		// AT-007 here only tests the host-observed running timestamp vs channel event.

		// Clean up.
		daemon.stopVM(t, vmID)
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stopCancel()
		daemon.waitVMState(stopCtx, t, vmID, "stopped")
		daemon.deleteVM(t, vmID)

		// Stop vmB from subtest 3 (if still alive).
		if vmBID != "" {
			bVM := daemon.apiGet(t, "/vms/"+vmBID)
			bState, _ := bVM["observed_state"].(string)
			switch bState {
			case "running":
				daemon.stopVM(t, vmBID)
				sc, sc2 := context.WithTimeout(context.Background(), 2*time.Minute)
				defer sc2()
				daemon.waitVMState(sc, t, vmBID, "stopped")
				daemon.deleteVM(t, vmBID)
			case "stopped":
				daemon.deleteVM(t, vmBID)
			}
		}

		evidenceSubtest(t, &evidence, "8_at007_ordering", fmt.Sprintf(
			"vm=%s running_transition_at=%q channel_established_at=%q running_not_before_channel=%v",
			vmID, runningAt, chanAt, runningNotBeforeChannel,
		))
	})

	// Write evidence file (only when the gate actually ran).
	evidencePath := filepath.Join(repoRoot, evidenceDir, fmt.Sprintf("m1a-gate-%s.txt", hostname))
	if err := os.MkdirAll(filepath.Join(repoRoot, evidenceDir), 0755); err != nil {
		t.Logf("write evidence: mkdir: %v", err)
	} else if err := os.WriteFile(evidencePath, []byte(evidence.String()), 0644); err != nil {
		t.Logf("write evidence: %v", err)
	} else {
		t.Logf("evidence written to %s", evidencePath)
	}
}

// ---------------------------------------------------------------------------
// Helpers shared by multiple subtests.
// ---------------------------------------------------------------------------

// buildBinary builds the named Go package and returns the path to the binary.
// Shared: build happens once per test run via the TestMain pattern would be ideal,
// but since integration_test is a package with TestMain already (or would conflict),
// we build lazily and cache in the test's temp dir. For Phase A the binaries are
// rebuilt per-test-binary invocation, which is fine since the gate test runs once.
func buildBinary(t *testing.T, pkg string) string {
	t.Helper()
	tmp, err := os.MkdirTemp("", "m1a-gate-build-*")
	if err != nil {
		t.Fatalf("buildBinary %s: mkdirtemp: %v", pkg, err)
	}
	// Extract the binary name from the package path.
	parts := strings.Split(pkg, "/")
	binName := parts[len(parts)-1]
	binPath := filepath.Join(tmp, binName)

	cmd := exec.Command("go", "build", "-o", binPath, pkg)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("buildBinary %s: %v", pkg, err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	return binPath
}

// readM1aManifest reads the jailer manifest for a VM from the gate's stateDir.
// Duplicates the manifest struct here to avoid importing internal/jailer from tests.
type m1aManifest struct {
	VMID   string `json:"vm_id"`
	BootID string `json:"boot_id"`
	Slot   int    `json:"slot"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	CID    uint32 `json:"cid"`
	CIDR   string `json:"cidr"`
}

func readM1aManifest(stateDir, vmID string) (m1aManifest, error) {
	path := filepath.Join(stateDir, "vms", vmID, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return m1aManifest{}, err
	}
	var m m1aManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return m1aManifest{}, fmt.Errorf("unmarshal manifest: %w", err)
	}
	return m, nil
}

// assertNoToken asserts that no 64-char lowercase hex string appears in body.
// This guards §15.3: the vsock auth token must never appear in responses.
func assertNoToken(t *testing.T, body []byte) {
	t.Helper()
	s := string(body)
	// Walk through candidates: any 64 consecutive chars in [0-9a-f].
	for i := 0; i+64 <= len(s); i++ {
		candidate := s[i : i+64]
		isHex := true
		for _, c := range candidate {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				isHex = false
				break
			}
		}
		if isHex {
			t.Errorf("§15.3 violation: 64-char hex token found in response body at offset %d: %q", i, candidate)
			return
		}
	}
}
