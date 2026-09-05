// ABOUTME: Terminal session route tests: create, list, close and lease, with a
// ABOUTME: real runner control socket behind the registry (SPEC §8.2, §14).
package api_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/api"
	"github.com/2389-research/observatory-v2/internal/events"
	"github.com/2389-research/observatory-v2/internal/guest/proto"
	"github.com/2389-research/observatory-v2/internal/runner"
	"github.com/2389-research/observatory-v2/internal/runtime/runtimetest"
	"github.com/2389-research/observatory-v2/internal/store"
	"github.com/2389-research/observatory-v2/internal/terminal"
)

const testBootID = "3f2a1c4e-0000-4000-8000-00000000beef"

// fakeRunner is a real runner control socket with a fake PTY behind it: the
// registry dials it, speaks the real ctl JSON, and gets real replies. Only the
// guest is stand-in, which is the seam this package does not own.
type fakeRunner struct {
	sockPath string
	bootID   string

	// createErr, when set, is what terminal-create answers instead of a PTY.
	createErr error

	created []runner.TerminalCtlRequest
	closed  []string
	open    map[string]bool

	// resumeOffset and gap are what an attach reports back; a test that cares
	// about replay sets them before dialling.
	resumeOffset string
	gap          bool
	// attached carries the guest end of each attach's pipe to the test.
	attached chan net.Conn
}

func newFakeRunner(t *testing.T) *fakeRunner {
	t.Helper()
	// Not t.TempDir(): a unix socket path is capped at 104 bytes on darwin and
	// t.TempDir() embeds the test's name, so a long name fails the bind rather
	// than the assertion.
	dir, err := os.MkdirTemp("", "at")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	f := &fakeRunner{
		sockPath:     filepath.Join(dir, "runner.sock"),
		bootID:       testBootID,
		open:         map[string]bool{},
		resumeOffset: "0",
		attached:     make(chan net.Conn, 8),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv, listenErr := runner.ListenCtl(ctx, f.sockPath, runner.CtlHandlers{
		TerminalCreate: func(_ context.Context, req runner.TerminalCtlRequest) (runner.TerminalCtlReply, error) {
			if f.createErr != nil {
				return runner.TerminalCtlReply{}, f.createErr
			}
			f.created = append(f.created, req)
			f.open[req.SessionID] = true
			return runner.TerminalCtlReply{
				SessionID: req.SessionID,
				PID:       4242,
				StartedAt: "2026-09-04T12:00:00.000000Z",
				BootID:    f.bootID,
			}, nil
		},
		TerminalClose: func(_ context.Context, req runner.TerminalCtlRequest) (runner.TerminalCtlReply, error) {
			f.closed = append(f.closed, req.SessionID)
			delete(f.open, req.SessionID)
			return runner.TerminalCtlReply{SessionID: req.SessionID, Reason: "closed_by_host"}, nil
		},
		TerminalList: func(context.Context) (runner.TerminalCtlReply, error) {
			out := []proto.TerminalSession{}
			for id := range f.open {
				out = append(out, proto.TerminalSession{SessionID: id, PID: 4242, Rows: 24, Cols: 80,
					HeadOffset: "0", TailOffset: "0"})
			}
			return runner.TerminalCtlReply{Sessions: out}, nil
		},
		TerminalAttach: func(_ context.Context, req runner.TerminalCtlRequest) (*runner.Relay, runner.TerminalCtlReply, error) {
			hostSide, guestSide := net.Pipe()
			f.attached <- guestSide
			return runner.NewRelay(hostSide, 0), runner.TerminalCtlReply{
				SessionID:    req.SessionID,
				ResumeOffset: f.resumeOffset,
				Gap:          f.gap,
				BootID:       f.bootID,
			}, nil
		},
	})
	if listenErr != nil {
		t.Fatalf("listen ctl: %v", listenErr)
	}
	t.Cleanup(srv.Close)
	return f
}

// nextAttach returns the guest end of the connection the last attach opened.
func (f *fakeRunner) nextAttach(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-f.attached:
		t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no attach reached the guest")
		return nil
	}
}

// newTerminalServer is the shared VM harness with a terminal registry wired to
// a fake runner. Every VM in the test dials the same socket, which is what a
// single-VM test wants and what a two-VM test tolerates: the sessions are still
// separated by the vm_id the registry records.
func newTerminalServer(t *testing.T) (*httptest.Server, *store.Store, *runtimetest.Fake, *fakeRunner, *terminal.Registry) {
	t.Helper()
	fr := newFakeRunner(t)
	reg := terminal.NewRegistry(terminal.Options{
		MaxReplayBytesPerSession: 256 << 10,
		MaxInflightBrowserBytes:  1 << 20,
		WriterLease:              30 * time.Second,
		Dial: func(ctx context.Context, vmID string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", fr.sockPath)
		},
	})
	srv, st, fake := newTemplateServerFull(t, nil, testAdmission(), reg, "")
	return srv, st, fake, fr, reg
}

// launchVM creates a VM through the API and waits for it to reach running.
func launchVM(t *testing.T, srvURL, name string) string {
	t.Helper()
	var got map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms",
		map[string]any{"name": name, "template_id": testTemplateDef.TemplateID},
		http.StatusCreated, &got)
	vm, _ := got["vm"].(map[string]any)
	op, _ := got["operation"].(map[string]any)
	vmID, _ := vm["vm_id"].(string)
	opID, _ := op["operation_id"].(string)
	if state := pollOpState(t, srvURL, opID, "succeeded"); state != "succeeded" {
		t.Fatalf("launch %s reached %q, want succeeded", name, state)
	}
	return vmID
}

// createTerminal opens a session on vmID and returns the decoded 201 body.
func createTerminal(t *testing.T, srvURL, vmID string, body any) map[string]any {
	t.Helper()
	var got map[string]any
	doRequest(t, http.MethodPost, srvURL+"/api/v1/vms/"+vmID+"/terminals", body,
		http.StatusCreated, &got)
	return got
}

// terminalError sends a request expected to fail and returns the typed error.
func terminalError(t *testing.T, method, url string, body any, wantStatus int) api.Error {
	t.Helper()
	var e api.Error
	doRequest(t, method, url, body, wantStatus, &e)
	return e
}

func TestCreateTerminalBindsTheSessionToTheVMsBoot(t *testing.T) {
	srv, _, _, fr, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-create")

	got := createTerminal(t, srv.URL, vmID, map[string]any{"rows": 40, "cols": 100})

	if got["session_id"] == "" || got["session_id"] == nil {
		t.Fatal("create response has no session_id")
	}
	if got["vm_id"] != vmID {
		t.Errorf("vm_id = %v, want %s", got["vm_id"], vmID)
	}
	// The boot id is what the runner reported, not something the host invented.
	if got["boot_id"] != testBootID {
		t.Errorf("boot_id = %v, want %s", got["boot_id"], testBootID)
	}
	if got["rows"] != float64(40) || got["cols"] != float64(100) {
		t.Errorf("rows/cols = %v/%v, want 40/100", got["rows"], got["cols"])
	}
	if got["created_at"] == "" || got["created_at"] == nil {
		t.Error("created_at missing")
	}
	if got["writer_available"] != true {
		t.Errorf("writer_available = %v, want true on a fresh session", got["writer_available"])
	}
	links, _ := got["links"].(map[string]any)
	if links["stream"] == nil || links["vm"] == nil {
		t.Errorf("links = %v, want stream and vm", links)
	}

	if len(fr.created) != 1 {
		t.Fatalf("runner saw %d creates, want 1", len(fr.created))
	}
	if fr.created[0].Rows != 40 || fr.created[0].Cols != 100 {
		t.Errorf("runner got rows/cols %d/%d, want 40/100", fr.created[0].Rows, fr.created[0].Cols)
	}
	if fr.created[0].RingBytes != 256<<10 {
		t.Errorf("runner got ring_bytes %d, want the configured replay bound", fr.created[0].RingBytes)
	}
}

func TestCreateTerminalDefaultsWindowSize(t *testing.T) {
	srv, _, _, fr, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-default")

	got := createTerminal(t, srv.URL, vmID, map[string]any{})

	if got["rows"] != float64(24) || got["cols"] != float64(80) {
		t.Errorf("rows/cols = %v/%v, want the documented 24/80", got["rows"], got["cols"])
	}
	if fr.created[0].Term != "xterm-256color" {
		t.Errorf("term = %q, want xterm-256color", fr.created[0].Term)
	}
}

func TestCreateTerminalOnAStoppedVMNamesTheState(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-stopped")

	// Stop it, then ask for a terminal.
	var vmGot map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID, http.StatusOK, &vmGot)
	rev, _ := vmGot["revision"].(string)
	doRequest(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions",
		map[string]any{"action": "stop", "expected_revision": rev}, http.StatusOK, nil)

	e := terminalError(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/terminals",
		map[string]any{}, http.StatusConflict)
	requireTeaching(t, e, "vm_not_running")
	state, _ := e.Details["observed_state"].(string)
	if state != "stopped" {
		t.Errorf("details.observed_state = %v, want stopped (details: %v)", e.Details["observed_state"], e.Details)
	}
	if !strings.Contains(e.Message, "stopped") {
		t.Errorf("message must name the actual state: %q", e.Message)
	}
}

func TestCreateTerminalPastTheCapNamesCapAndCount(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-cap")

	// testVMDefaults caps this host at 2 concurrent sessions per VM.
	createTerminal(t, srv.URL, vmID, map[string]any{})
	createTerminal(t, srv.URL, vmID, map[string]any{})

	e := terminalError(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/terminals",
		map[string]any{}, http.StatusConflict)
	requireTeaching(t, e, "terminal_limit_reached")
	if got, _ := e.Details["max_terminal_sessions"].(float64); got != 2 {
		t.Errorf("details.max_terminal_sessions = %v, want 2", e.Details["max_terminal_sessions"])
	}
	if got, _ := e.Details["open_sessions"].(float64); got != 2 {
		t.Errorf("details.open_sessions = %v, want 2", e.Details["open_sessions"])
	}

	// A closed session frees a slot: the cap counts open sessions, not history.
	var list map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID+"/terminals", http.StatusOK, &list)
	terms, _ := list["terminals"].([]any)
	first, _ := terms[0].(map[string]any)
	firstID, _ := first["session_id"].(string)
	doRequest(t, http.MethodDelete, srv.URL+"/api/v1/terminals/"+firstID, nil, http.StatusNoContent, nil)
	createTerminal(t, srv.URL, vmID, map[string]any{})
}

func TestCreateTerminalRunnerUnreachableTeaches(t *testing.T) {
	srv, _, _, fr, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-unreachable")
	fr.createErr = fmt.Errorf("no pty available")

	e := terminalError(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/terminals",
		map[string]any{}, http.StatusServiceUnavailable)
	requireTeaching(t, e, "terminal_unavailable")
	if !e.Retryable {
		t.Error("a runner that refused one create is worth retrying")
	}
}

func TestCreateTerminalRejectsUnknownFields(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-unknown")

	e := terminalError(t, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/terminals",
		map[string]any{"shell": "/bin/zsh"}, http.StatusBadRequest)
	requireTeaching(t, e, "malformed_request")
}

func TestListTerminalsIsScopedBoundedAndCursorable(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	vmA := launchVM(t, srv.URL, "term-list-a")
	vmB := launchVM(t, srv.URL, "term-list-b")

	first := createTerminal(t, srv.URL, vmA, map[string]any{})
	second := createTerminal(t, srv.URL, vmA, map[string]any{})
	other := createTerminal(t, srv.URL, vmB, map[string]any{})

	var all map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmA+"/terminals", http.StatusOK, &all)
	terms, _ := all["terminals"].([]any)
	if len(terms) != 2 {
		t.Fatalf("vm A listed %d terminals, want 2 (other VM's session must not appear)", len(terms))
	}
	ids := []string{}
	for _, raw := range terms {
		m, _ := raw.(map[string]any)
		id, _ := m["session_id"].(string)
		ids = append(ids, id)
	}
	if ids[0] != first["session_id"] || ids[1] != second["session_id"] {
		t.Errorf("list order = %v, want oldest first (%v, %v)", ids, first["session_id"], second["session_id"])
	}
	for _, raw := range terms {
		m, _ := raw.(map[string]any)
		if m["session_id"] == other["session_id"] {
			t.Error("vm B's session leaked into vm A's list")
		}
		if !isDecimalString(fmt.Sprint(m["output_bytes"])) || !isDecimalString(fmt.Sprint(m["input_bytes"])) {
			t.Errorf("byte counts must be decimal strings: %v / %v", m["output_bytes"], m["input_bytes"])
		}
	}

	// limit=1 bounds the page and next_after continues it.
	var page map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmA+"/terminals?limit=1", http.StatusOK, &page)
	pageTerms, _ := page["terminals"].([]any)
	if len(pageTerms) != 1 {
		t.Fatalf("limit=1 returned %d terminals", len(pageTerms))
	}
	next, _ := page["next_after"].(string)
	if next != first["session_id"] {
		t.Fatalf("next_after = %q, want the first session id", next)
	}
	var page2 map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmA+"/terminals?limit=1&after="+next, http.StatusOK, &page2)
	pageTerms2, _ := page2["terminals"].([]any)
	if len(pageTerms2) != 1 {
		t.Fatalf("second page returned %d terminals", len(pageTerms2))
	}
	got2, _ := pageTerms2[0].(map[string]any)
	if got2["session_id"] != second["session_id"] {
		t.Errorf("second page = %v, want the second session", got2["session_id"])
	}
	if last, _ := page2["next_after"].(string); last != "" {
		t.Errorf("next_after = %q at the end of the list, want empty", last)
	}
}

func TestListTerminalsRefusesAnUnreadableCursor(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-cursor")
	createTerminal(t, srv.URL, vmID, map[string]any{})

	e := terminalError(t, http.MethodGet,
		srv.URL+"/api/v1/vms/"+vmID+"/terminals?after=not-a-session", nil, http.StatusBadRequest)
	requireTeaching(t, e, "malformed_request")

	e = terminalError(t, http.MethodGet,
		srv.URL+"/api/v1/vms/"+vmID+"/terminals?limit=nine", nil, http.StatusBadRequest)
	requireTeaching(t, e, "malformed_request")
}

func TestDeleteTerminalIsIdempotent(t *testing.T) {
	srv, _, _, fr, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-delete")
	got := createTerminal(t, srv.URL, vmID, map[string]any{})
	id, _ := got["session_id"].(string)

	doRequest(t, http.MethodDelete, srv.URL+"/api/v1/terminals/"+id, nil, http.StatusNoContent, nil)
	doRequest(t, http.MethodDelete, srv.URL+"/api/v1/terminals/"+id, nil, http.StatusNoContent, nil)

	// The guest is asked exactly once: a second close of a closed session is
	// the caller's intent already satisfied, not another round trip.
	if len(fr.closed) != 1 {
		t.Errorf("runner saw %d closes, want 1", len(fr.closed))
	}

	var list map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID+"/terminals", http.StatusOK, &list)
	terms, _ := list["terminals"].([]any)
	closed, _ := terms[0].(map[string]any)
	if closed["state"] != "closed" {
		t.Errorf("state after delete = %v, want closed", closed["state"])
	}
	if closed["closed_at"] == nil || closed["closed_at"] == "" {
		t.Error("a closed session must publish closed_at")
	}
	if closed["reason"] != "closed_by_host" {
		t.Errorf("reason = %v, want the runner's reason", closed["reason"])
	}
}

func TestDeleteUnknownTerminalTeaches(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	e := terminalError(t, http.MethodDelete,
		srv.URL+"/api/v1/terminals/no-such-session", nil, http.StatusNotFound)
	requireTeaching(t, e, "not_found")
}

func TestTerminalLeaseRoundTrip(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-lease")
	got := createTerminal(t, srv.URL, vmID, map[string]any{})
	id, _ := got["session_id"].(string)
	url := srv.URL + "/api/v1/terminals/" + id + "/lease"

	var acquired map[string]any
	doRequest(t, http.MethodPost, url,
		map[string]any{"mode": "acquire", "conn_id": "conn-a"}, http.StatusOK, &acquired)
	if acquired["writer"] != true || acquired["holder"] != "conn-a" {
		t.Fatalf("acquire = %v, want writer with holder conn-a", acquired)
	}
	if acquired["reason"] == "" || acquired["reason"] == nil {
		t.Error("a lease answer must say why")
	}

	// A second connection is refused and told who holds it.
	var refused map[string]any
	doRequest(t, http.MethodPost, url,
		map[string]any{"mode": "acquire", "conn_id": "conn-b"}, http.StatusOK, &refused)
	if refused["writer"] != false || refused["holder"] != "conn-a" {
		t.Fatalf("second acquire = %v, want read-only with holder conn-a", refused)
	}

	// Steal takes it immediately.
	var stolen map[string]any
	doRequest(t, http.MethodPost, url,
		map[string]any{"mode": "steal", "conn_id": "conn-b"}, http.StatusOK, &stolen)
	if stolen["writer"] != true || stolen["holder"] != "conn-b" {
		t.Fatalf("steal = %v, want writer with holder conn-b", stolen)
	}

	// The list reflects the holder, so a read-only viewer can name it.
	var list map[string]any
	getJSON(t, srv.URL+"/api/v1/vms/"+vmID+"/terminals", http.StatusOK, &list)
	terms, _ := list["terminals"].([]any)
	m, _ := terms[0].(map[string]any)
	if m["writer_holder"] != "conn-b" {
		t.Errorf("writer_holder = %v, want conn-b", m["writer_holder"])
	}
	if m["writer_available"] != false {
		t.Errorf("writer_available = %v, want false while conn-b holds it", m["writer_available"])
	}

	// Release hands it back after its grace window; the holder is still named.
	var released map[string]any
	doRequest(t, http.MethodPost, url,
		map[string]any{"mode": "release", "conn_id": "conn-b"}, http.StatusOK, &released)
	if released["writer"] != false {
		t.Errorf("release = %v, want writer false", released)
	}
}

func TestTerminalLeaseRefusesBadRequests(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-lease-bad")
	got := createTerminal(t, srv.URL, vmID, map[string]any{})
	id, _ := got["session_id"].(string)
	url := srv.URL + "/api/v1/terminals/" + id + "/lease"

	e := terminalError(t, http.MethodPost, url,
		map[string]any{"mode": "borrow", "conn_id": "conn-a"}, http.StatusBadRequest)
	requireTeaching(t, e, "malformed_request")

	e = terminalError(t, http.MethodPost, url,
		map[string]any{"mode": "acquire"}, http.StatusBadRequest)
	requireTeaching(t, e, "malformed_request")
	if !strings.Contains(e.Message, "conn_id") {
		t.Errorf("message must name the missing field: %q", e.Message)
	}

	e = terminalError(t, http.MethodPost,
		srv.URL+"/api/v1/terminals/no-such-session/lease",
		map[string]any{"mode": "acquire", "conn_id": "conn-a"}, http.StatusNotFound)
	requireTeaching(t, e, "not_found")
}

func TestTerminalLeaseOnAClosedSessionTeaches(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-lease-closed")
	got := createTerminal(t, srv.URL, vmID, map[string]any{})
	id, _ := got["session_id"].(string)
	doRequest(t, http.MethodDelete, srv.URL+"/api/v1/terminals/"+id, nil, http.StatusNoContent, nil)

	e := terminalError(t, http.MethodPost, srv.URL+"/api/v1/terminals/"+id+"/lease",
		map[string]any{"mode": "acquire", "conn_id": "conn-a"}, http.StatusConflict)
	requireTeaching(t, e, "session_closed")
}

// Cross-owner: every terminal route denies a foreign resource the same way the
// VM routes do — the 404 of AT-079, with no side effect on the denied path.
func TestTerminalRoutesDenyCrossOwnerWithNoSideEffect(t *testing.T) {
	srv, st, _, fr, reg := newTerminalServer(t)
	ctx := context.Background()
	foreignVM, _ := seedForeignVM(t, ctx, st)

	e := terminalError(t, http.MethodPost, srv.URL+"/api/v1/vms/"+foreignVM+"/terminals",
		map[string]any{}, http.StatusNotFound)
	requireTeaching(t, e, "not_found")

	e = terminalError(t, http.MethodGet, srv.URL+"/api/v1/vms/"+foreignVM+"/terminals",
		nil, http.StatusNotFound)
	requireTeaching(t, e, "not_found")

	// A session another owner opened: seeded through the registry, which is the
	// trusted ingress for sessions the way the store is for VMs.
	foreign, err := reg.Create(ctx, foreignVM, terminal.Spec{
		Owner: otherOwner, User: "root", Rows: 24, Cols: 80,
	})
	if err != nil {
		t.Fatalf("seed foreign session: %v", err)
	}

	e = terminalError(t, http.MethodDelete, srv.URL+"/api/v1/terminals/"+foreign.ID,
		nil, http.StatusNotFound)
	requireTeaching(t, e, "not_found")

	e = terminalError(t, http.MethodPost, srv.URL+"/api/v1/terminals/"+foreign.ID+"/lease",
		map[string]any{"mode": "steal", "conn_id": "thief"}, http.StatusNotFound)
	requireTeaching(t, e, "not_found")

	// No side effects: the guest was never asked to close it, and no lease moved.
	if len(fr.closed) != 0 {
		t.Errorf("a denied delete closed %v on the guest", fr.closed)
	}
	after, ok := reg.Get(foreign.ID)
	if !ok {
		t.Fatal("the foreign session vanished")
	}
	if after.State != terminal.StateOpen {
		t.Errorf("foreign session state = %q, want open", after.State)
	}
	if after.WriterHolder != "" {
		t.Errorf("a denied lease request took the writer: holder = %q", after.WriterHolder)
	}
}

func TestTerminalLifecycleEventsAreRecorded(t *testing.T) {
	srv, st, _, _, _ := newTerminalServer(t)
	vmID := launchVM(t, srv.URL, "term-events")
	got := createTerminal(t, srv.URL, vmID, map[string]any{"rows": 30, "cols": 90})
	id, _ := got["session_id"].(string)
	doRequest(t, http.MethodDelete, srv.URL+"/api/v1/terminals/"+id, nil, http.StatusNoContent, nil)

	opened := findTerminalEvent(t, st, vmID, "terminal.session_opened")
	if opened.Data["session_id"] != id {
		t.Errorf("session_opened session_id = %v, want %s", opened.Data["session_id"], id)
	}
	if opened.VMID == nil || *opened.VMID != vmID {
		t.Errorf("session_opened vm_id = %v, want %s", opened.VMID, vmID)
	}
	if opened.BootID == nil || *opened.BootID != testBootID {
		t.Errorf("session_opened boot_id = %v, want %s", opened.BootID, testBootID)
	}
	if opened.Data["owner"] != "local_operator" {
		t.Errorf("session_opened owner = %v", opened.Data["owner"])
	}

	closedEv := findTerminalEvent(t, st, vmID, "terminal.session_closed")
	if closedEv.Data["session_id"] != id {
		t.Errorf("session_closed session_id = %v, want %s", closedEv.Data["session_id"], id)
	}
	if closedEv.Data["reason"] != "closed_by_host" {
		t.Errorf("session_closed reason = %v", closedEv.Data["reason"])
	}
	for _, field := range []string{"output_bytes", "input_bytes"} {
		v, ok := closedEv.Data[field].(string)
		if !ok || !isDecimalString(v) {
			t.Errorf("session_closed %s = %v, want a decimal string", field, closedEv.Data[field])
		}
	}
}

// A source stream is bound to exactly one VM (internal/store/append.go), so a
// single API-wide terminal stream can only ever record the first VM's sessions:
// every later VM's lifecycle event is refused and survives as a log line. One
// VM cannot show that, which is why this test opens two.
func TestTerminalLifecycleEventsAreRecordedForEveryVM(t *testing.T) {
	srv, st, _, _, _ := newTerminalServer(t)
	first := launchVM(t, srv.URL, "term-events-1")
	second := launchVM(t, srv.URL, "term-events-2")

	for _, vmID := range []string{first, second} {
		got := createTerminal(t, srv.URL, vmID, map[string]any{"rows": 24, "cols": 80})
		id, _ := got["session_id"].(string)
		doRequest(t, http.MethodDelete, srv.URL+"/api/v1/terminals/"+id, nil, http.StatusNoContent, nil)

		opened := findTerminalEvent(t, st, vmID, "terminal.session_opened")
		if opened.Data["session_id"] != id {
			t.Errorf("vm %s: session_opened session_id = %v, want %s", vmID, opened.Data["session_id"], id)
		}
		closed := findTerminalEvent(t, st, vmID, "terminal.session_closed")
		if closed.Data["session_id"] != id {
			t.Errorf("vm %s: session_closed session_id = %v, want %s", vmID, closed.Data["session_id"], id)
		}
	}
}

// findTerminalEvent reads the event log for one kind scoped to vmID.
func findTerminalEvent(t *testing.T, st *store.Store, vmID, kind string) *events.Envelope {
	t.Helper()
	res, err := st.Query(context.Background(), store.Query{VMID: &vmID, Kind: kind, Limit: 10})
	if err != nil {
		t.Fatalf("query %s: %v", kind, err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("found %d %s events, want 1", len(res.Events), kind)
	}
	return res.Events[0]
}

func TestTerminalRoutesAppearInMetaWhenBuilt(t *testing.T) {
	srv, _, _, _, _ := newTerminalServer(t)
	var m metaResponse
	getJSON(t, srv.URL+"/api/v1/meta", http.StatusOK, &m)
	if !m.Features["terminals"] {
		t.Error("a build serving terminal routes must say so in /meta")
	}
}

func TestTerminalRoutesStayStubbedWithoutARegistry(t *testing.T) {
	srv, _, _ := newTemplateServer(t)
	var m metaResponse
	getJSON(t, srv.URL+"/api/v1/meta", http.StatusOK, &m)
	if m.Features["terminals"] {
		t.Error("a build with no terminal registry must not claim the capability")
	}
	e := terminalError(t, http.MethodPost, srv.URL+"/api/v1/vms/any/terminals",
		map[string]any{}, http.StatusNotImplemented)
	requireTeaching(t, e, "missing_capability")
}
