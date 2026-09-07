// ABOUTME: Lifecycle mutations have host side effects, so they must outlive the
// ABOUTME: HTTP client that asked for them. These tests hang up mid-mutation.
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory/internal/runtime/runtimetest"
	"github.com/2389-research/observatory/internal/store"
)

// mutationCtxServer builds the template server with middleware that publishes
// the request context of every lifecycle mutation. A test waits on that context
// to know the server has observed the client's disconnect, instead of sleeping
// and hoping.
func mutationCtxServer(t *testing.T) (*httptest.Server, *store.Store, *runtimetest.Fake, <-chan context.Context) {
	t.Helper()
	ctxCh := make(chan context.Context, 4)
	srv, st, fake := newTemplateServerWrapped(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isAction := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/actions")
			isDelete := r.Method == http.MethodDelete
			if isAction || isDelete {
				select {
				case ctxCh <- r.Context():
				default:
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	return srv, st, fake, ctxCh
}

// vmRevision reads the VM's current revision string for an action's pin.
func vmRevision(t *testing.T, srvURL, vmID string) string {
	t.Helper()
	var vmResp map[string]any
	getJSON(t, srvURL+"/api/v1/vms/"+vmID, http.StatusOK, &vmResp)
	rev, _ := vmResp["revision"].(string)
	if rev == "" {
		t.Fatalf("VM %s has no revision in %v", vmID, vmResp)
	}
	return rev
}

// waitCall blocks until the fake has recorded method for vmID, so a test knows
// the runtime call is genuinely in flight before it hangs up.
func waitCall(t *testing.T, fake *runtimetest.Fake, method, vmID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, c := range fake.CallsFor(vmID) {
			if c.Method == method {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime %s(%s) never started; calls: %v", method, vmID, fake.CallsFor(vmID))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitVMState polls the store until the VM reaches want.
func waitVMState(t *testing.T, st *store.Store, vmID, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	last := ""
	for {
		vm, err := st.GetVM(context.Background(), vmID)
		if err == nil {
			last = vm.ObservedState
			if last == want {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("VM %s stuck in %q, want %q: the mutation died with its client", vmID, last, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitOpTerminal polls until no operation for vmID is still pending or running,
// then returns the states of that VM's operations by phase.
func waitOpTerminal(t *testing.T, st *store.Store, vmID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		stuck := ""
		for _, state := range []string{"pending", "running"} {
			ops, err := st.ListOperationsByState(context.Background(), state)
			if err != nil {
				t.Fatalf("list %s operations: %v", state, err)
			}
			for _, op := range ops {
				if op.VMID != nil && *op.VMID == vmID {
					stuck = op.Phase + "=" + op.State
				}
			}
		}
		if stuck == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("VM %s left operation %s: the operation died with its client", vmID, stuck)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// hangUpDuring issues req on its own connection, waits for the server to enter
// the runtime call, cancels the client, and waits for the server to observe the
// disconnect. It returns once the request context is dead.
func hangUpDuring(t *testing.T, req *http.Request, cancelClient context.CancelFunc, fake *runtimetest.Fake, method, vmID string, ctxCh <-chan context.Context) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()

	var reqCtx context.Context
	select {
	case reqCtx = <-ctxCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("handler never ran for %s(%s)", method, vmID)
	}

	waitCall(t, fake, method, vmID)
	cancelClient()
	<-done

	select {
	case <-reqCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("server never observed the client disconnect")
	}
}

// TestStopSurvivesClientDisconnect: a client that hangs up mid-stop must not
// abort the stop. The host work is already underway — signals sent, chroot to
// release — so cancelling it strands a live VM behind a row that says stopping.
func TestStopSurvivesClientDisconnect(t *testing.T) {
	srv, st, fake, ctxCh := mutationCtxServer(t)
	vmID := createRunningVM(t, srv.URL, fake)

	release := fake.Block("Stop", vmID)
	body, _ := json.Marshal(map[string]any{"action": "stop", "expected_revision": vmRevision(t, srv.URL, vmID)})
	clientCtx, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	req, err := http.NewRequestWithContext(clientCtx, http.MethodPost, srv.URL+"/api/v1/vms/"+vmID+"/actions", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build action request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	hangUpDuring(t, req, cancelClient, fake, "Stop", vmID, ctxCh)

	// The client is gone; the runtime is still working. Let it finish.
	close(release)

	waitVMState(t, st, vmID, "stopped")
	waitOpTerminal(t, st, vmID)
}

// TestForceDeleteSurvivesClientDisconnect: same rule on the delete path, where
// abandoning halfway leaks the jail and the reservation with it.
func TestForceDeleteSurvivesClientDisconnect(t *testing.T) {
	srv, st, fake, ctxCh := mutationCtxServer(t)
	vmID := createRunningVM(t, srv.URL, fake)

	release := fake.Block("ForceStop", vmID)
	clientCtx, cancelClient := context.WithCancel(context.Background())
	defer cancelClient()
	req, err := http.NewRequestWithContext(clientCtx, http.MethodDelete, srv.URL+"/api/v1/vms/"+vmID+"?force=true", nil)
	if err != nil {
		t.Fatalf("build delete request: %v", err)
	}

	hangUpDuring(t, req, cancelClient, fake, "ForceStop", vmID, ctxCh)

	close(release)

	waitVMState(t, st, vmID, "deleted")
	waitOpTerminal(t, st, vmID)
}
