// ABOUTME: The VM error map branch by branch — every error shape that reaches
// ABOUTME: writeVMError and the typed answer P-06 requires it to produce.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/runtime"
	"github.com/2389-research/observatory-v2/internal/store"
)

// mapVMError runs one error through the map and decodes the answer.
//
// This is the one test in the package that lives inside it. Handlers can reach
// most of these branches but not all — an idempotency conflict and a bare
// context error have no injection point through HTTP — and the whole point of
// the table is that the enumeration is complete.
func mapVMError(t *testing.T, err error) (int, Error) {
	t.Helper()
	rec := httptest.NewRecorder()
	writeVMError(rec, err)
	var e Error
	if decErr := json.NewDecoder(rec.Body).Decode(&e); decErr != nil {
		t.Fatalf("decode error body for %v: %v", err, decErr)
	}
	return rec.Code, e
}

// vmErrorCases enumerates every shape writeVMError recognises, plus the one it
// does not. Adding a branch without adding a row here leaves the new branch
// unproven; adding a row without a branch fails on the fallthrough's cause.
var vmErrorCases = []struct {
	name       string
	err        error
	wantStatus int
	wantCode   string
	wantCause  string
}{
	{"runtime unavailable", &runtime.UnavailableError{Reason: "no kvm"},
		http.StatusNotImplemented, "missing_capability", "runtime_unavailable"},
	{"admission refused", &store.AdmissionRefusal{Cause: "insufficient_memory", Message: "need 2048 MiB, only 512 MiB free"},
		http.StatusConflict, "insufficient_capacity", "admission_refused"},
	{"idempotency conflict", store.ErrIdempotencyConflict,
		http.StatusConflict, "idempotency_conflict", "idempotency_key_reused"},
	{"revision mismatch", &store.RevisionMismatchError{Current: 7},
		http.StatusConflict, "revision_mismatch", "optimistic_concurrency_failure"},
	{"invalid transition", &store.InvalidTransitionError{From: "running", To: "starting"},
		http.StatusConflict, "invalid_transition", "lifecycle_state_machine"},
	{"vm still live", store.ErrVMLive,
		http.StatusConflict, "vm_live", "vm_still_running"},
	{"unknown template", &runtime.ErrTemplateUnknown{Requested: "nope", KnownIDs: []string{"tmpl-test"}},
		http.StatusBadRequest, "template_unknown", "template_not_found"},
	{"invalid request", &runtime.ErrInvalidRequest{Reason: "name is required"},
		http.StatusBadRequest, "malformed_request", "body_invalid"},
	{"unknown action", &runtime.ErrUnknownAction{Known: []string{"start", "stop"}},
		http.StatusBadRequest, "malformed_request", "body_invalid"},
	{"release failed", &runtime.ErrReleaseFailed{VMID: "vm-1", Reason: "privd: invalid_state"},
		http.StatusInternalServerError, "internal", "resource_release_failed"},
	{"runtime verb failed", &runtime.ErrRuntimeOpFailed{VMID: "vm-1", Op: "stop", Err: errors.New("guest ignored the shutdown")},
		http.StatusInternalServerError, "internal", "runtime_operation_failed"},
	{"operation budget expired", context.DeadlineExceeded,
		http.StatusInternalServerError, "internal", "operation_timeout"},
	{"vm unknown", store.ErrVMUnknown,
		http.StatusNotFound, "not_found", "vm_unknown"},
	{"operation unknown", store.ErrOperationUnknown,
		http.StatusNotFound, "not_found", "operation_unknown"},
	{"nothing this layer knows", errors.New("sqlite: disk I/O error"),
		http.StatusInternalServerError, "internal", "unclassified"},
}

func TestWriteVMErrorNamesEveryShapeItKnows(t *testing.T) {
	for _, tc := range vmErrorCases {
		t.Run(tc.name, func(t *testing.T) {
			status, e := mapVMError(t, tc.err)
			if status != tc.wantStatus {
				t.Errorf("status = %d, want %d", status, tc.wantStatus)
			}
			if e.Code != tc.wantCode {
				t.Errorf("code = %q, want %q", e.Code, tc.wantCode)
			}
			if e.Cause != tc.wantCause {
				t.Errorf("cause = %q, want %q", e.Cause, tc.wantCause)
			}
			if e.Message == "" {
				t.Error("P-06: every error carries a message")
			}
			for _, r := range e.Remediation {
				if r.Action == "" || r.Rationale == "" {
					t.Errorf("P-06: remediation must be typed with a rationale: %+v", r)
				}
			}
		})
	}
}

// TestWriteVMErrorNeverBlamesStorage: storage_failure is a claim about which
// subsystem broke. Every branch above the fallthrough knows what went wrong and
// none of them is storage; the fallthrough does not know at all. A map that
// says storage_failure anywhere is guessing, and it sends the operator to the
// database for a fault that is somewhere else — twice already, for real.
func TestWriteVMErrorNeverBlamesStorage(t *testing.T) {
	for _, tc := range vmErrorCases {
		_, e := mapVMError(t, tc.err)
		if e.Cause == "storage_failure" {
			t.Errorf("%s answered storage_failure; the map does not know that", tc.name)
		}
	}
}

// TestWriteVMErrorFallthroughAdmitsItDoesNotKnow: the last branch answers every
// error nothing above matched. It cannot name a subsystem, cannot know whether
// a retry would differ, and must not echo an unclassified error to the caller —
// so it says so, and points at the two records that do know.
func TestWriteVMErrorFallthroughAdmitsItDoesNotKnow(t *testing.T) {
	secret := "sqlite: near \"SELECT\": syntax error"
	status, e := mapVMError(t, errors.New(secret))

	if status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", status)
	}
	if e.Cause != "unclassified" {
		t.Errorf("cause = %q, want unclassified", e.Cause)
	}
	if e.Retryable {
		t.Error("an unclassified fault gives no reason to believe a retry would differ")
	}
	if strings.Contains(e.Message, secret) {
		t.Errorf("message %q echoes an unclassified error back to the caller", e.Message)
	}
	if len(e.Remediation) == 0 {
		t.Error("P-06: the catch-all must still say where to look")
	}
}

// TestWriteVMErrorSeesThroughWrapping: the manager wraps as it unwinds, so the
// map has to match on type rather than on the outermost error. A runtime verb
// that failed because the runtime is unavailable is still a 501 — the host did
// not try and fail, it cannot try at all.
func TestWriteVMErrorSeesThroughWrapping(t *testing.T) {
	wrapped := &runtime.ErrRuntimeOpFailed{
		VMID: "vm-1",
		Op:   "pause",
		Err:  &runtime.UnavailableError{Reason: "pause not supported in M1a"},
	}
	status, e := mapVMError(t, wrapped)
	if status != http.StatusNotImplemented || e.Cause != "runtime_unavailable" {
		t.Errorf("status %d cause %q, want 501 runtime_unavailable", status, e.Cause)
	}
}

// TestContextErrorsReachTheMap: the branch that answers an expired operation
// budget is worth writing only if that shape arrives. Store reads hand a dead
// context straight back — no sql.ErrNoRows, no wrapping — and every handler
// passes what a read returns to writeVMError, so it does.
func TestContextErrorsReachTheMap(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "vmobs.sqlite"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := st.GetVM(ctx, "vm-anything"); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetVM on a dead context = %v, want context.Canceled", err)
	}

	deadCtx, deadCancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer deadCancel()
	if _, err := st.GetVM(deadCtx, "vm-anything"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetVM past its deadline = %v, want context.DeadlineExceeded", err)
	}
}
