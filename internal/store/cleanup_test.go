// ABOUTME: The cleanup-failure record carries a host error string, so it goes
// ABOUTME: through the §15.3 redaction pass before it is persisted.
package store_test

import (
	"strings"
	"testing"

	"github.com/2389-research/observatory-v2/internal/store"
)

// TestCleanupFailureReasonIsRedacted: the reason is whatever the runtime said,
// and a runtime error routinely quotes the request that failed. A privd or HTTP
// error carrying an Authorization header would otherwise put a live credential
// in the event stream, which §15.3 forbids and which no amount of care at the
// call sites can prevent — the text is not ours to sanitize there.
func TestCleanupFailureReasonIsRedacted(t *testing.T) {
	s := openStore(t)
	ctx := t.Context()
	vmID := "vm-redact-cleanup"

	secret := "Bearer sk-live-abcdefgh12345678"
	if err := s.RecordCleanupFailure(ctx, vmID, "deleting",
		"release refused by helper; request was: "+secret); err != nil {
		t.Fatalf("RecordCleanupFailure: %v", err)
	}

	res, err := s.Query(ctx, store.Query{VMID: &vmID, Kind: "vm.cleanup_failed"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Events) != 1 {
		t.Fatalf("got %d vm.cleanup_failed events, want 1", len(res.Events))
	}
	reason, _ := res.Events[0].Data["reason"].(string)
	if strings.Contains(reason, "sk-live-abcdefgh12345678") {
		t.Errorf("reason %q retains the credential", reason)
	}
	if !strings.Contains(reason, "release refused by helper") {
		t.Errorf("reason %q lost the part that explains the failure", reason)
	}
}

// TestCleanupFailureRequiresItsFields: a record with no reason is the thing this
// mechanism exists to replace, and one with no vm_id or state cannot be joined
// to the row it describes.
func TestCleanupFailureRequiresItsFields(t *testing.T) {
	s := openStore(t)
	for _, tc := range []struct{ vmID, state, reason string }{
		{"", "deleting", "why"},
		{"vm-1", "", "why"},
		{"vm-1", "deleting", ""},
	} {
		if err := s.RecordCleanupFailure(t.Context(), tc.vmID, tc.state, tc.reason); err == nil {
			t.Errorf("RecordCleanupFailure(%q, %q, %q) = nil, want an error", tc.vmID, tc.state, tc.reason)
		}
	}
}
