// ABOUTME: Verifies the guest filesystem collector's event contract at trusted ingress.
// ABOUTME: Mutation, coverage and loss evidence retain guest provenance and declared limits.
package events_test

import (
	"testing"

	"github.com/2389-research/observatory/internal/events"
)

func TestFilesystemCollectorKinds(t *testing.T) {
	for _, kind := range []string{"fs.create", "fs.modify", "fs.close_write", "fs.rename", "fs.delete", "fs.metadata", "fs.coverage", "fs.loss"} {
		t.Run(kind, func(t *testing.T) {
			info, ok := events.LookupKind(kind)
			if !ok {
				t.Fatalf("collector event %s would be rejected as unregistered", kind)
			}
			if info.Family != "fs" || info.Provenance != events.GuestReported || info.SchemaVersion != 1 {
				t.Fatalf("incorrect guest collector contract: %+v", info)
			}
			if info.Semantics == "" || len(info.Caveats) == 0 {
				t.Fatalf("collector event hides its meaning or observation limits: %+v", info)
			}
		})
	}
}
