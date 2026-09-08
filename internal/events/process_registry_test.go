// ABOUTME: Checks that emitted guest task and connect evidence is accepted at ingress.
// ABOUTME: Each kind declares guest provenance and its observation limits.
package events_test

import (
	"strings"
	"testing"

	"github.com/2389-research/observatory/internal/events"
)

func TestProcessCollectorKinds(t *testing.T) {
	for _, kind := range []string{"proc.fork", "proc.exec", "proc.exit", "proc.exec_attempt", "proc.exec_failed", "proc.loss", "socket.connect_attempt", "socket.connect_result"} {
		t.Run(kind, func(t *testing.T) {
			info, ok := events.LookupKind(kind)
			if !ok {
				t.Fatalf("emitted kind %s would be rejected", kind)
			}
			family, _, _ := strings.Cut(kind, ".")
			if info.Family != family || info.Provenance != events.GuestReported || info.SchemaVersion != 1 || info.Semantics == "" || len(info.Caveats) == 0 {
				t.Fatalf("incomplete guest evidence contract: %+v", info)
			}
		})
	}
}
