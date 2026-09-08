// ABOUTME: Pins boot-scoped event paging against real persisted guest and host events.
// ABOUTME: Keeps old boots and payload claims outside the active observation window.
package store_test

import (
	"testing"

	"github.com/2389-research/observatory/internal/store"
)

func TestQueryBootScope(t *testing.T) {
	s := openStore(t)
	vm, op := mustCreateVM(t, s, testUUID(1), "boot-scope", nil)
	boot, oldBoot, otherVM := testUUID(2), testUUID(3), testUUID(4)
	_, err := s.TransitionVM(t.Context(), store.TransitionInput{
		VMID: vm.VMID, To: "starting", Reason: "launch", OperationID: op.OperationID, BootID: &boot,
	})
	if err != nil {
		t.Fatal(err)
	}
	current := mustAppend(t, s, fsModify(testUUID(10), "1", &vm.VMID, &boot))
	old := fsModify(testUUID(11), "1", &vm.VMID, &oldBoot)
	old.Data["boot_id"] = boot // A guest payload cannot replace envelope identity.
	mustAppend(t, s, old)
	mustAppend(t, s, fsModify(testUUID(12), "1", &otherVM, &boot))
	page := queryAll(t, s, store.Query{VMID: &vm.VMID, BootID: &boot})
	if len(page.Events) != 2 {
		t.Fatalf("boot scope returned %d events, want launch transition and current guest event", len(page.Events))
	}
	if page.Events[0].Kind != "vm.state_changed" || page.Events[0].Data["boot_id"] != boot {
		t.Fatalf("missing host launch linkage: %+v", page.Events[0])
	}
	if *page.Events[1].EventID != current.EventID {
		t.Fatalf("wrong guest event: %+v", page.Events[1])
	}
	tail := queryAll(t, s, store.Query{VMID: &vm.VMID, BootID: &boot, Tail: true, Limit: 1})
	if len(tail.Events) != 1 || *tail.Events[0].EventID != current.EventID {
		t.Fatalf("tail crossed boot scope: %+v", tail)
	}
	empty := queryAll(t, s, store.Query{VMID: &vm.VMID, BootID: &boot, After: tail.NextAfter})
	if len(empty.Events) != 0 || empty.NextAfter != tail.NextAfter {
		t.Fatalf("resume crossed boot scope: %+v", empty)
	}
}
