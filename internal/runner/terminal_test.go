// ABOUTME: Relay tests: frames copy verbatim in both directions, and the queue is
// ABOUTME: bounded, so a stalled caller stops the vsock read instead of growing.
package runner

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"

	"github.com/2389-research/observatory-v2/internal/guest/proto"
)

// startRelay wires a relay between two real socket pairs: one standing in for
// the guest's port-10002 stream, one for the caller's control-socket
// connection. Nothing here fakes a frame — both ends speak the real codec.
func startRelay(t *testing.T, maxChunk int) (guestEnd, callerEnd net.Conn, r *Relay) {
	t.Helper()
	relayGuest, guestEnd := net.Pipe()
	relayCaller, callerEnd := net.Pipe()
	r = newRelay(relayGuest, maxChunk)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.Run(relayCaller, relayCaller)
	}()

	t.Cleanup(func() {
		r.Close()
		_ = relayCaller.Close()
		_ = guestEnd.Close()
		_ = callerEnd.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("relay did not stop within 2s of Close")
		}
	})
	return guestEnd, callerEnd, r
}

// ptyFrame builds a guest->host PTY payload: [offset:8 BE][bytes].
func ptyFrame(offset uint64, b []byte) []byte {
	p := make([]byte, 8+len(b))
	binary.BigEndian.PutUint64(p[:8], offset)
	copy(p[8:], b)
	return p
}

func TestRelayCopiesGuestOutputToTheCaller(t *testing.T) {
	guestEnd, callerEnd, _ := startRelay(t, 32<<10)

	want := ptyFrame(4096, []byte("total 12\r\ndrwxr-xr-x\r\n"))
	go func() { _ = proto.WriteFrame(guestEnd, proto.FramePTY, want) }()

	_ = callerEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, got, err := proto.ReadFrame(callerEnd)
	if err != nil {
		t.Fatalf("read relayed frame: %v", err)
	}
	if typ != proto.FramePTY {
		t.Errorf("frame type = 0x%02X, want FramePTY 0x%02X", typ, proto.FramePTY)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("relayed payload = %q, want %q; the relay copies frames, it does not rewrite them", got, want)
	}
}

func TestRelayCopiesCallerInputToTheGuest(t *testing.T) {
	guestEnd, callerEnd, _ := startRelay(t, 32<<10)

	// Host->guest PTY payload is [seq:8 BE][input bytes].
	want := ptyFrame(7, []byte("echo hi\n"))
	go func() { _ = proto.WriteFrame(callerEnd, proto.FramePTY, want) }()

	_ = guestEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, got, err := proto.ReadFrame(guestEnd)
	if err != nil {
		t.Fatalf("read input frame at the guest end: %v", err)
	}
	if typ != proto.FramePTY || !bytes.Equal(got, want) {
		t.Errorf("guest saw type 0x%02X payload %q; want 0x%02X %q", typ, got, proto.FramePTY, want)
	}
}

// A drop the guest reports must reach the caller unchanged: SPEC §8.2 wants the
// gap shown, and a relay that summarised it would be inventing evidence.
func TestRelayForwardsGuestControlFramesVerbatim(t *testing.T) {
	guestEnd, callerEnd, _ := startRelay(t, 32<<10)

	go func() {
		_ = proto.WriteControl(guestEnd, proto.KindTerminalDropped, proto.TerminalDropped{
			FromOffset: "9007199254740993",
			ToOffset:   "9007199254807000",
		})
	}()

	_ = callerEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	env, err := proto.ReadControl(callerEnd)
	if err != nil {
		t.Fatalf("read relayed control frame: %v", err)
	}
	if env.Kind != proto.KindTerminalDropped {
		t.Fatalf("kind = %q, want %q", env.Kind, proto.KindTerminalDropped)
	}
	var got proto.TerminalDropped
	if err := json.Unmarshal(env.Data, &got); err != nil {
		t.Fatalf("unmarshal dropped: %v", err)
	}
	if got.FromOffset != "9007199254740993" || got.ToOffset != "9007199254807000" {
		t.Errorf("dropped range = [%s,%s); the offsets must survive the relay as decimal strings",
			got.FromOffset, got.ToOffset)
	}
}

// §8.3: at the queue's limit the relay stops reading vsock. The guest then
// blocks on its own write, which is exactly the backpressure that lets the
// guest ring absorb the overflow and report the drop.
func TestRelayStopsReadingWhenItsQueueFills(t *testing.T) {
	const chunk = 1 << 10
	guestEnd, callerEnd, _ := startRelay(t, chunk)

	payload := ptyFrame(0, bytes.Repeat([]byte("x"), chunk))

	// Write until a write blocks: nobody is draining the caller end.
	sent := 0
	for i := 0; i < 200; i++ {
		if err := guestEnd.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("set write deadline: %v", err)
		}
		if err := proto.WriteFrame(guestEnd, proto.FramePTY, payload); err != nil {
			break
		}
		sent++
	}
	if sent == 0 {
		t.Fatal("the relay accepted nothing; a queue that never fills is not a queue")
	}
	if sent >= 200 {
		t.Fatalf("the relay swallowed %d frames without pausing; the queue is unbounded", sent)
	}
	t.Logf("guest wrote %d frames before the relay stopped reading", sent)

	// Draining the caller must let it resume.
	_ = callerEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := proto.ReadFrame(callerEnd); err != nil {
		t.Fatalf("drain one frame: %v", err)
	}
	if err := guestEnd.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set write deadline: %v", err)
	}
	if err := proto.WriteFrame(guestEnd, proto.FramePTY, payload); err != nil {
		t.Errorf("the relay did not resume after the consumer drained: %v", err)
	}
}

// Detaching is a closed caller connection. The guest stream must close with it
// so the guest can drop the attachment — the session itself lives on.
func TestRelayEndsWhenTheCallerHangsUp(t *testing.T) {
	guestEnd, callerEnd, _ := startRelay(t, 32<<10)

	_ = callerEnd.Close()

	_ = guestEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := proto.ReadFrame(guestEnd); err == nil {
		t.Error("the guest stream stayed open after the caller hung up")
	}
}

func TestFrameQueueBlocksAtItsByteBound(t *testing.T) {
	q := newFrameQueue(2048)
	body := bytes.Repeat([]byte("y"), 1024)

	for i := 0; i < 2; i++ {
		if err := q.push(wireFrame{typ: proto.FramePTY, payload: body}); err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
	}
	if got := q.queued(); got != 2048 {
		t.Errorf("queued = %d bytes, want 2048", got)
	}

	blocked := make(chan error, 1)
	go func() { blocked <- q.push(wireFrame{typ: proto.FramePTY, payload: body}) }()
	select {
	case err := <-blocked:
		t.Fatalf("a third push past the bound returned %v instead of blocking", err)
	case <-time.After(100 * time.Millisecond):
	}

	if _, err := q.pop(); err != nil {
		t.Fatalf("pop: %v", err)
	}
	select {
	case err := <-blocked:
		if err != nil {
			t.Errorf("push after a pop returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("push stayed blocked after the queue drained")
	}
}

// A frame larger than the whole bound still goes through when the queue is
// empty: refusing it would strand the stream, and the frame codec already caps
// a payload at proto.MaxBinaryFrame.
func TestFrameQueueAdmitsAnOversizeFrameWhenEmpty(t *testing.T) {
	q := newFrameQueue(16)
	done := make(chan error, 1)
	go func() { done <- q.push(wireFrame{typ: proto.FramePTY, payload: bytes.Repeat([]byte("z"), 4096)}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("oversize push into an empty queue returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an oversize frame deadlocked an empty queue")
	}
}

func TestFrameQueueCloseWakesBlockedWaiters(t *testing.T) {
	q := newFrameQueue(1024)

	popped := make(chan error, 1)
	go func() { _, err := q.pop(); popped <- err }()
	time.Sleep(50 * time.Millisecond)
	q.close()

	select {
	case err := <-popped:
		if err == nil {
			t.Error("pop returned no error after close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close left a pop blocked")
	}
	if err := q.push(wireFrame{typ: proto.FramePTY, payload: []byte("late")}); err == nil {
		t.Error("push into a closed queue returned no error")
	}
}

// The relay is a copier. §3 makes the runner the fault boundary for the
// terminal relay, and a boundary that runs guest-chosen programs is not one.
func TestRelayHasNoExec(t *testing.T) {
	src, err := os.ReadFile("terminal.go")
	if err != nil {
		t.Fatalf("read terminal.go: %v", err)
	}
	if bytes.Contains(src, []byte("exec.")) {
		t.Error("internal/runner/terminal.go references exec.; the relay copies frames, it never runs programs")
	}
}
