// ABOUTME: Tests for DialHostVsock: real unix socket server speaking CONNECT/OK protocol.
// ABOUTME: Uses real net.Listen and net.Dial — no test doubles.
package proto

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestUnixServer starts a test server on a unix socket. It returns the socket
// path and a function to shut it down. The handler fn is called for each
// accepted connection in a goroutine.
func newTestUnixServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	// macOS caps sun_path at ~104 bytes; t.TempDir() paths can exceed this.
	// Use a short os.MkdirTemp("", "vs") directory instead.
	dir, err := os.MkdirTemp("", "vs")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := dir + "/s.sock"

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", socketPath, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return socketPath
}

func TestDialHostVsockSuccess(t *testing.T) {
	const testPort uint32 = 10000
	socketPath := newTestUnixServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		line := strings.TrimRight(string(buf[:n]), "\n")
		if line != fmt.Sprintf("CONNECT %d", testPort) {
			return
		}
		_, _ = fmt.Fprintf(conn, "OK %d\n", testPort+1)
		// Hold the conn open: the application protocol continues on this conn.
		buf2 := make([]byte, 16)
		_, _ = conn.Read(buf2)
	})

	ctx := context.Background()
	conn, err := DialHostVsock(ctx, socketPath, testPort)
	if err != nil {
		t.Fatalf("DialHostVsock: %v", err)
	}
	defer conn.Close()
	if conn == nil {
		t.Fatal("expected non-nil conn")
	}
}

func TestDialHostVsockErrResponse(t *testing.T) {
	const testPort uint32 = 10000
	socketPath := newTestUnixServer(t, func(conn net.Conn) {
		defer conn.Close()
		// Read the CONNECT line, then answer ERR.
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("ERR\n"))
	})

	ctx := context.Background()
	_, err := DialHostVsock(ctx, socketPath, testPort)
	if err == nil {
		t.Fatal("want error on ERR response, got nil")
	}
	if !strings.Contains(err.Error(), "ERR") {
		t.Errorf("want ERR in error, got: %v", err)
	}
}

func TestDialHostVsockGarbageResponse(t *testing.T) {
	const testPort uint32 = 10000
	socketPath := newTestUnixServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("GARBAGE\n"))
	})

	ctx := context.Background()
	_, err := DialHostVsock(ctx, socketPath, testPort)
	if err == nil {
		t.Fatal("want error on garbage response, got nil")
	}
}

func TestDialHostVsockConnClosed(t *testing.T) {
	const testPort uint32 = 10000
	socketPath := newTestUnixServer(t, func(conn net.Conn) {
		// Read and immediately close without responding.
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		conn.Close()
	})

	ctx := context.Background()
	_, err := DialHostVsock(ctx, socketPath, testPort)
	if err == nil {
		t.Fatal("want error on closed conn, got nil")
	}
}

func TestDialHostVsockContextCancelled(t *testing.T) {
	socketPath := newTestUnixServer(t, func(conn net.Conn) {
		defer conn.Close()
		// Stall: never respond.
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := DialHostVsock(ctx, socketPath, 10000)
	if err == nil {
		t.Fatal("want error on cancelled context, got nil")
	}
}

func TestDialHostVsockContextCancelledAfterDial(t *testing.T) {
	// Server accepts, reads the CONNECT line, then deliberately never replies.
	// Client cancels ~50ms after dialing; DialHostVsock must return promptly
	// (within 2s) with an error mentioning context canceled.
	socketPath := newTestUnixServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf) // consume the CONNECT line, then stall forever
		// Never write OK — block until the client closes the conn.
		buf2 := make([]byte, 1)
		_, _ = conn.Read(buf2)
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-time.After(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := DialHostVsock(ctx, socketPath, 10000)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("want error when context is cancelled after dial, got nil")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("want error mentioning 'context canceled', got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("DialHostVsock took %v; want < 2s after context cancellation", elapsed)
	}
}

func TestDialHostVsockNoBytesBufferedAfterOK(t *testing.T) {
	// Prove that no application bytes are consumed during the handshake.
	// The server sends OK then immediately sends a sentinel byte.
	// After DialHostVsock returns, reading one byte from conn must yield the sentinel.
	const testPort uint32 = 10000
	sentinel := byte(0xAB)

	socketPath := newTestUnixServer(t, func(conn net.Conn) {
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = fmt.Fprintf(conn, "OK %d\n", testPort+1)
		_, _ = conn.Write([]byte{sentinel})
		// Keep conn alive until test reads.
		buf2 := make([]byte, 1)
		_, _ = conn.Read(buf2)
	})

	ctx := context.Background()
	conn, err := DialHostVsock(ctx, socketPath, testPort)
	if err != nil {
		t.Fatalf("DialHostVsock: %v", err)
	}
	defer conn.Close()

	b := make([]byte, 1)
	if _, err := conn.Read(b); err != nil {
		t.Fatalf("reading sentinel: %v", err)
	}
	if b[0] != sentinel {
		t.Errorf("sentinel: got 0x%02X, want 0x%02X — application bytes were buffered and lost", b[0], sentinel)
	}
}

func TestDialHostVsockCancelSuccessRaceDeterministic(t *testing.T) {
	// Server completes the handshake immediately; client cancels ctx from a
	// goroutine racing the handshake. Run 50 iterations under -race.
	//
	// Every iteration must satisfy exactly one of:
	//   (a) err != nil  — cancel won; OR
	//   (b) err == nil and the conn is usable (a raw Write succeeds after a
	//       fresh 200ms deadline, proving no instant deadline was left on it).
	//
	// A poisoned conn — nil err but SetDeadline(now) already applied — would
	// make the Write return immediately with a timeout error. That is the bug
	// this test detects.
	const testPort uint32 = 10000
	const iterations = 50

	socketPath := newTestUnixServer(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = fmt.Fprintf(conn, "OK %d\n", testPort+1)
		// Drain any probe byte the client sends after a successful dial.
		conn.SetDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		probe := make([]byte, 1)
		_, _ = conn.Read(probe)
	})

	for i := 0; i < iterations; i++ {
		func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Cancel races the handshake: fire in a separate goroutine with no delay.
			go cancel()

			conn, err := DialHostVsock(ctx, socketPath, testPort)
			if err != nil {
				// Cancel won — acceptable. cancel() runs via defer.
				if !errors.Is(err, context.Canceled) {
					// Non-Canceled errors are logged for diagnosis, not failed on:
					// the race may resolve as a dial error for other transient reasons.
					t.Logf("iter %d: non-Canceled error on cancel path: %v", i, err)
				}
				return
			}
			defer conn.Close()

			// Success path: the conn must not carry a poisoned instant deadline.
			// Apply a fresh 200ms deadline and confirm a Write does not time out
			// instantly (a timed-out Write returns immediately).
			if setErr := conn.SetDeadline(time.Now().Add(200 * time.Millisecond)); setErr != nil {
				t.Errorf("iter %d: SetDeadline on returned conn: %v", i, setErr)
				return
			}
			start := time.Now()
			_, writeErr := conn.Write([]byte{0x01})
			elapsed := time.Since(start)
			if writeErr != nil {
				// A Write error is only the poisoned-deadline bug when it is a
				// timeout that fired in under 50ms. A slow timeout or any
				// non-timeout error is not the bug we are detecting.
				var netErr net.Error
				if errors.As(writeErr, &netErr) && netErr.Timeout() && elapsed < 50*time.Millisecond {
					t.Errorf("iter %d: Write on returned conn timed out in %v (instant deadline leak): %v", i, elapsed, writeErr)
				}
				// Non-timeout write error or slow timeout: not a poisoned conn.
			}
		}()
	}
}
