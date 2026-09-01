// ABOUTME: DialHostVsock: Firecracker host-side CONNECT dialer for the guest vsock channel.
// ABOUTME: Writes "CONNECT <port>\n", reads "OK <hostport>\n" byte-at-a-time (no buffering).
package proto

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DialHostVsock connects to the Firecracker Unix domain socket at udsPath and
// performs the CONNECT handshake to reach the guest vsock port. Per §7.3 [S3]:
//   - Sends: "CONNECT <port>\n"
//   - Expects: "OK <hostport>\n"
//
// The OK line is read byte-at-a-time to a 64-byte cap so no application bytes
// are buffered and lost after the handshake. The returned net.Conn is ready
// for the application protocol.
func DialHostVsock(ctx context.Context, udsPath string, port uint32) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", udsPath)
	if err != nil {
		return nil, fmt.Errorf("dial unix %s: %w", udsPath, err)
	}

	// If the context has a deadline, apply it to the handshake writes/reads.
	if dl, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(dl); err != nil {
			conn.Close()
			return nil, fmt.Errorf("set deadline: %w", err)
		}
	}

	// Watcher: for cancel-only contexts (no deadline), unblock handshake I/O
	// when ctx is cancelled by forcing an immediate deadline on the conn.
	// Invariant: watcher exit strictly precedes conn escape; cancel-vs-success
	// is resolved by the ctx.Err() check below, not by timing.
	watchDone := make(chan struct{})
	watcherExited := make(chan struct{})
	go func() {
		defer close(watcherExited)
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Now()) //nolint:errcheck
		case <-watchDone:
		}
	}()

	hsErr := func() error {
		// Write the CONNECT line.
		req := fmt.Sprintf("CONNECT %d\n", port)
		if _, err := conn.Write([]byte(req)); err != nil {
			conn.Close()
			if ctx.Err() != nil {
				return fmt.Errorf("write CONNECT: %w", ctx.Err())
			}
			return fmt.Errorf("write CONNECT: %w", err)
		}

		// Read the OK line one byte at a time to avoid consuming application bytes.
		line, err := readLineByByte(conn, 64)
		if err != nil {
			conn.Close()
			if ctx.Err() != nil {
				return fmt.Errorf("read handshake response: %w", ctx.Err())
			}
			return fmt.Errorf("read handshake response: %w", err)
		}

		// Validate the response.
		if !strings.HasPrefix(line, "OK ") {
			conn.Close()
			return fmt.Errorf("vsock handshake failed: got %q, want OK <port>", line)
		}

		return nil
	}()

	// Signal watcher and wait for it to fully exit before the conn can escape.
	// After this point the watcher cannot touch conn.
	close(watchDone)
	<-watcherExited

	if hsErr != nil {
		return nil, hsErr
	}

	// Cancel raced a successful handshake: honor the cancel deterministically.
	if ctx.Err() != nil {
		conn.Close()
		return nil, fmt.Errorf("dial host vsock: %w", ctx.Err())
	}

	// Clear any instant deadline the watcher may have applied before it exited.
	if err := conn.SetDeadline(zeroTime); err != nil {
		conn.Close()
		return nil, fmt.Errorf("clear deadline: %w", err)
	}

	return conn, nil
}

// readLineByByte reads from conn one byte at a time until it sees '\n' or
// reaches maxBytes. It returns the line without the trailing newline.
func readLineByByte(conn net.Conn, maxBytes int) (string, error) {
	var buf [1]byte
	var line strings.Builder
	for line.Len() < maxBytes {
		_, err := conn.Read(buf[:])
		if err != nil {
			return "", fmt.Errorf("read line byte: %w", err)
		}
		if buf[0] == '\n' {
			return line.String(), nil
		}
		line.WriteByte(buf[0])
	}
	return "", fmt.Errorf("handshake response line exceeds %d bytes", maxBytes)
}

// zeroTime clears conn deadlines when passed to SetDeadline.
var zeroTime time.Time
