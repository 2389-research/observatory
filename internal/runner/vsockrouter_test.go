// ABOUTME: A stand-in for Firecracker's vsock multiplexer, shared by the runner's
// ABOUTME: tests: one unix socket carrying many guest ports, chosen by the CONNECT line.

//go:build unix

package runner_test

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

// vsockRouter mimics Firecracker's vsock multiplexer: one UDS carrying many
// guest ports, chosen by the CONNECT line. The runner dials 10000 for control,
// 10001 for telemetry and 10002 for each attached session, so a single-port
// stub cannot serve it — and one that ignores the requested port would hand
// telemetry to the control channel and call the test green.
type vsockRouter struct {
	ln    net.Listener
	mu    sync.Mutex
	ports map[uint32]*portListener
}

func newVsockRouter(t *testing.T, path string, ports ...uint32) *vsockRouter {
	t.Helper()
	ln, err := listen0600(path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	r := &vsockRouter{ln: ln, ports: map[uint32]*portListener{}}
	for _, p := range ports {
		r.ports[p] = newPortListener()
	}
	go r.accept()
	t.Cleanup(func() {
		_ = ln.Close()
		for _, pl := range r.ports {
			_ = pl.Close()
		}
	})
	return r
}

func (r *vsockRouter) listener(port uint32) net.Listener {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ports[port]
}

func (r *vsockRouter) accept() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.route(conn)
	}
}

func (r *vsockRouter) route(conn net.Conn) {
	var line []byte
	buf := make([]byte, 1)
	for len(line) < 64 {
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			return
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	var port uint32
	if _, err := fmt.Sscanf(string(line), "CONNECT %d", &port); err != nil {
		conn.Close()
		return
	}
	r.mu.Lock()
	pl := r.ports[port]
	r.mu.Unlock()
	if pl == nil {
		conn.Close()
		return
	}
	if _, err := conn.Write([]byte("OK 12345\n")); err != nil {
		conn.Close()
		return
	}
	pl.deliver(conn)
}

// portListener is a net.Listener fed by the router rather than by the kernel.
type portListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPortListener() *portListener {
	return &portListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *portListener) deliver(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.closed:
		c.Close()
	}
}

func (l *portListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *portListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *portListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "vsock" }
func (dummyAddr) String() string  { return "guest" }

// listen0600 creates a unix socket with mode 0600.
func listen0600(path string) (net.Listener, error) {
	old := umask(0o177)
	defer umask(old)
	return net.Listen("unix", path)
}
