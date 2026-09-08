// ABOUTME: Exercises descriptor replies through real Unix sockets and pipe descriptors.
// ABOUTME: Checks framing bounds, close-on-exec and descriptor cleanup on rejected replies.
//go:build linux

package privd

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func descriptorPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	client, err := net.DialUnix("unix", nil, ln.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	for _, conn := range []*net.UnixConn{client, server} {
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return client, server
}

func TestDescriptorReplyTransfersOwnedCopies(t *testing.T) {
	client, server := descriptorPair(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := writeMsgFiles(server, Response{OK: true}, []*os.File{r}); err != nil {
		t.Fatal(err)
	}
	var response Response
	files, err := readMsgFiles(client, &response)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(files)
	if !response.OK || len(files) != 1 {
		t.Fatalf("response=%+v files=%d", response, len(files))
	}
	flags, err := unix.FcntlInt(files[0].Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received descriptor inherited across exec: flags=%d err=%v", flags, err)
	}
	if _, err := w.Write([]byte("captured")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(files[0], buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "captured" {
		t.Fatalf("descriptor points at wrong object: %q", buf)
	}
	closeFiles(files)
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		t.Fatalf("receiver closed sender ownership: %v", err)
	}
}

func TestDescriptorReplyRejectsAndClosesMalformedRights(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		body  []byte
	}{
		{"nine", 9, []byte{0, 0, 0, 2, '{', '}'}},
		{"too-many", 16, []byte{0, 0, 0, 2, '{', '}'}},
		{"oversize", 1, []byte{0, 1, 0, 0}},
		{"bad-json", 1, []byte{0, 0, 0, 1, '!'}},
		{"truncated-body", 1, []byte{0, 0, 0, 3, '{'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := descriptorPair(t)
			file, err := os.Open("/dev/null")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			fds := make([]int, tc.count)
			for i := range fds {
				fds[i] = int(file.Fd())
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := server.WriteMsgUnix(tc.body, unix.UnixRights(fds...), nil); err != nil {
				t.Fatal(err)
			}
			if err := server.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			var response Response
			files, err := readMsgFiles(client, &response)
			if err == nil || len(files) != 0 {
				closeFiles(files)
				t.Fatalf("accepted malformed reply: files=%d err=%v", len(files), err)
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != len(before) {
				t.Fatalf("descriptor leak: before=%d after=%d", len(before), len(after))
			}
		})
	}
}

type countedDescriptorJSON struct{ calls int }

func (v *countedDescriptorJSON) MarshalJSON() ([]byte, error) {
	v.calls++
	return []byte(`{"ok":true}`), nil
}

func TestDescriptorReplySerializesOnceWithoutFiles(t *testing.T) {
	client, server := descriptorPair(t)
	value := &countedDescriptorJSON{}
	if err := writeMsgFiles(server, value, nil); err != nil {
		t.Fatal(err)
	}
	var response Response
	files, err := readMsgFiles(client, &response)
	defer closeFiles(files)
	if err != nil || !response.OK || len(files) != 0 || value.calls != 1 {
		t.Fatalf("response=%+v files=%d calls=%d err=%v", response, len(files), value.calls, err)
	}
}

func TestDescriptorReplyCountsRightsAcrossReads(t *testing.T) {
	client, server := descriptorPair(t)
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	fd := int(file.Fd())
	if _, _, err := server.WriteMsgUnix([]byte{0}, unix.UnixRights(fd, fd, fd, fd), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.WriteMsgUnix([]byte{0, 0, 2, '{', '}'}, unix.UnixRights(fd, fd, fd, fd, fd), nil); err != nil {
		t.Fatal(err)
	}
	var response Response
	files, err := readMsgFiles(client, &response)
	if err == nil || len(files) != 0 {
		closeFiles(files)
		t.Fatalf("accepted cumulative rights: %d %v", len(files), err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("descriptor leak: before=%d after=%d", len(before), len(after))
	}
}

func TestDescriptorReplyHandlesSocketBackpressure(t *testing.T) {
	client, server := descriptorPair(t)
	raw, err := server.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 1024) }); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	want := Response{OK: true, Message: strings.Repeat("x", 60000)}
	finished := make(chan error, 1)
	go func() { finished <- writeMsgFiles(server, want, []*os.File{file}) }()
	var got Response
	files, err := readMsgFiles(client, &got)
	defer closeFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if got.Message != want.Message || len(files) != 1 {
		t.Fatalf("partial or repeated response: message=%d files=%d", len(got.Message), len(files))
	}
}

func TestDescriptorReplyRetainsRightsOnSplitFrame(t *testing.T) {
	client, server := descriptorPair(t)
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	body := []byte(`{"ok":true}`)
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	if _, _, err := server.WriteMsgUnix(header[:1], unix.UnixRights(int(file.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write(append(header[1:], body...)); err != nil {
		t.Fatal(err)
	}
	var response Response
	files, err := readMsgFiles(client, &response)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(files)
	if len(files) != 1 || !response.OK {
		t.Fatalf("lost descriptor or frame: %+v, %d", response, len(files))
	}
}
