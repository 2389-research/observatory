// ABOUTME: Transfers bounded collector descriptor replies over the authenticated privd socket.
// ABOUTME: Retains length-prefixed framing and closes every received descriptor on errors.
//go:build linux

package privd

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const maxReplyFiles = 8

// writeMsgFiles leaves ownership of the original descriptors with its caller.
// A partial stream write sends the remaining bytes without repeating rights.
func writeMsgFiles(conn *net.UnixConn, value any, files []*os.File) error {
	if len(files) > maxReplyFiles {
		return fmt.Errorf("descriptor reply exceeds %d files", maxReplyFiles)
	}
	fds := make([]int, len(files))
	for i, file := range files {
		if file == nil || file.Fd() == ^uintptr(0) {
			return fmt.Errorf("invalid reply descriptor")
		}
		fds[i] = int(file.Fd())
	}
	var frame bytes.Buffer
	if err := WriteMsg(&frame, value); err != nil {
		return err
	}
	data := frame.Bytes()
	n := 0
	if len(fds) > 0 {
		rights := unix.UnixRights(fds...)
		written, oobn, err := conn.WriteMsgUnix(data, rights, nil)
		if err != nil {
			return err
		}
		if oobn != len(rights) || written == 0 {
			return io.ErrShortWrite
		}
		n = written
	}
	for n < len(data) {
		written, err := conn.Write(data[n:])
		n += written
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type descriptorReader struct {
	conn  *net.UnixConn
	files []*os.File
}

func (r *descriptorReader) Read(data []byte) (int, error) {
	control := make([]byte, unix.CmsgSpace((maxReplyFiles+1)*4))
	n, oobn, flags, _, err := r.conn.ReadMsgUnix(data, control)
	if err != nil {
		return 0, err
	}
	// Go uses MSG_CMSG_CLOEXEC on Linux. Parse even a truncated control buffer
	// before rejecting it, so all descriptors the kernel installed are closed.
	messages, parseErr := unix.ParseSocketControlMessage(control[:oobn])
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
			parseErr = fmt.Errorf("unexpected descriptor reply control message")
			continue
		}
		fds, rightsErr := unix.ParseUnixRights(&message)
		if rightsErr != nil {
			parseErr = rightsErr
			continue
		}
		for _, fd := range fds {
			r.files = append(r.files, os.NewFile(uintptr(fd), "privd-observer"))
		}
	}
	if parseErr != nil {
		// Returning a full byte count with this error lets io.ReadFull discard
		// the error. Rejected control data must invalidate the entire frame.
		return 0, parseErr
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return 0, fmt.Errorf("truncated descriptor reply")
	}
	if len(r.files) > maxReplyFiles {
		return 0, fmt.Errorf("descriptor reply exceeds %d files", maxReplyFiles)
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// readMsgFiles returns owned close-on-exec descriptors only for a complete valid
// frame. The caller must validate their count/types against the reply metadata.
func readMsgFiles(conn *net.UnixConn, value any) ([]*os.File, error) {
	r := &descriptorReader{conn: conn}
	if err := ReadMsg(r, value); err != nil {
		closeFiles(r.files)
		return nil, err
	}
	return r.files, nil
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
