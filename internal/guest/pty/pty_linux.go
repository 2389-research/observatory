// ABOUTME: Linux PTY allocation: unlock /dev/ptmx, name the slave, set the window size.
// ABOUTME: Everything that needs a kernel lives here; the broker above it is portable.
//go:build linux

package pty

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Open allocates a pseudo-terminal pair sized rows by cols and returns the
// master file together with the slave device path. The caller opens the
// slave, hands it to the child, and closes its own copy.
func Open(rows, cols uint16) (*os.File, string, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/ptmx: %w", err)
	}
	var name string
	err = control(master, func(fd int) error {
		// A freshly allocated slave is locked: unlocking here, before the
		// child exists, is what makes the pts openable at exec time.
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			return fmt.Errorf("unlock pty: %w", err)
		}
		n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
		if err != nil {
			return fmt.Errorf("read pty number: %w", err)
		}
		name = fmt.Sprintf("/dev/pts/%d", n)
		return nil
	})
	if err == nil {
		err = setWinsize(master, rows, cols)
	}
	if err != nil {
		_ = master.Close()
		return nil, "", err
	}
	return master, name, nil
}

// setWinsize tells the terminal driver how large the screen is. The driver
// signals SIGWINCH to the foreground process group on every change.
func setWinsize(master *os.File, rows, cols uint16) error {
	return control(master, func(fd int) error {
		ws := unix.Winsize{Row: rows, Col: cols}
		if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &ws); err != nil {
			return fmt.Errorf("set window size to %dx%d: %w", rows, cols, err)
		}
		return nil
	})
}

// control runs fn with the file's descriptor, held open for the duration.
// os.File.Fd would put the file back into blocking mode and cost us the
// runtime poller, which is what lets Close interrupt a parked read.
func control(f *os.File, fn func(fd int) error) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return fmt.Errorf("pty syscall conn: %w", err)
	}
	var inner error
	if err := raw.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return fmt.Errorf("pty control: %w", err)
	}
	return inner
}
