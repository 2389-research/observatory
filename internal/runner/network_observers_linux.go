// ABOUTME: Adopts the network observer descriptors the jailer adapter passed across exec.
// ABOUTME: Hands each reader generation its own dups so a closed reader keeps the sockets.
//go:build linux

package runner

import (
	"fmt"
	"os"

	"github.com/2389-research/observatory/internal/privd"
	"golang.org/x/sys/unix"
)

// adoptNetworkObservers takes ownership of the descriptors the adapter placed at
// FirstObserverFD and up, in the binding's socket order, and proves they are the
// sockets that binding names. exec clears close-on-exec on inherited descriptors,
// so the runner restores it before anything else can inherit them.
func adoptNetworkObservers(bundle *privd.NetworkObserverBundle) (*privd.NetworkObserverBundle, error) {
	if bundle == nil || len(bundle.Sockets) == 0 {
		return nil, fmt.Errorf("no observer binding was passed to this runner")
	}
	out := &privd.NetworkObserverBundle{Binding: bundle.Binding, Sockets: bundle.Sockets}
	for i := range bundle.Sockets {
		fd := FirstObserverFD + i
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			_ = out.Close()
			return nil, fmt.Errorf("inherited observer descriptor %d: %w", fd, err)
		}
		file := os.NewFile(uintptr(fd), fmt.Sprintf("network-observer-%d", i))
		if file == nil {
			_ = out.Close()
			return nil, fmt.Errorf("inherited observer descriptor %d is not open", fd)
		}
		out.Files = append(out.Files, file)
	}
	if err := privd.ValidateObserverDescriptors(out); err != nil {
		_ = out.Close()
		return nil, err
	}
	return out, nil
}

// dupNetworkObservers gives one reader generation its own descriptors. The
// reader closes every file it is handed, so a generation must never be given the
// masters the runner keeps for its lifetime. The dups share each socket's open
// file description, so they inherit its nonblocking mode and its receive queue.
func dupNetworkObservers(masters *privd.NetworkObserverBundle) (*privd.NetworkObserverBundle, error) {
	out := &privd.NetworkObserverBundle{Binding: masters.Binding, Sockets: masters.Sockets}
	for i, master := range masters.Files {
		raw, err := master.SyscallConn()
		if err != nil {
			_ = out.Close()
			return nil, fmt.Errorf("observer descriptor %d: %w", i, err)
		}
		duplicate, dupErr := -1, error(nil)
		if err := raw.Control(func(fd uintptr) {
			duplicate, dupErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
		}); err != nil {
			_ = out.Close()
			return nil, fmt.Errorf("observer descriptor %d: %w", i, err)
		}
		if dupErr != nil {
			_ = out.Close()
			return nil, fmt.Errorf("observer descriptor %d: %w", i, dupErr)
		}
		file := os.NewFile(uintptr(duplicate), master.Name()+"-generation")
		if file == nil {
			_ = unix.Close(duplicate)
			_ = out.Close()
			return nil, fmt.Errorf("observer descriptor %d duplicate is not open", i)
		}
		out.Files = append(out.Files, file)
	}
	return out, nil
}
