// ABOUTME: OpenPinned — resolves a pinned artifact under a trusted root, refuses
// ABOUTME: untrusted placement, and hands back the descriptor its digest covers.
package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ErrUnsafePath classifies a refusal about where the artifact is, not what is in
// it: a symlink standing in for the file or one of its parents, a directory
// anyone may replace entries in, a path that climbs out of the root, or
// something that is not a regular file.
var ErrUnsafePath = errors.New("lock: artifact path is not trusted")

// ErrBytesChanged classifies a refusal about the contents: the file is where it
// should be and could be read, and its digest is not the pinned one. Errors
// carrying it are *DigestError, which holds both digests.
var ErrBytesChanged = errors.New("lock: artifact bytes do not match the pinned digest")

// DigestError reports a file whose contents are not what the lock pins. It
// carries the computed digest so a caller can report it without parsing a
// message, and unwraps to ErrBytesChanged for classification.
type DigestError struct {
	Path string
	Got  string
	Want string
}

func (e *DigestError) Error() string {
	return fmt.Sprintf("%s: %s has %s, want %s", ErrBytesChanged, e.Path, e.Got, e.Want)
}

// Unwrap makes errors.Is(err, ErrBytesChanged) true for a *DigestError.
func (e *DigestError) Unwrap() error { return ErrBytesChanged }

// OpenPinned resolves rel under root, refuses an untrusted path, verifies the
// SHA-256 of the file it opened, and returns that descriptor seeked back to
// zero. The returned file is the caller's to close.
//
// The descriptor is the point. A caller that verifies a path and then reopens it
// to read has verified one inode and used whatever the name pointed at the
// second time; copying from the descriptor OpenPinned returns closes that window
// because there is no second resolution to lose.
//
// What the path walk is, and is not: the per-component Lstat below is a
// placement check — it refuses an artifact tree that is symlinked or writable by
// anyone who is not the operator. It is deliberately not a defence against an
// attacker racing us between the Lstat and the open, and cannot be made into one
// by adding more Lstats. That job belongs to the descriptor, which holds one
// inode from verification through use.
func OpenPinned(root, rel, wantSHA256 string) (*os.File, error) {
	if !filepath.IsLocal(rel) || filepath.Clean(rel) != rel {
		return nil, fmt.Errorf("%w: %q is not a clean path inside the artifact root", ErrUnsafePath, rel)
	}

	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("artifact root %s: %w", root, err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("%w: artifact root %s is not a directory", ErrUnsafePath, root)
	}
	if err := refuseWritable(root, rootInfo); err != nil {
		return nil, err
	}

	parts := strings.Split(rel, string(filepath.Separator))
	current := root
	for i, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("artifact %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrUnsafePath, current)
		}
		if i < len(parts)-1 {
			if err := refuseWritable(current, info); err != nil {
				return nil, err
			}
		}
	}

	return openPinnedFile(current, wantSHA256)
}

// openPinnedFile opens one file by absolute path and verifies its digest through
// the descriptor it returns. It is the half of OpenPinned that applies to a path
// vmobs does not own the parents of — an install_path naming a system binary.
func openPinnedFile(path, wantSHA256 string) (*os.File, error) {
	// O_NOFOLLOW so the last component cannot be a link at the moment of the
	// open, which is the only moment that matters. O_NONBLOCK so a fifo left in
	// the artifact's place returns a descriptor to reject instead of parking the
	// open until someone writes to it.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrUnsafePath, path)
		}
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: %s is not a regular file (mode %s)", ErrUnsafePath, path, info.Mode())
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return nil, err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != wantSHA256 {
		f.Close()
		return nil, &DigestError{Path: path, Got: got, Want: wantSHA256}
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// refuseWritable rejects a directory any user on the host may write to. Such a
// directory lets an unrelated account replace the artifact under it, which makes
// the pinned digest a statement about one moment rather than about the file.
//
// It checks the other-write bit and not the group-write bit. Group-writable
// directories are how this host actually ships artifacts: /srv/vmobs is
// harper:vmobs-fixture mode 0775 so the fixture group can stage into it, and
// the build tree's images/dist is 0775 as well. Refusing group-writable would
// refuse the real deployment, and it would also refuse every t.TempDir() on a
// umask-002 host, since Go creates that directory with os.Mkdir(dir, 0777).
// The cost is that anyone in a deliberately shared group can swap an artifact
// without this check noticing; the digest still catches the swap, and group
// membership on this host is an administrative decision, not an open door.
func refuseWritable(path string, info os.FileInfo) error {
	if perm := info.Mode().Perm(); perm&0o002 != 0 {
		return fmt.Errorf("%w: %s is world-writable (mode %04o)", ErrUnsafePath, path, perm)
	}
	return nil
}

// classify turns an OpenPinned error into the Got label and Detail a Mismatch
// carries. The labels are distinct answers to distinct questions, and collapsing
// any pair of them sends an operator to the wrong place: "absent" means build
// the artifact, "unsafe_path" means fix where it lives, and a digest means the
// bytes are not the pinned ones.
func classify(err error) (got, detail string) {
	var de *DigestError
	switch {
	case errors.As(err, &de):
		return de.Got, ""
	case errors.Is(err, os.ErrNotExist):
		return "absent", ""
	case errors.Is(err, ErrUnsafePath):
		return "unsafe_path", err.Error()
	default:
		return "unreadable", err.Error()
	}
}

// Describe renders a Mismatch as one operator-facing line. Detail is appended
// when the label alone does not say what to fix — "unsafe_path" names a policy,
// the detail names the directory.
func (m Mismatch) Describe() string {
	line := fmt.Sprintf("%s: want %s got %s", m.Subject, m.Want, m.Got)
	if m.Detail != "" {
		line += " (" + m.Detail + ")"
	}
	return line
}
