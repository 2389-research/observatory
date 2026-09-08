// ABOUTME: Durable publication of ownership records: atomic overwrite plus the fsync barriers behind it.
// ABOUTME: A caller that gets nil here may act on the record; any other answer means the record is unsettled.
package durable

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// An ownership record — privd's per-VM ledger entry, the jailer's manifest —
// says which host resources a VM owns. Losing one strands the resources it
// named; reading a torn one is worse, because the identities it half-describes
// can be handed to a second VM. Both are prevented the same way: write the
// bytes to a temporary file, make them durable, rename over the final name so
// a reader sees the complete old record or the complete new one, then make the
// rename itself durable.
//
// The last step is the one that is easy to omit. A rename is atomic against a
// concurrent reader whether or not the directory is synced; it is durable
// against a crash only after the directory entry reaches the disk.
//
// A barrier that cannot be taken is reported, never assumed. The caller of a
// failed publication does not know whether the record is the old one or the
// new one, and must not treat either as settled — which for these records
// means it must not reuse the identities they name.
//
// What this does not buy: on a tmpfs there is no backing store, so every
// barrier here is a no-op that returns success. That is the right answer for a
// record whose whole directory is meant to vanish at reboot, and the wrong
// thing to quote as evidence of crash durability. See the ledger's own comment.

// WriteFile publishes data at path with the given mode, atomically and
// durably. A reader concurrent with it sees either the complete previous
// content or the complete new content.
func WriteFile(path string, mode os.FileMode, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".publish-*.tmp")
	if err != nil {
		return fmt.Errorf("durable: create temporary file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()

	// Every failure below abandons the temporary file, so it is removed on the
	// way out and the original cause is the one returned.
	fail := func(err error) error {
		_ = os.Remove(tmpPath)
		return err
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fail(fmt.Errorf("durable: write %s: %w", tmpPath, err))
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fail(fmt.Errorf("durable: chmod %s: %w", tmpPath, err))
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fail(fmt.Errorf("durable: sync %s: %w", tmpPath, err))
	}
	if err := tmp.Close(); err != nil {
		return fail(fmt.Errorf("durable: close %s: %w", tmpPath, err))
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fail(fmt.Errorf("durable: publish %s: %w", path, err))
	}
	// Past this point the new content is live. A failure here leaves it live
	// but not durable, which is exactly what the error says.
	if err := SyncDir(dir); err != nil {
		return fmt.Errorf("durable: sync directory after publishing %s: %w", path, err)
	}
	return nil
}

// Remove deletes path and makes the deletion durable. An absent path is not an
// error: the record is gone, which is what the caller asked for.
func Remove(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("durable: remove %s: %w", path, err)
	}
	if err := SyncDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("durable: sync directory after removing %s: %w", path, err)
	}
	return nil
}

// RemoveAll deletes the tree at path and makes its disappearance durable.
// Like Remove, an absent path is not an error.
func RemoveAll(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("durable: remove tree %s: %w", path, err)
	}
	// A prior attempt may have removed the tree but failed its barrier. Absence
	// is not durability: retry the barrier on the nearest surviving ancestor.
	parent := filepath.Dir(path)
	for {
		err := SyncDir(parent)
		if err == nil {
			return nil
		}
		if !errors.Is(err, fs.ErrNotExist) || filepath.Dir(parent) == parent {
			return fmt.Errorf("durable: sync directory after removing %s: %w", path, err)
		}
		parent = filepath.Dir(parent)
	}
}

// MkdirAll creates path and any missing parents, then syncs its ancestor entries.
// Existing entries also need barriers: they may come from an earlier failed call,
// including one in another process. Visibility alone is not durable publication.
func MkdirAll(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("durable: mkdir %s: %w", path, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("durable: absolute directory %s: %w", path, err)
	}
	for parent := filepath.Dir(abs); ; parent = filepath.Dir(parent) {
		if err := SyncDir(parent); err != nil {
			return fmt.Errorf("durable: sync ancestor after creating %s: %w", path, err)
		}
		if filepath.Dir(parent) == parent {
			return nil
		}
	}
}

// SyncDir makes a directory's own entries durable — the barrier a rename or an
// unlink needs before its effect survives a crash.
func SyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("durable: open directory %s: %w", path, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("durable: sync directory %s: %w", path, err)
	}
	return nil
}
