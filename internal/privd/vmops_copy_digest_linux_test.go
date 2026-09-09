// ABOUTME: Holds staged artifact digests against the bytes actually copied into the jail.
// ABOUTME: Exercises same-inode mutation after verification without mocked filesystem operations.
//go:build linux

package privd

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCopyFromPinnedFdRejectsChangedInodeContents(t *testing.T) {
	for _, name := range []string{"fc-config.json", "config.ext4", "rootfs.ext4"} {
		t.Run(name, func(t *testing.T) {
			stage := t.TempDir()
			original := []byte("verified artifact contents")
			namePath := filepath.Join(stage, name)
			if err := os.WriteFile(namePath, original, 0o600); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(original)
			staged := StagedFile{Name: name, SHA256: hex.EncodeToString(digest[:])}
			stageDir, err := openDirNoFollow(stage)
			if err != nil {
				t.Fatal(err)
			}
			defer stageDir.Close()
			source, err := VerifyStagedFileAt(stageDir, staged)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			// WriteFile truncates and writes the existing inode. The verified open
			// descriptor now reads different bytes despite its unchanged identity.
			if err := os.WriteFile(namePath, []byte("changed artifact contents"), 0o600); err != nil {
				t.Fatal(err)
			}
			destination, err := openDirNoFollow(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer destination.Close()
			requestedUID := os.Getuid()
			if requestedUID == 0 {
				requestedUID = 65534
			}
			err = CopyFromPinnedFd(source, destination, staged, requestedUID, os.Getgid())
			var backend *BackendError
			if !errors.As(err, &backend) || backend.Cause != "digest_mismatch" {
				t.Fatalf("changed inode was not refused as a digest mismatch: %v", err)
			}
			copied, err := os.Stat(filepath.Join(destination.Name(), name))
			if err != nil {
				t.Fatal(err)
			}
			if owner := copied.Sys().(*syscall.Stat_t).Uid; owner != uint32(os.Getuid()) {
				t.Fatalf("rejected bytes transferred ownership: uid=%d", owner)
			}
		})
	}
}
