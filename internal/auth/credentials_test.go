package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitVerifyRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	if _, err := InitStore(dir, "local_operator", "hunter2hunter2"); err != nil {
		t.Fatalf("InitStore: %v", err)
	}
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	owner, err := s.VerifyPassword("local_operator", "hunter2hunter2")
	if err != nil || owner != "local_operator" {
		t.Fatalf("verify = %q, %v; want local_operator, nil", owner, err)
	}
	if _, err := s.VerifyPassword("local_operator", "wrong-password"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password err = %v, want ErrBadCredentials", err)
	}
	if _, err := s.VerifyPassword("nobody", "hunter2hunter2"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user err = %v, want ErrBadCredentials", err)
	}
}

func TestInitRefusesReinit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	if _, err := InitStore(dir, "op", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	if _, err := InitStore(dir, "op", "longenoughpw"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("reinit err = %v, want ErrAlreadyInitialized", err)
	}
}

func TestOpenMissingStoreFails(t *testing.T) {
	if _, err := OpenStore(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("OpenStore on missing dir succeeded")
	}
}

func TestStorePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	if _, err := InitStore(dir, "op", "longenoughpw"); err != nil {
		t.Fatal(err)
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %o, want 700", di.Mode().Perm())
	}
	fi, _ := os.Stat(filepath.Join(dir, "operator.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("operator.json mode = %o, want 600", fi.Mode().Perm())
	}
}

func TestInitStoreTightensExistingDir(t *testing.T) {
	// Pre-create the dir with permissive 0755; InitStore must tighten it.
	dir := filepath.Join(t.TempDir(), "auth")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := InitStore(dir, "op", "longenoughpw"); err != nil {
		t.Fatalf("InitStore: %v", err)
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode after InitStore = %o, want 700", di.Mode().Perm())
	}
}

func TestOpenStoreRejectsInsecureDir(t *testing.T) {
	// Initialize a valid store, then widen the dir — OpenStore must refuse.
	dir := filepath.Join(t.TempDir(), "auth")
	if _, err := InitStore(dir, "op", "longenoughpw"); err != nil {
		t.Fatalf("InitStore: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := OpenStore(dir)
	if err == nil {
		t.Fatal("OpenStore on 0755 dir succeeded; want error")
	}
	msg := err.Error()
	if !strings.Contains(msg, dir) {
		t.Errorf("error %q does not mention the path %q", msg, dir)
	}
}
