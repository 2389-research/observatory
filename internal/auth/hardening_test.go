// ABOUTME: Credential lifetime bounds and real filesystem publication failures.
// ABOUTME: Retry checks distinguish visible revocations from acknowledged durable writes.
package auth

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenDurationBounds(t *testing.T) {
	s, err := InitStore(filepath.Join(t.TempDir(), "auth"), "op", "password")
	if err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []time.Duration{-1, -time.Minute, time.Duration(153722867)*time.Minute + 1} {
		before, _ := s.ListTokens()
		secret, _, err := s.CreateToken("bad", "op", ttl)
		if err == nil || secret != "" {
			t.Errorf("duration %v minted token", ttl)
		}
		after, _ := s.ListTokens()
		if len(after) != len(before) {
			t.Errorf("invalid duration %v changed store", ttl)
		}
	}
}

func TestRevocationPublicationFailureAndRetry(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission failure requires unprivileged process")
	}
	dir := filepath.Join(t.TempDir(), "auth")
	s, err := InitStore(dir, "op", "password")
	if err != nil {
		t.Fatal(err)
	}
	secret, rec, err := s.CreateToken("ci", "op", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	if err := s.RevokeToken(rec.ID); err == nil {
		t.Error("acknowledged revocation with unavailable directory barrier")
	}
	records, err := s.ListTokens()
	if err != nil || len(records) != 1 || records[0].RevokedAt == "" {
		t.Fatalf("rename must be visible before failed barrier: %v %v", records, err)
	}
	// Reopening must not turn visible state into proof the barrier succeeded.
	reopened, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.RevokeToken(rec.ID); err == nil {
		t.Error("retry acknowledged visible but unsettled revocation")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := reopened.RevokeToken(rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.VerifyToken(secret); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("revoked secret accepted: %v", err)
	}
}

func TestMintPublicationFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission failure requires unprivileged process")
	}
	dir := filepath.Join(t.TempDir(), "auth")
	s, err := InitStore(dir, "op", "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	secret, _, err := s.CreateToken("ci", "op", 0)
	if err == nil || secret != "" {
		t.Fatal("mint acknowledged publication without directory barrier")
	}
}

func TestInitDirectoryPublicationFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission failure requires unprivileged process")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
	if _, err := InitStore(filepath.Join(parent, "auth"), "op", "password"); err == nil {
		t.Fatal("init acknowledged unsynced credential directory")
	}
}

func TestInitDirectoryPublicationRetry(t *testing.T) {
	if dir := os.Getenv("VMOBS_AUTH_INIT_RETRY_DIR"); dir != "" {
		if _, err := InitStore(dir, "op", "password"); err == nil {
			t.Fatal("fresh process acknowledged unsettled credential ancestors")
		}
		return
	}
	if os.Getuid() == 0 {
		t.Skip("permission failure requires unprivileged process")
	}
	for _, suffix := range []string{"auth", "nested/parent/auth"} {
		t.Run(suffix, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, suffix)
			if err := os.Chmod(parent, 0300); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
			for range 2 {
				if _, err := InitStore(dir, "op", "password"); err == nil {
					t.Fatal("acknowledged credential initialization without ancestor barrier")
				}
			}
			if _, err := os.Stat(dir); err != nil {
				t.Fatalf("directory must be visible after barrier failure: %v", err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestInitDirectoryPublicationRetry$")
			cmd.Env = append(os.Environ(), "VMOBS_AUTH_INIT_RETRY_DIR="+dir)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("fresh-process retry: %v\n%s", err, out)
			}
			if _, err := OpenStore(dir); err == nil {
				t.Fatal("reopened credentials whose ancestor publication failed")
			}
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := InitStore(dir, "op", "password"); err != nil {
				t.Fatal(err)
			}
			s, err := OpenStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.VerifyPassword("op", "password"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestCredentialsSurviveProcessCrash kills subprocesses after acknowledged writes.
// The page cache survives these crashes: this does not simulate power loss.
func TestCredentialsSurviveProcessCrash(t *testing.T) {
	if stage := os.Getenv("VMOBS_AUTH_CRASH_STAGE"); stage != "" {
		dir := os.Getenv("VMOBS_AUTH_CRASH_DIR")
		var s *Store
		var err error
		switch stage {
		case "init":
			s, err = InitStore(dir, "op", "password")
		default:
			s, err = OpenStore(dir)
		}
		if err != nil {
			t.Fatal(err)
		}
		switch stage {
		case "mint":
			secret, rec, err := s.CreateToken("crash", "op", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.NewEncoder(os.Stdout).Encode(struct {
				Secret string
				Record TokenRecord
			}{secret, rec}); err != nil {
				t.Fatal(err)
			}
		case "revoke":
			if err := s.RevokeToken(os.Getenv("VMOBS_AUTH_CRASH_ID")); err != nil {
				t.Fatal(err)
			}
		}
		process, err := os.FindProcess(os.Getpid())
		if err != nil {
			t.Fatal(err)
		}
		if err := process.Kill(); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	dir := filepath.Join(t.TempDir(), "parent", "auth")
	crash := func(stage, id string) []byte {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestCredentialsSurviveProcessCrash$")
		cmd.Env = append(os.Environ(), "VMOBS_AUTH_CRASH_STAGE="+stage, "VMOBS_AUTH_CRASH_DIR="+dir, "VMOBS_AUTH_CRASH_ID="+id)
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || !strings.Contains(exit.String(), "killed") {
			t.Fatalf("expected killed child, got %v: %s", err, out)
		}
		return out
	}
	crash("init", "")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyPassword("op", "password"); err != nil {
		t.Fatal(err)
	}
	var minted struct {
		Secret string
		Record TokenRecord
	}
	if err := json.Unmarshal(crash("mint", ""), &minted); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyToken(minted.Secret); err != nil {
		t.Fatal(err)
	}
	crash("revoke", minted.Record.ID)
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyToken(minted.Secret); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("revoked token accepted: %v", err)
	}
	for path, mode := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, operatorFile): 0600, filepath.Join(dir, tokensFile): 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s mode=%o want %o", path, info.Mode().Perm(), mode)
		}
	}
}

func TestOperatorPublicationFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("permission failure requires unprivileged process")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	path := filepath.Join(dir, operatorFile)
	if err := writeFileAtomic(path, []byte("{}")); err == nil {
		t.Fatal("operator publication ignored directory barrier failure")
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("publication did not reach post-rename failure: %v", err)
	}
}
