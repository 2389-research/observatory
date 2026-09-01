// ABOUTME: Tests for scoped CLI token creation, verification, listing, and
// ABOUTME: revocation — confirms hashes never escape the package boundary.
package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenMintVerifyRevoke(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	s, err := InitStore(dir, "local_operator", "longenoughpw")
	if err != nil {
		t.Fatal(err)
	}
	secret, rec, err := s.CreateToken("ci", "local_operator", 0)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if !strings.HasPrefix(secret, "vmobs_") {
		t.Fatalf("secret %q lacks vmobs_ prefix", secret)
	}
	got, err := s.VerifyToken(secret)
	if err != nil || got.ID != rec.ID || got.Owner != "local_operator" {
		t.Fatalf("verify = %+v, %v", got, err)
	}
	if err := s.RevokeToken(rec.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := s.VerifyToken(secret); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("revoked verify err = %v, want ErrBadCredentials", err)
	}
}

func TestTokenExpiry(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	s, _ := InitStore(dir, "op", "longenoughpw")
	secret, _, err := s.CreateToken("short", "op", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := s.VerifyToken(secret); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("expired verify err = %v, want ErrBadCredentials", err)
	}
}

func TestListTokensExposesNoSecrets(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	s, _ := InitStore(dir, "op", "longenoughpw")
	secret, _, _ := s.CreateToken("a", "op", 0)
	list, err := s.ListTokens()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", list, err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "tokens.json"))
	if strings.Contains(string(raw), secret) {
		t.Fatal("tokens.json contains the raw secret")
	}
	if strings.Contains(fmt.Sprintf("%+v", list), secret) {
		t.Fatal("ListTokens leaked the raw secret")
	}
}

func TestVerifyUnknownToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auth")
	s, _ := InitStore(dir, "op", "longenoughpw")
	if _, err := s.VerifyToken("vmobs_bogus"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("err = %v, want ErrBadCredentials", err)
	}
	if err := s.RevokeToken("tok-none"); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("revoke unknown = %v, want ErrTokenNotFound", err)
	}
}
