// ABOUTME: File-based credential store: one operator account (argon2id) and
// ABOUTME: CLI tokens, in a 0700 dir with 0600 atomic-rename JSON files.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/2389-research/observatory/internal/durable"
	"golang.org/x/crypto/argon2"
)

var (
	ErrBadCredentials     = errors.New("invalid username or password")
	ErrAlreadyInitialized = errors.New("credential store already initialized")
)

const operatorFile = "operator.json"

// Store holds the path to the credential directory. mu serializes all
// read-modify-write operations on tokens.json across concurrent calls.
type Store struct {
	dir string
	mu  sync.Mutex
}

type passwordHash struct {
	Algorithm string `json:"algorithm"` // "argon2id"
	Salt      string `json:"salt"`      // base64url
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Hash      string `json:"hash"` // base64url, 32 bytes
}

type operatorRecord struct {
	Version      int          `json:"version"`
	Username     string       `json:"username"`
	PasswordHash passwordHash `json:"password_hash"`
	CreatedAt    string       `json:"created_at"` // RFC3339 UTC
}

// dummyRecord is built once at package init and used to ensure that
// verification for an unknown username still burns an argon2 work unit,
// preventing timing side-channels from revealing whether a username exists.
var dummyRecord passwordHash

func init() {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	dummyRecord = hashPassword("dummy-constant-password", salt)
}

func hashPassword(password string, salt []byte) passwordHash {
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return passwordHash{
		Algorithm: "argon2id",
		Salt:      base64.RawURLEncoding.EncodeToString(salt),
		Time:      1, MemoryKiB: 64 * 1024, Threads: 4,
		Hash: base64.RawURLEncoding.EncodeToString(key),
	}
}

func (p passwordHash) verify(password string) bool {
	salt, err := base64.RawURLEncoding.DecodeString(p.Salt)
	if err != nil {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(p.Hash)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// InitStore creates the credential directory (0700) and writes an operator
// record. It fails with ErrAlreadyInitialized if operator.json already exists.
// If the directory already exists with wider permissions, InitStore tightens
// it to 0700 before proceeding.
func InitStore(dir, username, password string) (*Store, error) {
	if err := durable.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create credential dir: %w", err)
	}
	// MkdirAll does not chmod an existing directory; enforce 0700 explicitly.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure credential dir: %w", err)
	}
	opPath := filepath.Join(dir, operatorFile)
	if _, err := os.Stat(opPath); err == nil {
		return nil, ErrAlreadyInitialized
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	rec := operatorRecord{
		Version:      1,
		Username:     username,
		PasswordHash: hashPassword(password, salt),
		CreatedAt:    nowUTC(),
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal operator record: %w", err)
	}
	if err := writeFileAtomic(opPath, data); err != nil {
		return nil, fmt.Errorf("write operator record: %w", err)
	}
	return &Store{dir: dir}, nil
}

// OpenStore opens an existing credential store. It fails if operator.json is
// absent (use InitStore to create one) or if the directory has group/other
// access bits set (required mode is 0700; the error names the path so the
// daemon can surface it as a remediable config problem).
func OpenStore(dir string) (*Store, error) {
	di, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("credential store not initialized at %s: %w", dir, err)
	}
	if di.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("credential dir %s has insecure permissions %o (required: 0700); run: chmod 700 %s", dir, di.Mode().Perm(), dir)
	}
	opPath := filepath.Join(dir, operatorFile)
	if _, err := os.Stat(opPath); err != nil {
		return nil, fmt.Errorf("credential store not initialized at %s: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// VerifyPassword checks username and password against the stored operator
// record. Unknown usernames still run a full argon2 computation against the
// package-level dummy record so the call duration reveals no information
// about whether the username exists.
func (s *Store) VerifyPassword(username, password string) (owner string, err error) {
	opPath := filepath.Join(s.dir, operatorFile)
	data, err := os.ReadFile(opPath)
	if err != nil {
		return "", fmt.Errorf("read operator record: %w", err)
	}
	var rec operatorRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return "", fmt.Errorf("parse operator record: %w", err)
	}
	if username != rec.Username {
		// Burn a work unit so timing cannot confirm the username.
		_ = dummyRecord.verify(password)
		return "", ErrBadCredentials
	}
	if !rec.PasswordHash.verify(password) {
		return "", ErrBadCredentials
	}
	return rec.Username, nil
}

// writeFileAtomic publishes private credentials with file and directory barriers.
// A post-rename failure may leave the new bytes visible; callers must return it.
func writeFileAtomic(path string, data []byte) error {
	return durable.WriteFile(path, 0o600, data)
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}
