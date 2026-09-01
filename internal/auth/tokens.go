// ABOUTME: Scoped CLI token management: create, verify, list, and revoke
// ABOUTME: tokens whose SHA-256 hashes are stored at rest; raw secrets never persist.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ErrTokenNotFound is returned by RevokeToken when the token ID does not exist.
var ErrTokenNotFound = errors.New("token not found")

const tokensFile = "tokens.json"

// TokenRecord is the exported view of a token: all fields except the hash.
// ExpiresAt and RevokedAt are RFC3339 UTC strings; "" means none.
type TokenRecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
	RevokedAt string `json:"revoked_at"`
}

// tokenEntry is the internal storage shape: one row in tokens.json.
// sha256Hex is the hex-encoded SHA-256 of the raw secret bytes and never
// leaves this package.
type tokenEntry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	SHA256Hex string `json:"sha256"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"` // "" = no expiry
	RevokedAt string `json:"revoked_at"` // "" = not revoked
}

// tokenStore is the on-disk file shape.
type tokenStore struct {
	Version int          `json:"version"`
	Tokens  []tokenEntry `json:"tokens"`
}

// toRecord copies a tokenEntry to a TokenRecord, dropping the hash.
func (e tokenEntry) toRecord() TokenRecord {
	return TokenRecord{
		ID:        e.ID,
		Name:      e.Name,
		Owner:     e.Owner,
		CreatedAt: e.CreatedAt,
		ExpiresAt: e.ExpiresAt,
		RevokedAt: e.RevokedAt,
	}
}

// loadTokens reads tokens.json from the store directory. A missing file is
// treated as an empty set — the file is written lazily on first CreateToken.
func (s *Store) loadTokens() (tokenStore, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, tokensFile))
	if errors.Is(err, os.ErrNotExist) {
		return tokenStore{Version: 1}, nil
	}
	if err != nil {
		return tokenStore{}, fmt.Errorf("read tokens file: %w", err)
	}
	var ts tokenStore
	if err := json.Unmarshal(data, &ts); err != nil {
		return tokenStore{}, fmt.Errorf("parse tokens file: %w", err)
	}
	return ts, nil
}

// saveTokens writes the token store to disk atomically.
func (s *Store) saveTokens(ts tokenStore) error {
	data, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal tokens: %w", err)
	}
	return writeFileAtomic(filepath.Join(s.dir, tokensFile), data)
}

// CreateToken mints a new token with the given name, owner, and TTL.
// ttl == 0 means no expiry. Returns the raw secret (only exposure ever) and
// the new TokenRecord. The secret is "vmobs_" + base64.RawURLEncoding(32
// random bytes); only its SHA-256 is persisted.
func (s *Store) CreateToken(name, owner string, ttl time.Duration) (secret string, rec TokenRecord, err error) {
	// Generate token secret: 32 random bytes, base64url-encoded with prefix.
	rawSecret := make([]byte, 32)
	if _, err := rand.Read(rawSecret); err != nil {
		return "", TokenRecord{}, fmt.Errorf("generate token secret: %w", err)
	}
	secret = "vmobs_" + base64.RawURLEncoding.EncodeToString(rawSecret)

	// Generate token ID: 4 random bytes, hex-encoded.
	idBytes := make([]byte, 4)
	if _, err := rand.Read(idBytes); err != nil {
		return "", TokenRecord{}, fmt.Errorf("generate token id: %w", err)
	}
	id := "tok-" + hex.EncodeToString(idBytes)

	// Hash the raw secret bytes (not the string) for storage.
	sum := sha256.Sum256([]byte(secret))
	sha256Hex := hex.EncodeToString(sum[:])

	now := nowUTC()
	expiresAt := ""
	if ttl > 0 {
		expiresAt = time.Now().UTC().Add(ttl).Format(time.RFC3339Nano)
	}

	entry := tokenEntry{
		ID:        id,
		Name:      name,
		Owner:     owner,
		SHA256Hex: sha256Hex,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		RevokedAt: "",
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ts, err := s.loadTokens()
	if err != nil {
		return "", TokenRecord{}, err
	}
	ts.Tokens = append(ts.Tokens, entry)
	if err := s.saveTokens(ts); err != nil {
		return "", TokenRecord{}, err
	}

	return secret, entry.toRecord(), nil
}

// VerifyToken checks the candidate secret against the token store.
// Returns ErrBadCredentials for any of: unknown token, revoked token, expired
// token. The caller learns nothing about which condition triggered.
func (s *Store) VerifyToken(secret string) (TokenRecord, error) {
	sum := sha256.Sum256([]byte(secret))
	candidateHex := hex.EncodeToString(sum[:])

	s.mu.Lock()
	defer s.mu.Unlock()

	ts, err := s.loadTokens()
	if err != nil {
		return TokenRecord{}, err
	}

	for _, entry := range ts.Tokens {
		if entry.SHA256Hex != candidateHex {
			continue
		}
		// Hash matched — check revocation.
		if entry.RevokedAt != "" {
			return TokenRecord{}, ErrBadCredentials
		}
		// Check expiry.
		if entry.ExpiresAt != "" {
			exp, err := time.Parse(time.RFC3339Nano, entry.ExpiresAt)
			if err != nil {
				// Unparseable expiry is treated as expired; corrupt record is unsafe.
				return TokenRecord{}, ErrBadCredentials
			}
			if time.Now().UTC().After(exp) {
				return TokenRecord{}, ErrBadCredentials
			}
		}
		return entry.toRecord(), nil
	}

	return TokenRecord{}, ErrBadCredentials
}

// ListTokens returns all token records without any hash fields.
func (s *Store) ListTokens() ([]TokenRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts, err := s.loadTokens()
	if err != nil {
		return nil, err
	}

	records := make([]TokenRecord, 0, len(ts.Tokens))
	for _, entry := range ts.Tokens {
		records = append(records, entry.toRecord())
	}
	return records, nil
}

// RevokeToken marks a token as revoked by ID.
// Returns ErrTokenNotFound if no token with that ID exists.
// Idempotent: revoking an already-revoked token succeeds.
func (s *Store) RevokeToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts, err := s.loadTokens()
	if err != nil {
		return err
	}

	for i, entry := range ts.Tokens {
		if entry.ID != id {
			continue
		}
		// Found — set RevokedAt if not already set (idempotent).
		if ts.Tokens[i].RevokedAt == "" {
			ts.Tokens[i].RevokedAt = nowUTC()
			if err := s.saveTokens(ts); err != nil {
				return err
			}
		}
		return nil
	}

	return ErrTokenNotFound
}
