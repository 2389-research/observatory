# P5: Authentication Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build SPEC §15.1 (R-11): a single local operator account, browser sessions with CSRF protection, scoped CLI tokens, per-resource owner authorization with cross-owner denial (AT-079 API slice), an offline credential bootstrap, and an `https` server mode so the first non-loopback bind is legal. Plus the three P4 follow-ups (Task 1).

**Architecture:** A new `internal/auth` package owns identity, the file-based credential store (argon2id operator record + SHA-256-hashed tokens), and in-memory sessions with CSRF tokens. The API layer gains an authentication middleware (cookie sessions + bearer tokens, exempt list: `GET /meta`, `POST /auth/login`), `/auth/*` endpoints, and per-resource owner checks that answer cross-owner access with the same 404 as an unknown ID. The daemon gains `init-auth` (offline bootstrap) and a TLS listener mode. `require_authentication: false` remains valid only on loopback and injects the `local_operator` identity through the same middleware path — one identity pipeline, no parallel unauthenticated code path.

**Tech Stack:** Go, `golang.org/x/crypto/argon2` (new dependency), stdlib `crypto/*` for tokens/TLS test certs, existing modernc.org/sqlite store, real HTTP in tests.

**Spec:** `docs/SPEC.md` §14 (audit + error taxonomy), §14.1 (CLI), §15.1 (deployment mode), §15.3 (secret handling — no tokens in URLs/logs); R-11; `docs/ACCEPTANCE.md` AT-079 (API slice: cross-owner API access, CSRF mutations). Terminal/WebSocket/artifact/helper-RPC slices of R-11 are Linux-track (L0+).

## Global Constraints

- Canonical gate: `scripts/check` before every commit claim. Direct Go invocations need `env -u GOROOT mise exec -- go ...`.
- TDD per feature; tests use real components (real files under `t.TempDir()`, real SQLite, real HTTP via `httptest`, real TLS handshakes). The fake runtime is unit-test only.
- Every API response bounded; errors carry typed `cause` + `remediation` where the system knows the remediation space (P-06).
- Event kinds MUST be registered in `internal/events` before anything emits them.
- Store-synthesized and host-scoped events ride the host-wide stream (envelope `vm_id` null) — established P2/P3 deviation. Auth events do the same.
- Secrets never in URLs, query strings, logs, or events: no session IDs, token secrets, or passwords in any event `data`, error detail, or log line. Token secrets are shown exactly once at mint.
- Conventional commit per component. No pushes.
- New deviations get recorded in PLAN.md's deviation log at Task 13; the rulings below are pre-approved content for it.
- `docs/` edits (example config) require `uv run docs/validation/check.py` green plus a dated revision appended to `docs/VALIDATION.md` in the same commit.

## Design rulings fixed by this plan (record in PLAN.md deviations at Task 13)

- **A1** — `auth.mode: local_operator` is the only built auth mode. `server.trust_forwarded_identity: true` (reverse-proxy identity, §15.1's "or" branch) is refused at config validation as not built. YAGNI; the spec offers either.
- **A2** — `require_authentication: false` is valid only with `server.mode: loopback_only`; the middleware then injects identity `local_operator` (host-ACL trust — the P1–P4 model, kept for dev). Non-loopback always authenticates; enforced at config validation and at bind.
- **A3** — Sessions are in-memory with a fixed absolute TTL (`auth.session_ttl_minutes`, default 720). Daemon restart logs the browser out. No session material at rest; no sliding renewal.
- **A4** — CSRF: synchronizer token per session, required via `X-CSRF-Token` on every cookie-authenticated mutation (POST/PUT/PATCH/DELETE). Bearer-token requests are exempt (a browser cannot set `Authorization` cross-origin). When an `Origin` header is present on a cookie-authenticated mutation it must exactly equal `server.public_origin`. `auth.csrf_protection`, `auth.session_cookie_http_only` cannot be false while authentication is enabled (config error): there is no built "cookies without CSRF" mode.
- **A5** — CLI tokens: `vmobs_` + 43 base64url chars (256 random bits), stored SHA-256-hashed. Sent as `Authorization: Bearer`. Scope = the owner's full API (single-operator V1): "scoped" means bound to owner identity, revocable, optionally expiring — not per-route grants.
- **A6** — The credential store is a directory (`auth.credential_store`): `operator.json` (argon2id: t=1, m=64MiB, p=4, 16B salt, 32B key, params stored alongside) and `tokens.json`. Dir 0700, files 0600, atomic tempfile+rename writes, re-read per operation (external mint/revoke visible immediately; V1 scale makes caching pointless). Deliberately not in the event-store SQLite: credentials and evidence are different trust domains.
- **A7** — Bootstrap is offline: `vmobsd init-auth` creates the credential store and mints one initial token, printed once. No unauthenticated bootstrap endpoint. Password arrives via `-password-stdin` or `VMOBSD_OPERATOR_PASSWORD`, never argv (§15.3). Re-running against an initialized store is an error. Password rotation = delete + re-init (documented; a rotate command is future work).
- **A8** — Denial taxonomy: missing/invalid credentials → 401 `unauthenticated` (remediation: login or bearer token); expired/unknown session → 401 cause `session_invalid_or_expired`; CSRF/origin failure → 403 `csrf_rejected` / `origin_rejected`; cross-owner resource access → the same 404 `not_found` body as an unknown ID (existence hidden; §14 groups "unauthorized/not found").
- **A9** — Owner scoping applies to owned resources: vms, operations, runs (+ reports), vm-batches, and their mutations. Host-scoped surfaces (meta, events, situation, attention, annotations, host/status, templates) require authentication but not ownership — they are the host's shared evidence plane. Annotations record the authenticated identity as `author`.
- **A10** — System-initiated operations (reconcile repairs, report generation, post-run stops) carry the owning resource's owner — the system acts on the owner's behalf; a distinct `system` owner would hide those operations from the operator's own authorized reads. `ManagerConfig.Owner` is deleted; creation paths take an explicit `owner` parameter from trusted ingress.
- **A11** — Auth event kinds (all `host_observed`, host-wide stream): `auth.session_created`, `auth.session_ended`, `auth.login_failed`, `auth.token_created`, `auth.token_revoked`. Login attempts are globally serialized with a post-failure delay (default 500ms; test-tunable), so the unauthenticated path cannot flood the event stream. Event data carries bounded username (≤64 bytes, truncation marker) and connection remote address — never passwords, session IDs, or token secrets.
- **A12** — `server.mode: https` with `tls_cert_file`/`tls_key_file` is the one non-loopback mode: it forces `require_authentication: true`, `session_cookie_secure: true`, and an `https://` `public_origin`. `loopback_only` mode refuses configured TLS files (a cert nothing serves is a config lie). Exact-origin WebSocket checks arrive with terminals (L0).
- **A13** — Auth routes live at `/api/v1/auth/{login,logout,session,tokens}` — §14's table names no auth routes; §15.1 demands the capability. `GET /auth/session` answers in every mode (identity `local_operator`, method `none` when auth is off) so agents always have a whoami. Login/logout/token routes answer 409 `auth_disabled` when `require_authentication: false`.

## File Structure

```
internal/auth/auth.go            Identity type, context injection helpers
internal/auth/credentials.go     credential store: operator record, argon2id, atomic writes
internal/auth/tokens.go          token mint/verify/list/revoke (SHA-256 at rest)
internal/auth/sessions.go        in-memory sessions, TTL, CSRF tokens
internal/api/auth.go             middleware + /auth/* handlers + auth error shapes
internal/api/api.go              (modify) AuthConfig param, route table, /meta auth block
internal/api/{vms,runs,batches,working_set}.go  (modify) identity threading, owner checks
internal/events/registry.go      (modify) five auth.* kinds
internal/config/config.go        (modify) auth validation, session_ttl_minutes, TLS fields, https mode
internal/runtime/manager.go      (modify) closing gate; owner params; drop cfg.Owner
internal/runtime/runs.go         (modify) async stopVMAfterRun; owner attribution
internal/runtime/batch.go        (modify) owner param
internal/store/vms.go            (modify) VMQuery.Owner filter
internal/store/runs.go           (modify) RunQuery.Owner filter
cmd/vmobsd/main.go               (modify) init-auth subcommand, auth wiring, TLS listener
cmd/vmobs/main.go                (modify) bearer token transport, VMOBS_TOKEN/VMOBS_CA
cmd/vmobs/auth.go                auth subcommands: whoami, token create/list/revoke
docs/examples/host-config.yaml   (modify) session_ttl_minutes, tls_* fields
scripts/smoke                    (modify) full auth flow
```

---

### Task 1: P4 follow-ups — closing gate, async post-run stop, conclude-args HTTP mapping

**Files:**
- Modify: `internal/runtime/manager.go` (Manager struct, Close, all `wg.Add` sites)
- Modify: `internal/runtime/runs.go` (postConclude paths, stopVMAfterRun)
- Modify: `internal/api/runs.go` (conclude error mapping)
- Test: `internal/runtime/manager_test.go`, `internal/runtime/runs_test.go`, `internal/api/runs_test.go`

**Interfaces:**
- Produces: `func (m *Manager) goTracked(fn func()) bool` — starts fn in a wg-tracked goroutine unless the manager is closing; returns whether it started. All later tasks that add manager goroutines MUST use it.

Background (gotchas.md): `wg.Add` sites race `Close()`'s `wg.Wait()`-then-`cancel()`; `stopVMAfterRun` blocks the conclusion goroutine for up to the stop grace period; `ErrConcludeArgsMissing` currently falls through to a 500.

- [ ] **Step 1: Write the failing closing-gate test** in `internal/runtime/manager_test.go`:

```go
// TestCloseGateStopsNewWork: goroutines enqueued after Close starts must not
// start; goroutines enqueued before must complete. Run with -race.
func TestCloseGateStopsNewWork(t *testing.T) {
	m := newTestManager(t) // use the file's existing helper for a fake-runtime manager
	started := make(chan struct{})
	release := make(chan struct{})
	if ok := m.goTracked(func() { close(started); <-release }); !ok {
		t.Fatal("goTracked refused work before Close")
	}
	<-started

	closeDone := make(chan struct{})
	go func() { close(release); m.Close(); close(closeDone) }()
	<-closeDone

	if ok := m.goTracked(func() { t.Error("work started after Close") }); ok {
		t.Fatal("goTracked accepted work after Close")
	}
}
```

Adapt the constructor call to the existing test helper in that file (read it first; do not invent a new helper if one exists).

- [ ] **Step 2: Run it, verify failure** — `goTracked` undefined:

`env -u GOROOT mise exec -- go test ./internal/runtime/ -run TestCloseGateStopsNewWork -race` → compile error.

- [ ] **Step 3: Implement the gate** in `internal/runtime/manager.go`. Add to the Manager struct:

```go
	closeMu sync.RWMutex
	closed  bool
```

Add the method and rewrite Close:

```go
// goTracked runs fn on a goroutine tracked by the close gate. It returns
// false (and does not run fn) once Close has begun: work enqueued during
// shutdown would race wg.Wait. Every manager goroutine must start here.
func (m *Manager) goTracked(fn func()) bool {
	m.closeMu.RLock()
	defer m.closeMu.RUnlock()
	if m.closed {
		return false
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		fn()
	}()
	return true
}

// Close waits for all in-flight tracked goroutines, then releases the
// manager's context. The gate flips first so no new goroutine can slip in
// between wg.Wait and cancel.
func (m *Manager) Close() {
	m.closeMu.Lock()
	m.closed = true
	m.closeMu.Unlock()
	m.wg.Wait()
	m.cancel()
}
```

Convert every existing `m.wg.Add(1); go func() { defer m.wg.Done(); ... }()` site (manager.go launch enqueue, runs.go postConclude report-gen goroutine, runs.go SubmitRunResult conclusion goroutine, and any others `grep -n "wg.Add" internal/runtime` finds) to `m.goTracked(func() { ... })`. Where the old code assumed the goroutine always started, keep behavior sensible on `false`: dropping the work is correct during shutdown (reconcile on next start repairs — that is exactly what reconcile is for; note this in a comment at each converted site where it matters).

- [ ] **Step 4: Make stopVMAfterRun async.** In `internal/runtime/runs.go`, the postConclude path currently calls `m.stopVMAfterRun(run.VMID)` synchronously. Wrap it: `m.goTracked(func() { m.stopVMAfterRun(run.VMID) })`. Update the function comment: it now runs on a tracked goroutine so conclusion returns without waiting out the stop grace period; Close still drains it.

- [ ] **Step 5: Fix tests that assumed synchronous stop.** Run `env -u GOROOT mise exec -- go test ./internal/runtime/ -race`. Any test asserting the VM is `stopping`/`stopped` immediately after a conclusion must poll the store for the state with a deadline (~2s, 10ms interval) instead. Keep assertions on store state, not goroutine timing (gotchas.md).

- [ ] **Step 6: Write the failing API mapping test** in `internal/api/runs_test.go` (use the file's existing server/run helpers):

```go
// TestConcludeRunNoArgsReturns400: POST conclude with neither verdict nor
// abort must answer a typed 400, not a 500.
func TestConcludeRunNoArgsReturns400(t *testing.T) {
	// create an operator_verdict run via the existing helper, then:
	resp := doJSON(t, srv, "POST", "/api/v1/runs/"+runID+"/conclude", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var e struct{ Error struct{ Code, Cause string } }
	decode(t, resp, &e)
	if e.Error.Cause != "conclude_args_missing" {
		t.Fatalf("cause = %q, want conclude_args_missing", e.Error.Cause)
	}
}
```

Match the existing test file's request/decode helpers exactly (read neighboring conclude tests first).

- [ ] **Step 7: Run it, verify failure** (currently 500). Then map the error in `internal/api/runs.go` next to the existing `ErrVerdictCriteriaMismatch` mapping (~line 286):

```go
	if errors.Is(err, runtime.ErrConcludeArgsMissing) {
		writeError(w, http.StatusBadRequest, Error{
			Code:      "validation_failed",
			Message:   "conclude requires a verdict or abort:true",
			Retryable: false,
			Cause:     "conclude_args_missing",
			Details:   map[string]any{"run_id": runID},
		})
		return
	}
```

Copy the exact Error field style of the sibling mappings in that function.

- [ ] **Step 8: Full gate and commit.**

Run: `scripts/check` → green.

```bash
git add internal/runtime/manager.go internal/runtime/runs.go internal/runtime/manager_test.go internal/runtime/runs_test.go
git commit -m "fix(runtime): close gate for tracked goroutines; async post-run stop"
git add internal/api/runs.go internal/api/runs_test.go
git commit -m "fix(api): map ErrConcludeArgsMissing to 400 conclude_args_missing"
```

Also remove the now-fixed "Manager wg.Add/Close race" and "stopVMAfterRun latency" entries from `gotchas.md` (replace with one line describing goTracked as the required pattern) — fold into the first commit.

---

### Task 2: internal/auth — identity and credential store

**Files:**
- Create: `internal/auth/auth.go`, `internal/auth/credentials.go`
- Test: `internal/auth/credentials_test.go`

**Interfaces:**
- Produces:
  - `type Identity struct { Owner, Method, SessionID, TokenID string }` (Method ∈ `"session" | "token" | "none"`)
  - `func WithIdentity(ctx context.Context, id Identity) context.Context` / `func IdentityFrom(ctx context.Context) (Identity, bool)`
  - `func InitStore(dir, username, password string) (*Store, error)` — mkdir 0700, writes operator.json; error if operator.json exists
  - `func OpenStore(dir string) (*Store, error)` — error if operator.json missing
  - `func (s *Store) VerifyPassword(username, password string) (owner string, err error)` — constant-shape: unknown username still runs argon2 against a fixed dummy hash
  - `var ErrBadCredentials = errors.New(...)`, `var ErrAlreadyInitialized = errors.New(...)`

- [ ] **Step 1: Write failing tests** in `internal/auth/credentials_test.go`:

```go
package auth

import (
	"errors"
	"os"
	"path/filepath"
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
```

- [ ] **Step 2: Run, verify compile failure.** `env -u GOROOT mise exec -- go test ./internal/auth/` → package does not exist.

- [ ] **Step 3: Implement.** `internal/auth/auth.go`:

```go
// ABOUTME: Identity carried by authenticated requests, and the context
// ABOUTME: plumbing trusted ingress uses to hand it to handlers.
package auth

import "context"

// Identity is who a request acts as. Owner is the resource-owner string
// persisted on created rows. Method records how the identity was proven:
// "session" (cookie), "token" (bearer), or "none" (auth disabled by config).
type Identity struct {
	Owner     string
	Method    string
	SessionID string // set when Method == "session"
	TokenID   string // set when Method == "token"
}

type ctxKey struct{}

// WithIdentity is called only by the API middleware (trusted ingress).
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}
```

`internal/auth/credentials.go` — the operator record. Argon2id params t=1, m=64*1024 KiB, p=4, 32-byte key, 16-byte random salt; params serialized next to the hash so verification never guesses:

```go
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

	"golang.org/x/crypto/argon2"
)

var (
	ErrBadCredentials     = errors.New("invalid username or password")
	ErrAlreadyInitialized = errors.New("credential store already initialized")
)

const operatorFile = "operator.json"

type Store struct {
	dir string
	mu  sync.Mutex // serializes file writes (tokens.json read-modify-write)
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
```

`InitStore`: `os.MkdirAll(dir, 0o700)`, fail with `ErrAlreadyInitialized` if operator.json exists (`os.Stat`), generate salt via `crypto/rand`, write record with `writeFileAtomic`. `OpenStore`: stat dir and operator.json, return `&Store{dir: dir}`. `VerifyPassword`: read operator.json; if username mismatch, verify against a package-level dummy record (built once from a fixed salt+password at init) and return `ErrBadCredentials` regardless — the work factor stays constant either way. `writeFileAtomic(path string, data []byte)`: `os.CreateTemp` in dir, chmod 0600, write, close, `os.Rename`. `nowUTC()` helper returning `time.Now().UTC().Format(time.RFC3339)`.

Dependency: after the import exists, run `env -u GOROOT mise exec -- go get golang.org/x/crypto@latest && env -u GOROOT mise exec -- go mod tidy` (gotcha: never `go get` before the import is written).

- [ ] **Step 4: Run tests, verify pass.** `env -u GOROOT mise exec -- go test ./internal/auth/ -race` → PASS. (The argon2 dummy-verify makes failures take ~50ms each; that is the intended work factor, not a slow test to fix.)

- [ ] **Step 5: Commit.**

```bash
git add internal/auth/auth.go internal/auth/credentials.go internal/auth/credentials_test.go go.mod go.sum
git commit -m "feat(auth): identity type and argon2id credential store"
```

---

### Task 3: internal/auth — scoped tokens

**Files:**
- Create: `internal/auth/tokens.go`
- Test: `internal/auth/tokens_test.go`

**Interfaces:**
- Produces:
  - `type TokenRecord struct { ID, Name, Owner, CreatedAt string; ExpiresAt, RevokedAt string /* "" = none, RFC3339 */ }`
  - `func (s *Store) CreateToken(name, owner string, ttl time.Duration) (secret string, rec TokenRecord, err error)` — ttl 0 = no expiry
  - `func (s *Store) VerifyToken(secret string) (TokenRecord, error)` — `ErrBadCredentials` on unknown/revoked/expired
  - `func (s *Store) ListTokens() ([]TokenRecord, error)` — never returns hashes
  - `func (s *Store) RevokeToken(id string) error` — `ErrTokenNotFound` if absent; idempotent if already revoked
  - `var ErrTokenNotFound = errors.New(...)`

- [ ] **Step 1: Write failing tests** in `internal/auth/tokens_test.go`:

```go
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
```

- [ ] **Step 2: Run, verify failure** (undefined functions).

- [ ] **Step 3: Implement** `internal/auth/tokens.go`. Storage shape `tokens.json`: `{"version":1,"tokens":[{id,name,owner,sha256,created_at,expires_at,revoked_at}]}` where `sha256` is hex of the raw secret bytes' hash. Secret: `"vmobs_" + base64.RawURLEncoding(32 random bytes)`; ID: `"tok-" + hex(4 random bytes)`. All operations take `s.mu`, read the file fresh (`os.ReadFile`, missing file = empty set), act, and (for writes) persist via `writeFileAtomic`. `VerifyToken`: hash the candidate with `sha256.Sum256`, linear scan for the hex match, then check `RevokedAt == ""` and expiry (`ExpiresAt == "" || now < ExpiresAt`); any miss → `ErrBadCredentials` (one error for unknown/revoked/expired: a probing client learns nothing). `ListTokens` returns records copied without the hash field (the internal storage struct and the exported `TokenRecord` are separate types; the hash never leaves the package). Time comparisons parse RFC3339 UTC strings.

- [ ] **Step 4: Run tests, verify pass** with `-race`.

- [ ] **Step 5: Commit.**

```bash
git add internal/auth/tokens.go internal/auth/tokens_test.go
git commit -m "feat(auth): scoped CLI tokens hashed at rest"
```

---

### Task 4: internal/auth — sessions with CSRF tokens

**Files:**
- Create: `internal/auth/sessions.go`
- Test: `internal/auth/sessions_test.go`

**Interfaces:**
- Produces:
  - `type Session struct { ID, Owner, CSRFToken string; CreatedAt, ExpiresAt time.Time }`
  - `func NewSessions(ttl time.Duration) *Sessions`
  - `func (s *Sessions) Create(owner string) Session`
  - `func (s *Sessions) Get(id string) (Session, bool)` — false for unknown or expired (expired entries deleted lazily)
  - `func (s *Sessions) Revoke(id string) bool`

- [ ] **Step 1: Write failing tests** in `internal/auth/sessions_test.go`:

```go
func TestSessionLifecycle(t *testing.T) {
	sm := NewSessions(time.Hour)
	sess := sm.Create("local_operator")
	if sess.ID == "" || sess.CSRFToken == "" || sess.ID == sess.CSRFToken {
		t.Fatalf("weak session material: %+v", sess)
	}
	got, ok := sm.Get(sess.ID)
	if !ok || got.Owner != "local_operator" {
		t.Fatalf("Get = %+v, %v", got, ok)
	}
	if !sm.Revoke(sess.ID) {
		t.Fatal("Revoke returned false for a live session")
	}
	if _, ok := sm.Get(sess.ID); ok {
		t.Fatal("session survived revoke")
	}
}

func TestSessionExpiry(t *testing.T) {
	sm := NewSessions(10 * time.Millisecond)
	sess := sm.Create("op")
	time.Sleep(30 * time.Millisecond)
	if _, ok := sm.Get(sess.ID); ok {
		t.Fatal("expired session still valid")
	}
}

func TestSessionIDsUnique(t *testing.T) {
	sm := NewSessions(time.Hour)
	seen := map[string]bool{}
	for range 100 {
		s := sm.Create("op")
		if seen[s.ID] {
			t.Fatal("duplicate session ID")
		}
		seen[s.ID] = true
	}
}
```

- [ ] **Step 2: Run, verify failure.**

- [ ] **Step 3: Implement** `internal/auth/sessions.go`: map keyed by ID under a mutex; IDs and CSRF tokens are `base64.RawURLEncoding` of 32 `crypto/rand` bytes each; `Create` opportunistically sweeps expired entries (no background goroutine — the daemon has enough lifecycles to manage); `Get` deletes-and-refuses expired entries; fixed absolute expiry `CreatedAt.Add(ttl)` (ruling A3). ABOUTME header: in-memory browser sessions; restart logs the operator out by design.

- [ ] **Step 4: Run tests, verify pass** with `-race`.

- [ ] **Step 5: Commit.**

```bash
git add internal/auth/sessions.go internal/auth/sessions_test.go
git commit -m "feat(auth): in-memory sessions with absolute TTL and CSRF tokens"
```

---

### Task 5: config — auth validation, session TTL, https mode fields

**Files:**
- Modify: `internal/config/config.go`
- Modify: `docs/examples/host-config.yaml`, `docs/VALIDATION.md`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces:
  - `Auth.SessionTTLMinutes int` (yaml `session_ttl_minutes`; 0 → default 720 applied in `Load`)
  - `Server.TLSCertFile, Server.TLSKeyFile string` (yaml `tls_cert_file`, `tls_key_file`)
  - `server.mode` accepts `loopback_only` and `https`; validation matrix per rulings A1/A2/A4/A12
  - `func (c *Config) AuthEnabled() bool` → `c.Auth.RequireAuthentication`

- [ ] **Step 1: Write failing table tests** in `internal/config/config_test.go`. Follow the file's existing test style (read it first). Cases, each mutating a known-good base config (helper: load the docs example, then tweak):

```go
func TestAuthAndModeValidation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string // substring; "" = valid
	}{
		{"example is valid", func(c *Config) {}, ""},
		{"trust_forwarded_identity refused", func(c *Config) { c.Server.TrustForwardedIdentity = true }, "trust_forwarded_identity"},
		{"auth mode must be local_operator", func(c *Config) { c.Auth.Mode = "reverse_proxy" }, "auth.mode"},
		{"auth on requires credential store", func(c *Config) { c.Auth.CredentialStore = "" }, "credential_store"},
		{"auth on requires csrf", func(c *Config) { c.Auth.CSRFProtection = false }, "csrf_protection"},
		{"auth on requires httponly", func(c *Config) { c.Auth.SessionCookieHTTPOnly = false }, "session_cookie_http_only"},
		{"samesite none refused", func(c *Config) { c.Auth.SessionCookieSameSite = "none" }, "session_cookie_same_site"},
		{"negative ttl refused", func(c *Config) { c.Auth.SessionTTLMinutes = -1 }, "session_ttl_minutes"},
		{"https mode needs cert", func(c *Config) { c.Server.Mode = "https"; c.Server.TLSKeyFile = "k.pem" }, "tls_cert_file"},
		{"https mode needs key", func(c *Config) { c.Server.Mode = "https"; c.Server.TLSCertFile = "c.pem" }, "tls_key_file"},
		{"https forces auth", func(c *Config) {
			c.Server.Mode = "https"
			c.Server.TLSCertFile, c.Server.TLSKeyFile = "c.pem", "k.pem"
			c.Server.PublicOrigin = "https://vmobs.example:8787"
			c.Auth.SessionCookieSecure = true
			c.Auth.RequireAuthentication = false
		}, "require_authentication"},
		{"https forces secure cookies", func(c *Config) {
			c.Server.Mode = "https"
			c.Server.TLSCertFile, c.Server.TLSKeyFile = "c.pem", "k.pem"
			c.Server.PublicOrigin = "https://vmobs.example:8787"
			c.Auth.SessionCookieSecure = false
		}, "session_cookie_secure"},
		{"https needs https origin", func(c *Config) {
			c.Server.Mode = "https"
			c.Server.TLSCertFile, c.Server.TLSKeyFile = "c.pem", "k.pem"
			c.Auth.SessionCookieSecure = true
			// PublicOrigin stays http://...
		}, "public_origin"},
		{"https allows non-loopback listen", func(c *Config) {
			c.Server.Mode = "https"
			c.Server.TLSCertFile, c.Server.TLSKeyFile = "c.pem", "k.pem"
			c.Server.PublicOrigin = "https://vmobs.example:8787"
			c.Auth.SessionCookieSecure = true
			c.Server.Listen = "0.0.0.0:8787"
		}, ""},
		{"loopback mode refuses tls files", func(c *Config) { c.Server.TLSCertFile = "c.pem" }, "tls_cert_file"},
		{"unknown mode refused", func(c *Config) { c.Server.Mode = "tailscale" }, "server.mode"},
	}
	// for each: load example, mutate, Validate(), assert error substring or nil.
}
```

Also a small test: `SessionTTLMinutes` 0 in YAML → 720 after `Load` (write a minimal temp YAML omitting the field).

- [ ] **Step 2: Run, verify failures** (unknown fields / missing validation).

- [ ] **Step 3: Implement.** Add the three struct fields. In `Validate`, replace the hard `loopback_only` check with the matrix:

```go
	switch c.Server.Mode {
	case "loopback_only":
		if err := requireLoopback(c.Server.Listen); err != nil {
			add("server.listen: %v", err)
		}
		if c.Server.TLSCertFile != "" || c.Server.TLSKeyFile != "" {
			add("tls_cert_file/tls_key_file are set but server.mode is loopback_only; a cert nothing serves is a config lie")
		}
		// require_authentication: false is legal here and only here —
		// loopback + host ACLs, the P1–P4 trust model, kept for dev.
	case "https":
		if c.Server.TLSCertFile == "" {
			add("server.mode https requires tls_cert_file")
		}
		if c.Server.TLSKeyFile == "" {
			add("server.mode https requires tls_key_file")
		}
		if !c.Auth.RequireAuthentication {
			add("server.mode https requires auth.require_authentication: true")
		}
		if !c.Auth.SessionCookieSecure {
			add("server.mode https requires auth.session_cookie_secure: true")
		}
		if !strings.HasPrefix(c.Server.PublicOrigin, "https://") {
			add("server.mode https requires an https:// public_origin, got %q", c.Server.PublicOrigin)
		}
	default:
		add("server.mode %q is not supported: loopback_only or https", c.Server.Mode)
	}
	if c.Server.TrustForwardedIdentity {
		add("server.trust_forwarded_identity is not built in this version; only direct local_operator auth exists")
	}
	if c.Auth.RequireAuthentication {
		if c.Auth.Mode != "local_operator" {
			add("auth.mode %q is not built: only local_operator", c.Auth.Mode)
		}
		if c.Auth.CredentialStore == "" {
			add("auth.credential_store is required when require_authentication is true")
		}
		if !c.Auth.CSRFProtection {
			add("auth.csrf_protection cannot be disabled while authentication is enabled")
		}
		if !c.Auth.SessionCookieHTTPOnly {
			add("auth.session_cookie_http_only cannot be disabled while authentication is enabled")
		}
		if ss := c.Auth.SessionCookieSameSite; ss != "strict" && ss != "lax" {
			add("auth.session_cookie_same_site must be strict or lax, got %q", ss)
		}
	}
	if c.Auth.SessionTTLMinutes < 0 {
		add("auth.session_ttl_minutes must be >= 0, got %d", c.Auth.SessionTTLMinutes)
	}
```

In `Load`, after decode, default: `if cfg.Auth.SessionTTLMinutes == 0 { cfg.Auth.SessionTTLMinutes = 720 }` (before Validate). Add `AuthEnabled()`.

- [ ] **Step 4: Update the example config.** In `docs/examples/host-config.yaml` add under `auth:`: `session_ttl_minutes: 720` (comment: absolute browser-session lifetime; restart also ends sessions) and under `server:`: `tls_cert_file: ""` / `tls_key_file: ""` (comment: required in `mode: https`, must be empty in loopback_only). Run `uv run docs/validation/check.py` → green; append a dated revision line to `docs/VALIDATION.md` with the real output summary.

- [ ] **Step 5: Run tests + gate.** `scripts/check` → green (config tests + docs check).

- [ ] **Step 6: Commit.**

```bash
git add internal/config/config.go internal/config/config_test.go docs/examples/host-config.yaml docs/VALIDATION.md
git commit -m "feat(config): auth and https-mode validation matrix"
```

---

### Task 6: events — register auth kinds

**Files:**
- Modify: `internal/events/registry.go`
- Test: `internal/events/registry_test.go`

**Interfaces:**
- Produces registered kinds: `auth.session_created`, `auth.session_ended`, `auth.login_failed`, `auth.token_created`, `auth.token_revoked` — all provenance `host_observed`, family `auth`.

- [ ] **Step 1: Write the failing test.** Read `registry_test.go` first and extend its existing registration-coverage test style:

```go
func TestAuthKindsRegistered(t *testing.T) {
	for _, k := range []string{
		"auth.session_created", "auth.session_ended", "auth.login_failed",
		"auth.token_created", "auth.token_revoked",
	} {
		def, ok := events.Lookup(k) // use the registry's actual lookup API
		if !ok {
			t.Fatalf("%s not registered", k)
		}
		if def.Provenance != "host_observed" {
			t.Fatalf("%s provenance = %q", k, def.Provenance)
		}
	}
}
```

Adapt `Lookup`/field names to the registry's real API (read the file; do not guess).

- [ ] **Step 2: Run, verify failure.**

- [ ] **Step 3: Register the five kinds** following the exact entry shape of existing kinds (semantics + caveats fields as the table defines). Semantics one-liners: session_created "operator login established a browser session"; session_ended "operator logout ended a session" (caveat: expiry is lazy and does not emit); login_failed "a login attempt failed" (caveat: serialized and delayed at ingress, so volume is bounded; username is bounded to 64 bytes); token_created "a CLI token was minted" (caveat: data carries token id and name, never the secret); token_revoked "a CLI token was revoked". Ensure `family=auth` is queryable wherever families are derived/validated (follow how `run.*` kinds made `family=run` valid — grep `familyKnown` or equivalent).

- [ ] **Step 4: Run package tests, verify pass.** Also `env -u GOROOT mise exec -- go test ./internal/store/ -run Family` (or the relevant family-validation tests) to confirm `family=auth` queries validate.

- [ ] **Step 5: Commit.**

```bash
git add internal/events/registry.go internal/events/registry_test.go
git commit -m "feat(events): register auth event kinds"
```

---

### Task 7: API — authentication middleware, /auth/login|logout|session, CSRF

**Files:**
- Create: `internal/api/auth.go`
- Modify: `internal/api/api.go` (New signature, route table, /meta)
- Modify: `cmd/vmobsd/main.go` (serve() wiring)
- Modify: all `api.New` call sites in tests (`internal/api/api_test.go` helpers, `internal/api/working_set_test.go`, `cmd/vmobs/main_test.go`, `cmd/vmobsd/main_test.go`)
- Test: `internal/api/auth_test.go`

**Interfaces:**
- Consumes: Task 2 `auth.Store`/`Identity`, Task 4 `auth.Sessions`, Task 5 config fields, Task 6 kinds.
- Produces:
  - `type AuthConfig struct { Enabled bool; Creds *auth.Store; Sessions *auth.Sessions; PublicOrigin string; CookieSameSite http.SameSite; CookieSecure bool; LoginDelay time.Duration }`
  - `func New(st *store.Store, eng *situation.Engine, mgr *runtime.Manager, ac AuthConfig) http.Handler`
  - Routes: `POST /auth/login`, `POST /auth/logout`, `GET /auth/session`; feature `auth`; `/meta` gains `"auth": {"required": bool, "mode": "local_operator"}` and Links `auth_login`, `auth_session`.
  - Cookie name `vmobs_session`; CSRF header `X-CSRF-Token`.
  - Later tasks read identity via `auth.IdentityFrom(r.Context())` — it is ALWAYS present on non-exempt routes (method `none` when disabled).

- [ ] **Step 1: Write failing tests** in `internal/api/auth_test.go`. Build two helpers next to the existing `newServer` pattern (read `api_test.go` first and reuse its store/engine/manager construction):

```go
// newAuthServer: credential store in t.TempDir() with operator
// local_operator / password "correct-horse-battery", sessions TTL 1h,
// LoginDelay 1ms, PublicOrigin "http://127.0.0.1:8787".
// Returns (*httptest.Server, *auth.Store).
```

Test cases (each a separate test function; use real HTTP requests against httptest):

1. `TestUnauthenticatedRequestsDenied`: with auth enabled, `GET /api/v1/vms`, `GET /api/v1/events`, `POST /api/v1/vms` all → 401, body code `unauthenticated`, remediation array non-empty and mentioning `/api/v1/auth/login`. `GET /api/v1/meta` → 200 (exempt).
2. `TestLoginLogoutFlow`: `POST /auth/login` `{"username":"local_operator","password":"correct-horse-battery"}` → 200; response body has `owner`, `expires_at`, `csrf_token`; `Set-Cookie` has `vmobs_session`, `HttpOnly`, `SameSite=Strict`, `Path=/`. Cookie + CSRF header on `GET /auth/session` → 200 same owner (GET needs no CSRF; assert it works without the header too). `POST /auth/logout` with cookie + CSRF → 200; the same cookie afterward → 401 cause `session_invalid_or_expired`.
3. `TestLoginBadPassword`: wrong password → 401 code `unauthenticated`, cause `invalid_credentials`; store gains one `auth.login_failed` event (query the store directly for kind); its data contains no password material (assert the literal password string absent from the raw event payload).
4. `TestCSRFEnforced` (AT-079 CSRF slice): login; cookie-authed `POST /api/v1/annotations` without `X-CSRF-Token` → 403 cause `csrf_rejected`, and the annotation was NOT created (list is empty — deny without side effects); with a wrong token → 403; with the right token → 2xx.
5. `TestOriginChecked`: cookie-authed mutation with `Origin: https://evil.example` → 403 cause `origin_rejected`; with `Origin` equal to PublicOrigin → passes CSRF stage (2xx given the token).
6. `TestAuthDisabledInjectsLocalOperator`: `AuthConfig{Enabled: false}` server: `GET /api/v1/vms` → 200 with no credentials; `GET /auth/session` → 200 `{"owner":"local_operator","method":"none"}`; `POST /auth/login` → 409 code `auth_disabled`.
7. `TestSessionEventsEmitted`: successful login emits `auth.session_created`; logout emits `auth.session_ended`; neither event's raw payload contains the session cookie value (grab it from the jar and assert absence).

- [ ] **Step 2: Run, verify compile failure** (`AuthConfig` undefined).

- [ ] **Step 3: Implement `internal/api/auth.go`.** Key pieces:

```go
// ABOUTME: Authentication boundary: session-cookie and bearer-token
// ABOUTME: middleware, /auth handlers, CSRF and origin enforcement.
```

- `AuthConfig` as in Interfaces. `api.New` becomes `New(st, eng, mgr, ac AuthConfig)`; it keeps building the mux, then returns `s.withAuth(s.mux)`.
- `withAuth(next http.Handler) http.Handler`:
  - Exempt: `GET basePath+"/meta"` and `POST basePath+"/auth/login"` → pass through untouched.
  - `!ac.Enabled` → inject `auth.Identity{Owner: "local_operator", Method: "none"}`, next.
  - `Authorization: Bearer <secret>` present → `Creds.VerifyToken`; failure → 401 cause `invalid_token`; success → identity `{Owner, Method: "token", TokenID}`.
  - Else cookie `vmobs_session` → `Sessions.Get`; miss → 401 cause `session_invalid_or_expired` (plus expire the cookie in the response); hit → identity `{Owner, Method: "session", SessionID}`.
  - Neither → 401 `unauthenticated`, remediation: `[{action: "login", method: "POST", path: "/api/v1/auth/login", rationale: "obtain a session cookie"}, {action: "bearer_token", rationale: "send Authorization: Bearer with a token from vmobs auth token create"}]` — match the existing `Remediation` struct fields exactly (read `errors.go`).
  - Session identity + mutating method (`POST|PUT|PATCH|DELETE`): if `Origin` header present and != `ac.PublicOrigin` → 403 `origin_rejected`. Then `X-CSRF-Token` must equal the session's CSRFToken (constant-time compare) → else 403 `csrf_rejected` with remediation "GET /api/v1/auth/session and send its csrf_token in X-CSRF-Token".
  - Inject identity, next.
- `handleAuthLogin`: 409 `auth_disabled` when `!ac.Enabled`. `http.MaxBytesReader` 4096. Decode `{username, password}`. Global `loginMu sync.Mutex` on the Server serializes attempts. On `ErrBadCredentials`: append `auth.login_failed` event (data: `username` truncated to 64 bytes with `truncated: true` marker when cut, `remote_addr` from `r.RemoteAddr`), sleep `ac.LoginDelay`, 401 cause `invalid_credentials`. On success: `Sessions.Create(owner)`, set cookie (HttpOnly always — config validation guarantees it; SameSite/Secure from ac; Path `/`; `Expires` = session expiry), append `auth.session_created` (data: owner, remote_addr, expires_at — no session ID), respond `{owner, expires_at, csrf_token}`.
- `handleAuthLogout`: requires session identity (bearer → 400 cause `not_a_session`); revoke, expire cookie, append `auth.session_ended` (data: owner, reason "logout"), respond `{"ended": true}`.
- `handleAuthSession`: whoami per ruling A13: session → `{owner, method: "session", expires_at, csrf_token}`; token → `{owner, method: "token", token_id}`; none → `{owner, method: "none"}`.
- Event appends go through the store exactly as other host-scoped events do (host-wide stream, envelope vm_id null) — copy the pattern from the attention/annotation append sites in the store/api, using the store's public append surface from the api package (find how `annotation.created` reaches the store from `working_set.go` and mirror it).
- `/meta`: add `Auth struct{ Required bool; Mode string }` to the meta payload plus Links `auth_login`, `auth_session`.

- [ ] **Step 4: Wire the daemon.** In `cmd/vmobsd/main.go` `serve()`: when `cfg.AuthEnabled()`, `auth.OpenStore(cfg.Auth.CredentialStore)` — on error, refuse to serve: `fmt.Errorf("auth.require_authentication is true but the credential store at %s is not initialized (run: vmobsd init-auth -config ...): %w", ...)`. Build `auth.NewSessions(time.Duration(cfg.Auth.SessionTTLMinutes) * time.Minute)`. Map SameSite string → `http.SameSiteStrictMode`/`Lax`. `LoginDelay: 500 * time.Millisecond`. Pass `AuthConfig` to `api.New`.

- [ ] **Step 5: Mechanical sweep.** Update every `api.New(` call site: existing non-auth tests pass `api.AuthConfig{Enabled: false}` (they keep testing their own concerns under the dev identity). Check `scripts/smoke`'s generated config: if it sets `require_authentication: true`, flip it to `false` for now (Task 13 turns the full flow on); leave a `# P5 Task 13 enables auth here` comment.

- [ ] **Step 6: Run the full gate.** `scripts/check` → green, including `-race` on `./internal/api/`.

- [ ] **Step 7: Commit.**

```bash
git add internal/api/auth.go internal/api/api.go internal/api/auth_test.go internal/api/api_test.go internal/api/working_set_test.go cmd/vmobsd/main.go cmd/vmobs/main_test.go cmd/vmobsd/main_test.go scripts/smoke
git commit -m "feat(api): authentication boundary with sessions and CSRF"
```

---

### Task 8: API — token management endpoints

**Files:**
- Modify: `internal/api/auth.go`, `internal/api/api.go` (routes)
- Test: `internal/api/auth_test.go`

**Interfaces:**
- Consumes: Task 3 token store, Task 7 middleware/identity.
- Produces: `POST /auth/tokens` `{name, ttl_minutes?}` → 201 `{token: {id,name,owner,created_at,expires_at}, secret}` (secret appears exactly here, never again); `GET /auth/tokens` → `{tokens: [...]}` no secrets; `DELETE /auth/tokens/{id}` → 200 `{revoked: true}`, 404 unknown id.

- [ ] **Step 1: Write failing tests** (extend `auth_test.go`, reuse `newAuthServer` + a logged-in session):

1. `TestTokenLifecycleOverAPI`: session+CSRF `POST /auth/tokens` `{"name":"ci"}` → 201 with `vmobs_`-prefixed secret; that secret as `Authorization: Bearer` on `GET /api/v1/vms` → 200; `GET /auth/tokens` → one record, raw body does not contain the secret; session+CSRF `DELETE /auth/tokens/{id}` → 200; the bearer now → 401; store has `auth.token_created` + `auth.token_revoked` events whose payloads don't contain the secret.
2. `TestTokenCreateRequiresAuth`: no credentials → 401; bearer-token identity may mint (a token can mint a successor — single-operator V1) → 201.
3. `TestTokenTTL`: `{"name":"short","ttl_minutes":1}` → record `expires_at` non-empty ≈ now+1m.
4. `TestTokenEndpointsDisabled`: `Enabled: false` server → `POST /auth/tokens` 409 `auth_disabled`.

- [ ] **Step 2: Run, verify failure** (routes 404).

- [ ] **Step 3: Implement** the three handlers in `internal/api/auth.go` + route-table rows (feature `auth`). Creation assigns owner from `auth.IdentityFrom(ctx)` — the request body has no owner field (trusted-ingress assignment, same rule as annotations). `ttl_minutes` ≤ 0 or absent → no expiry; bound name to 128 bytes (400 `validation_failed` beyond). Emit `auth.token_created` / `auth.token_revoked` (data: token id, name, owner).

- [ ] **Step 4: Run tests, verify pass.** `scripts/check` → green.

- [ ] **Step 5: Commit.**

```bash
git add internal/api/auth.go internal/api/api.go internal/api/auth_test.go
git commit -m "feat(api): token mint, list, revoke endpoints"
```

---

### Task 9: owner scoping — identity threading and cross-owner denial (AT-079 API slice)

**Files:**
- Modify: `internal/api/{vms,runs,batches,working_set}.go` — identity from context; owner checks
- Modify: `internal/runtime/manager.go`, `internal/runtime/batch.go`, `internal/runtime/runs.go` — owner parameters; delete `ManagerConfig.Owner` and `Manager.Owner()`
- Modify: `internal/store/vms.go` (`VMQuery.Owner`), `internal/store/runs.go` (`RunQuery.Owner`)
- Test: `internal/api/owner_scope_test.go`, plus mechanical updates across runtime/api/store tests

**Interfaces:**
- Consumes: identity injection from Task 7.
- Produces:
  - `Manager.CreateVM(ctx, owner string, req CreateVMRequest)` (adapt name/shape to the real current signature — owner becomes the first data argument)
  - `Manager.CreateBatch(ctx, owner string, ...)` likewise
  - `VMQuery.Owner string` / `RunQuery.Owner string` — when non-empty, SQL adds `AND owner = ?`
  - api helper: `func (s *Server) resourceOwner(w http.ResponseWriter, r *http.Request, owner string) bool` — writes the standard 404 `not_found` body (same writer as unknown-ID) and returns false when `owner != identity.Owner`

- [ ] **Step 1: Write failing cross-owner tests** in `internal/api/owner_scope_test.go`. Seed a foreign owner's resources directly through the store (the test is trusted ingress): create a VM row, a run, an operation, and a batch owned by `"other_operator"` using the store's own creation functions with that owner. Authenticate normally (bearer token from `newAuthServer`, owner `local_operator`). Assert, naming AT-079 in a comment:

```go
// AT-079 (API slice): cross-owner access is denied without side effects,
// indistinguishable from a missing resource.
```

1. `GET /vms/{foreignID}` → 404, body identical (code+cause) to `GET /vms/vm-nonexistent`.
2. `POST /vms/{foreignID}/actions` (valid stop body, correct expected_revision) → 404 AND the foreign VM's state is unchanged in the store (no side effects) AND no new operation row exists for it.
3. `DELETE /vms/{foreignID}` → 404; VM still present.
4. `GET /operations/{foreignOpID}` → 404. `GET /vm-batches/{foreignBatchID}` → 404.
5. `GET /runs/{foreignRunID}` → 404; `GET /runs/{foreignRunID}/report` → 404; `POST /runs/{foreignRunID}/conclude` (abort) → 404 and the run's phase unchanged.
6. `POST /vms/{foreignID}/runs` → 404.
7. `GET /vms` and `GET /runs` list responses exclude foreign rows entirely.
8. Owned resources still fully work (create a VM as local_operator via the API, get/action it → 2xx) — scoping must not break the owner's own path.
9. Created resources carry the authenticated owner: a VM created through the API has `owner == "local_operator"` in the store (assigned from the token identity, never from a request field), and an annotation created via the API has `author == "local_operator"`.

- [ ] **Step 2: Run, verify failures** (foreign resources currently visible).

- [ ] **Step 3: Implement.**
- api: at the top of every owned-resource handler, `ident, _ := auth.IdentityFrom(r.Context())` (middleware guarantees presence; on the impossible miss, 500). After fetching the resource, `if !s.resourceOwner(w, r, res.Owner) { return }` before ANY action or operation insert. List handlers set `q.Owner = ident.Owner`. Run creation uses `ident.Owner` (replacing `s.manager.Owner()` at runs.go:356). Annotations author + attention-ack actor use `ident.Owner`; delete the `operatorAuthor` const.
- store: add `Owner` to `VMQuery`/`RunQuery`, `AND owner = ?` when non-empty. Extend one existing store list test per query type with an owner-filter case.
- runtime: `CreateVM`/`CreateBatch` take `owner string` explicitly (callers: api handlers pass `ident.Owner`); internal action/report/stop paths attribute to the resource's stored owner (ruling A10): `InsertActionOperation{Owner: vm.Owner}`, `InsertReportOperation(..., run.Owner, ...)`, `stopVMAfterRun` uses the VM's owner. Delete `ManagerConfig.Owner` and `Manager.Owner()`; fix every construction site (tests) — mechanical, `grep -rn "Owner:" internal/runtime cmd | grep -v _test` first, then tests.
- `cmd/vmobsd/main.go`: drop the `Owner: "local_operator"` line from ManagerConfig.

- [ ] **Step 4: Run the full gate.** `scripts/check` → green with `-race`. The pre-existing suites (vms/runs/batches tests) must pass unmodified in behavior — where they constructed ManagerConfig with Owner, pass owner at the call sites instead.

- [ ] **Step 5: Commit.**

```bash
git add internal/api internal/runtime internal/store cmd/vmobsd
git commit -m "feat(api): per-resource owner authorization with cross-owner 404s"
```

---

### Task 10: vmobsd init-auth — offline bootstrap

**Files:**
- Modify: `cmd/vmobsd/main.go` (subcommand dispatch)
- Test: `cmd/vmobsd/main_test.go`

**Interfaces:**
- Consumes: `auth.InitStore`, `auth.Store.CreateToken`.
- Produces: `vmobsd init-auth -config PATH [-username local_operator] [-token-name initial] [-password-stdin]` → creates credential store at `cfg.Auth.CredentialStore`, mints one token, prints exactly: line 1 `operator: <username>`, line 2 `token: <secret>` to stdout (everything else to stderr). Exit 1 with a clear error on re-init. Password from `-password-stdin` (first line of stdin) or `VMOBSD_OPERATOR_PASSWORD`; both absent → usage error. No `-password` argv flag exists (§15.3: argv leaks).

- [ ] **Step 1: Write failing tests.** Refactor `main.go` so the logic is testable without exec: extract `func runInitAuth(cfgPath, username, tokenName string, passwordSrc io.Reader, stdout, stderr io.Writer) error`. Tests (in `cmd/vmobsd/main_test.go`, real files):

1. `TestInitAuthCreatesStoreAndToken`: temp config (auth enabled, credential_store under t.TempDir); password via reader; stdout has `operator: local_operator` and a `vmobs_` token; `auth.OpenStore` + `VerifyPassword` + `VerifyToken` all succeed against the created store.
2. `TestInitAuthRefusesReinit`: second call errors mentioning "already initialized"; original password still verifies.
3. `TestInitAuthRequiresPassword`: nil/empty password source and no env → error naming both sources. Password shorter than 8 bytes → error.
4. `TestServeRefusesUninitializedAuth`: config with `require_authentication: true` pointing at an empty credential dir → `serve()` returns an error mentioning `init-auth` (extend the existing serve test pattern in this file).

- [ ] **Step 2: Run, verify failure.**

- [ ] **Step 3: Implement.** `main()` dispatches on `os.Args[1] == "init-auth"` before flag parsing (subcommand gets its own FlagSet); default username `local_operator` (continuity with dev-mode rows); trim exactly one trailing newline from the stdin password; mint token named by `-token-name` (default `initial`) with no expiry; print the two stdout lines; log the credential-store path to stderr. The serve path already refuses uninitialized stores (Task 7 Step 4) — test 4 just pins it.

- [ ] **Step 4: Run tests + gate.** `scripts/check` → green.

- [ ] **Step 5: Commit.**

```bash
git add cmd/vmobsd/main.go cmd/vmobsd/main_test.go
git commit -m "feat(vmobsd): init-auth offline credential bootstrap"
```

---

### Task 11: CLI — bearer tokens and auth subcommands

**Files:**
- Modify: `cmd/vmobs/main.go` (client transport)
- Create: `cmd/vmobs/auth.go`
- Test: `cmd/vmobs/auth_cli_test.go`

**Interfaces:**
- Consumes: Task 7/8 endpoints; the CLI's existing client struct (read `main.go:120-170` — `c.base`, request construction) and exit-code contract (0/1/2/3).
- Produces:
  - Global: `--token` flag and `VMOBS_TOKEN` env (flag wins); when set, every request carries `Authorization: Bearer <secret>`. `VMOBS_CA` env / `--ca` flag: path to a PEM CA bundle added to the client's `tls.Config.RootCAs` (for self-signed https deployments).
  - `vmobs auth whoami` — GET /auth/session, prints owner+method (and `--json` passthrough).
  - `vmobs auth token create --name NAME [--ttl-minutes N]` — prints the secret once to stdout (plus a stderr warning that it will not be shown again).
  - `vmobs auth tokens` — list.
  - `vmobs auth token revoke ID`.

- [ ] **Step 1: Write failing tests** in `cmd/vmobs/auth_cli_test.go`, following the existing CLI test harness (read `main_test.go` / `run_cli_test.go` first — they spin a real server and call the CLI entry with args):

1. `TestCLIBearerToken`: auth-enabled server (reuse/adapt the api `newAuthServer` construction inside the CLI test package); mint a token via the API; `vmobs --token <secret> vm list` (adapt to real subcommand syntax) → exit 0; without the token → exit 1 and stderr mentions `unauthenticated` + the login remediation.
2. `TestCLIWhoami`: `vmobs --token X auth whoami` → stdout contains owner `local_operator` and method `token`; `--json` output parses and matches the API shape.
3. `TestCLITokenLifecycle`: `auth token create --name ci2` prints a `vmobs_` secret; `auth tokens` lists it without the secret; `auth token revoke <id>` → subsequent call with the revoked token exits 1.
4. `TestCLITokenEnvVar`: same as 1 via `VMOBS_TOKEN` env (the harness must set env on the CLI invocation, not the test process globally, if the entry point allows; otherwise `t.Setenv`).

- [ ] **Step 2: Run, verify failure.**

- [ ] **Step 3: Implement.** Token plumbing in the client's single request-construction choke point (main.go ~line 150): `if c.token != "" { req.Header.Set("Authorization", "Bearer "+c.token) }`. CA loading: read PEM, `x509.NewCertPool` + `AppendCertsFromPEM`, set on the client's transport. `auth.go` subcommands follow the existing subcommand file pattern (`vm.go` / `run.go`): flags before positionals (Go flag contract, gotchas.md), `--json` parity, exit codes via the existing error mapping. Never print the token secret except the one `create` line; revoke/list refer by ID.

- [ ] **Step 4: Run tests + gate.** `scripts/check` → green.

- [ ] **Step 5: Commit.**

```bash
git add cmd/vmobs/main.go cmd/vmobs/auth.go cmd/vmobs/auth_cli_test.go
git commit -m "feat(cli): bearer token auth and auth subcommands"
```

---

### Task 12: daemon — https mode

**Files:**
- Modify: `cmd/vmobsd/main.go` (listener/TLS)
- Test: `cmd/vmobsd/tls_test.go`

**Interfaces:**
- Consumes: Task 5 config fields.
- Produces: in `https` mode the daemon serves TLS from `tls_cert_file`/`tls_key_file` and may bind non-loopback; in `loopback_only` mode behavior is unchanged (bound-address loopback check stays).

- [ ] **Step 1: Write failing tests** in `cmd/vmobsd/tls_test.go`:

1. Test helper `writeSelfSigned(t, dir) (certPath, keyPath, certPEM)`: `crypto/ecdsa` P-256 key, self-signed `x509.Certificate` for `127.0.0.1` (IPAddresses), 1h validity, PEM-encoded files. Real crypto, no fixtures.
2. `TestServeHTTPS`: full config — mode https, listen `127.0.0.1:0`, `public_origin: "https://127.0.0.1"`, secure cookies, auth enabled with an init-auth'd credential store (call `auth.InitStore` + `CreateToken` directly). Start `serve()` (existing test pattern with the `ready` callback for the bound addr). Client with the cert in RootCAs: `GET https://<addr>/api/v1/meta` → 200. Bearer `GET /api/v1/vms` → 200. Plain `http://` GET to the same addr → error (TLS server refuses cleartext).
3. `TestLoopbackModeStillRefusesNonLoopback`: existing behavior pinned — loopback_only config forced onto a non-loopback listen fails at Validate (config-level, from Task 5) — and the serve-level bound-address check still exists for defense in depth (assert the code path via a loopback_only config whose listen resolves loopback: serves fine).

- [ ] **Step 2: Run, verify failure** (serve has no TLS path).

- [ ] **Step 3: Implement** in `serve()`:

```go
	switch cfg.Server.Mode {
	case "https":
		go func() { serveErr <- srv.ServeTLS(ln, cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile) }()
	default: // loopback_only — keep the bound-address check exactly as-is
		go func() { serveErr <- srv.Serve(ln) }()
	}
```

Move the existing `IsLoopback` bound-address check inside the loopback_only branch (https mode legitimately binds non-loopback; config already forced auth+TLS there). Set `MinVersion: tls.VersionTLS12` via `srv.TLSConfig`. Secure cookie flag already flows from config (Task 7).

- [ ] **Step 4: Run tests + gate.** `scripts/check` → green.

- [ ] **Step 5: Commit.**

```bash
git add cmd/vmobsd/main.go cmd/vmobsd/tls_test.go
git commit -m "feat(vmobsd): https server mode for non-loopback deployment"
```

---

### Task 13: smoke, PLAN close-out, gotchas render

**Files:**
- Modify: `scripts/smoke`, `PLAN.md`, `gotchas.md`

- [ ] **Step 1: Extend `scripts/smoke`** (read it fully first; keep its structure/conventions). New sequence: config now sets `require_authentication: true` + a temp credential store; run `vmobsd init-auth` with password via stdin, capture the token; assert unauthenticated `vmobs vm list` exits 1 mentioning unauthenticated; assert `vmobs --token T auth whoami` exits 0; run the existing VM/run smoke flow WITH the token; curl login flow: POST login with the password → cookie jar; mutation without CSRF header → 403; GET /auth/session → csrf_token; mutation with cookie+CSRF → success; token revoke via CLI → revoked token exits 1. Every assertion prints what it proved (smoke's existing style).

- [ ] **Step 2: Run `scripts/smoke`** → green. Fix what it finds (that is its job).

- [ ] **Step 3: PLAN.md close-out.** Mark P5 done in the phase table. Append deviations A1–A13 (dated 2026-08-31, prefix `(P5-A#)`) — copy the ruling texts from this plan, adjusted for anything that changed during build. Append a session-log entry: what landed, commit range, gate status, next phase (L0). Remove PLAN.md line 24's auth note or amend it: P5 landed, non-loopback now requires `mode: https`.

- [ ] **Step 4: gotchas.md render.** Add entries: (1) goTracked is the only sanctioned way to start manager goroutines (from Task 1); (2) auth middleware injects identity on every non-exempt route — handlers may assume it; (3) cross-owner access must answer the standard 404 writer, never a distinct 403 (existence hiding); (4) token secrets exist in exactly two places: the mint response and the operator's memory — logs/events/lists carry IDs only; (5) `require_authentication: false` is loopback-only dev mode; smoke runs with auth ON.

- [ ] **Step 5: Final gate.** `scripts/check` AND `scripts/smoke` → both green, output captured.

- [ ] **Step 6: Commit.**

```bash
git add scripts/smoke PLAN.md gotchas.md
git commit -m "test(smoke): auth boundary end-to-end; docs(plan): close P5"
```

---

## Self-review checklist (run after writing, before execution)

1. **Spec coverage:** §15.1 sentence by sentence — loopback default (unchanged), HTTPS for remote (T12), local operator account (T2/T10), no reverse-proxy trust (A1 validation, T5), secure/HttpOnly/SameSite cookies (T5/T7), CSRF on mutations (T7), session expiration (T4), per-resource authorization + cross-owner denial (T9), CLI scoped tokens (T3/T8/T11), no tokens in URLs/logs (A5/A6, asserted in T3/T8 tests). WebSocket origin checks + terminal tickets: L0 (out of scope, recorded). §14 audit: auth events T6/T7/T8.
2. **Placeholder scan:** no TBDs; mechanical steps name their grep and their target shape.
3. **Type consistency:** `AuthConfig` fields match between T7 definition and T8/T9/T11/T12 consumers; `Identity.Method` values consistent (`session`/`token`/`none`); error causes consistent across tasks (`unauthenticated`, `invalid_credentials`, `session_invalid_or_expired`, `invalid_token`, `csrf_rejected`, `origin_rejected`, `auth_disabled`, `conclude_args_missing`).
