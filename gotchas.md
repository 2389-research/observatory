# Gotchas

Distilled working knowledge for agents and collaborators in this repo. Append entries; keep each a few lines.

- **No process ceremony with Harper.** Don't announce skill usage, workflow compliance, or plans-before-acting. He interrupted mid-task to stop it ("please stop"). Keep the discipline (verify, be honest about what ran), skip the narration — the first visible action should be real work.
- **Canonical check is `uv run docs/validation/check.py`.** Run it after touching anything in `docs/`; append a dated revision to `docs/VALIDATION.md` with the real output. Never rewrite earlier revisions — they're the historical record.
- **`gofmt -l` exits 0 even when it lists unformatted files.** Chaining `gofmt -l ... && git commit` commits unformatted code (burned two commits this way). The gate is `scripts/check`, which captures the output and fails on non-empty; use it, not ad-hoc chains.
- **Go toolchain here needs `env -u GOROOT mise exec -- go ...`** — inherited GOROOT points at a removed toolchain. `scripts/check` self-heals this; direct `go` invocations don't.
- **`go mod tidy` prunes deps nothing imports yet.** Add a dep with `go get` only after code imports it, or tidy will silently drop it and the next build fails with "no required module provides package".
- **golangci-lint caps duplicate findings at 3 per message** (`max-same-issues`), so "21 issues" can understate. Errcheck noise categories are excluded via `.golangci.yml` (`std-error-handling` preset); genuine ignores stay explicit `_ =` in code.
- **§5.2 state matrix: no direct live→stopped transition.** `running` and `paused` must go through `stopping` before reaching `stopped`. Force-stop and force-delete paths both need the intermediate step. A direct `→stopped` attempt returns `InvalidTransitionError`.
- **Manager.Close() must call `wg.Wait()` BEFORE `cancel()`.** Cancelling context first makes in-flight goroutines' store calls fail immediately, leaving VMs stuck in transitional states. The correct order: drain workers, then cancel.
- **Testing semaphore caps: use store state, not goroutine timing.** Goroutine-side "inflight" counters can show peak > cap even when the semaphore is working correctly (goroutine activity spans longer than semaphore occupancy). Count VMs in "starting" state instead — a VM stays there while its Launch call is blocked inside the semaphore slot.
