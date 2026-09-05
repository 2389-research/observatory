# zd43 — anchor privd's privileged operations to descriptors

> **Status: design, awaiting Doctor Biz's review.** No privd source changes until it is read. If approved, the Tasks section below is the plan; the findings and measurements above it are the argument.

**Goal:** privd names a process by a descriptor, not a pid, and names a file by a descriptor plus one bare component, not a path. Every operation privd performs as root is then aimed by something the kernel pins, so the window between deciding what to touch and touching it closes.

## Where this came from

`zd43` inventoried privd's privileged surface. Finding 1 — `StagedFile.Name` was documented as a basename with nothing enforcing it — is fixed and merged (`9029e94`). It converted controller-uid code execution into a root file write; the proof measured 60 caller-chosen bytes landing outside the jail root.

Three findings stayed open. This document designs their fix. Measurement has changed the shape of all three since the kata comment: one grew teeth, one lost most of them, and one turned out to need a smaller mechanism than proposed.

---

## Finding 2 — a signal is aimed by a pid

`SignalVM` (`internal/privd/vmops.go:423`) calls `CheckSignalIdentity` (`:152`), which reads `/proc/<pid>/stat` and compares field 22 against the ledger's starttime. It then calls `unix.Kill(entry.PID, sig)` at `:439`. Between the read and the kill, the pid is just a number. If the VMM exits in that gap and the host reissues its pid, the SIGKILL lands on whatever now holds it — as root, chosen by nothing.

`killJailedVMM` (`:385`) has the same shape with a longer gap: read pid file, read stat for comm, read cmdline for argv, then `unix.Kill` at `:414`. Four syscalls of window instead of one.

The window is narrow. It is not zero, and `pid_max` on aibox03 is 4194304, which makes reuse rare rather than impossible. I did **not** demonstrate a stray signal — forcing a pid recycle needs `ns_last_pid`, which needs privileges I do not have on that host. The argument here is about the shape of the code, not about an observed hit.

### What replaces it

`os.FindProcess(pid)` on Linux calls `pidfd_open`. Measured on aibox03, go1.27.0:

```
  FindProcess(3302451): open fds 9 -> 10
  fd 12 -> anon_inode:[pidfd]
  Signal(0) while alive                          -> ALLOWED
  Signal(0) after exit and reap                  -> refused: os: process already finished
  syscall.Kill(pid,0) after exit and reap        -> refused: no such process
  FindProcess(4194303).Signal(0)                 -> refused: os: process already finished
```

So the standard library already gives us the mechanism; no `unix.PidfdOpen` call of our own is needed. `p.Signal` goes to `pidfd_send_signal` when the handle is a pidfd (`os/exec_unix.go:84`), and it fails closed on a process that is gone.

The order matters, and it is what makes the argument airtight without resting on a kernel claim I cannot test here:

1. `os.FindProcess(pid)` — take the descriptor **first**.
2. Read `/proc/<pid>/stat` and compare starttime, comm, argv as today.
3. `p.Signal(sig)`.

If the pid was recycled before step 1, step 2 sees a different starttime and refuses. If it were recycled after step 1, the descriptor still refers to the original process, so step 3 signals a dead process and gets ESRCH. Either way no stray signal, whether or not a held pidfd pins the pid number.

`Process.Release` must be called (or the process value dropped) so the fd does not leak; privd holds one per signal, not per VM.

**Fallback:** none. `pidfd_open` is Linux 5.3; aibox03 runs 6.8.0-138-generic. If `FindProcess` falls back to a bare pid on some older kernel, `Signal` behaves exactly as today — the change cannot be worse than the code it replaces, so no version gate is needed.

---

## Finding 3 — a file is aimed by a path

Every privileged file operation builds a string and hands it to the kernel to resolve from `/`. Two of these matter and two turned out not to.

### 3a. The jail root is writable by the guest's uid — and privd echoes what it finds there

This is the one that grew teeth while I was designing the fix for something else.

`StartVM` chowns the whole jail tree to the VM's uid (`chownTree`, `:224`), execs the jailer, waits up to 10s for `v.sock`, and then reads `<jail>/root/firecracker.pid` by path (`:266`). The jailer pivot_roots into `<jail>/root`, so that pid file sits at `/firecracker.pid` inside the VMM's own mount namespace, in a directory that uid owns. During the wait, a VMM that has been taken over can unlink it and put a symlink there.

privd, as root, then reads through it — and echoes the bytes:

- `vmops.go:272` — `fmt.Errorf("privd: parse firecracker.pid %q: %w", string(pidData), err)`. That error travels back over the socket to the controller.
- `vmops.go:394` — `r.log.Printf("abort start %s: firecracker.pid holds %q, ...", vmID, raw)`. That lands in privd's log.

`raw` is the whole file, trimmed. Point the link at a root-only file and the first parse failure hands its contents to the caller. That is a file-read oracle across the exact boundary SPEC §3.3 puts privd there to hold, and the escape hatch is a `%q` in an error string, not the open.

I have **not** run this. It is read from the path construction (`root := filepath.Join(r.cfg.JailBase, "firecracker", req.VMID, "root")` at `:202`, `pidFile := filepath.Join(root, "firecracker.pid")` at `:265`) and from `chownTree` handing that directory to `req.UID`. Both halves are in the file; the exploit is not.

`CopyFromPinnedFd` (`:99`) has the same exposure with a write instead of a read: `os.OpenFile(dstPath, O_WRONLY|O_CREATE|O_TRUNC)`, no `O_NOFOLLOW`, no `O_EXCL`. `StartVM`'s `MkdirAll` does not clear a jail root left by an earlier failed start, and that leftover is already chowned to the VM's uid.

### 3b. `stage_dir` is resolved, checked, and then thrown away

`handleStartVM` (`server.go:278`) runs `filepath.EvalSymlinks(r.StageDir)` and compares the result against the resolved `StageRoot` with a string prefix. It then discards `resolved` and passes the original `r.StageDir` through; `StartVM` re-derives from it at `vmops.go:181`. Check one path, use another.

The fix here is smaller than anchoring. The controller builds the stage dir at `internal/jailer/launch.go:137`:

```go
stageDir := filepath.Join(a.cfg.StageRoot, vmID)
```

Exactly one component under the stage root, named by the VM id. privd already has its own `--stage-root` (`cmd/vmobs-privd/flags.go:29`, default `/srv/vmobs/stage`), already validates `vm_id` with `ValidVMID`, and the M1a gate's path reconciliation already asserts the two roots are the same directory (`tests/integration/m1a_gate_test.go:1349`). **privd can derive the stage dir and stop reading the caller's.** Same move as the `ValidStagedName` allowlist: delete a caller-controlled input from the privileged surface rather than validate it harder.

### 3c and 3d — what shrank

Two things I proposed on the kata are mostly already true, and the doc would be dishonest if it kept claiming them.

**Removal is already descriptor-relative.** `os.RemoveAll` on Unix recurses with `openat`/`unlinkat` against fds and unlinks a symlink rather than following it (`os/removeall_at.go`). `AbortStartVM` (`:306`) and `ReleaseVM` (`:450`) are not the hole I described. What remains is that the top components of `<JailBase>/firecracker/<id>` are resolved by name — and `JailBase` is config, `<id>` is `ValidVMID`-checked. There is no attack there I can name. Anchoring it is consistency, not a fix, and it is the item to cut if this gets trimmed.

**`chownTree` is already symlink-safe.** It walks with `filepath.WalkDir`, which does not descend through symlinks, and chowns with `os.Lchown`, which changes the link and not its target.

---

## Measurements

All run on aibox03 (6.8.0-138-generic, go1.27.0), in `t.TempDir()`, touching nothing on the host.

`os.Root` — the anchored-directory type in the standard library:

```
  OpenFile "../../victim/owned.txt"              -> refused: path escapes from parent
  OpenFile "evil/owned.txt" (symlink out)        -> refused: path escapes from parent
  OpenFile "abs/passwd" (absolute symlink)       -> refused: path escapes from parent
  RemoveAll "../victim"                          -> refused: path escapes from parent
  Lchown "../victim" 1000:1000                   -> refused: path escapes from parent
  OpenFile "vmlinux" O_EXCL (first time)         -> ALLOWED
  OpenFile "vmlinux" O_EXCL (leftover present)   -> refused: file exists
  Lchown "vmlinux" 1000:1000                     -> ALLOWED
  MkdirAll "a/b/c"                               -> ALLOWED
  RemoveAll "a"                                  -> ALLOWED
  OpenRoot on a symlinked stage root             -> ALLOWED
    ...then Open "rootfs.ext4" under it          -> ALLOWED
```

The last two matter: `os.OpenRoot` follows symlinks in the root's *own* name, which is the case `EvalSymlinks` exists for today (`/var/vmobs/stage → /mnt/storage/stage`). So a `Root` replaces the resolve-and-compare dance without breaking a symlinked root.

**One trap, measured:**

```
  "vmlinux" -> "real", plain O_RDONLY              -> ALLOWED
  "vmlinux" -> "real", O_RDONLY|O_NOFOLLOW         -> ALLOWED
  os.OpenFile O_NOFOLLOW (today's behaviour)       -> refused: too many levels of symbolic links
```

`Root.OpenFile` **ignores a caller's `O_NOFOLLOW`** for a symlink that stays inside the root. Porting `VerifyStagedFile` to `os.Root` naively would silently loosen a refusal that holds today. Hence the mechanism below.

Go's `os.Root` does not use `openat2`; it opens each component with `openat`+`O_NOFOLLOW` against the previous fd and resolves symlinks itself (`os/root_unix.go:67`). It is anchored, and it is not `RESOLVE_BENEATH`. Its documented residual races are on `Chmod`/`Chown`/`Chtimes`; we use `Lchown`, which is not among them.

---

## The design

**`ValidStagedName` already guarantees every staged name is one of five bare filenames.** A bare name has no intermediate components to protect, so a single `openat` against a retained directory fd is complete — no multi-component resolver needed, and `O_NOFOLLOW` on that one syscall means what it says. `os.Root` earns its place in exactly one spot: the stage directory, whose name has components privd did not choose.

| Site | Today | After |
|---|---|---|
| stage dir | caller's string, `EvalSymlinks` + prefix compare, then discarded | derived `<StageRoot>/<vm_id>`, opened via a `Root` held on `StageRoot` |
| staged file read | `os.OpenFile(stageDir/name, O_NOFOLLOW)` | `unix.Openat(stageFd, name, O_RDONLY\|O_NOFOLLOW\|O_CLOEXEC)` |
| jail root | `os.MkdirAll` by path | `os.MkdirAll` by path, then open and **retain** the fd |
| staged file write | `os.OpenFile(root/name, O_CREATE\|O_TRUNC)` | `unix.Openat(jailFd, name, O_WRONLY\|O_CREAT\|O_EXCL\|O_NOFOLLOW)` |
| chown of that file | `os.Lchown(dstPath)` | `unix.Fchownat(jailFd, name, uid, gid, AT_SYMLINK_NOFOLLOW)` |
| `v.sock` wait | `os.Stat(root/v.sock)` | `unix.Fstatat(jailFd, "v.sock", ..., AT_SYMLINK_NOFOLLOW)` |
| jail root chmod | `os.Chmod(root, 0750)` | `unix.Fchmod(jailFd, 0750)` |
| `firecracker.pid` read | `os.ReadFile(root/firecracker.pid)` | `unix.Openat(jailFd, "firecracker.pid", O_RDONLY\|O_NOFOLLOW)`, read at most 32 bytes |
| signal | `CheckSignalIdentity` then `unix.Kill(pid)` | `os.FindProcess` **then** identity **then** `p.Signal` |
| removal | `os.RemoveAll(jailDir)` | unchanged — already `unlinkat`-relative |

Two things are not about descriptors at all and are the cheapest fixes in the set:

- **Stop echoing file bytes.** `vmops.go:272` and `:394` put the whole pid file into an error and a log. Read a bounded prefix and echo through `truncateName` — the helper `9029e94` already added for exactly this.
- **`O_EXCL` on the staged writes.** A jail root left by a crashed privd is a directory owned by another uid whose contents privd knows nothing about. Today the copy writes into it. With `O_EXCL` the start refuses.

---

## Two calls I want you to make, Doctor Biz

**1. What should a leftover jail root do to a start?**

`O_EXCL` turns debris into a permanent failure for that VM id until someone removes the directory. Two ways out:

- *(recommended)* Refuse with a typed `invalid_state` naming the directory and what to do about it. No new destruction on the start path, and an operator sees the mess instead of privd silently reusing it. Costs: a stuck VM needs a human.
- Have `StartVM` clear the debris itself — the same identity-gated kill `AbortStartVM` uses, then remove, then create fresh. Self-healing. Costs: `start_vm` now deletes a directory tree, guarded only by the ledger saying PID 0 for that id.

I lean hard on the first: adding a recursive delete to the start path to avoid an operator ticket is a bad trade in a component that runs as root.

**2. Should privd stop reading `stage_dir` from the wire?**

Deriving `<StageRoot>/<vm_id>` deletes a caller-controlled path from the privileged surface. The field stays in the protocol; privd would either ignore it or refuse a request whose `stage_dir` disagrees with the derivation. I prefer **refuse on disagreement** — silently ignoring a field the caller set is how the next confusing bug gets written.

Both are reversible and neither blocks the rest, so if you want to defer them I will implement the anchoring with today's semantics and open a follow-up.

---

## Tasks

Each is a commit. TDD: the red test first, and each fix carries a mutation proof that the test bites.

- [ ] **T1 — signals take a descriptor.** `SignalVM` and `killJailedVMM` do `os.FindProcess` first, identity second, `p.Signal` third; `Release` the handle. Test: a `SignalVM` against a ledger entry whose starttime does not match still refuses (the existing behaviour), and a handle taken on a live process signals it. Mutation: reorder to identity-then-open and show the test that pins the order fails.
- [ ] **T2 — stop echoing file bytes.** Bound the `firecracker.pid` read to 32 bytes and truncate it in both the error at `:272` and the log at `:394`. Test: a pid file holding 4 KiB of junk yields an error whose message is bounded and does not contain the junk.
- [ ] **T3 — retain the jail-root fd.** `StartVM` opens the jail root after `MkdirAll` and keeps the fd for the copies, the chowns, the `v.sock` wait, the chmod and the pid read. `CopyFromPinnedFd` takes a dirfd instead of a dir path. Test: a symlink planted at `<jail>/root/firecracker.pid` pointing outside the jail is refused, and the start fails with a typed cause instead of reading through it.
- [ ] **T4 — `O_EXCL` on staged writes**, plus whichever debris policy you pick in call 1. Test: a pre-existing `vmlinux` in the jail root fails the start with the typed cause.
- [ ] **T5 — the stage side.** Hold one `os.Root` on `StageRoot`, opened at daemon start; derive the stage dir from `vm_id`; `openat` each staged file against that dirfd with `O_NOFOLLOW`. Delete the `EvalSymlinks` block at `server.go:275-290`. Test: a symlink at `<stage>/<id>/vmlinux` is still refused (the trap above — this test is the one that catches a naive `os.Root` port), and a symlinked `StageRoot` still works.
- [ ] **T6 — gate.** `scripts/check` locally, `go test ./internal/privd/ ./internal/jailer/` on aibox03, and the live M1a gate. Real Firecracker VMs must still boot through all of it.

Removal stays as it is. If you want it anchored for symmetry, say so and it becomes T7; I would not spend the lines otherwise.

## What this does not fix

- The `RunCmd` hook path skips the `v.sock` wait, the chmod and the pid read entirely, so T3's coverage in unit tests is partial by construction; the live gate is what exercises the real path.
- `os.Root` is not `openat2`. Nothing here defends against a bind mount or a `/proc` special file placed in the tree by something that already has root.
- privd still trusts its own config: `JailBase` and `StageRoot` come from flags, and a wrong flag is a wrong root. That is an install-time concern, not a request-time one.
