# Multi-device contract

🇬🇧 **English** · [🇷🇺 Русский](../../ru/guide/multi-device.md)

**Status:** v0.4 — locking primitives stable; sync semantics frozen.

`hidden-volume` is a single-file, single-writer encrypted store. This
document is the contract between the library and any host-app that
runs on more than one device, syncs over a network, or hands a
container off between processes. It defines what the library
guarantees, what it does NOT do, and the patterns host-apps are
expected to follow.

If anything in this document conflicts with `DESIGN.md`, `DESIGN.md`
wins.

## TL;DR

- The library serializes writers per file via `flock(LOCK_EX)`. Two
  processes opening the same file write-mode at the same time → the
  second gets `Error::Busy`. Readers (`open_readonly`) coexist freely;
  a writer blocks all readers.
- The library does NOT do P2P sync, vector clocks, conflict resolution,
  or merging. A container file represents one timeline; if you have
  multiple devices, you have multiple files, and reconciliation is a
  host-app concern at the KV / message-log layer above the library.
- Rollback / fork detection is provided to the host-app as two
  primitives: [`Space::commit_seq`] and [`Space::commit_history`]. The
  host-app stores anchors externally (TPM, server counter, signed log)
  and compares them on reopen.

## What the library provides

### Per-file write exclusion (v0.4)

- `Container::create` and `Container::open` acquire `LOCK_EX` on the
  underlying file. Auto-released on drop. Error: `Error::Busy` when
  contended (distinct from `Error::Io`).
- `Container::open_readonly` acquires `LOCK_SH`. Multiple readers
  coexist. A writer blocks all readers and vice versa. Write methods
  on a read-only handle return `Error::ReadOnly`.
- Lock semantics are POSIX `flock(2)` (per-OFD on Linux/macOS via
  Rust 1.89+ `File::try_lock`). NFS and other distributed filesystems
  may relax this — do not run the container on a network filesystem
  that does not honour `flock`.

### Per-space monotonic seq

[`Space::commit_seq`] returns a `u64` that increments by 1 on every
successful `commit_tx`. Initial value is 1 (assigned at
`create_space`). A successful commit → the new value is durable on
disk before the call returns.

### Per-space history of recoverable anchors

[`Space::commit_history`] returns a sorted-ascending slice of every
`seq` whose Superblock chunk is still on disk and decrypts under this
space's key. Replicas at the same seq are deduplicated.

The slice is computed once at open time (during the trial-decrypt
scan that already runs) and updated in-place by every successful
`commit_tx`. No additional I/O on the read path.

## What the library does NOT provide

| Capability | Why not | Where it belongs |
|---|---|---|
| Concurrent writers from two devices | The format is append-only with a single seq counter; concurrent writers would race the seq and tear the 3-fsync barrier | Host-app: serialize writers (one device at a time) |
| Vector clocks / Lamport clocks | Library tracks one timeline | Host-app: encode a clock as KV entries inside the space |
| Merge / conflict resolution | "Latest wins" is too crude for messengers; CRDT choice is app-specific | Host-app: read both sides via `iter_log` / `list`, merge in app code, write the merged state in one tx |
| Network sync, transport, encryption-in-flight | Out of scope (different threat model than at-rest) | Host-app: TLS / Noise / Signal protocol over your transport |
| Cross-device replay protection | The library is a local store; what gets *into* it is the host-app's call | Host-app: signed messages, dedup keys |

## Multi-device patterns

The library supports four host-app patterns. Pick one explicitly; do
not mix them.

### Pattern A — Single device

The default. One physical file, one process at a time, `LOCK_EX`
enforces it. Use `Container::open` and `Container::open_readonly`
freely.

### Pattern B — Sequential hand-off (one shared file, multiple processes)

A single container file that multiple processes (possibly on
different devices via a shared filesystem) take turns writing to.

- Only ONE writer at a time. The library's `LOCK_EX` enforces this on
  filesystems that honour `flock`.
- Each writer increments `commit_seq` monotonically. Reading `commit_seq`
  immediately after `Container::open_space` tells the new writer
  exactly where the previous writer left off.
- Storage MUST honour `flock` semantics. A network filesystem that
  silently ignores locks (some NFSv3 setups, SMB without proper
  setup) will allow concurrent writers and *will* corrupt the file.
  The library cannot detect this — the host-app deployer must.

This pattern is the simplest if you actually have a coordinating
filesystem. It is NOT the recommended default for a P2P messenger —
see Pattern D.

### Pattern C — Read-only fan-out

One writer process, many readers. The writer holds `LOCK_EX`, readers
use `Container::open_readonly` (`LOCK_SH`). Readers see the snapshot
that was on disk at open time; new commits become visible only on
re-open. Do not mix readers with `Container::open` — `Container::open`
is `LOCK_EX` and will be blocked by the readers.

### Pattern D — Replicated containers (one container per device)

The recommended pattern for a P2P messenger.

Each device has its OWN container file. The "same conversation"
exists as separate KV / log entries on each device, replicated by the
host-app's sync protocol. The library is unaware of replication.

Practical consequences:

- Each device's `commit_seq` is independent. A device's `commit_history`
  reflects its local timeline, not the global one.
- Conflict resolution lives entirely in the host-app. Common picks:
  - **CRDT** (operation-based or state-based). Each KV entry is a
    CRDT cell; merging two devices' state is deterministic.
  - **Vector clock per message**. Encode `(device_id, counter)` in
    the value of each log entry. Resolve conflicts by total order
    over vector clocks.
  - **Server-as-source-of-truth**. A central server holds the
    canonical timeline; each device's container caches it.
- The library does not learn about other devices. Device identity,
  pairing, and authentication are host-app concerns.

This pattern composes with Pattern A locally on each device.

## Anchor patterns (rollback detection)

A snapshot adversary (T2 in `DESIGN.md` §1) can replace the file with
a copy from a previous time. The library cannot detect this on its
own — it has no notion of "what time it is" or "what state I last
committed". The host-app provides external anchors.

### Anchor primitive

After every successful commit, the host-app records `commit_seq()`
plus optionally a fingerprint (e.g., BLAKE3 over the Superblock seq
and root_hash bytes — both already stored in `Space`'s state) to a
location the adversary cannot rewrite:

| Storage | Pros | Cons |
|---|---|---|
| TPM / Secure Enclave NV counter | Hardware-rooted; survives OS reinstall | Mobile platform restrictions; counter exhaustion |
| Server-side counter (HMAC'd) | Easy to deploy; quota'd | Online dependency; server compromise = no anchor |
| Signed log on a separate device | No online dependency | Out-of-band sync UX cost |
| Plain file on the same disk | Trivially defeated by the same snapshot adversary | Useless on its own; only as defense-in-depth |

### Rollback / fork-detection algorithm

On `Container::open_space`:

1. Read external anchor `(anchor_seq, anchor_fp)`.
2. Compute current `current_seq = space.commit_seq()`.
3. Compare:
   - `current_seq < anchor_seq` → **rollback**. Refuse to proceed; the
     file has been replaced with an older version. Surface to the user;
     do NOT silently accept new writes (you would lose anchored data).
   - `current_seq >= anchor_seq` AND `anchor_seq` is in
     `space.commit_history()` → **clean continuation**. Accept.
   - `current_seq >= anchor_seq` AND `anchor_seq` is NOT in
     `space.commit_history()` → **fork**. The file's timeline diverges
     from your anchor. Treat as adversarial.

The `commit_history()` membership test is the part that distinguishes
"someone reset the file to an even *newer* state I never committed"
from "I just opened a file I haven't touched in a while".

### What anchors expose

An adversary who can read your anchor learns the existence and
activity-rate of the *anchored* space. Anchoring a space is a
deniability tradeoff:

- **Main / public space** — anchor freely. Its existence is
  acknowledged.
- **Decoy / duress space** — do NOT anchor. The whole point is
  plausible deniability, and a publicly-readable anchor for a "hidden"
  space is self-defeating.
- **Hidden space (real)** — anchor only to a storage location whose
  presence is itself plausibly deniable (your TPM has many uses; a
  server you also use for unrelated things).

The library does not enforce this — it is host-app policy. Store the
choice ("which spaces are anchored") encrypted inside the space whose
anchor you are protecting, never in the clear.

## Compaction and history

`Container::compact_known` produces a fresh container
with a fresh salt and `container_id`. The destination's
`commit_history` for each space starts at `[1]` regardless of the
source's history.

Host-app responsibilities at compaction time:

1. Re-anchor every anchored space against the new `commit_seq` after
   the first post-compaction commit.
2. Until the new anchor is durable, treat the new container as
   "pending verification" — a snapshot adversary that captured the
   moment between compaction and re-anchor can replay the old
   container with full authority.
3. The compaction is itself an event your other devices may need to
   know about (the file's `container_id` changed). If you sync at the
   file layer (Pattern B), every other device must be informed; if
   you sync at the application layer (Pattern D), nothing changes
   from the peer's view.

## Cross-references

- `DESIGN.md` §5 — discovery scan, what is on disk
- `DESIGN.md` §6 — fsync barriers, what "successful commit" means
- `DESIGN.md` §7 — Superblock replicas, what survives a torn write
- `DESIGN.md` §11.2 — rollback ordering invariant
- `tests/multi_device.rs` — test coverage for these primitives
- `tests/locking.rs` — `flock` semantics tests
- `tests/readonly.rs` — `LOCK_SH` semantics tests

[`Space::commit_seq`]: ../src/space/mod.rs
[`Space::commit_history`]: ../src/space/mod.rs
