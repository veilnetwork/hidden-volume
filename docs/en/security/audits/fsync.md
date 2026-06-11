# fsync ordering audit

🇬🇧 **English** · [🇷🇺 Русский](../../../ru/security/audits/fsync.md)

**Status:** v0.5 first pass complete. **All barriers in place; no
issues found.**

This document traces every `fsync` call through the codebase, verifies
the ordering invariants documented in `DESIGN.md` §6 / `src/tx/mod.rs`,
and records the failure-mode analysis. Update on every change to
`commit_tx`, `vacuum_orphans`, or any path that writes chunks.

## Methodology

`grep -rn "fsync\|sync_all" src/`. Every call site classified by:

  - What write(s) preceded it
  - What invariant it establishes
  - Crash-safety implication if the call is missed or out of order

`File::sync_all()` is the underlying syscall. On Linux this is `fsync(2)`
(both data and metadata). On macOS `fsync(2)` (note: macOS `fsync` does
NOT flush the disk write cache by default; for stronger durability,
`F_FULLFSYNC` is needed — host-app concern, see §3 below).

## Inventory of fsync sites

| Site | What was written | Invariant established |
|---|---|---|
| `ContainerFile::create` | 1 header chunk | header durable before space creation can begin |
| `Container::create_with_options` (post initial-garbage) | 0..N garbage chunks | initial decoy size durable before app sees a "ready" container |
| `Space::create` (post initial Superblock replicas) | N SB chunks | space's initial Superblock visible after Container::create_space returns Ok |
| `Space::commit_tx` Barrier 1 (post Phase 0/1) | DataBatch + IndexNode chunks for this Tx | data durable before referencing Commit lands |
| `Space::commit_tx` Barrier 2 (post Commit) | Commit chunk | "intent" durable before Superblock lands |
| `Space::commit_tx` Barrier 3 (post Superblock replicas) | N new SB chunks | new state visible — recovery picks max-seq SB which is now this one |
| `Space::commit_tx` (post-padding, conditional) | 0..(bucket-1) garbage chunks | post-commit padding durable; observer's next file-size measurement reflects the bucket |
| `Space::vacuum_orphans` (conditional, post-scrub) | 0..N scrubbed slots | orphan IndexNodes overwritten with random; scrub durable after function returns Ok |

Total: **7 distinct fsync sites**, of which **3 are unconditional barriers
in `commit_tx`** (matching the documented "3-fsync barrier" protocol).

## Tx::commit ordering trace

This is the critical path. Walk-through:

```text
Tx::commit
  └── Space::commit_tx
       │
       │  -- Phase 0: log → DataBatch chunks --
       │  for each log namespace with pending appends:
       │    encode_batch(zstd) → bytes
       │    append_chunk(DataBatch, bytes)        ◄── extends file
       │    record batch_slot in pending_kv
       │
       │  -- Phase 1: KV → IndexNode chunks --
       │  for each touched namespace:
       │    flatten + apply ops
       │    write_tree_for_namespace:
       │      try single-leaf encode
       │      else pack_into_leaves greedy first-fit
       │      append leaf chunks                  ◄── extends file
       │      append InternalNode chunk           ◄── extends file
       │
       │  ★ BARRIER 1: file.fsync()
       │    All Phase 0 + Phase 1 chunks now durable.
       │
       │  -- Phase 2: Commit chunk --
       │  build CommitPayload { roots: [...], tx_root_hash }
       │  encode → cp_bytes
       │  append_chunk(Commit, cp_bytes)          ◄── extends file
       │
       │  ★ BARRIER 2: file.fsync()
       │    Commit chunk durable. Without Phase 2 visible, no SB will
       │    point here in step 3. Crash before this barrier → no
       │    Commit chunk → recovery uses old SB.
       │
       │  -- Phase 3: Superblock replicas --
       │  build new_sb { seq, root_slot=commit_slot, root_hash }
       │  for _ in 0..superblock_replicas:
       │    append_superblock(&new_sb)            ◄── extends file
       │
       │  ★ BARRIER 3: file.fsync()
       │    New SB visible. After this point, the new state is
       │    "committed" — recovery picks max-seq SB which is now this.
       │
       │  state.superblock = new_sb (in-memory bookkeeping)
       │
       │  -- Phase 4 (conditional): padding --
       │  if padding_policy says we need pad_count > 0:
       │    append_garbage_chunks(pad_count)      ◄── extends file
       │    ★ BARRIER 4: file.fsync()
       │
       └── return new_seq
```

## Crash-safety analysis per barrier

### Crash before Barrier 1
File contains some prefix of new chunks (DataBatch + IndexNode). New
Commit and new SB don't exist. Recovery scans, picks the highest-seq
SB that's still readable (the previous one). Orphan chunks read as
garbage from the recovered state's POV.

**Result:** rollback to previous commit. Tested by
`crash_after_index_node_before_commit_rolls_back`.

### Crash between Barrier 1 and Barrier 2
File contains all Phase 0/1 chunks (durable) plus possibly the Commit
chunk if write returned but fsync didn't complete. Either way, the
new SB is not yet written. Recovery picks the previous SB.

**Result:** rollback. Same recovery path as above.

### Crash between Barrier 2 and Barrier 3
File contains all data + Commit (durable) plus possibly the new SB if
write returned but fsync didn't complete. Two sub-cases:

- New SB chunk is fully written and was flushed to disk by the OS
  before crash: AEAD-passes on scan, becomes the max-seq SB →
  **Tx is visible.**
- New SB chunk is partially written or didn't reach disk: AEAD fails
  on scan, gets dropped from `found` → max-seq SB is the previous
  one → **Tx rolled back.**

Either outcome is acceptable: the user either sees the new state
(success) or the previous state (rollback). No torn / inconsistent
state. Tested by
`crash_after_commit_before_superblock_rolls_back`.

### Crash between Barrier 3 and Barrier 4 (padding)
Tx is durably committed (new SB visible). The padding garbage chunks
may or may not be on disk. Either way:
- New SB references the Commit. Commit references its data chunks.
- All data chunks are durable (Barrier 1).
- Padding chunks read as random regardless (they ARE random) — they
  AEAD-fail and are simply ignored by recovery scan.

**Result:** Tx is visible. File may be slightly shorter than the
pad-policy intended; on the next commit, padding will catch up.

### Crash during Barrier 4 (conditional padding)
Same outcome as the prior bullet. Padding fsync is best-effort —
its only purpose is making the file size observable to a snapshot
adversary at the bucket-rounded value, not data integrity.

## Other fsync paths

### `Space::create`
Writes N initial SB replicas, then a single fsync. After this fsync
returns, the space exists durably and a fresh `Container::open_space`
will find it. No partial-create-state visible to subsequent calls.

### `Space::vacuum_orphans`
Scans, identifies orphan IndexNode chunks, scrubs them in place.
After scrubbing all selected slots, ONE fsync — only if at least
one chunk was scrubbed (the empty-set case is a no-op).

Crash mid-vacuum:
- Some slots scrubbed, others not. New SB is unchanged (vacuum
  doesn't write a new SB).
- Recovery: latest SB still valid; reachable tree still intact (vacuum
  only touches orphans).
- Re-running vacuum on next open is idempotent — already-scrubbed
  slots simply AEAD-fail and aren't in the orphan candidate set.

**Result:** correct on crash. Idempotent on re-run.

## Failure-mode notes

### `sync_all()` errors
Every `fsync()` call propagates errors via `?`. If `sync_all()` returns
`Err`, the Tx aborts. Caller sees `Error::Io(_)`. The on-disk state may
be: any prefix of the writes durable, with the post-error writes
volatile in OS buffers — same crash-safety analysis as above. Caller
should NOT retry the same Tx without first re-opening the container
to re-derive state.

### macOS `F_FULLFSYNC`
On macOS, `fsync(2)` flushes the filesystem buffer cache to the disk's
write cache, but does NOT force the disk to write to platter (the
SQLite folks documented this extensively). For strong durability on
macOS, `F_FULLFSYNC` is the right call. We use `sync_all` which maps
to `fsync` — host-app should be aware. Documented as out-of-scope at
this layer; tracked as a v0.5.x option to set per-platform behavior.

### Linux `fsync` and write-cache
Modern Linux kernels with default-mounted ext4/xfs/btrfs DO flush the
disk write cache on `fsync(2)`. SATA `FLUSH CACHE` / NVMe `FLUSH`
commands are issued. This matches our durability model. Older kernels
or tuned-for-performance mounts (`barrier=0`, `nobarrier`) may skip
the device flush — host-app responsibility to mount with default
options.

### Out-of-scope
- Disk firmware ignoring FLUSH (rare; affects all fsync-based systems
  equally).
- Power loss between disk-FLUSH-CACHE and platter-write (handled by
  modern enterprise drives via supercap / power-loss-protection).
- Filesystem-level torn writes within a 4 KiB chunk on FS that don't
  guarantee atomic 4 KiB writes (most modern FS DO; we rely on this).

## Audit log

| Date | Change | Reviewer |
|---|---|---|
| Initial v0.5 | First pass. Traced 7 fsync sites; all in correct positions. The 3-fsync barrier protocol in `commit_tx` matches `DESIGN.md` §6. Crash semantics correct at every barrier (validated by `tests/crash_recovery.rs`). No fixes needed. | Self-audit |
