# Operations playbook

🇬🇧 **English** · [🇷🇺 Русский](../../ru/guide/operations.md)

Practical recipes for **deploying, backing up, migrating, and
recovering** a `hidden-volume` container. Audience: ops-minded
host-app developers and system integrators. Written as runnable
recipes, not theory.

If anything here conflicts with `DESIGN.md` or
`docs/en/security/threat-model.md`, those documents win.

## Contents

- §1. Backup and restore
- §2. Key rotation (password change)
- §3. Argon2 parameter migration (re-tuning device class)
- §4. Recovery from corruption / partial writes
- §5. Storage budget management (compact, vacuum)
- §6. Multi-device deployment recipes
- §7. Forensic scrub before disposal
- §8. Container size monitoring
- §9. What to do when something goes wrong

---

## 1. Backup and restore

### 1.1 What "backup" means here

A `hidden-volume` container is a **single file**. Backup = copy the
file. Restore = put the file back. There is no special export or
import format — the file *is* the data, encrypted.

### 1.2 When to back up

- **Cold backup** — file copied while no process holds an
  exclusive lock on it. Use this for routine daily / hourly
  backups. Acquire `LOCK_SH` via [`Container::open_readonly`] to
  guarantee no concurrent writer is mid-commit, copy the bytes,
  release the lock.
- **Hot backup** — file copied while the writer is open. Avoid.
  If unavoidable, the writer's commit-in-progress may produce a
  half-written tail; the resulting backup is almost certainly
  recoverable (3-fsync protocol + property-based crash-recovery
  test), but there is no guarantee about *which* commit you
  recovered to.

### 1.3 Cold-backup recipe

```rust,ignore
// Acquire LOCK_SH for the duration of the copy.
let _guard = hidden_volume::Container::open_readonly(path)?;
std::fs::copy(path, &backup_path)?;
// _guard drops here, releasing the shared lock.
```

The shared lock prevents new writer locks from being acquired
during the copy. Existing writers (if any) finish their current
Tx; new Tx can't start until the lock releases.

### 1.4 Restore recipe

```rust,ignore
// 1. Verify no writer holds the original.
//    (If you can't be sure, the safe move is to fail loudly.)
// 2. Replace the file atomically.
std::fs::rename(&backup_path, path)?; // overwrites
// 3. Re-anchor every space whose host-app uses commit_seq for
//    rollback detection (see docs/en/guide/multi-device.md).
//    A restore is INDISTINGUISHABLE from a rollback attack to the
//    library — your anchor strategy must explicitly authorize
//    "this restore is intentional".
```

**Anchor warning.** If the host-app implements rollback detection
against an external anchor (TPM / server counter / signed log),
restoring a backup will trigger the rollback alarm because
`commit_seq()` of the restored file is older than the anchor.
The host-app must offer an "I'm restoring a backup" path that
explicitly acknowledges the seq drop and re-anchors. Otherwise
users will be locked out after every restore.

### 1.5 Backup verification

After a backup, verify the file decrypts and the Merkle chain is
intact:

```rust,ignore
let mut c = hidden_volume::Container::open_readonly(&backup_path)?;
for password in known_passwords {
    let mut s = c.open_space(password)?;
    let _report = s.verify_integrity()?;
}
```

`verify_integrity` walks the Merkle hash chain end-to-end (~125 µs
for a 1 100-entry namespace; see `docs/en/contributing/benchmarks.md`) and surfaces any
hash mismatch as `Error::IntegrityFailure { detail, slot }`.

---

## 2. Key rotation (password change)

### 2.1 Single space

```rust,ignore
let old: &[u8] = b"current-password";
let new: &[u8] = b"new-password";
hidden_volume::Container::change_passwords(
    path,
    &[(old, new)],
    options,
)?;
```

Mechanics: writes a fresh container at a sibling temp file named
`.{stem}.hv-rotate.{16hex}.tmp` (the random 16-hex suffix avoids
collisions; the leading dot keeps it out of casual listings), then
`rename(2)`s it over `path` under the source `LOCK_EX` with a
parent-dir `fsync`. On any failure the temp is removed and the
original `path` is untouched. See [`Container::change_passwords`]
for the full contract.

**Data-loss-by-design warning.** Spaces NOT listed in the password
mapping are **silently and permanently dropped** — see §2.2 and the
boxed warning there. This applies equally to `change_passwords` and
`compact_known`. The library cannot enumerate deniable spaces (that
is the whole point of the format), so it has no way to detect "you
forgot a space" and cannot warn you. The host-app is solely
responsible for confirming the password set is complete before
calling.

### 2.2 Multi-space — change one, preserve others

```rust,ignore
let main_old: &[u8] = b"main-old";
let main_new: &[u8] = b"main-new";
let hidden_kept: &[u8] = b"hidden-pw";
hidden_volume::Container::change_passwords(
    path,
    &[
        (main_old, main_new),         // rotate
        (hidden_kept, hidden_kept),   // preserve verbatim
    ],
    options,
)?;
```

> **⚠ DATA LOSS BY DESIGN.** Spaces NOT mentioned in the mapping
> are **silently and permanently dropped** — same destructive
> semantics as `compact_known`. An empty or incomplete password
> list drops *every* unlisted space. This is a **deniability
> property, not a bug**: the library cannot and must not enumerate
> deniable spaces, so it has no way to know a space exists that you
> forgot to list, and therefore cannot detect or warn about the
> data loss. The host-app MUST confirm the password set is complete
> before calling. To preserve a space, list it as a no-op `(p, p)`
> pair.

### 2.3 After rotation

- Re-anchor (see §1.4 anchor warning) — `commit_history` resets
  to `[1]` after the implicit repack. Any anchor that referenced a
  pre-rotation seq will now look like a fork.
- Run [`Space::verify_integrity`] on every space to confirm.
- The OS allocator may reuse the old container's blocks for
  unrelated data. For forensic-grade scrub of the underlying
  storage, see §7.

---

## 3. Argon2 parameter migration

Argon2id parameters live in the cleartext header (set at create
time). The library refuses to open a container with parameters
below `Argon2Params::MIN`; you cannot DOWNGRADE a container in
place. To re-tune (e.g., user upgraded from a Cortex-A53 phone to
a flagship and the unlock budget is now larger), perform a no-op
password rotation with new Argon2 params via
[`Container::change_passwords`]:

```rust,ignore
use hidden_volume::container::RepackOptions;
use hidden_volume::crypto::kdf::Argon2Params;

// A no-op-mapping rotation (each password mapped to itself) drives
// the parameter migration through the safe IN-PLACE primitive
// (atomic_rewrite_under_source_lock): source LOCK_EX held across
// the rename, parent-dir fsync, temp removed on error.
hidden_volume::Container::change_passwords(
    path,
    &[(password, password)],   // identity map = migrate params only
    RepackOptions {
        argon2: Argon2Params::HEAVY,   // was DEFAULT
        ..Default::default()
    },
)?;
```

> **⚠** List EVERY space's password in the identity map. Any space
> whose password is omitted is dropped (see §2.2 data-loss warning).

Do NOT roll your own `Container::repack(path, dest, ..)` +
`std::fs::rename(dest, path)`: that re-introduces the M1
lost-update race the library fixes internally — no source lock is
held across the rename, there is no parent-dir fsync, and a failed
repack leaves the partial `dest` for the caller to clean up.
`change_passwords` (and `compact_known`) route through the
in-place primitive that closes all three gaps.

Same anchor / verify caveats as §2.

**Memory footprint.** Audit pass 16 (R-STREAMING-REPACK) made
`Container::repack` memory-bounded: log namespaces are walked one
paginated page at a time with per-page `Tx::commit`, working set
≈ 4 MiB per page regardless of total log volume. Multi-GiB log
namespaces no longer require monitoring host RSS during repack;
KV namespaces still collect once per namespace but are
structurally bounded by the 2-level B+ tree cap.

**File-size cap.** Repack destination growth is gated by
`MAX_OPEN_SCAN_CHUNKS = 16M` chunks ≈ 64 GiB (audit pass 17 B);
exceeding it surfaces as `Error::ContainerTooLarge { extra, cap }`.
Note this fires **mid-copy**, not before any write — when you call
the raw `Container::repack(path, dest, ..)` primitive directly, a
partial `dest` may already exist on disk at the point the error is
returned, and it is **caller-owned**: you must remove it yourself.
The in-place `change_passwords` / `compact_known` wrappers handle
this cleanup for you (the temp is removed on any error). The cap is
symmetric with the open-side scan budget — a successfully-repacked
file is guaranteed to be re-openable.

**Choosing parameters.** See `DESIGN.md` §11.1:

| Preset | Memory | Iterations | Use case |
|---|---|---|---|
| `LIGHT`   |  16 MiB | 3 | Low-end ARM (Cortex-A53) |
| `DEFAULT` |  64 MiB | 3 | Mid-range mobile (last 5y) |
| `HEAVY`   | 256 MiB | 4 | Desktop / server-class |

Don't dynamically tune mid-deployment — pick at create time, and
migrate via repack only when the user's device changes class.

---

## 4. Recovery from corruption / partial writes

### 4.1 What recovery means

The library's recovery model is documented in `DESIGN.md` §7. In
short: the open-path scan picks the maximum-seq Superblock that
AEAD-decrypts under the space's key. A torn write at the file
tail (truncate-at-chunk-boundary or kernel-panic-mid-fsync) leaves
prior Superblock as max-seq and the system rolls back.

### 4.2 Diagnostic recipe

```rust,ignore
// 1. Open read-only — skips the auto-vacuum tree-walk that would
//    otherwise propagate corruption errors as AuthFailed.
let mut c = hidden_volume::Container::open_readonly(path)?;
let mut s = c.open_space(password)?;

// 2. Walk the Merkle chain.
match s.verify_integrity() {
    Ok(report) => println!("OK: {report:?}"),
    Err(hidden_volume::Error::IntegrityFailure { detail, slot }) => {
        eprintln!("corruption at slot {slot}: {detail}");
        // proceed to §4.3
    }
    Err(other) => return Err(other),
}
```

### 4.3 If `verify_integrity` reports a mismatch

The corruption is localized to the reported slot. Recovery options
in increasing destructive order:

1. **Bit-flip (filesystem-level)** — single-byte flip in a
   Superblock chunk. With multi-replica config (`superblock_replicas`
   ≥ 2; default 3), other replicas survive; the open path silently
   picks an intact one. No action required beyond a future
   `compact_known` to reclaim the corrupted chunk.
2. **Single IndexNode chunk corrupted** — the namespace's tree is
   broken. Run `Container::compact_known` with all known passwords:
   data within the corrupted subtree is lost, but the rest of the
   namespace's reachable entries are preserved.
3. **Single Commit chunk corrupted** — the entire latest commit is
   lost; previous commits remain. Recovery rolls back to the prior
   max-seq Superblock automatically (as documented in `DESIGN.md`
   §7); recently-written data is lost.
4. **Header chunk corrupted** — the container is unrecoverable.
   Restore from backup (§1.4).

### 4.4 If the file is truncated

Truncate-at-chunk-boundary: recovery picks the last fully-written
Superblock and rolls back. No special action needed beyond
re-opening the file.

Truncate-mid-chunk (file size not aligned to 4 KiB): the library
**tolerates** the unaligned trailing tail — the chunk grid is
`N = (file_size / CHUNK_SIZE) - 1` (rounding down), so the partial
final chunk is ignored and treated as reclaimable free space (see
`docs/en/reference/format.md` §1). Recovery then picks the last
fully-written Superblock, exactly as in the aligned case. No
hex-editor truncation is needed; re-opening the file is sufficient.

---

## 5. Storage budget management

### 5.1 Why the file grows monotonically

A messenger container grows because of:

- New messages (DataBatch chunks).
- Edits / overwrites (orphan DataBatch chunks).
- Deletes (orphan IndexNode chunks until vacuum_orphans).
- Padding / decoy chunks (size obfuscation).

**Crucially, scrubbed slots are NOT reused** by subsequent writes.
This is **load-bearing for deniability** (DESIGN §9 — see the
"slot-reuse prohibition" subsection): in-place re-writes of a known
file offset would give a multi-snapshot adversary (T2') an
unambiguous "this slot is active" signal that can't be explained
away as decoy growth. Every Tx commit therefore appends to the end
of the file; the holes left by `vacuum_orphans` /
`vacuum_data_batches` stay on disk as uniform-random bytes.

The only way to reclaim disk space is **L5 — full compaction**
(`Container::compact_known`), which rewrites the file from scratch
under one `LOCK_EX`-held flock and rotates the `container_id`.
Audit pass 16 (R-STREAMING-REPACK) made this memory-bounded
(≈ 4 MiB working set per page) so it's safe to run on weak hardware
even with multi-GiB log namespaces.

### 5.2 Measuring live-ratio: `Space::utilization_ratio`

`SpaceStats::utilization_ratio()` returns the fraction of the file's
slot grid owned by this space, in `[0.0, 1.0]`. A multi-space
container will have ratios that sum to less than 1.0 (the rest is
garbage padding + foreign hidden spaces); a single-space container
approaches 1.0 minus padding overhead.

```rust,ignore
let stats = space.stats()?;
println!(
    "live: {} / {} chunks ({:.1}% utilization)",
    stats.owned_chunk_count,
    stats.total_slot_count,
    stats.utilization_ratio() * 100.0,
);
```

The CLI exposes the same number: `hv dump-stats <path>` prints
`utilization_ratio: 0.612 (61.2% live)`.

### 5.3 Reclaim recipe (lightweight)

```rust,ignore
// Cheap forward-secrecy + cleanup for log namespaces.
// Safe to run on a live writer — no rename, no temp file.
// Does NOT shrink the file; only zeroes out orphan DataBatch slots.
space.vacuum_data_batches()?;
```

Run periodically (e.g. once per app launch) to reclaim batches
orphaned by message edits / deletes. Cost: a few ms per active log
namespace.

### 5.4 Reclaim recipe (full) — when to compact

```rust,ignore
// Heavyweight: full repack + size reclaim + container_id rotation.
// Resets commit_history to [1]; re-anchor required.
drop(space);                  // release flock first
drop(container);
hidden_volume::Container::compact_known(path, &all_passwords, options)?;
```

**Triggers — pick one or combine.** The library does not enforce a
schedule; the host-app is the right place to decide because the
right cadence depends on UX (does compaction during launch hurt
perceived startup time?) and on storage budgets:

```rust,ignore
// Pattern 1: live-ratio threshold (recommended for messenger).
// Heavy-delete workloads (expired conversations, "delete account X")
// drift the file's high-water mark up while live content shrinks.
const RECLAIM_THRESHOLD: f64 = 0.5;
if stats.utilization_ratio() < RECLAIM_THRESHOLD
    && stats.total_slot_count > 1024  // skip on near-empty new containers
{
    schedule_compact();
}

// Pattern 2: absolute size budget (supplementary).
// User-visible quota — typical mobile target ≤ 1 GiB.
const SIZE_BUDGET_CHUNKS: u64 = 256 * 1024;  // 1 GiB at CHUNK_SIZE
if stats.total_slot_count > SIZE_BUDGET_CHUNKS {
    schedule_compact();
}

// Pattern 3: idle-time defer (least intrusive UX).
// Run on first launch after ≥ N days of inactivity, when the user
// is not waiting on a chat to open.
let last_compact_age = last_compact_at.elapsed();
if last_compact_age > Duration::from_secs(14 * 24 * 3600) {
    schedule_compact_on_next_idle();
}

// Pattern 4: privacy event (immediate).
// User just hit "delete this account" / "wipe history". A
// guaranteed-physical scrub demands compact (rotates container_id
// too — defends against multi-snapshot byte-diff that may have
// already captured the live data before deletion).
on_privacy_action(|| {
    schedule_compact();
});
```

Use any combination. For a messenger, Pattern 1 + Pattern 4 is the
common pair: ambient drift handled by live-ratio, explicit deletes
handled immediately.

**Cost.** `compact_known` runs a full Tx-by-Tx rewrite of every
unlocked space. On x86 desktop ~300-500 MB/s through-put is
realistic; on weak ARM ~50-100 MB/s. Argon2 cost is paid once per
unlocked space (one fresh derivation against the new salt). Audit
pass 16 made memory ≈ 4 MiB per page regardless of total size —
no host-RSS babysitting required.

**Atomicity.** `compact_known` is in-place: writes a sibling tmp
file named `.{stem}.hv-compact.{16hex}.tmp` (rotation uses
`.{stem}.hv-rotate.{16hex}.tmp`), `fsync`s it, then `rename`s over
the source under `LOCK_EX` + `fsync_parent_dir`. Crash mid-rename
either keeps the old file intact or atomically replaces it; never
partial state.

**Stale temp cleanup.** A crash *before* the rename can leave a
sibling `.{stem}.hv-rotate.{16hex}.tmp` or `.{stem}.hv-compact.{16hex}.tmp`
file behind. These are inert (they never replaced the live
container) but they consume disk and leak nothing. Host apps should
glob the container's directory for `.{stem}.hv-*.{hex}.tmp`
siblings and delete them at startup, **while the container is not
open** (deleting a temp that a concurrent in-progress rotate/compact
is actively writing would corrupt that operation — only sweep when
you hold, or know no one holds, the container).

Use this recipe when:
- Live-ratio drops below threshold (see triggers above).
- File size is dominated by garbage / orphan chunks (typical after
  a mass delete).
- Argon2 params need to change (§3).
- Padding policy or initial garbage budget needs to change.

### 5.4 Decoy size obfuscation

`ContainerOptions::initial_garbage_chunks` and
`PaddingPolicy::{BucketGrowth, FixedRatio}` exist to make file
size uninformative to a snapshot adversary. Defaults are NOT to
add padding (zero bytes overhead). Production deployments
defending against T2' (multi-snapshot byte-diff) should:

- Set `initial_garbage_chunks` so the file starts at a "this
  could be anything" size (e.g. 32-256 MiB).
- Set `padding_policy = BucketGrowth { bucket_chunks: N }` so the
  file size jumps in N-chunk increments instead of revealing
  per-commit growth.

See `DESIGN.md` §1 for what this defends and §8 for policy
mechanics.

---

## 6. Multi-device deployment recipes

Pick **one** pattern explicitly. Mixing them silently corrupts
state. Full contract: `docs/en/guide/multi-device.md`.

### 6.1 Pattern A — single device

Default. One file, one process, `LOCK_EX` enforced. No special
ops.

### 6.2 Pattern B — sequential hand-off (one shared file)

Multiple processes / devices take turns writing. ONLY ONE writer
at a time; library's `LOCK_EX` enforces this on filesystems that
honour `flock(2)`. Storage MUST honour flock semantics — NFSv3
without `lockd`, SMB without proper setup, FUSE filesystems etc.
may silently allow concurrent writers and corrupt the file. Test
with two-writer integration before deploying.

### 6.3 Pattern C — read-only fan-out

One writer process, many readers. Writer holds `LOCK_EX` (default
open path); readers use `Container::open_readonly` (`LOCK_SH`).
Multiple readers coexist with one writer; readers see the
snapshot at their open time and observe new commits only on
re-open.

### 6.4 Pattern D — replicated containers (RECOMMENDED for messengers)

One container per device. Each device's commit_seq is
independent. Reconciliation lives in the host-app's sync layer
(CRDT, vector clock, or server-as-source-of-truth). The library
is sync-unaware.

---

## 7. Forensic scrub before disposal

When the user retires a device, the container file should be
made unrecoverable. The library cannot guarantee this on its own
because:

- Modern flash storage (SSD, eMMC, UFS) implements wear-leveling
  via an FTL. Writing zeros to a file does NOT overwrite the
  physical NAND cells; the FTL just remaps the LBA. Old NAND cells
  may be accessible via firmware-level extraction.
- Magnetic disks support secure erase via `hdparm --security-erase`
  but this is whole-drive only.

### 7.1 Best-effort logical scrub

```rust,ignore
// Overwrite the file with random bytes, then delete.
let len = std::fs::metadata(path)?.len();
let f = std::fs::OpenOptions::new().write(true).open(path)?;
let mut buf = [0u8; 4096];
let mut written = 0u64;
while written < len {
    hidden_volume::crypto::rng::fill(&mut buf)?;
    use std::io::{Seek, SeekFrom, Write};
    let mut f = &f;
    f.seek(SeekFrom::Start(written))?;
    let to_write = std::cmp::min(buf.len() as u64, len - written) as usize;
    f.write_all(&buf[..to_write])?;
    written += to_write as u64;
}
f.sync_all()?;
drop(f);
std::fs::remove_file(path)?;
```

This is best-effort against software-level recovery. Against a
forensic adversary with hardware access, only **whole-device secure
erase** (vendor-specific) or **physical destruction** of the
storage media provides strong guarantees.

### 7.2 Defense-in-depth recommendation

For users in adversarial environments:

1. Store the container on a full-disk-encrypted volume (LUKS /
   FileVault / BitLocker). Disposal becomes "throw away the FDE
   key", not "scrub the file".
2. On Linux, run on a `tmpfs` if persistence isn't required —
   power-off destroys the data without disk traces.
3. Pair with a bootable USB on which the FDE key lives — losing
   the USB makes the disk unreadable.

---

## 8. Container size monitoring

```rust,ignore
let stats = space.stats()?;
let owned_bytes = stats.owned_chunk_count as u64 * 4096;
let file_bytes = std::fs::metadata(path)?.len();
let overhead_pct = 100 * (file_bytes - owned_bytes) / file_bytes;
println!(
    "{} owned chunks ({} KiB) in a {} KiB file ({}% padding/orphans)",
    stats.owned_chunk_count,
    owned_bytes / 1024,
    file_bytes / 1024,
    overhead_pct,
);
```

Interpret:

- **0-30% overhead** — typical steady-state: padding policy and
  decoy garbage. No action.
- **30-70%** — accumulated orphans from deletes / overwrites.
  Run `vacuum_data_batches` (cheap) or `compact_known` (full).
- **>70%** — pathological accumulation. Investigate workload
  (rapid put-delete cycles? frequent `commit_seq` rotations?)
  before compacting.

---

## 9. What to do when something goes wrong

| Symptom | Diagnosis | Recipe |
|---|---|---|
| `Error::AuthFailed` on every space | Wrong password OR wrong file OR header corruption | Try other passwords; verify `container_id` in header is unchanged from a known-good backup; if all fail, restore from backup |
| `Error::Busy` | Another writer holds `LOCK_EX` | Wait; retry once after a delay; do NOT loop tightly — it's almost always a stuck process or a stale lock from a crashed peer |
| `Error::Malformed` on open | Header corrupted (a mid-chunk-truncated *tail* is tolerated, not rejected — see §4.4) | Restore from backup |
| `Error::IntegrityFailure { slot, detail }` | Specific chunk has wrong hash; AEAD passed but Merkle didn't | §4.3 |
| `Error::ReadOnly` from a write call | Container was opened via `open_readonly` | Reopen via `Container::open` (acquires `LOCK_EX`) |
| `Error::Cancelled` | A `CancelToken` was fired during the operation | Operation aborted; safe to retry (no partial state on disk) |
| `Error::PayloadTooLarge` on commit | A single record exceeds the chunk capacity | Reduce the record size; for messages > 8 KiB, store in a separate KV namespace with a content-addressed key |
| Disk fills mid-commit | OS returned `ENOSPC` | The commit aborted before fsync — recovery rolls back to prior commit. Free disk space, retry |
| Process killed mid-Tx | OS killed the process before commit completed | Recovery rolls back to prior commit on next open; no action required |
| Process killed mid-fsync | Same as above with possibly a torn last-chunk write | Recovery picks max-seq Superblock; torn chunk silently ignored |
| Open succeeds but namespace count is 0 | Empty space (no commits yet) OR `commit_history` rolled back | Check `commit_seq()` and `commit_history()` against external anchor |

---

## 10. Cross-references

- `docs/en/guide/integration.md` — host-app integration narrative.
- `docs/en/guide/multi-device.md` — host-app sync / anchor contract.
- `docs/en/security/threat-model.md` — formal adversary / invariant catalog.
- `DESIGN.md` — on-disk format and crash-safety invariants.
- `docs/en/contributing/benchmarks.md` — performance baselines and Argon2 tuning targets.
- `SECURITY.md` — vulnerability disclosure policy.

[`Container::open_readonly`]: ../src/container/mod.rs
[`Container::change_passwords`]: ../src/container/mod.rs
[`Container::repack`]: ../src/container/mod.rs
[`Space::verify_integrity`]: ../src/space/mod.rs
