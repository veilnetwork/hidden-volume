# Integration guide

🇬🇧 **English** · [🇷🇺 Русский](../../ru/guide/integration.md)

How to build a host-app — typically a decentralized messenger — on top of
`hidden-volume`. This is the narrative complement to `DESIGN.md` (formal
spec) and the per-API rustdoc (reference). Read this first.

If anything in this document conflicts with `DESIGN.md`, `DESIGN.md` wins.

## What you get

`hidden-volume` is the **local at-rest persistence layer**. It owns one
file. Inside that file there are 1+ encrypted spaces, each unlocked by a
distinct password. From the host-app's perspective each space looks like
a tiny KV store + an append-only log namespace, both transactional.

What it does NOT include:
- Network transport. P2P, sync, transit encryption — host-app concern.
- Identity / pairing / contact discovery. Host-app concern.
- Push notifications, UI state, IME caches. Host-app concern.

The library is sync at the core, with an optional thin tokio wrapper.

---

## 1. Quick start

```rust
use hidden_volume::{Container, crypto::kdf::Argon2Params};
use hidden_volume::space::index::Namespace;

# fn main() -> hidden_volume::Result<()> {
// Create a container. Pick a hardware-tier preset:
let mut container = Container::create(
    "/path/to/messenger.store",
    Argon2Params::DEFAULT,  // see §2 for the LIGHT/DEFAULT/HEAVY trade-off
)?;

// Create a space (one user profile / one chat partition).
let mut space = container.create_space(b"correct horse battery staple")?;

// Write KV settings + a couple of contacts in one transaction.
let mut tx = space.begin_tx();
tx.put(Namespace::SETTINGS, b"username", b"alice")?;
tx.put(Namespace::CONTACTS, b"bob",   b"bob@example.com")?;
tx.commit()?;

// Append messages to the message log namespace.
let mut tx = space.begin_tx();
tx.append_log(Namespace::MESSAGE_LOG, 1, b"hi bob")?;
tx.append_log(Namespace::MESSAGE_LOG, 2, b"how are you")?;
tx.commit()?;

drop(space);
drop(container);

// Re-open elsewhere.
let mut container = Container::open("/path/to/messenger.store")?;
let mut space = container.open_space(b"correct horse battery staple")?;
assert_eq!(
    space.get(Namespace::SETTINGS, b"username")?.as_deref(),
    Some(&b"alice"[..])
);
# Ok(()) }
```

---

## 2. Hardware tuning (Argon2 presets)

Argon2id parameters live in the cleartext header (set at create time).
Pick one preset per device class — don't try to dynamically tune.

| Preset | Memory | Iterations | Parallelism | When |
|---|---|---|---|---|
| [`Argon2Params::LIGHT`]   |  16 MiB | 3 | 1 | Low-end ARM (Cortex-A53, embedded) |
| [`Argon2Params::DEFAULT`] |  64 MiB | 3 | 1 | Mid-range mobile (last 5y phones) |
| [`Argon2Params::HEAVY`]   | 256 MiB | 4 | 4 | Desktop / server-class |

[`Argon2Params::MIN`] is the floor; the library refuses to open or
create below this. It exists to defend against a malicious-host attack
that would force a victim into a trivially brute-forceable param set.

The host-app should pick one preset per *new* container based on
device-tier detection. `Container::repack` is the migration path for
re-tuning later.

### Open-scan parallelism (`parallel-scan` feature)

The Argon2 preset above is a per-unlock CPU cost. Once Argon2 is
done, the open-scan walks every chunk in the file (O(N) AEAD
trial-decrypts). On large containers — heavy-history messengers
crossing ~200 MiB — that scan becomes the dominant unlock cost.

The `parallel-scan` Cargo feature (Unix-only) parallelizes that
scan via rayon's work-stealing pool, capped at 4 threads, with a
process-wide `OnceLock`-cached pool. Public surface:
[`Container::open_space_parallel`] / [`open_space_with_keys_parallel`]
(both behind `#[cfg(all(feature = "parallel-scan", unix))]`).

**Measured speedup on a 12-thread x86 host** (full numbers in
[`docs/en/contributing/benchmarks.md`](../contributing/benchmarks.md)):

| User profile size | Sequential unlock | Parallel unlock |
|---|---:|---:|
| Light (~40 MiB) | 52 ms | 18 ms |
| Average (~200 MiB) | 608 ms | 264 ms |
| Heavy (~400 MiB) | **1.5 s** | **0.2 s** |

**TL;DR for messenger devs.** Enable `parallel-scan` for any
multi-core host with messenger-realistic history (≥ 40 MiB). The
speedup grows with size — at 400 MiB the unlock drops from 1.5 s
("did the app freeze?") to 200 ms (invisible). Leave the feature
OFF on single-core mobile (Cortex-A53 class): the 4-thread cap
collapses to 1, no speedup, and you'd pay rayon's ~6 MiB binary
size for nothing.

[`Container::open_space_parallel`]: ../src/container/mod.rs
[`open_space_with_keys_parallel`]: ../src/container/mod.rs

---

## 3. The two storage models inside one space

Within a space you choose how to store data per `Namespace` (a single
byte tag).

### KV namespace

Use [`Tx::put`] / [`Tx::delete`] / [`Space::get`] / [`Space::list`] /
[`Space::count`]. Backed by a B+ tree of [`IndexNode`] chunks.

- Cap per namespace: ~5 000–10 000 entries (depending on key/value size).
- Keys ≤ 256 bytes; values ≤ 2 048 bytes.
- Use for: settings, contacts, identity material, anything where
  random-access by key beats sequential scan.

### Log namespace (DataBatch)

Use [`Tx::append_log`] / [`Space::read_log`] / [`Space::iter_log_after`] /
[`Space::iter_log_before`] / [`Space::iter_log`]. Records are zstd-batched
and stored as a [`ChunkKind::DataBatch`] chunk per Tx.

- Caller picks `log_id: u64` per record (typically a monotonically-
  increasing counter or a timestamp).
- Cap per record: 8 KiB. For larger media use a separate KV namespace
  with a content-addressed key.
- Use for: message log, event audit trail, any append-heavy stream.

Pre-defined namespace constants: [`Namespace::SETTINGS`],
[`CONTACTS`], [`MESSAGE_LOG`], [`MEDIA`]. Define your own with
`Namespace(byte)` for byte values not in `RESERVED`.

---

## 4. Multi-space and multi-device

This section is a TL;DR. The full contract is in
[`docs/en/guide/multi-device.md`](multi-device.md).

### Multiple spaces in one file

```rust
# fn run(container: &mut hidden_volume::Container) -> hidden_volume::Result<()> {
let main   = container.create_space(b"main-password")?;
drop(main);
let hidden = container.create_space(b"hidden-password")?; // independent
drop(hidden);
let duress = container.create_space(b"duress-password")?; // decoy
# Ok(()) }
```

Each space is cryptographically independent. An adversary holding the
file plus one password cannot prove other spaces exist (D2 in
`DESIGN.md`).

### Multi-device patterns

Pick **one** explicitly:

| Pattern | When | How |
|---|---|---|
| Single device | default | `Container::open` (`LOCK_EX` enforced) |
| Sequential hand-off (one shared file, multiple processes) | rare; needs flock-honoring FS | each writer opens and closes; lock serializes |
| Read-only fan-out (one writer, many readers) | snapshot UIs, backup tools | writer holds `LOCK_EX`, readers use [`Container::open_readonly`] (`LOCK_SH`) |
| Replicated containers (one container per device) | **recommended for P2P messengers** | each device has its own file, sync at the message-log layer (host-app responsibility) |

Per-space rollback / fork detection: see §7.

---

## 5. Pagination (message-history scrolling)

Don't call [`Space::iter_log`] on a long-running namespace — it
materializes the whole namespace into memory.

Use [`Space::iter_log_after`] (oldest-first cursor) or
[`Space::iter_log_before`] (newest-first cursor, the canonical chat
pattern).

```rust
# fn run(space: &mut hidden_volume::Space<'_>) -> hidden_volume::Result<()> {
use hidden_volume::space::index::Namespace;

// First page: 50 latest messages.
let page1 = space.iter_log_before(Namespace::MESSAGE_LOG, None, 50)?;
// Subsequent pages: pass the oldest log_id from the previous page.
let cursor = page1.last().map(|(id, _)| *id);
let page2 = space.iter_log_before(Namespace::MESSAGE_LOG, cursor, 50)?;
# Ok(()) }
```

Memory bound: `O(limit)` decoded entries plus a few touched DataBatch
chunks (cached per call). Independent of total namespace size.

For oldest-first feeds (e.g., archive export), use `iter_log_after`
with the same cursor pattern.

---

## 6. Cancellation (mobile UX)

Long operations (`open_space` scan, `repack`) need to be abortable
when the user cancels. Tokio's `spawn_blocking` does NOT abort a
running closure; the library uses cooperative cancellation via
[`CancelToken`].

```rust
use hidden_volume::cancel::CancelToken;
# fn run(container: &mut hidden_volume::Container) -> hidden_volume::Result<()> {
let token = CancelToken::new();
let arm = token.clone();

// Fire cancel from another thread — typically a UI button handler.
std::thread::spawn(move || {
    std::thread::sleep(std::time::Duration::from_secs(5));
    arm.cancel();
});

match container.open_space_cancellable(b"password", &token) {
    Ok(_space) => { /* unlocked in time */ }
    Err(hidden_volume::Error::Cancelled) => { /* user pressed cancel */ }
    Err(other) => return Err(other),
}
# Ok(()) }
```

Cancellable APIs:
- [`Container::open_space_cancellable`] / [`open_space_with_keys_cancellable`]
- [`Container::repack_cancellable`]
- [`Container::compact_known_cancellable`]

Argon2 derivation is NOT cancellable (RustCrypto is uninterruptible);
the post-Argon2 cancel check fires before the (cancellable) scan
begins.

For the async path (separate crate `hidden-volume-async`), use
[`AsyncContainer::run_cancellable`]:

```rust,ignore
use hidden_volume_async::AsyncContainer;

let result = container.run_cancellable(token, |c, t| {
    let mut space = c.open_space_cancellable(b"password", t)?;
    let page = space.iter_log_before(Namespace::MESSAGE_LOG, None, 50)?;
    Ok(page)
}).await;
```

---

## 7. Rollback / fork detection (anchors)

A snapshot adversary can swap the file with an older copy. The library
cannot detect this on its own. You provide an **external anchor**.

After every successful commit, persist `space.commit_seq()` in
TPM / Secure Enclave / a server counter. On reopen:

```rust
# fn run(space: &mut hidden_volume::Space<'_>, anchor_seq: u64) -> hidden_volume::Result<()> {
let cur = space.commit_seq();
let history = space.commit_history();
if cur < anchor_seq {
    panic!("rollback detected — file replaced with older version");
}
if !history.contains(&anchor_seq) {
    panic!("fork detected — timeline diverges from anchor");
}
// else: clean continuation, proceed.
# Ok(()) }
```

Full algorithm + anchor-storage tradeoffs:
[`docs/en/guide/multi-device.md`](multi-device.md).

**Privacy contract.** Do NOT anchor decoy / hidden spaces — the anchor
itself reveals the existence of the space.

---

## 8. Key caching (skip Argon2 on relaunch)

Argon2id is intentionally slow (~100 ms–1 s per unlock). For an app
that re-opens many times, cache the derived [`SpaceKeys`] in
platform-native secure storage (Keychain / Secret Service / Android
Keystore):

```rust
# fn run(container: &mut hidden_volume::Container) -> hidden_volume::Result<()> {
// First unlock — pay Argon2 cost once.
let keys = container.derive_space_keys(b"password")?;
// store_in_keychain(&keys);

// Subsequent unlocks — skip Argon2.
// let keys = load_from_keychain();
let _space = container.open_space_with_keys(keys)?;
# Ok(()) }
```

Trade-off: an attacker compromising BOTH the file AND the host OS's
keyring recovers data without brute-forcing. For maximum-paranoia
spaces (decoy, hidden) don't cache — pay Argon2 every time.

---

## 8b. Storage / About-this-profile UI ([`Space::stats`])

For the typical messenger "Storage" / "About this profile" page, use
[`Space::stats`] to fetch every common counter in one call:

```rust,ignore
let s = space.stats()?;
println!(
    "seq {}, history {} entries, {} chunks owned, {} total items",
    s.commit_seq,
    s.commit_history_len,
    s.owned_chunk_count,
    s.total_entries(),
);
for (ns, count) in &s.namespace_counts {
    println!("  namespace {} → {} entries", ns.0, count);
}
```

Cost: walks each active namespace's KV-index tree once (same as
calling `count` per namespace summed). Read-only safe.

## 9. Integrity verification

Per-chunk AEAD already protects against bit-flip corruption (any byte
change → `AuthFailed` on the chunk). For end-to-end verification of
the Merkle hash chain (Superblock → Commit → IndexNode tree), call
[`Space::verify_integrity`]:

```rust
# fn run(space: &mut hidden_volume::Space<'_>) -> hidden_volume::Result<()> {
let report = space.verify_integrity()?;
println!(
    "verified {} chunks across {} namespaces, max tree depth {}",
    report.chunks_verified, report.namespaces_verified, report.max_depth,
);
# Ok(()) }
```

Returns `Error::IntegrityFailure { detail, slot }` on any mismatch.
Cost: O(N) chunk reads where N is the reachable subtree (a few ms for
typical messenger histories).

When to call: after sync from a peer, periodically as a self-test, or
after a host-app crash recovery.

---

## 10. Padding & decoy size

Single-snapshot deniability (D1) requires the file to look like
random-noise. The defaults already satisfy this; for stronger
multi-snapshot resistance use:

- [`ContainerOptions::initial_garbage_chunks`] — pre-write N decoy
  chunks at create time so the file has a non-trivial initial size.
- [`PaddingPolicy::BucketGrowth`] — round file size up to bucket
  multiples on each commit, masking per-commit growth.
- [`PaddingPolicy::FixedRatio`] — append a percentage of garbage per
  real chunk written.

Set via `Container::create_with_options` or runtime via
[`Container::set_padding_policy`].

---

## 10a. Erase a whole namespace

When the user clicks "Clear chat history" or "Wipe contacts", use
[`Space::erase_namespace`] instead of looping `Tx::delete` by hand:

```rust,ignore
use hidden_volume::space::index::Namespace;

let removed = space.erase_namespace(Namespace::MESSAGE_LOG)?;
println!("dropped {removed} messages");
```

This issues a single Tx that deletes every entry in the namespace and
commits. The new commit omits the namespace from its `IndexRoot` set
(the rebuilt tree is empty); old IndexNode chunks become orphans.

**Forward-secrecy gap for log namespaces.** `vacuum_orphans` (run
automatically on the next `open_space`) scrubs the orphan IndexNode
chunks — so the *keys* are gone — but it does NOT scrub `DataBatch`
chunks (a single batch may still hold live entries from other
log_ids). The actual message bytes remain on disk, AEAD-decryptable
by anyone with the password.

To close that gap **without a full compact**, call
[`Space::vacuum_data_batches`] — it walks every namespace's KV index,
collects referenced batch_slots, and scrubs every owned DataBatch
chunk that isn't referenced anywhere:

```rust,ignore
// "Clear chat history" — recommended recipe (cheap, in-place):
space.erase_namespace(Namespace::MESSAGE_LOG)?;
let scrubbed = space.vacuum_data_batches()?;
println!("scrubbed {scrubbed} orphan DataBatch chunks");
```

`vacuum_data_batches` also reclaims orphan batches created by
**overwrites** (re-appending the same `log_id` with a new payload
makes the prior batch unreachable; full compaction or this method
clears it). For "always-on" forward-secrecy on a messenger that
edits messages, run `vacuum_data_batches` periodically (e.g. once
per app launch).

When you actually want a full rewrite (size reclaim, container_id
rotation, history reset) use `compact_known` instead — see §11.

For KV namespaces (settings, contacts) the post-vacuum_orphans state
is already forward-secret; nothing else to do.

## 10b. Password change

Users will eventually want to change a space's password. Use
[`Container::change_passwords`]:

```rust,ignore
use hidden_volume::Container;

// Change "old-pw" → "new-pw"; keep the hidden space untouched.
let other_kept: &[u8] = b"hidden-pw";
Container::change_passwords(
    path,
    &[(b"old-pw", b"new-pw"), (other_kept, other_kept)],
    options,
)?;
```

Each mapping entry is `(open_with, write_as)`:
- `open_with == write_as` → preserve verbatim.
- `open_with != write_as` → rotate to the new password.

> **⚠ DATA LOSS BY DESIGN.** Spaces NOT mentioned in the mapping
> are **silently and permanently dropped** (same destructive
> semantics as `compact_known`). An empty / incomplete password
> list drops *every* unlisted space. This is a deniability property:
> the library cannot enumerate deniable spaces, so it cannot detect
> or warn about the loss — the host-app MUST confirm the password
> set is complete before calling. To preserve a space whose password
> isn't being rotated, list it as a no-op `(p, p)` pair.

Mechanics: writes a fresh container at a sibling temp file named
`.{stem}.hv-rotate.{16hex}.tmp`, then atomic-renames over `path`
under the source `LOCK_EX` with a parent-dir `fsync`. On any
failure the temp is removed and the original `path` is untouched.
The cancellable variant (`change_passwords_cancellable`) honours a
`CancelToken` at every namespace / Tx boundary; on cancel the temp
is removed and `Error::Cancelled` is returned.

**Forward-secrecy note.** After rotation, the old container's blocks
are released to the filesystem. The allocator may reuse them; for
forensic-grade scrub of the underlying storage, host-app must run a
separate tool. On flash, the FTL further obscures originals but
does not strongly guarantee deletion.

## 11. Compaction (forward-secrecy + size reclaim)

Every open of a space runs [`Space::vacuum_orphans`] → previous
IndexNode chunks (orphaned by the latest commit) are scrubbed. This
gives forward-secrecy for KV deletes after one reopen.

For DEEP scrub (also reclaiming DataBatch space + dropping historical
Superblock replicas + size reduction), use:

```rust
# use hidden_volume::container::RepackOptions;
# fn run(path: &std::path::Path, options: RepackOptions) -> hidden_volume::Result<()> {
hidden_volume::Container::compact_known(path, &[b"main-pw"], options)?;
# Ok(()) }
```

Trade-off: `compact_known` PERMANENTLY DESTROYS any space whose
password is not supplied. (Historical note: a `compact_all`
synonym existed pre-2026-05-02 cleanup; removed as a documentation-
only duplicate. Same destructive semantics — caller asserts they
have all passwords.)

After compaction the new container has a fresh `container_id`; host
must re-anchor (see §7).

---

## 12. Anti-patterns

Things to NOT do:

- **Don't iter_log a 100K-message namespace** — use pagination (§5).
- **Don't anchor a decoy/hidden space** — its existence becomes public.
- **Don't pass user-supplied input as a `Namespace`** — `Namespace`
  is a 1-byte tag, not a user identifier.
- **Don't share a file between processes via NFS** unless your NFS
  honors `flock(2)`. The library's lock acquisition will silently
  succeed but corruption can occur.
- **Don't wrap `iter_log` results in arbitrary memory expansion** —
  payloads are owned `Vec<u8>` (see `docs/en/security/audits/plaintext.md`
  for why the library does NOT wrap them in `Zeroizing`; key
  material and Rust-side password copies on FFI / async / CLI ARE
  zeroized — audit pass 16 + 17). For mlocking host-app payloads,
  do it at process scope.
- **Don't change Argon2 params at runtime** — params are baked into
  the cleartext header at create time. Use `repack` to re-tune.
- **Don't ignore `Error::Busy`** — it means another writer holds the
  exclusive lock. Don't retry in a tight loop; surface to the user.

---

## 13. Common questions

**Q: How big can a container be?**
A: Hard cap is `MAX_OPEN_SCAN_CHUNKS = 16M` chunks ≈ **64 GiB**
(audit pass 16 TM1 — bounds DoS via inflated-file). Both the
write-side (`Container::create_with_options` initial garbage,
post-commit padding, `repack` destination growth) and the read-side
(open-scan) refuse to cross this cap; the write-side surfaces it as
`Error::ContainerTooLarge { extra, cap }` (audit pass 17 B), the
read-side as `Error::Malformed("container exceeds open-scan
budget")`. Within the cap, the practical limit is RAM during the
open scan; streaming open keeps RAM bounded by `O(M·16 B)` where M =
owned chunks (see DESIGN §5). `repack` is also bounded — audit pass
16 R-STREAMING-REPACK made it pageable through log namespaces with
≈ 4 MiB working set per page. On 4 GiB ARM, a 10 GiB container
scans in ~10 s.

**Q: Can two spaces share data?**
A: No. Each space is cryptographically independent. The host-app can
keep a contact list per space and route messages at the application
layer.

**Q: Can I delete a single message?**
A: Yes — `Tx::delete(MESSAGE_LOG, log_id_key)`. Forward-secrecy via
`vacuum_orphans` (next reopen) clears the IndexNode chunk pointing
at it. The DataBatch chunk containing the message bytes is scrubbed
on the next `compact_known` call.

**Q: What happens if I `delete` a key that isn't there?**
A: It is **intentionally not a no-op**: deleting an absent key still
writes a commit and advances the sequence number. This is by design,
not a wasted write. If a missing-key delete short-circuited (skipped
the commit), then *whether the file grew / whether `commit_seq`
moved* would observably reveal "that key existed" vs "it did not" to
a multi-snapshot adversary (T2') watching the container — a key-
existence oracle. Writing the commit unconditionally makes a delete
an **intentional tombstone-anchor**: present-key and absent-key
deletes are indistinguishable from the outside. Host apps should not
treat the extra commit as a bug or try to elide it.

**Q: How do I know an unlock attempt failed?**
A: `open_space` returns `Error::AuthFailed`. The same error covers
"wrong password" and "no such space" — by design (D2). Don't try to
distinguish them; surface a generic "unlock failed" to the user.

**Q: Is the file format stable?**
A: Yes. v1.0.0 shipped and froze the on-disk format at generation
v3. A reader refuses any `format_version != 3`. Any future layout
change requires a new generation (v4) plus a migration tool; it will
not silently re-interpret a v3 file. See `docs/en/reference/format.md`
§7 (cross-version policy).

**Q: Do I need a special filesystem?**
A: ext4 / APFS / NTFS all work. Networked filesystems must honor
`flock(2)`. ZFS / Btrfs snapshots are fine for backups but
intermediate-snapshot deniability is weakened (see DESIGN §1 T2').

---

## 14. Where to read next

| Topic | Doc |
|---|---|
| Format spec rationale, threat model summary, invariants | `DESIGN.md` |
| Canonical wire-format spec (v1.0-frozen byte layout) | `docs/en/reference/format.md` |
| Formal threat model (adversaries, audit history, review request) | `docs/en/security/threat-model.md` |
| Backup / restore / key rotation / recovery / scrub recipes | `docs/en/guide/operations.md` |
| Cross-generation migration (export/re-import; no in-place vN → vM) | `docs/en/guide/migration.md` |
| Semver coverage policy (what's covered, what's not, post-v1.0) | `docs/en/reference/semver.md` |
| P2P-sync contract, anchor strategy | `docs/en/guide/multi-device.md` |
| Constant-time audit | `docs/en/security/audits/constant-time.md` |
| Memory hygiene audit | `docs/en/security/audits/memory.md` |
| Plaintext-leak audit | `docs/en/security/audits/plaintext.md` |
| fsync ordering audit | `docs/en/security/audits/fsync.md` |
| Benchmarks / target numbers | `docs/en/contributing/benchmarks.md` |
| Roadmap | `TASKS.md` |
| Per-API rustdoc | `cargo doc --open` |

[`Argon2Params::LIGHT`]: ../src/crypto/kdf.rs
[`Argon2Params::DEFAULT`]: ../src/crypto/kdf.rs
[`Argon2Params::HEAVY`]: ../src/crypto/kdf.rs
[`Argon2Params::MIN`]: ../src/crypto/kdf.rs
[`Tx::put`]: ../src/tx/mod.rs
[`Tx::delete`]: ../src/tx/mod.rs
[`Tx::append_log`]: ../src/tx/mod.rs
[`Space::get`]: ../src/space/mod.rs
[`Space::list`]: ../src/space/mod.rs
[`Space::count`]: ../src/space/mod.rs
[`Space::read_log`]: ../src/space/mod.rs
[`Space::iter_log`]: ../src/space/mod.rs
[`Space::iter_log_after`]: ../src/space/mod.rs
[`Space::iter_log_before`]: ../src/space/mod.rs
[`Space::verify_integrity`]: ../src/space/mod.rs
[`Space::vacuum_orphans`]: ../src/space/mod.rs
[`Container::open_readonly`]: ../src/container/mod.rs
[`Container::set_padding_policy`]: ../src/container/mod.rs
[`Container::open_space_cancellable`]: ../src/container/mod.rs
[`open_space_with_keys_cancellable`]: ../src/container/mod.rs
[`Container::repack_cancellable`]: ../src/container/mod.rs
[`Container::compact_known_cancellable`]: ../src/container/mod.rs
[`Container::change_passwords`]: ../src/container/mod.rs
[`Space::erase_namespace`]: ../src/space/mod.rs
[`Space::stats`]: ../src/space/mod.rs
[`Space::vacuum_data_batches`]: ../src/space/mod.rs
[`AsyncContainer::run_cancellable`]: ../crates/hidden-volume-async/src/lib.rs
[`CancelToken`]: ../src/cancel.rs
[`Namespace::SETTINGS`]: ../src/space/index.rs
[`CONTACTS`]: ../src/space/index.rs
[`MESSAGE_LOG`]: ../src/space/index.rs
[`MEDIA`]: ../src/space/index.rs
[`IndexNode`]: ../src/space/index.rs
[`ChunkKind::DataBatch`]: ../src/chunk/kind.rs
[`ContainerOptions::initial_garbage_chunks`]: ../src/container/mod.rs
[`PaddingPolicy::BucketGrowth`]: ../src/padding.rs
[`PaddingPolicy::FixedRatio`]: ../src/padding.rs
