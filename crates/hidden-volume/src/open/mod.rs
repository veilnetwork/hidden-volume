//! Discovery scan and recovery. See DESIGN §5, §7.
//!
//! Trial-decrypts every slot with the candidate space's per-slot key. The
//! result tells us which slots belong to this space and what kind they
//! are. Slots that fail AEAD are silently ignored — they may be garbage,
//! another space, or actual corruption, and we MUST NOT distinguish.
//!
//! ## Streaming memory profile
//!
//! Per slot we hold one ciphertext chunk (4 KiB stack array) and at most
//! one decrypted Plaintext (≈4 KiB heap, with a `Zeroizing<Vec<u8>>`
//! parent buffer per `aead.open`); both are dropped before the next
//! iteration. Across the whole scan we accumulate only:
//!
//! - `owned_slots: Vec<u64>` — 8 bytes per owned chunk.
//! - the latest-seq Superblock's payload (≈48 bytes total).
//! - `commit_history: Vec<u64>` — 8 bytes per *Superblock* chunk owned
//!   (deduplicated to one per seq at the end).
//!
//! That is ~16 bytes per owned chunk in the asymptotic limit (negligible
//! on weak ARM with 4 GiB of containers); the previous implementation
//! kept every Plaintext in memory for the duration of the scan
//! (~4 KiB per owned chunk, ≈250× larger). See DESIGN §5.

use crate::cancel::CancelToken;
use crate::chunk::ChunkKind;
use crate::chunk::format::Plaintext;
use crate::container::ContainerFile;
use crate::crypto::aead::{ChunkAead, make_aad};
use crate::crypto::derive::{SpaceKeys, derive_chunk_key};
use crate::space::SpaceState;
use crate::space::superblock::Superblock;
use crate::{Error, NONCE_LEN, PLAINTEXT_LEN, Result, TAG_LEN};

/// How often to poll the cancel token during the scan loop. Chosen so
/// that the per-iteration polling cost is negligible (one `Acquire`
/// load per ~64 slots ≈ once per 256 KiB of file scanned), while still
/// keeping the worst-case latency from cancel-fire to abort under a
/// few milliseconds even on weak ARM (where AEAD-decrypt is the
/// bottleneck at ~5 µs/slot).
const CANCEL_POLL_PERIOD: u64 = 64;

/// Hard cap on the slot count the open-scan path will trial-decrypt.
/// Audit pass 14 TM1 / pass 16 mitigation: a T2 file-modify adversary
/// (or a bug-inflated container) can grow `path` to arbitrary size by
/// appending garbage chunks. Without a cap, every subsequent
/// `Container::open` runs an O(N) AEAD-attempt sweep — denial of
/// service via wall-clock-time inflation (a 1 TiB file is ≈ 256 M
/// chunks ≈ 30 min of trial-decrypt on x86, multi-hour on Cortex-A53).
///
/// `16 × 1024 × 1024 = 16 777 216` chunks at `CHUNK_SIZE = 4096` bytes
/// caps the file at **64 GiB** before open is rejected. This is
/// orders of magnitude above any realistic messenger-storage profile
/// (typical mobile container is ≤ 2 GiB; desktop ≤ 16 GiB) and still
/// bounds worst-case scan time to ≈ 5-15 minutes even on slow ARM.
///
/// Triggers `Error::Malformed("file too large for open-scan budget …")`
/// at the start of `scan_and_recover_with_cancel` (and the parallel /
/// mmap variants). Diagnostic detail includes the observed chunk
/// count.
///
/// **Override is intentionally not in the v1.0 public surface.**
/// Integrators with use cases beyond 64 GiB per container should
/// either partition into multiple containers (one per
/// conversation / per device) or wait for the v1.x opt-in
/// `OpenOptions::max_scan_chunks` knob (post-1.0 roadmap).
pub const MAX_OPEN_SCAN_CHUNKS: u64 = 16 * 1024 * 1024;

/// Reject if the slot count exceeds [`MAX_OPEN_SCAN_CHUNKS`]. Called
/// from every scan path (sequential, parallel, mmap) before any AEAD
/// work runs, so the rejection is fast (a single u64 compare).
///
/// Audit pass 16 TM1 added this gate as a DoS budget. Audit pass 17
/// F-4 trimmed the error-string leak: previously the message inlined
/// "audit pass 16 TM1 mitigation; see crate::open::MAX_OPEN_SCAN_CHUNKS",
/// which surfaced internal release-engineering metadata to foreign-side
/// FFI consumers. The pointer now lives only in this code-comment.
fn check_scan_budget(total: u64) -> Result<()> {
    if total > MAX_OPEN_SCAN_CHUNKS {
        return Err(Error::Malformed("container exceeds open-scan budget"));
    }
    Ok(())
}

/// Scan the container with `keys` and reconstruct space state.
///
/// Cost: O(N) per open, where N = number of slots. ~200 ms per GiB on
/// modern x86, ~1 s per GiB on mobile ARM (DESIGN §5).
///
/// Memory: O(M) where M = number of *owned* slots, NOT all slots.
/// Each owned slot adds 8 bytes to `owned_slots` and at most 8 bytes
/// to `commit_history` (Superblocks only). Decrypted plaintext bytes
/// are dropped immediately after they are inspected — see module docs.
///
/// Internal helper — public callers go through `Container::open_space` /
/// `create_space`.
pub(crate) fn scan_and_recover(
    container: &mut ContainerFile,
    keys: SpaceKeys,
) -> Result<SpaceState> {
    scan_and_recover_with_cancel(container, keys, None)
}

/// Constant-time-scan variant of [`scan_and_recover`] — F-TM1
/// mitigation (audit pass 3 carried-forward #7). For each slot,
/// runs a ChaCha20 timing-equalizer on MAC-fail so the per-chunk
/// wall-clock is independent of ownership.
///
/// **Cost.** Approximately doubles the open-time on garbage-heavy
/// containers (the equalizer cost is paid for every non-owned
/// chunk). On a sparse 16M-chunk container at worst, ~5-10 seconds
/// extra wall-clock vs the default sequential path.
///
/// **Benefit.** Closes the dominant component of the TM1 timing
/// oracle on this scan path. The aggregate per-chunk wall-clock
/// becomes mostly a function of `total_slot_count`, with a small
/// parsing+alloc residual on MAC-pass that is NOT equalized (see
/// threat-model §4.4 honest-scope table).
///
/// **v1.0 scope.** The CT mitigation is available for all three
/// scan modes: sequential ([`scan_and_recover_constant_time`]),
/// parallel-scan ([`scan_and_recover_parallel_constant_time`]),
/// and mmap ([`scan_and_recover_mmap_constant_time`]). All three
/// use the same per-chunk equalizer.
pub(crate) fn scan_and_recover_constant_time(
    container: &mut ContainerFile,
    keys: SpaceKeys,
) -> Result<SpaceState> {
    scan_and_recover_inner(container, keys, None, true)
}

/// Cancellable variant of [`scan_and_recover`]. Polls the supplied
/// [`CancelToken`] every `CANCEL_POLL_PERIOD` slots and bails with
/// [`Error::Cancelled`] if the flag is set. Pass `None` to disable
/// the cancel pathway (matching the behavior of `scan_and_recover`).
pub(crate) fn scan_and_recover_with_cancel(
    container: &mut ContainerFile,
    keys: SpaceKeys,
    cancel: Option<&CancelToken>,
) -> Result<SpaceState> {
    scan_and_recover_inner(container, keys, cancel, false)
}

/// Inner implementation shared by [`scan_and_recover_with_cancel`]
/// (constant_time=false) and [`scan_and_recover_constant_time`]
/// (constant_time=true). Both are sequential; only the per-slot
/// timing-equalizer toggle differs.
fn scan_and_recover_inner(
    container: &mut ContainerFile,
    keys: SpaceKeys,
    cancel: Option<&CancelToken>,
    constant_time: bool,
) -> Result<SpaceState> {
    // v3: container_id is derived per-space inside SpaceKeys::from_master,
    // no longer stored in the cleartext header.
    let container_id = keys.container_id;
    let total = container.slot_count();
    check_scan_budget(total)?;

    let mut owned_slots: Vec<u64> = Vec::new();
    let mut commit_history: Vec<u64> = Vec::new();

    // Track ALL distinct AEAD-passing Superblock seqs we see, keyed by
    // seq → payload bytes (≈48 B). Replicas at the same seq are
    // bit-equal so we keep only one per seq (first-wins; subsequent
    // replicas are dropped with their payload Vec).
    //
    // We can't decode-and-pick-best inline because of audit D2 / D3:
    // if the highest-seq SB AEAD-passes but `Superblock::decode` later
    // fails (writer bug, future-format chunk we don't understand,
    // physically-improbable bit corruption that AEAD missed), we must
    // **fall back** to the next-highest-seq SB rather than abort
    // recovery. So we collect candidates and decode at the end with
    // descending-seq iteration.
    let mut sb_candidates: std::collections::BTreeMap<u64, Vec<u8>> =
        std::collections::BTreeMap::new();

    for slot in 0..total {
        // Cooperative cancel check at coarse granularity. At slot 0 we
        // also check so that cancelling before scan starts surfaces
        // immediately on empty / nearly-empty files.
        if let Some(token) = cancel
            && slot.is_multiple_of(CANCEL_POLL_PERIOD)
        {
            token.check()?;
        }

        let chunk = container.read_slot(slot)?;
        let pt = match try_decrypt_with_options(&keys, &container_id, slot, &chunk, constant_time) {
            Some(pt) => pt,
            None => continue,
        };
        owned_slots.push(slot);

        if pt.kind == ChunkKind::Superblock {
            commit_history.push(pt.seq);
            // First-wins on tie. Audit pass 7 (D4): same-seq replicas
            // MUST be bit-equal by construction — `commit_tx` writes
            // the same `new_sb` payload N times (`superblock_replicas`
            // copies). A writer-bug regression that produced
            // same-seq-different-payload SBs would silently mask
            // first-wins; the `debug_assert!` catches it in tests.
            // Release builds keep first-wins semantics with no cost.
            //
            // Only retain payloads that are exactly a Superblock's
            // encoded length. `Superblock::decode` rejects any other
            // length downstream, so this is behaviour-preserving — but
            // it bounds memory: without it, a key-holder could forge
            // up to MAX_OPEN_SCAN_CHUNKS distinct-seq Superblock-kind
            // chunks each carrying a PAYLOAD_CAP-sized payload and make
            // `open` retain tens of GiB (audit pass 20). Non-matching
            // payloads still counted toward `commit_history` above.
            if pt.payload.len() == Superblock::ENCODED_LEN {
                use std::collections::btree_map::Entry;
                match sb_candidates.entry(pt.seq) {
                    Entry::Vacant(e) => {
                        e.insert(pt.payload);
                    },
                    Entry::Occupied(e) => {
                        debug_assert!(
                            e.get() == &pt.payload,
                            "same-seq Superblock replicas must be bit-equal"
                        );
                    },
                }
            }
        }
        // pt is consumed (payload moved or dropped at end-of-iter
        // for non-Superblock kinds; kind+seq are Copy).
    }

    // Recoverable-commit anchors for host-app rollback / multi-device
    // logic (DESIGN §11.2, docs/en/guide/multi-device.md). Every Superblock that
    // AEAD-decrypts under this key is a commit anchor that recovery
    // *could* fall back to if the latest replicas were lost. Replicas at
    // the same seq are deduplicated.
    commit_history.sort_unstable();
    commit_history.dedup();

    if sb_candidates.is_empty() {
        return Err(Error::AuthFailed);
    }

    // Try Superblock::decode on candidates in descending-seq order; on
    // decode failure (malformed-but-AEAD-valid SB), drop the candidate
    // and try the next-highest seq. Audit D2 fix: previous behavior
    // failed open entirely if the top-seq SB had a malformed payload.
    //
    // Audit pass 14: also reject SBs whose decoded `Superblock.seq`
    // disagrees with the chunk-level `Plaintext.seq`. The two should
    // always be equal (both written by `commit_tx`'s `new_seq`); a
    // mismatch indicates either a writer-bug regression or a
    // post-AEAD tamper by a key-holder. Surfacing as `Malformed`
    // (and trying the next candidate) is safer than silently
    // adopting the decoded payload's seq while the chunk-level seq
    // says something else.
    let mut superblock: Option<Superblock> = None;
    for (chunk_seq, payload) in sb_candidates.iter().rev() {
        match Superblock::decode(payload) {
            Ok(sb) if sb.seq == *chunk_seq => {
                superblock = Some(sb);
                break;
            },
            Ok(_) | Err(_) => {
                // Either decode failed, or decoded seq disagrees with
                // chunk-level seq. Try the next candidate.
                continue;
            },
        }
    }
    let superblock = superblock.ok_or(Error::Malformed(
        "every recoverable Superblock failed to decode",
    ))?;

    Ok(SpaceState {
        keys,
        container_id,
        superblock,
        owned_slots,
        commit_history,
        last_padding_error: None,
    })
}

/// Parallel variant of [`scan_and_recover`] using rayon's work-stealing
/// pool. Behaviorally identical: produces the same `SpaceState` for
/// the same input. Reads use `pread(2)` (positional reads on a shared
/// `&File`) so multiple threads contend only on the OS page cache,
/// not on a Rust mutex.
///
/// **When to use.** On multi-core hosts (desktop / server) when scan
/// time matters. On single-core mobile this gives no speedup and
/// pulls in rayon's ~6 MiB of code; gate the parallel path behind the
/// `parallel-scan` feature for that reason.
///
/// **Unix-only** because the underlying `read_slot_concurrent` uses
/// Unix's `pread`. Windows callers stay on the sequential path.
///
/// **Memory.** Per-slot work is independent so peak memory is
/// `O(threads · PLAINTEXT_LEN)` ciphertext + plaintext buffers in
/// flight, plus the same `O(M · 16 B)` final state as sequential.
#[cfg(all(feature = "parallel-scan", unix))]
pub(crate) fn scan_and_recover_parallel(
    container: &ContainerFile,
    keys: SpaceKeys,
) -> Result<crate::space::SpaceState> {
    scan_and_recover_parallel_inner(container, keys, false)
}

/// Constant-time-scan companion to [`scan_and_recover_parallel`]
/// (v1.0 ship of TM1 CT for the parallel-scan path).
///
/// Equivalent to [`scan_and_recover_parallel`] except every MAC-fail
/// runs the ChaCha20 timing-equalizer over the chunk body length.
/// Per-chunk wall-clock becomes independent of ownership on the
/// dominant component. See `scan_and_recover_constant_time` rustdoc
/// for the residual parsing+alloc swing that is NOT equalized.
#[cfg(all(feature = "parallel-scan", unix))]
pub(crate) fn scan_and_recover_parallel_constant_time(
    container: &ContainerFile,
    keys: SpaceKeys,
) -> Result<crate::space::SpaceState> {
    scan_and_recover_parallel_inner(container, keys, true)
}

#[cfg(all(feature = "parallel-scan", unix))]
fn scan_and_recover_parallel_inner(
    container: &ContainerFile,
    keys: SpaceKeys,
    constant_time: bool,
) -> Result<crate::space::SpaceState> {
    use rayon::prelude::*;

    // v3: container_id is derived per-space inside SpaceKeys::from_master,
    // no longer stored in the cleartext header.
    let container_id = keys.container_id;
    let total = container.slot_count();
    check_scan_budget(total)?;

    /// Per-thread accumulator. `try_fold` builds one of these per work
    /// chunk; `try_reduce` merges them. Using fold/reduce instead of
    /// `map().collect()` avoids materializing a full `Vec<Option<Found>>`
    /// across all slots — for a 10 K-slot container that intermediate
    /// is ~80 KiB of `Option<Found>` plus per-Superblock payload Vecs,
    /// and the allocator contention dominates wall-clock at high
    /// thread counts.
    ///
    /// Audit D2: `sb_candidates` keeps every distinct-seq SB payload we
    /// see, not just the highest-seq one. This lets the post-merge step
    /// fall back to lower-seq SBs if the highest fails to decode.
    #[derive(Default)]
    struct Acc {
        owned_slots: Vec<u64>,
        commit_history: Vec<u64>,
        sb_candidates: std::collections::BTreeMap<u64, Vec<u8>>,
    }

    // Coarse-grained chunking: each parallel work item processes
    // CHUNK_SIZE consecutive slots sequentially, with no per-slot
    // synchronization. A single slot's work (pread + AEAD-decrypt
    // + BLAKE3) is ~5 µs — well below rayon's per-task overhead. At
    // CHUNK_SIZE=256 each work item is ~1.3 ms, amortizing it.
    const CHUNK_SIZE: u64 = 256;
    let num_chunks = total.div_ceil(CHUNK_SIZE);

    // Bounded thread pool, lazily initialized once per process so we
    // don't pay pool-construction cost on every open. Empirically
    // (BENCH.md "Parallel-scan tuning"), AEAD-decrypt + small-chunk
    // pread saturate L1 cache / memory bandwidth long before they
    // saturate cores: on a 12-thread x86 host, 2 threads beat sequential
    // by 1.6×, but 12 threads are ~3× SLOWER than sequential. We cap
    // at 4 threads to stay on the good side of the cliff regardless
    // of host core count. For a single-core host this collapses to 1
    // (effectively sequential through rayon machinery).
    // G5 (audit pass 5): fallible build is propagated as
    // `Error::Internal` instead of panicking. `OnceLock::get_or_init`
    // takes `FnOnce -> T`, so we hand-roll a `get` + `set` chain to
    // allow the build closure to return `Result`. The race between
    // two threads racing past `get()` and both calling `build()` is
    // benign — `OnceLock::set` returns the loser's pool back, which
    // is dropped (idempotent, identical config).
    static POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();
    let pool = match POOL.get() {
        Some(p) => p,
        None => {
            let n = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2)
                .min(4);
            let built = rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .thread_name(|i| format!("hv-scan-{i}"))
                .build()
                .map_err(|_| Error::Internal("rayon pool build failed"))?;
            // If another thread won the race, `set` returns Err with our
            // pool, and we drop it. Either way `POOL.get()` is now Some.
            let _ = POOL.set(built);
            POOL.get().expect("just set or another thread set first")
        },
    };

    let acc = pool.install(|| {
        (0..num_chunks)
            .into_par_iter()
            .try_fold(Acc::default, |mut acc, chunk_idx| -> Result<Acc> {
                let start = chunk_idx * CHUNK_SIZE;
                let end = (start + CHUNK_SIZE).min(total);
                for slot in start..end {
                    let chunk = container.read_slot_concurrent(slot)?;
                    let pt = match try_decrypt_with_options(
                        &keys,
                        &container_id,
                        slot,
                        &chunk,
                        constant_time,
                    ) {
                        Some(pt) => pt,
                        None => continue,
                    };
                    acc.owned_slots.push(slot);
                    if pt.kind == ChunkKind::Superblock {
                        acc.commit_history.push(pt.seq);
                        // Audit pass 7 (D4): see sequential variant for rationale.
                        // Audit pass 20: length-gate the candidate (memory bound).
                        use std::collections::btree_map::Entry;
                        if pt.payload.len() == Superblock::ENCODED_LEN {
                            match acc.sb_candidates.entry(pt.seq) {
                                Entry::Vacant(e) => {
                                    e.insert(pt.payload);
                                },
                                Entry::Occupied(e) => {
                                    debug_assert!(
                                        e.get() == &pt.payload,
                                        "same-seq Superblock replicas must be bit-equal"
                                    );
                                },
                            }
                        }
                    }
                }
                Ok(acc)
            })
            .try_reduce(Acc::default, |mut a, b| -> Result<Acc> {
                a.owned_slots.extend(b.owned_slots);
                a.commit_history.extend(b.commit_history);
                // Merge candidates from both halves. Same-seq cross-thread
                // replicas must be bit-equal (writer wrote them as one
                // batch with identical payload) — audit pass 7 (D4).
                use std::collections::btree_map::Entry;
                for (seq, payload) in b.sb_candidates {
                    match a.sb_candidates.entry(seq) {
                        Entry::Vacant(e) => {
                            e.insert(payload);
                        },
                        Entry::Occupied(e) => {
                            debug_assert!(
                                e.get() == &payload,
                                "same-seq Superblock replicas must be bit-equal across threads"
                            );
                        },
                    }
                }
                Ok(a)
            })
    })?;

    let Acc {
        mut owned_slots,
        mut commit_history,
        sb_candidates,
    } = acc;

    // Parallel walk doesn't preserve slot order — sort to match the
    // sequential contract (and to keep vacuum_orphans / audit walkers
    // deterministic).
    owned_slots.sort_unstable();
    commit_history.sort_unstable();
    commit_history.dedup();

    if sb_candidates.is_empty() {
        return Err(Error::AuthFailed);
    }
    // Audit D2: try decode on candidates in descending-seq order;
    // fall back to lower-seq SB if highest fails to decode.
    // Audit pass 14: also require `Superblock.seq == chunk seq`
    // (mismatch ⇒ writer-bug or key-holder tamper, fall through).
    let superblock = sb_candidates
        .iter()
        .rev()
        .find_map(|(chunk_seq, payload)| {
            Superblock::decode(payload)
                .ok()
                .filter(|sb| sb.seq == *chunk_seq)
        })
        .ok_or(Error::Malformed(
            "every recoverable Superblock failed to decode",
        ))?;

    Ok(crate::space::SpaceState {
        keys,
        container_id,
        superblock,
        owned_slots,
        commit_history,
        last_padding_error: None,
    })
}

/// Memory-mapped variant of [`scan_and_recover`] (`mmap` feature,
/// Unix only). Maps the entire container file once, then slices each
/// chunk out of the mapping for AEAD-decryption — zero allocation
/// per chunk on the read path.
///
/// **When to use.** Read-mostly host workloads (bulk scan, audit,
/// integrity walk) where the kernel page cache is the dominant cost
/// of `read_slot`. On warm-cache repeat opens the wins are smaller
/// because `pread` already pays no extra copy beyond the page-cache
/// fault. On cold-cache first-open of a multi-GiB file the mmap path
/// avoids per-chunk syscall overhead entirely.
///
/// **Unix-only.** memmap2 builds on Windows but with different MAP_*
/// semantics; matching cfg with `parallel-scan` keeps the supported
/// platforms uniform.
///
/// **Safety.**
/// `Mmap::map(&File)` is `unsafe` because concurrent mutation of the
/// file by another process would expose torn reads / aliasing
/// violations to safe Rust. We rely on the
/// [`LOCK_EX`](crate::container::ContainerFile)
/// (writer) and `LOCK_SH` (this read path) flock guarantees acquired
/// at `Container::open`/`open_readonly` time to exclude concurrent
/// writers. On filesystems that don't honour `flock(2)` (some NFS,
/// SMB without proper setup, FUSE), this guarantee is weaker — the
/// existing `mmap` documentation in `docs/en/contributing/benchmarks.md` and
/// `docs/en/guide/multi-device.md` already calls out that hidden-volume
/// containers MUST live on `flock`-honouring storage.
#[cfg(all(feature = "mmap", unix))]
pub(crate) fn scan_and_recover_mmap(
    container: &ContainerFile,
    keys: SpaceKeys,
) -> Result<crate::space::SpaceState> {
    scan_and_recover_mmap_inner(container, keys, false)
}

/// Constant-time-scan companion to [`scan_and_recover_mmap`] (v1.0
/// ship of TM1 CT for the mmap path).
///
/// Equivalent to [`scan_and_recover_mmap`] except every MAC-fail
/// runs the ChaCha20 timing-equalizer over the chunk body length.
/// Same residual-swing caveat as the sequential variant — see
/// `scan_and_recover_constant_time` rustdoc.
#[cfg(all(feature = "mmap", unix))]
pub(crate) fn scan_and_recover_mmap_constant_time(
    container: &ContainerFile,
    keys: SpaceKeys,
) -> Result<crate::space::SpaceState> {
    scan_and_recover_mmap_inner(container, keys, true)
}

#[cfg(all(feature = "mmap", unix))]
fn scan_and_recover_mmap_inner(
    container: &ContainerFile,
    keys: SpaceKeys,
    constant_time: bool,
) -> Result<crate::space::SpaceState> {
    // v3: container_id is derived per-space inside SpaceKeys::from_master,
    // no longer stored in the cleartext header.
    let container_id = keys.container_id;
    let total = container.slot_count();
    check_scan_budget(total)?;

    // SAFETY: see method docs. Concurrent file mutation excluded by the
    // outer flock.
    let mmap = unsafe { memmap2::Mmap::map(container.raw_file()).map_err(Error::Io)? };

    // Sanity: file size should be (1 + total) * CHUNK_SIZE bytes
    // (header + slot grid). If the file changed underneath us between
    // ContainerFile::open and the mmap call, bail with Malformed.
    //
    // Audit F2 (2026-05-03): use checked arithmetic. On 32-bit `usize`
    // (e.g. Android armv7 with `mmap` feature enabled), `total` over
    // ~1M slots wraps the multiplication. Unreachable on 64-bit but
    // defense-in-depth on the platform we'd actually ship the mmap
    // feature to.
    let total_plus_header = (total as usize)
        .checked_add(1)
        .ok_or(Error::Internal("mmap slot count + header overflows usize"))?;
    let expected_len = total_plus_header
        .checked_mul(crate::CHUNK_SIZE)
        .ok_or(Error::Internal("mmap expected length overflows usize"))?;
    if mmap.len() < expected_len {
        return Err(Error::Malformed("mmap shorter than expected slot grid"));
    }

    let mut owned_slots: Vec<u64> = Vec::new();
    let mut commit_history: Vec<u64> = Vec::new();
    // Audit D2: collect every distinct-seq SB; decode in descending-seq
    // order at the end with fallback. See `scan_and_recover` doc.
    let mut sb_candidates: std::collections::BTreeMap<u64, Vec<u8>> =
        std::collections::BTreeMap::new();

    for slot in 0..total {
        let offset = (1 + slot) as usize * crate::CHUNK_SIZE;
        // SAFETY: bounds checked above via expected_len.
        let chunk: &[u8; crate::CHUNK_SIZE] = (&mmap[offset..offset + crate::CHUNK_SIZE])
            .try_into()
            .map_err(|_| Error::Internal("mmap slice not chunk-sized"))?;

        let pt = match try_decrypt_with_options(&keys, &container_id, slot, chunk, constant_time) {
            Some(pt) => pt,
            None => continue,
        };
        owned_slots.push(slot);

        if pt.kind == ChunkKind::Superblock {
            commit_history.push(pt.seq);
            // Audit pass 7 (D4): see sequential variant for rationale.
            // `debug_assert!` catches a writer-bug regression that
            // produces same-seq-different-payload SBs.
            use std::collections::btree_map::Entry;
            match sb_candidates.entry(pt.seq) {
                Entry::Vacant(e) => {
                    e.insert(pt.payload);
                },
                Entry::Occupied(e) => {
                    debug_assert!(
                        e.get() == &pt.payload,
                        "same-seq Superblock replicas must be bit-equal"
                    );
                },
            }
        }
    }

    commit_history.sort_unstable();
    commit_history.dedup();

    if sb_candidates.is_empty() {
        return Err(Error::AuthFailed);
    }
    // Audit pass 14: same chunk-vs-decoded seq cross-check as the
    // sequential / parallel scan paths.
    let superblock = sb_candidates
        .iter()
        .rev()
        .find_map(|(chunk_seq, payload)| {
            Superblock::decode(payload)
                .ok()
                .filter(|sb| sb.seq == *chunk_seq)
        })
        .ok_or(Error::Malformed(
            "every recoverable Superblock failed to decode",
        ))?;

    Ok(crate::space::SpaceState {
        keys,
        container_id,
        superblock,
        owned_slots,
        commit_history,
        last_padding_error: None,
    })
}

/// Try AEAD-decrypt of one chunk under one space's key schedule.
/// Returns `None` for any failure — never logs, never branches in a way
/// that distinguishes "wrong key" from "corruption" (DESIGN D2).
///
/// `constant_time` toggles the **constant-time scan** opt-in. When
/// `true`, a MAC-fail path runs
/// [`crate::crypto::aead::equalize_timing_via_chacha20`] over the
/// chunk body length so the per-chunk wall-clock is independent of
/// ownership — closes the dominant component of the TM1 timing
/// oracle on whatever scan path is consuming this primitive
/// (sequential / parallel / mmap). Adds approximately one ChaCha20
/// stream-cipher worth of CPU time per garbage chunk (≈ µs/chunk).
///
/// See threat-model §4.4 F-TM1 mitigation roadmap and the public
/// `Container::open_space_constant_time` /
/// `_parallel_constant_time` / `_mmap_constant_time` entries.
fn try_decrypt_with_options(
    keys: &SpaceKeys,
    container_id: &[u8; 32],
    slot: u64,
    chunk: &[u8; crate::CHUNK_SIZE],
    constant_time: bool,
) -> Option<Plaintext> {
    let key = derive_chunk_key(&keys.aead_root, container_id, slot);
    let aead = ChunkAead::new(&key);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&chunk[..NONCE_LEN]);
    let ct = &chunk[NONCE_LEN..];
    debug_assert_eq!(ct.len(), PLAINTEXT_LEN + TAG_LEN);
    let aad = make_aad(container_id, slot);
    match aead.open(&nonce, ct, aad) {
        Ok(pt_bytes) => Plaintext::decode(&pt_bytes).ok(),
        Err(_) => {
            if constant_time {
                // Consume CPU time equivalent to the body decrypt we
                // would have done on a successful MAC; discard
                // output. The chunk body that *would* have been
                // decrypted is `PLAINTEXT_LEN` bytes long.
                crate::crypto::aead::equalize_timing_via_chacha20(crate::PLAINTEXT_LEN);
            }
            None
        },
    }
}
