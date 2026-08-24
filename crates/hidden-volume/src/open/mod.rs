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
//! - `owned_slots` — one BIT per slot in the file ([`crate::space::slots`]).
//! - up to [`MAX_SB_CANDIDATES`] Superblock payloads (≈48 bytes each).
//! - `commit_history: Vec<u64>` — 8 bytes per distinct commit seq, with
//!   replicas collapsed before the list doubles.
//!
//! Measured end to end by `tests/open_peak_memory.rs`: **0.16 bytes of peak
//! heap per owned slot**, which is ~2.5 MiB at [`MAX_OPEN_SCAN_CHUNKS`]. It
//! was 27.5 bytes — 440 MiB at the cap — until report9 HV-13 replaced the
//! owned-slot `Vec<u64>` with the bitmap, collapsed the anchor replicas, and
//! capped the backward hunt's candidate window. See DESIGN §5.

use crate::cancel::CancelToken;
use crate::chunk::ChunkKind;
use crate::chunk::format::Plaintext;
use crate::container::ContainerFile;
use crate::crypto::aead::{ChunkAead, make_aad};
use crate::crypto::derive::{SpaceKeys, derive_chunk_key};
use crate::space::SpaceState;
use crate::space::checkpoint::{CheckpointChunk, MAX_CHECKPOINT_CHAIN};
use crate::space::superblock::{NO_RECORD, Superblock};
use crate::{Error, NONCE_LEN, PLAINTEXT_LEN, Result, TAG_LEN};

/// How far back from the end of the file the fast-open reverse scan
/// looks for the latest superblock (and thus the checkpoint pointer).
/// The latest commit's superblock replicas sit just before its
/// post-commit padding tail, so the latest superblock is within
/// `padding_count + replicas` slots of the end — far inside this
/// budget for any realistic padding preset (256 KiB ⇒ 64 chunks,
/// 1 MiB ⇒ 256). If no superblock is found within the budget (our
/// space went quiet while other spaces grew the file), the fast-path
/// declines and the caller falls back to the full O(total) scan.
///
/// Correctness does not hinge on this budget being large enough to
/// catch the *absolute* latest superblock: the fast-path only needs
/// *some* recent superblock to recover the (carried-forward)
/// checkpoint pointer; the authoritative latest superblock is then
/// re-derived by the selective scan of the full tail
/// `[cp_high_water, total)`. See [`try_fast_scan_inner`].
const REVERSE_SCAN_BUDGET: u64 = 4096;

/// Test seams: a counter of fast-path engagements and a toggle to force
/// the full scan, so a test can assert the fast path was actually taken
/// and compare it against a forced full scan. Compiled out of release
/// builds entirely.
///
/// **Thread-local** so concurrently-running `#[test]`s (cargo's default)
/// don't race on shared state: a synchronous `open_space` runs the scan
/// on the calling test's thread, so the thread-local counter/toggle are
/// the same instance the test reads.
///
/// Reachable two ways, and it needs both. `#[cfg(test)]` covers in-crate
/// unit tests (`space::checkpoint`, `space::reuse_tests`). The
/// `test-hooks` feature covers `tests/*.rs`, which are SEPARATE crates
/// linked against a non-test build of this one and therefore cannot see
/// a `cfg(test)` item at all. `tests/open_peak_memory_fast_path.rs`
/// needs it: only an integration-test binary can install the
/// `#[global_allocator]` that measures peak bytes, and without this
/// counter such a test cannot prove which scan path it measured.
#[cfg(any(test, feature = "test-hooks"))]
#[cfg_attr(feature = "test-hooks", doc(hidden))]
pub mod test_hooks {
    use std::cell::Cell;

    thread_local! {
        static DISABLE: Cell<bool> = const { Cell::new(false) };
        static HITS: Cell<u64> = const { Cell::new(0) };
    }

    /// Force the full scan on this thread, so a test can compare the two
    /// paths on one fixture.
    pub fn set_disable(v: bool) {
        DISABLE.with(|c| c.set(v));
    }
    pub fn disabled() -> bool {
        DISABLE.with(Cell::get)
    }
    /// How many times the fast path has engaged on this thread since
    /// [`reset_hits`].
    pub fn hits() -> u64 {
        HITS.with(Cell::get)
    }
    pub fn reset_hits() {
        HITS.with(|c| c.set(0));
    }
    pub(crate) fn record_hit() {
        HITS.with(|c| c.set(c.get() + 1));
    }
}

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
/// ## What the cap costs in memory (report9 HV-13)
///
/// The audit put the open scan's peak at "256+ MiB at this cap" from an
/// assumed per-slot cost. Measured instead, by
/// `tests/open_peak_memory.rs`, it was **27.5 bytes of peak heap per owned
/// slot** — ≈440 MiB at this cap, worse than the estimate and far past what a
/// phone has. A device that could hold a 64 GiB container could not open one.
///
/// It is **0.16 bytes per owned slot now**, ≈2.5 MiB at this cap. Three
/// things carried the old figure: `owned_slots` was a `Vec<u64>` (eight bytes
/// per owned chunk, retained for the life of the handle — a bitmap now, in
/// `space::slots`); the commit-anchor list took a push per superblock
/// CHUNK, so replicas inflated it before the final dedup; and the backward
/// superblock hunt kept every distinct-seq candidate in its window, which runs
/// on every open and was the actual peak.
///
/// Read the extrapolation with its fixture in mind. That measurement commits
/// once per iteration, so it is close to a worst case for slots-per-commit; a
/// container that reached this cap by holding DATA rather than history has
/// more slots per commit and a lower figure still.
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
///
/// **Audit HV-13**: the answer is [`Error::ContainerTooLarge`], not
/// `Error::Malformed`. An over-budget container is not malformed — every
/// byte in it is exactly what the writer wrote — and the two call for
/// opposite responses from a host app: a corrupt container's data is gone,
/// an over-budget one's is intact and reachable by splitting the file.
/// Reporting the corruption error for the size condition told the host the
/// wrong one of those, and the variant that says the right one already
/// existed and was already used by the symmetric write-side gate.
///
/// The check reads the slot count and nothing else — no key material is
/// touched before it — so the outcome is identical for every password and
/// for none, and the fact it reveals (the file's size) is one that anyone
/// who can `stat` the file already has.
fn check_scan_budget(total: u64) -> Result<()> {
    if total > MAX_OPEN_SCAN_CHUNKS {
        return Err(Error::ContainerTooLarge {
            chunks: total,
            cap: MAX_OPEN_SCAN_CHUNKS,
        });
    }
    Ok(())
}

/// Scan the container with `keys` and reconstruct space state.
///
/// Cost: O(N) per open, where N = number of slots. ~200 ms per GiB on
/// modern x86, ~1 s per GiB on mobile ARM (DESIGN §5).
///
/// Memory: one bit per slot in the file for `owned_slots`, plus 8 bytes per
/// distinct commit seq in `commit_history` (Superblocks only). Decrypted
/// plaintext bytes are dropped immediately after they are inspected — see
/// module docs.
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
///
/// **No checkpoint fast path.** All three CT modes scan every slot.
/// The selective fast-open visits only a working set, so its duration
/// is a function of what the space holds — a correct password finishes
/// early, a wrong one pays the full sweep, and equalizing per-chunk
/// work cannot hide a signal carried by the NUMBER of chunks visited.
/// That is the exact leak this entry point exists to remove, so it
/// takes the full scan the doubled cost above already describes.
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

    // Fast-open: if a checkpoint pointer is recoverable from a recent
    // superblock, trial-decrypt only the recorded working set + the
    // tail appended since, instead of every slot. Any inconsistency
    // (no checkpoint, unreadable checkpoint, budget/shape violation)
    // returns `None` and we fall through to the full scan, which is
    // always correct. The fast-path is **post-authentication**: an
    // adversary without this space's key cannot decrypt the reverse-
    // scan superblocks or the checkpoint chunk, so a wrong-password
    // attempt always pays the full O(total) scan (no fast-vs-slow
    // timing oracle for password guessing); and the selective scan
    // never touches another space's slots, so a decoy open's wall-
    // clock reflects only the decoy's own working set, never the
    // existence of hidden spaces. See `crate::space::checkpoint`.
    // ...but NOT under the constant-time contract. The paragraph above is a
    // fair defence of the fast path on the DEFAULT scan, where speed is the
    // point and the residual leak is an accepted trade. It does not hold for
    // `scan_and_recover_constant_time`, whose entire published purpose is that
    // the host's wall-clock "can't leak which space (or none) matched": the
    // sentence "a decoy open's wall-clock reflects only the decoy's own
    // working set" IS the leak that API exists to remove. Equalising each
    // chunk does not help when the number of chunks visited is itself the
    // signal — a correct password touches a working set, a wrong one pays the
    // full O(total) scan, and an observer of unlock time can tell those apart
    // and estimate the working set besides.
    //
    // No speed is lost by anyone who did not ask for this. The constant-time
    // entry point is opt-in and already documents that it roughly doubles open
    // time; its callers have paid for equal timing and were quietly being
    // handed back the speed instead.
    let fast_enabled = !constant_time && {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            !test_hooks::disabled()
        }
        #[cfg(not(any(test, feature = "test-hooks")))]
        {
            true
        }
    };
    if fast_enabled
        && let Some(state) = try_fast_scan_inner(
            container,
            &keys,
            &container_id,
            total,
            cancel,
            constant_time,
        )?
    {
        #[cfg(any(test, feature = "test-hooks"))]
        test_hooks::record_hit();
        return Ok(state);
    }

    // --- Full scan: trial-decrypt every slot. ---
    //
    // The owned-set bitmap is sized to the file up front: it will be asked
    // about every slot in `0..total` regardless of how many turn out to be
    // ours, so growing it a word at a time buys nothing.
    let mut acc = ScanAcc {
        owned_slots: crate::space::slots::OwnedSet::with_capacity(total),
        ..ScanAcc::default()
    };
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
        accumulate_owned_slot(&mut acc, slot, pt);
    }

    finalize_scan(keys, acc)
}

/// Per-slot scan accumulator — the `owned_slots` / `commit_history` /
/// `sb_candidates` triple shared by the full and fast scan paths.
///
/// `sb_candidates` tracks ALL distinct AEAD-passing Superblock seqs,
/// keyed by seq → payload bytes. Replicas at the same seq are bit-equal
/// so we keep one per seq (first-wins). We can't decode-and-pick-best
/// inline because of audit D2 / D3: if the highest-seq SB AEAD-passes
/// but `Superblock::decode` later fails (writer bug, future-format
/// chunk, physically-improbable bit corruption that AEAD missed), we
/// must fall back to the next-highest-seq SB — so candidates are
/// collected and decoded at the end in descending-seq order.
///
/// How many distinct-seq Superblock payloads that fallback may hold at once.
/// Audit pass 20 bounded each entry to a canonical superblock length; the
/// COUNT stayed open, so a key-holder could forge one distinct-seq Superblock
/// per scanned chunk and have us hold all of them. Reaching the Nth candidate
/// means N consecutive superblocks were forged or corrupt, and 64 is far past
/// any state a writer produces.
const MAX_SB_CANDIDATES: usize = 64;

/// Insert one AEAD-passing Superblock payload into a candidate map, keeping the
/// map bounded.
///
/// ## Why this is a function
///
/// The insert used to be written out at each accumulation site — sequential,
/// parallel worker, parallel reduce, mmap — and only the sequential copy
/// carried the [`MAX_SB_CANDIDATES`] cap. The others could accumulate one
/// distinct-seq entry per scanned chunk, so a container holding the key (or a
/// buggy writer) exhausted memory on exactly the builds that enable
/// `parallel-scan` or `mmap` — a limit that depended on which feature flags
/// were on (audit H-02). Four copies of a rule is three chances to fix one of
/// them; there is one now.
///
/// **Last writer wins.** Replicas of one publish are bit-equal, so this only
/// decides a collision between two DIFFERENT payloads under one seq — which
/// `attempted_seq` now prevents us from creating, but a container written by an
/// older build may already hold one. Slots are append-only and the reduce is
/// ordered, so the later entry is the later commit; first-wins silently
/// reverted to the older one, losing a commit that had already returned Ok. It
/// also matches `find_latest_superblock_reverse`, which scans backward and so
/// already kept the highest slot.
///
/// **Lowest seqs are dropped.** `finalize_scan` walks candidates in descending
/// seq and stops at the first that decodes, so anything below the top few is
/// only ever reached if that many consecutive superblocks are
/// malformed-but-AEAD-valid. The fall-through survives; the unbounded map does
/// not.
fn push_sb_candidate(
    candidates: &mut std::collections::BTreeMap<u64, Vec<u8>>,
    seq: u64,
    payload: Vec<u8>,
) {
    // No `debug_assert!` that same-seq payloads are bit-equal, though the
    // accumulation sites cited one for four audit passes. It cannot exist here:
    // a container written by an older build legitimately holds two different
    // payloads under one seq — `a_repeated_seq_keeps_the_later_payload` is
    // exactly that shape — so asserting it would abort a debug build for
    // reading a file this library must read. The condition is a writer-bug
    // signal only for containers THIS build wrote, and this function cannot
    // tell the two apart.
    candidates.insert(seq, payload);
    while candidates.len() > MAX_SB_CANDIDATES {
        candidates.pop_first();
    }
}

/// Fold one owned-but-unparsable Superblock `seq` into the running maximum.
///
/// The three scan backends (sequential, parallel, mmap) each keep their own
/// copy of the candidate loop — that duplication is what let the audit's
/// candidate cap ship in one backend only. The RULE lives here so at least it
/// cannot drift, even while the loops do.
fn note_unparsable_sb(cur: &mut Option<u64>, seq: u64) {
    *cur = Some(cur.map_or(seq, |s: u64| s.max(seq)));
}

/// Resolve `SpaceState::unreadable_newer_superblock`.
///
/// Only state NEWER than the era we settled on is dangerous; an unreadable
/// superblock at or below it is superseded history, not a writer that got
/// ahead of us.
fn newer_unreadable_sb(undecodable: Option<u64>, chosen_seq: u64) -> Option<u64> {
    #[cfg(test)]
    if forced_unreadable_newer() {
        return Some(chosen_seq + 1);
    }
    undecodable.filter(|s| *s > chosen_seq)
}

#[cfg(test)]
thread_local! {
    /// Test-only: make every space opened on this thread report a newer
    /// superblock it could not parse.
    ///
    /// The state cannot be produced honestly from a test: it takes a superblock
    /// that AEAD-passes under our key and then fails to parse, which means
    /// writing one with a future format — the very thing this build does not
    /// know how to do. Setting the field on an already-open handle covers the
    /// callers that take `&mut Space`, and covers NOTHING that opens the space
    /// itself, which is exactly where the destructive container flows live.
    ///
    /// Thread-local rather than global, for the reason `FILL_FAILS_AT` records:
    /// a process-global fires inside whatever unrelated open a parallel test
    /// thread happens to be making.
    static FORCE_UNREADABLE_NEWER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arm [`FORCE_UNREADABLE_NEWER`] on this thread; disarms on drop so a
/// panicking test cannot leak it into whatever runs next in the same thread.
#[cfg(test)]
pub(crate) struct ForcedUnreadableNewerState;

#[cfg(test)]
impl ForcedUnreadableNewerState {
    pub(crate) fn arm() -> Self {
        FORCE_UNREADABLE_NEWER.with(|c| c.set(true));
        Self
    }
}

#[cfg(test)]
impl Drop for ForcedUnreadableNewerState {
    fn drop(&mut self) {
        FORCE_UNREADABLE_NEWER.with(|c| c.set(false));
    }
}

#[cfg(test)]
fn forced_unreadable_newer() -> bool {
    FORCE_UNREADABLE_NEWER.with(std::cell::Cell::get)
}

#[derive(Default)]
struct ScanAcc {
    owned_slots: crate::space::slots::OwnedSet,
    commit_history: Vec<u64>,
    sb_candidates: std::collections::BTreeMap<u64, Vec<u8>>,
    /// Highest `seq` of an owned Superblock chunk whose payload this build
    /// could not parse. See `SpaceState::unreadable_newer_superblock` — a
    /// chunk that AEAD-passed is ours, so failing to parse it means a writer
    /// we do not understand got here first.
    unparsable_sb_seq: Option<u64>,
    /// Decoy-pool slots this scan recovered from the checkpoint chain,
    /// before the owned set is subtracted. Empty on the full-scan path:
    /// a full scan reads no checkpoint, so it has nothing to recover the
    /// pool from and the space starts the session append-only. That is a
    /// cost (a session's worth of reuse) and not a hazard — the pool is a
    /// hint whose absence only leaks disk.
    ///
    /// The cost stays a session's worth only because the checkpoint writer
    /// carries the previous record's pool forward when this is empty; without
    /// that, one refresh from such a session records the emptiness and the
    /// accumulated set is gone for good (report9 HV-14). See
    /// `Space::write_self_heal_checkpoint`.
    recorded_pool: crate::space::pool::DecoyPool,
    /// Whether this scan READ the checkpoint chain, as opposed to finding
    /// nothing to read. An empty `recorded_pool` cannot tell the two apart —
    /// a chain can honestly record an empty pool — and the checkpoint writer
    /// needs the difference. See `SpaceState::pool_recovered`.
    read_the_record: bool,
}

/// Capacity at which the commit-anchor list dedups itself rather than
/// doubling again.
///
/// The list takes a push per owned Superblock CHUNK, and a commit publishes
/// several replicas of the same superblock — so it inflates several-fold over
/// the distinct seqs it ends up holding. Measured on a fixture: 4096 entries
/// of capacity for 801 distinct anchors, and the doubling that reached it
/// briefly held one and a half copies, which was the open's peak once the
/// owned set became a bitmap (report9 HV-13).
///
/// Below this it is not worth a sort: the whole list fits in a few cache
/// lines and the doubling costs less than the pass.
const COMMIT_HISTORY_DEDUP_AT: usize = 1024;

/// Record a commit anchor, collapsing replicas before the list doubles.
///
/// The final `sort` + `dedup` in `finalize_scan_at` is unchanged and still
/// the authority; this only keeps the list from carrying every replica until
/// then.
fn push_commit_anchor(history: &mut Vec<u64>, seq: u64) {
    if history.len() == history.capacity() && history.capacity() >= COMMIT_HISTORY_DEDUP_AT {
        history.sort_unstable();
        history.dedup();
    }
    history.push(seq);
}

/// Fold one scan's anchors into another's, collapsing replicas across the
/// join.
///
/// The parallel reduce concatenated the two halves, which is the one place
/// the cap above could not reach: each worker's list is collapsed while it
/// grows, and then a reduce tree puts every worker's replicas back together
/// untouched. `push_commit_anchor` per element would be worse, not better —
/// it re-sorts a list that is about to be sorted anyway — so the join is one
/// extend and one collapse.
///
/// Bounded by the same threshold rather than by a count of workers: what
/// matters is how big the joined list is, and a reduce tree gives no useful
/// bound on how many halves have already been joined into either side.
///
/// Compiled only where it is called. The sequential scan has one accumulator
/// and pushes into it; joining halves is a thing only the parallel reduce
/// does, so outside `parallel-scan` this function has no caller and
/// `-D warnings` — which this project sets workspace-wide in CI — turns that
/// into a build error on every job that does not enable the feature.
#[cfg(any(all(feature = "parallel-scan", unix), test))]
fn merge_commit_anchors(history: &mut Vec<u64>, other: Vec<u64>) {
    history.extend(other);
    if history.len() >= COMMIT_HISTORY_DEDUP_AT {
        history.sort_unstable();
        history.dedup();
    }
}

/// Fold one owned (AEAD-passing) slot's plaintext into the accumulator.
/// Shared verbatim by the full and selective (fast) scan loops so they
/// produce identical state for the same slot set.
fn accumulate_owned_slot(acc: &mut ScanAcc, slot: u64, mut pt: Plaintext) {
    acc.owned_slots.insert(slot);
    if pt.kind == ChunkKind::Superblock {
        push_commit_anchor(&mut acc.commit_history, pt.seq);
        // LAST writer wins on a tie, and this comment used to say the
        // opposite. Every path here funnels into `push_sb_candidate`,
        // whose `BTreeMap::insert` replaces — see its doc for why that
        // is the right answer: slots are append-only, so the later
        // entry is the later commit, and first-wins reverted to one
        // that had already returned Ok.
        //
        // It also promised a `debug_assert!` catching a writer bug that
        // produces same-seq-different-payload superblocks. There is
        // none, and there cannot be one here: an older build's container
        // holds exactly that shape legitimately, so the assert would
        // abort a debug build for reading a file this library must read.
        //
        // Length-gate to the two canonical superblock lengths (48 short
        // / 56 long-with-checkpoint) — a memory bound (audit pass 20):
        // without it a key-holder could forge MAX_OPEN_SCAN_CHUNKS
        // distinct-seq Superblock chunks each carrying a PAYLOAD_CAP
        // payload. Non-matching payloads still counted toward
        // `commit_history` above. `Superblock::decode` is the
        // canonical-form authority downstream.
        if !Superblock::is_valid_encoded_len(pt.payload.len()) {
            // Not a length this build knows. Older builds hit exactly this
            // branch on the 56-byte checkpoint-bearing form and simply moved
            // on, silently presenting an older era and then vacuuming the
            // newer one away.
            note_unparsable_sb(&mut acc.unparsable_sb_seq, pt.seq);
        }
        if Superblock::is_valid_encoded_len(pt.payload.len()) {
            push_sb_candidate(
                &mut acc.sb_candidates,
                pt.seq,
                std::mem::take(&mut pt.payload),
            );
        }
    }
}

/// Pick the winning superblock (descending-seq with the audit-D2
/// fall-through and the audit-pass-14 chunk-vs-decoded seq cross-check)
/// and assemble the `SpaceState`. Shared by every scan path.
fn finalize_scan(keys: SpaceKeys, acc: ScanAcc) -> Result<SpaceState> {
    finalize_scan_at(keys, acc, u64::MAX)
}

/// [`finalize_scan`] with the file's slot count, so a recovered decoy
/// pool can be clamped to slots that exist. The full-scan path recovers
/// no pool and passes `u64::MAX`.
fn finalize_scan_at(keys: SpaceKeys, acc: ScanAcc, total: u64) -> Result<SpaceState> {
    let ScanAcc {
        owned_slots,
        mut commit_history,
        sb_candidates,
        unparsable_sb_seq,
        recorded_pool,
        read_the_record,
    } = acc;

    // Recoverable-commit anchors for host-app rollback / multi-device
    // logic (DESIGN §11.2). Replicas at the same seq are deduplicated.
    commit_history.sort_unstable();
    commit_history.dedup();

    if sb_candidates.is_empty() {
        return Err(Error::AuthFailed);
    }

    // Try Superblock::decode on candidates in descending-seq order; on
    // decode failure (malformed-but-AEAD-valid SB) drop the candidate
    // and try the next-highest seq (audit D2). Also reject SBs whose
    // decoded `Superblock.seq` disagrees with the chunk-level
    // `Plaintext.seq` (audit pass 14) — a mismatch indicates a
    // writer-bug or post-AEAD tamper by a key-holder.
    // A candidate that passes the length gate but fails `decode` counts the
    // same as one that failed the gate: it is ours, and we cannot read it.
    let mut undecodable_seq = unparsable_sb_seq;
    let superblock = sb_candidates
        .iter()
        .rev()
        .find_map(|(chunk_seq, payload)| match Superblock::decode(payload) {
            Ok(sb) if sb.seq == *chunk_seq => Some(sb),
            _ => {
                note_unparsable_sb(&mut undecodable_seq, *chunk_seq);
                None
            },
        })
        .ok_or(Error::Malformed(
            "every recoverable Superblock failed to decode",
        ))?;
    // Only NEWER unreadable state is dangerous. One at or below the era we
    // settled on is superseded history, not a writer that got ahead of us.
    let unreadable_newer_superblock = newer_unreadable_sb(undecodable_seq, superblock.seq);

    // The pool as recorded, MINUS everything this scan found we own. This
    // subtraction is what lets the recorded pool be as stale as the
    // checkpoint refresh policy allows: a slot a later commit reused
    // decrypts under our key again, so the scan reports it owned and it
    // leaves the pool here, whatever the checkpoint said about it. Without
    // this line a stale pool would hand a live slot to the allocator.
    let mut pool = recorded_pool;
    pool.subtract_owned(&owned_slots);
    debug_assert!(
        total == u64::MAX || pool.iter().all(|s| s < total),
        "the recorded pool must already be clamped to the file"
    );

    Ok(SpaceState {
        keys,
        superblock,
        owned_slots,
        pool,
        pool_recovered: read_the_record,
        reuse_count: 0,
        churn_count: 0,
        reuse_floor: usize::MAX,
        // Every Superblock chunk the scan decrypted contributed its seq here,
        // including replicas of a publish that never completed — so the max is
        // exactly "the highest number that may already be on disk".
        attempted_seq: commit_history.iter().copied().max().unwrap_or(0),
        commit_history,
        last_hardening_error: None,
        last_publish_error: None,
        roots_payload_cache: None,
        unreadable_newer_superblock,
    })
}

/// Find the most recent superblock by scanning **backward** from the
/// end of the file, bounded by [`REVERSE_SCAN_BUDGET`]. Returns the
/// max-seq decodable superblock candidate found in the window (with
/// the same audit-D2 / pass-14 selection as the full scan), or `None`
/// if the window holds no recoverable superblock for this space.
///
/// Used by the fast-path only to recover the (carried-forward)
/// checkpoint pointer; it need not be the absolute latest superblock
/// (the selective scan re-derives that authoritatively).
fn find_latest_superblock_reverse(
    container: &mut ContainerFile,
    keys: &SpaceKeys,
    container_id: &[u8; 32],
    total: u64,
    cancel: Option<&CancelToken>,
    constant_time: bool,
) -> Result<Option<Superblock>> {
    if total == 0 {
        return Ok(None);
    }
    let lo = total.saturating_sub(REVERSE_SCAN_BUDGET);
    let mut sb_candidates: std::collections::BTreeMap<u64, Vec<u8>> =
        std::collections::BTreeMap::new();
    let mut slot = total;
    let mut examined: u64 = 0;
    while slot > lo {
        slot -= 1;
        // Same cadence as the full scan. This phase reads and trial-decrypts
        // up to `REVERSE_SCAN_BUDGET` slots, and it used to do so with no
        // cancel check at all — so a caller who cancelled during a fast open
        // waited out the whole budget, which is precisely the promise the
        // scan's own documentation makes and the fast path quietly broke
        // (report9 HV-12).
        if let Some(token) = cancel
            && examined.is_multiple_of(CANCEL_POLL_PERIOD)
        {
            token.check()?;
        }
        examined += 1;
        let chunk = container.read_slot(slot)?;
        let mut pt = match try_decrypt_with_options(keys, container_id, slot, &chunk, constant_time)
        {
            Some(pt) => pt,
            None => continue,
        };
        if pt.kind == ChunkKind::Superblock && Superblock::is_valid_encoded_len(pt.payload.len()) {
            // Through the capped helper, like the other three loops. This one
            // used to keep every distinct-seq superblock in the window: up to
            // REVERSE_SCAN_BUDGET payloads, held while the window is walked.
            //
            // It is the same gap the neighbouring comment warns about — "the
            // three scan backends each keep their own copy of the candidate
            // loop, and that duplication is what let the audit's candidate cap
            // ship in one backend only" — with a fourth loop nobody counted.
            // Measured, it WAS the open's peak: this phase runs before the
            // fast path decides it cannot proceed, so every open paid it, and
            // on an 800-commit fixture it held 800 payloads at once.
            //
            // The cap keeps the highest seqs, which is what this function
            // returns; the D2 fallback depth becomes 64, the same as
            // everywhere else.
            push_sb_candidate(&mut sb_candidates, pt.seq, std::mem::take(&mut pt.payload));
        }
    }
    Ok(sb_candidates.iter().rev().find_map(|(chunk_seq, payload)| {
        Superblock::decode(payload)
            .ok()
            .filter(|sb| sb.seq == *chunk_seq)
    }))
}

/// What one checkpoint chain records, as [`read_checkpoint_chain`]
/// hands it back. A named struct rather than a tuple because the two
/// slot lists are the same type and mean opposite things: mixing them up
/// hands the allocator a live slot, and `(u64, Vec<u64>, Vec<u64>)` at a
/// call site says nothing about which is which.
pub(crate) struct RecordedCheckpoint {
    /// Slot count at checkpoint-write time. Recorded slots are below it;
    /// the reader scans `[high_water, total)` fresh.
    #[allow(
        dead_code,
        reason = "read by the fast scan; the writer wants only the pool"
    )]
    pub(crate) high_water: u64,
    /// The complete owned-slot set below the high-water.
    #[allow(
        dead_code,
        reason = "read by the fast scan; the writer wants only the pool"
    )]
    pub(crate) owned: crate::space::slots::OwnedSet,
    /// The recorded decoy pool — a hint, corrected by subtracting the
    /// scan's owned set. See [`crate::space::pool`].
    pub(crate) pool: crate::space::pool::DecoyPool,
}

/// Read the checkpoint chain rooted at `head`, returning the slot count
/// at checkpoint-write time, the complete owned-slot set below it, and
/// the recorded decoy pool. Returns `None` on ANY inconsistency
/// (unreadable / wrong-kind / malformed chunk, inconsistent high-water
/// across the chain, a high-water past the end of the file, over-long
/// chain, or recorded entries exceeding the open-scan budget), so the
/// caller falls back to the full scan. Every read is trial-decrypted
/// under this space's key, so an adversary without the key cannot drive
/// this path. `constant_time` keeps the per-chunk timing equalizer
/// engaged.
///
/// **What is clamped rather than rejected, and why** (report13 HV13-L9).
/// A recorded slot at or past the high-water is dropped: it names nothing
/// the checkpoint claims to summarize, and both outputs are sized to the
/// high-water. Order and duplicates are not checked at all — a bitmap has
/// no order to be wrong about, which is what the `sort` and `dedup` on the
/// old `Vec<u64>` form were for. Nor is owned/pool disjointness: the
/// caller subtracts its scan's owned set from the pool anyway
/// ([`crate::space::pool`]), and that subtraction is the authority, since
/// it corrects a stale record as well as a malformed one.
///
/// Rejecting instead would be worse than useless here. A chain the reader
/// refuses is a chain the checkpoint WRITER also refuses — it reads the
/// record it is superseding through this same function — so the pool
/// accumulated across every prior session is recorded away as empty and
/// gone for good, which is report9 HV-14 arrived at from the other side.
pub(crate) fn read_checkpoint_chain(
    container: &mut ContainerFile,
    keys: &SpaceKeys,
    container_id: &[u8; 32],
    head: u64,
    total: u64,
    cancel: Option<&CancelToken>,
    constant_time: bool,
) -> Result<Option<RecordedCheckpoint>> {
    // Bitmaps, filled entry by entry as the chain is walked. The two lists
    // used to be `Vec<u64>` here and were poured into a bitmap by the caller
    // one line later, so the eight-bytes-per-slot form existed only to be
    // read once — peak `8 * (|owned| + |pool|)` on top of the bitmap that
    // replaced it, and the pool half was RETAINED for the life of the handle.
    // Measured over a 1500/6000-commit pair, that was 13.55 bytes per file
    // slot — 216.8 MiB at the open-scan cap; streaming straight into the
    // bitmaps reads 0.47, or 7.5 MiB. See
    // `tests/open_peak_memory_fast_path.rs`.
    //
    // Sized once the high-water is known, which is also where it is bounded
    // by the file — see below.
    let mut owned = crate::space::slots::OwnedSet::default();
    let mut pool = crate::space::pool::DecoyPool::default();
    // Raw entries read, not distinct bits set: the budget below exists to
    // stop a forged chain making the reader work through more entries than
    // the file could hold, and collapsing duplicates would let a chain of
    // repeats run to `MAX_CHECKPOINT_CHAIN` hops for free.
    let mut entries: usize = 0;
    let mut high_water: Option<u64> = None;
    // `cp_seq` carries the same promise `cp_high_water` does — "same value in
    // every chunk of one chain", says its doc — and nothing outside the tests
    // read it. A field written by the writer, decoded by the reader and then
    // ignored states an invariant it does not hold: two chunks from DIFFERENT
    // checkpoints could be spliced into one walk and the result folded into a
    // single recorded state. AEAD keeps a keyless attacker out of this, so
    // what it refuses is a faulty or key-holding writer — the same audience as
    // the high-water check beside it, which is enforced.
    let mut seq: Option<u64> = None;
    let mut cur = head;
    let mut hops: u64 = 0;
    while cur != NO_RECORD {
        // Every hop is a read plus a trial-decrypt, and the chain may run to
        // `MAX_CHECKPOINT_CHAIN` of them (report9 HV-12). Checked per hop
        // rather than every 64: a hop is far more expensive than a slot read,
        // and the chain is short enough that the check costs nothing.
        if let Some(token) = cancel {
            token.check()?;
        }
        hops += 1;
        if hops > MAX_CHECKPOINT_CHAIN || cur >= total {
            return Ok(None);
        }
        let chunk = container.read_slot(cur)?;
        let pt = match try_decrypt_with_options(keys, container_id, cur, &chunk, constant_time) {
            Some(pt) => pt,
            None => return Ok(None),
        };
        if pt.kind != ChunkKind::Checkpoint {
            return Ok(None);
        }
        let cc = match CheckpointChunk::decode(&pt.payload) {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };
        match seq {
            None => seq = Some(cc.cp_seq),
            Some(first) if first == cc.cp_seq => {},
            // A link from another checkpoint. Same answer as a mismatched
            // high-water: stop and let the caller fall back to a full scan,
            // rather than fold two eras into one state.
            Some(_) => return Ok(None),
        }
        let hw = match high_water {
            None => {
                // Checked HERE, before a single bit is set, and not by the
                // caller after the walk as it used to be: the two bitmaps are
                // keyed on the slot index, so an over-large high-water is no
                // longer eight harmless bytes in a `Vec` but a `vec![0u64; n]`
                // the process aborts on. A checkpoint can only summarize the
                // past, so its high-water lies within the current file
                // (equal is fine — nothing appended since).
                if cc.cp_high_water > total {
                    return Ok(None);
                }
                owned = crate::space::slots::OwnedSet::with_capacity(cc.cp_high_water);
                pool = crate::space::pool::DecoyPool::with_capacity(cc.cp_high_water);
                high_water = Some(cc.cp_high_water);
                cc.cp_high_water
            },
            Some(hw) if hw == cc.cp_high_water => hw,
            Some(_) => return Ok(None),
        };
        entries = entries
            .saturating_add(cc.owned.len())
            .saturating_add(cc.pool.len());
        if entries > MAX_OPEN_SCAN_CHUNKS as usize {
            return Ok(None);
        }
        // Clamped, not rejected. A recorded slot at or past the high-water
        // names no slot the checkpoint claims to summarize, and the bitmaps
        // are sized to the high-water, so it is dropped rather than believed.
        // Order and duplicates need no check at all now that both sides are
        // sets: what a `Vec` had to be sorted for, a bitmap is by
        // construction (report13 HV13-L9).
        for &slot in cc.owned.iter().filter(|&&s| s < hw) {
            owned.insert(slot);
        }
        for &slot in cc.pool.iter().filter(|&&s| s < hw) {
            pool.record(slot);
        }
        cur = cc.next_slot;
    }
    // `None` only if `head == NO_RECORD` (empty chain) — caller already
    // guards that, but be explicit: no high-water ⇒ no usable checkpoint.
    Ok(high_water.map(|high_water| RecordedCheckpoint {
        high_water,
        owned,
        pool,
    }))
}

/// Fast-open selective scan. Returns `Some(state)` when a checkpoint
/// drove an O(working-set + tail) reconstruction, or `None` to signal
/// "fall back to the full scan."
///
/// The reconstructed state is provably identical to a full scan's: the
/// head region `[0, cp_high_water)` is covered by the checkpoint's
/// recorded owned set, each entry re-validated by trial-decrypt (so a
/// slot scrubbed since the checkpoint is dropped exactly as a full scan
/// would drop it; appends-only + scrub-only-removes-ownership guarantee
/// no head slot becomes *newly* owned after the checkpoint), and the
/// tail `[cp_high_water, total)` is scanned fresh — which also captures
/// the authoritative latest superblock (always written at or above the
/// last checkpoint's high-water).
fn try_fast_scan_inner(
    container: &mut ContainerFile,
    keys: &SpaceKeys,
    container_id: &[u8; 32],
    total: u64,
    cancel: Option<&CancelToken>,
    constant_time: bool,
) -> Result<Option<SpaceState>> {
    // Phase A: recover the checkpoint pointer from a recent superblock.
    let head_sb = match find_latest_superblock_reverse(
        container,
        keys,
        container_id,
        total,
        cancel,
        constant_time,
    )? {
        Some(sb) => sb,
        None => return Ok(None),
    };
    if head_sb.checkpoint_slot == NO_RECORD {
        return Ok(None);
    }

    // Phase B: read the checkpoint chain → (high_water, owned_below,
    // pool_below).
    let recorded = match read_checkpoint_chain(
        container,
        keys,
        container_id,
        head_sb.checkpoint_slot,
        total,
        cancel,
        constant_time,
    )? {
        Some(x) => x,
        None => return Ok(None),
    };
    let RecordedCheckpoint {
        high_water: cp_high_water,
        owned: mut head_owned,
        pool: pool_below,
    } = recorded;

    // Phase C: selective scan over the recorded owned set (head), the
    // recorded pool, and the fresh tail. Both recorded halves were clamped
    // to the head region as they were read; the tail is scanned in full.
    //
    // **The pool must be scanned, not merely carried.** The completeness
    // induction in `crate::space::checkpoint` used to rest on "no slot
    // below the high-water becomes newly owned after the checkpoint",
    // which held because writes only appended. Reuse is exactly the
    // operation that breaks it — and it breaks it in one place only:
    // pool slots are the only sub-high-water slots a later commit can
    // write to. Visiting them restores the induction with `owned ∪ pool`
    // as the covered region, and hands `finalize_scan_at` the ownership
    // facts it needs to subtract a stale pool entry that has since gone
    // live.
    // The union is the pool half poured onto the owned half, and neither is
    // copied: both arrive as bitmaps. Held as `Vec<u64>` and chained into a
    // third vector, this cost eight bytes per recorded slot three times over
    // — 13.55 bytes per slot in the FILE, measured, against 0.47 now
    // (report11 HV-M1, report13 HV13-M4). `OwnedSet` is ascending and
    // deduplicated by construction, which is what the sort and dedup that
    // used to follow were restoring.
    for slot in pool_below.iter() {
        head_owned.insert(slot);
    }

    let mut acc = ScanAcc {
        recorded_pool: pool_below,
        read_the_record: true,
        ..ScanAcc::default()
    };
    // The selective set: recorded head-owned + pool slots, then the fresh
    // tail.
    let selective = head_owned.iter().chain(cp_high_water..total);
    for (i, slot) in selective.enumerate() {
        if let Some(token) = cancel
            && (i as u64).is_multiple_of(CANCEL_POLL_PERIOD)
        {
            token.check()?;
        }
        let chunk = container.read_slot(slot)?;
        if let Some(pt) = try_decrypt_with_options(keys, container_id, slot, &chunk, constant_time)
        {
            accumulate_owned_slot(&mut acc, slot, pt);
        }
    }

    // If no superblock survived (e.g. the checkpoint pointed us at a
    // stale region and the tail held none), decline rather than error
    // — the full scan is the authority.
    if acc.sb_candidates.is_empty() {
        return Ok(None);
    }
    finalize_scan_at(keys.clone(), acc, total).map(Some)
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
        owned_slots: crate::space::slots::OwnedSet,
        commit_history: Vec<u64>,
        sb_candidates: std::collections::BTreeMap<u64, Vec<u8>>,
        /// Mirrors `ScanAcc`'s field. The parallel backend keeps its own
        /// accumulator, and a guard that lands in only one backend is exactly
        /// how the audit's candidate cap ended up half-applied.
        unparsable_sb_seq: Option<u64>,
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
                    let mut pt = match try_decrypt_with_options(
                        &keys,
                        &container_id,
                        slot,
                        &chunk,
                        constant_time,
                    ) {
                        Some(pt) => pt,
                        None => continue,
                    };
                    acc.owned_slots.insert(slot);
                    if pt.kind == ChunkKind::Superblock {
                        push_commit_anchor(&mut acc.commit_history, pt.seq);
                        // Audit pass 7 (D4): see sequential variant for rationale.
                        // Audit pass 20: length-gate the candidate (memory bound).
                        // Accepts both canonical lengths (48 / 56); anything
                        // else is a superblock this build cannot read — see
                        // `SpaceState::unreadable_newer_superblock`.
                        if !Superblock::is_valid_encoded_len(pt.payload.len()) {
                            note_unparsable_sb(&mut acc.unparsable_sb_seq, pt.seq);
                        }
                        if Superblock::is_valid_encoded_len(pt.payload.len()) {
                            push_sb_candidate(
                                &mut acc.sb_candidates,
                                pt.seq,
                                std::mem::take(&mut pt.payload),
                            );
                        }
                    }
                }
                Ok(acc)
            })
            .try_reduce(Acc::default, |mut a, b| -> Result<Acc> {
                a.owned_slots.union_from(&b.owned_slots);
                merge_commit_anchors(&mut a.commit_history, b.commit_history);
                // Without this the flag survives only if the unreadable
                // superblock happened to land in the accumulator that won the
                // reduce — i.e. it would hold on some runs and not others.
                if let Some(seq) = b.unparsable_sb_seq {
                    note_unparsable_sb(&mut a.unparsable_sb_seq, seq);
                }
                // Merge candidates from both halves. Same-seq cross-thread
                // replicas must be bit-equal (writer wrote them as one
                // batch with identical payload) — audit pass 7 (D4).
                //
                // Capped here too, and that is the point of routing through
                // `push_sb_candidate`: two accumulators each holding at most
                // MAX_SB_CANDIDATES merge into up to twice that, and a reduce
                // tree of W workers compounds it. Bounding only the workers
                // would have left the ceiling proportional to thread count.
                for (seq, payload) in b.sb_candidates {
                    push_sb_candidate(&mut a.sb_candidates, seq, payload);
                }
                Ok(a)
            })
    })?;

    let Acc {
        owned_slots,
        mut commit_history,
        sb_candidates,
        unparsable_sb_seq,
    } = acc;

    // The parallel walk does not preserve slot order, and the sequential
    // contract is ascending. The owned set is a bitmap, which is ascending by
    // construction — only the history still needs sorting.
    commit_history.sort_unstable();
    commit_history.dedup();

    if sb_candidates.is_empty() {
        return Err(Error::AuthFailed);
    }
    // Audit D2: try decode on candidates in descending-seq order;
    // fall back to lower-seq SB if highest fails to decode.
    // Audit pass 14: also require `Superblock.seq == chunk seq`
    // (mismatch ⇒ writer-bug or key-holder tamper, fall through).
    let mut undecodable_seq = unparsable_sb_seq;
    let superblock = sb_candidates
        .iter()
        .rev()
        .find_map(|(chunk_seq, payload)| match Superblock::decode(payload) {
            Ok(sb) if sb.seq == *chunk_seq => Some(sb),
            _ => {
                note_unparsable_sb(&mut undecodable_seq, *chunk_seq);
                None
            },
        })
        .ok_or(Error::Malformed(
            "every recoverable Superblock failed to decode",
        ))?;
    let unreadable_newer_superblock = newer_unreadable_sb(undecodable_seq, superblock.seq);

    Ok(crate::space::SpaceState {
        keys,
        superblock,
        owned_slots,
        // The parallel / mmap backends are full scans by construction —
        // they read no checkpoint, so there is no recorded pool to
        // recover and this session writes append-only. A cost, not a
        // hazard: an absent pool leaks disk and nothing else.
        pool: crate::space::pool::DecoyPool::default(),
        pool_recovered: false,
        reuse_count: 0,
        churn_count: 0,
        reuse_floor: usize::MAX,
        // Every Superblock chunk the scan decrypted contributed its seq here,
        // including replicas of a publish that never completed — so the max is
        // exactly "the highest number that may already be on disk".
        attempted_seq: commit_history.iter().copied().max().unwrap_or(0),
        commit_history,
        last_hardening_error: None,
        last_publish_error: None,
        roots_payload_cache: None,
        unreadable_newer_superblock,
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

    let mut owned_slots = crate::space::slots::OwnedSet::with_capacity(total);
    let mut commit_history: Vec<u64> = Vec::new();
    // Audit D2: collect every distinct-seq SB; decode in descending-seq
    // order at the end with fallback. See `scan_and_recover` doc.
    let mut sb_candidates: std::collections::BTreeMap<u64, Vec<u8>> =
        std::collections::BTreeMap::new();
    // Highest seq of an owned Superblock this build could not parse — see
    // `SpaceState::unreadable_newer_superblock`.
    let mut unparsable_sb_seq: Option<u64> = None;

    for slot in 0..total {
        let offset = (1 + slot) as usize * crate::CHUNK_SIZE;
        // SAFETY: bounds checked above via expected_len.
        let chunk: &[u8; crate::CHUNK_SIZE] = (&mmap[offset..offset + crate::CHUNK_SIZE])
            .try_into()
            .map_err(|_| Error::Internal("mmap slice not chunk-sized"))?;

        let mut pt =
            match try_decrypt_with_options(&keys, &container_id, slot, chunk, constant_time) {
                Some(pt) => pt,
                None => continue,
            };
        owned_slots.insert(slot);

        if pt.kind == ChunkKind::Superblock {
            // Through the capped helper, like the other two backends. Raw
            // `push` here kept every replica of every commit until the sort
            // at the end of the scan: on a file whose slots are all
            // superblocks of one era that is `MAX_OPEN_SCAN_CHUNKS * 8` =
            // 128 MiB of one repeated number, where the sequential scan holds
            // a few hundred entries for the same input (report13 HV13-L1).
            push_commit_anchor(&mut commit_history, pt.seq);
            // Audit pass 7 (D4): see sequential variant for rationale.
            // The tie goes to the LAST writer, and the `debug_assert!`
            // this used to cite does not exist — an older container holds
            // same-seq-different-payload legitimately, so it cannot.
            //
            // Length-gate the retained payload to the two canonical
            // superblock lengths (48 / 56) — same memory bound the
            // sequential / parallel scan paths apply (audit pass 20).
            // Previously the mmap path omitted this gate; closed here
            // alongside the 56-byte long-form addition. Non-matching
            // payloads still counted toward `commit_history` above.
            if !Superblock::is_valid_encoded_len(pt.payload.len()) {
                note_unparsable_sb(&mut unparsable_sb_seq, pt.seq);
            }
            if Superblock::is_valid_encoded_len(pt.payload.len()) {
                push_sb_candidate(&mut sb_candidates, pt.seq, std::mem::take(&mut pt.payload));
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
    let mut undecodable_seq = unparsable_sb_seq;
    let superblock = sb_candidates
        .iter()
        .rev()
        .find_map(|(chunk_seq, payload)| match Superblock::decode(payload) {
            Ok(sb) if sb.seq == *chunk_seq => Some(sb),
            _ => {
                note_unparsable_sb(&mut undecodable_seq, *chunk_seq);
                None
            },
        })
        .ok_or(Error::Malformed(
            "every recoverable Superblock failed to decode",
        ))?;
    let unreadable_newer_superblock = newer_unreadable_sb(undecodable_seq, superblock.seq);

    Ok(crate::space::SpaceState {
        keys,
        superblock,
        owned_slots,
        // The parallel / mmap backends are full scans by construction —
        // they read no checkpoint, so there is no recorded pool to
        // recover and this session writes append-only. A cost, not a
        // hazard: an absent pool leaks disk and nothing else.
        pool: crate::space::pool::DecoyPool::default(),
        pool_recovered: false,
        reuse_count: 0,
        churn_count: 0,
        reuse_floor: usize::MAX,
        // Every Superblock chunk the scan decrypted contributed its seq here,
        // including replicas of a publish that never completed — so the max is
        // exactly "the highest number that may already be on disk".
        attempted_seq: commit_history.iter().copied().max().unwrap_or(0),
        commit_history,
        last_hardening_error: None,
        last_publish_error: None,
        roots_payload_cache: None,
        unreadable_newer_superblock,
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

#[cfg(test)]
mod unreadable_superblock_rule_tests {
    use super::{newer_unreadable_sb, note_unparsable_sb};

    #[test]
    fn the_highest_unparsable_seq_wins() {
        let mut cur = None;
        note_unparsable_sb(&mut cur, 7);
        note_unparsable_sb(&mut cur, 3);
        note_unparsable_sb(&mut cur, 11);
        assert_eq!(cur, Some(11));
    }

    /// Only state NEWER than the era we opened is dangerous.
    ///
    /// An unreadable superblock at or below it is superseded history — a
    /// leftover from a crashed publish, or a replica of an era we already moved
    /// past. Treating those as "a newer writer got here" would make every
    /// container with one stale malformed chunk permanently unwritable.
    #[test]
    fn only_seqs_above_the_chosen_era_are_dangerous() {
        assert_eq!(newer_unreadable_sb(Some(9), 8), Some(9));
        assert_eq!(newer_unreadable_sb(Some(8), 8), None);
        assert_eq!(newer_unreadable_sb(Some(7), 8), None);
        assert_eq!(newer_unreadable_sb(None, 8), None);
    }
}

#[cfg(test)]
mod candidate_bound_tests {
    use super::{MAX_SB_CANDIDATES, push_sb_candidate};
    use std::collections::BTreeMap;

    /// Audit H-02. The cap existed, but only in the sequential accumulator —
    /// the `parallel-scan` and `mmap` paths wrote the same insert out again
    /// without it, so how much memory a hostile container could make us hold
    /// depended on which feature flags the build enabled.
    #[test]
    fn the_candidate_map_stays_bounded_however_many_arrive() {
        let mut map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for seq in 0..(MAX_SB_CANDIDATES as u64 * 40) {
            push_sb_candidate(&mut map, seq, vec![0u8; 48]);
            assert!(
                map.len() <= MAX_SB_CANDIDATES,
                "map grew to {} at seq {seq}",
                map.len()
            );
        }
        assert_eq!(map.len(), MAX_SB_CANDIDATES);
    }

    /// Which ones survive matters: `finalize_scan` walks DESCENDING and stops
    /// at the first that decodes, so dropping the top of the range instead of
    /// the bottom would discard the newest state and silently return an older
    /// era — the exact failure H-01 was about.
    #[test]
    fn the_highest_seqs_are_the_ones_kept() {
        let mut map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        for seq in 0..(MAX_SB_CANDIDATES as u64 * 3) {
            push_sb_candidate(&mut map, seq, vec![0u8; 48]);
        }
        let lowest_kept = *map.keys().next().expect("non-empty");
        let highest_kept = *map.keys().next_back().expect("non-empty");
        assert_eq!(highest_kept, MAX_SB_CANDIDATES as u64 * 3 - 1);
        assert_eq!(lowest_kept, highest_kept - MAX_SB_CANDIDATES as u64 + 1);
    }

    /// Last writer wins on a same-seq collision. A container written by an
    /// older build can hold two different payloads under one seq; first-wins
    /// reverted to the older one and lost a commit that had already returned
    /// Ok.
    #[test]
    fn a_repeated_seq_keeps_the_later_payload() {
        let mut map: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        push_sb_candidate(&mut map, 7, vec![1u8; 48]);
        push_sb_candidate(&mut map, 7, vec![2u8; 48]);
        assert_eq!(map.len(), 1);
        assert_eq!(map[&7], vec![2u8; 48]);
    }
}

#[cfg(test)]
mod commit_anchor_tests {
    use super::{COMMIT_HISTORY_DEDUP_AT, merge_commit_anchors, push_commit_anchor};

    /// The join must not be the one place replicas survive.
    ///
    /// Each worker's list is collapsed while it grows, and the reduce then put
    /// every worker's replicas back together with a plain `extend`. The
    /// sequential backend holds a few hundred entries for an input the
    /// parallel one held every copy of, and the mmap backend — which pushed
    /// raw — held all of them outright (report13 HV13-L1).
    #[test]
    fn joining_two_halves_collapses_the_replicas_across_the_seam() {
        // Two halves that each look collapsed on their own and share every
        // seq — a commit's superblock replicas split across workers.
        let mut a: Vec<u64> = (0..COMMIT_HISTORY_DEDUP_AT as u64).collect();
        let b: Vec<u64> = (0..COMMIT_HISTORY_DEDUP_AT as u64).collect();
        merge_commit_anchors(&mut a, b);
        assert_eq!(
            a.len(),
            COMMIT_HISTORY_DEDUP_AT,
            "the seam kept a second copy of every anchor"
        );
        assert_eq!(a, (0..COMMIT_HISTORY_DEDUP_AT as u64).collect::<Vec<_>>());
    }

    /// And it must not LOSE one. The bound is on replicas, never on reach:
    /// `commit_history` is the host's rollback evidence, and an anchor
    /// dropped here is an era a host can no longer name.
    #[test]
    fn joining_keeps_every_distinct_anchor() {
        let mut a: Vec<u64> = vec![9, 4, 4, 1];
        merge_commit_anchors(&mut a, vec![7, 1, 12]);
        let mut got = a.clone();
        got.sort_unstable();
        got.dedup();
        assert_eq!(got, vec![1, 4, 7, 9, 12]);
    }

    /// Small joins are left alone: below the threshold the list fits in a few
    /// cache lines and the pass costs more than the doubling it saves.
    #[test]
    fn a_small_join_is_not_worth_a_sort() {
        let mut a: Vec<u64> = vec![3, 3];
        merge_commit_anchors(&mut a, vec![3]);
        assert_eq!(a, vec![3, 3, 3], "a short list was sorted for nothing");
    }

    /// The per-element helper the two other backends use, on the same input:
    /// pushing replicas past the threshold must not grow without bound.
    #[test]
    fn pushing_replicas_collapses_rather_than_doubling_forever() {
        let mut history = Vec::new();
        for _ in 0..(COMMIT_HISTORY_DEDUP_AT * 8) {
            push_commit_anchor(&mut history, 42);
        }
        assert!(
            history.capacity() <= COMMIT_HISTORY_DEDUP_AT * 2,
            "capacity reached {} for one distinct anchor",
            history.capacity()
        );
    }
}

#[cfg(test)]
mod hv13_budget_tests {
    use super::{MAX_OPEN_SCAN_CHUNKS, check_scan_budget};
    use crate::Error;

    /// The boundary itself. `check_scan_budget` rejects on `>`, so the cap is
    /// the last openable count — a container exactly at it must open, and one
    /// slot past it must not. Testing far from the boundary would pass just as
    /// happily with a `>=`, which would make the largest legal container
    /// unreadable.
    #[test]
    fn the_cap_is_inclusive_and_one_past_it_is_not() {
        assert!(
            check_scan_budget(MAX_OPEN_SCAN_CHUNKS).is_ok(),
            "a container exactly at the cap must still open — the write side \
             allows it, so refusing it here would strand a file this library made"
        );
        assert!(check_scan_budget(MAX_OPEN_SCAN_CHUNKS + 1).is_err());
    }

    /// Audit HV-13. The rejection must say "too large", not "malformed".
    ///
    /// The distinction is the finding: an over-budget container has lost
    /// nothing — every byte is what the writer wrote, and splitting the file
    /// brings it back — while `Malformed` is what this library says when data
    /// is gone. A host app that cannot tell them apart will either destroy a
    /// recoverable container or reassure a user whose data is not there.
    #[test]
    fn an_over_budget_container_is_too_large_rather_than_malformed() {
        let err = check_scan_budget(MAX_OPEN_SCAN_CHUNKS + 1).unwrap_err();
        match err {
            Error::ContainerTooLarge { chunks, cap } => {
                assert_eq!(cap, MAX_OPEN_SCAN_CHUNKS);
                assert_eq!(
                    chunks,
                    MAX_OPEN_SCAN_CHUNKS + 1,
                    "the caller needs the observed count to decide how far to split"
                );
            },
            Error::Malformed(m) => {
                panic!("an intact over-budget container was reported as corrupt ({m:?})")
            },
            other => panic!("expected ContainerTooLarge, got {other:?}"),
        }
    }

    /// The read side and the write side must agree at the boundary, or the
    /// library can write a file it cannot open. Pass 17 B made the CHECKS
    /// symmetric; this pins that the ANSWERS are too, so a later change to one
    /// error shape cannot quietly leave the other behind — which is exactly
    /// how the two drifted the first time.
    #[test]
    fn both_sides_of_the_budget_answer_with_the_same_variant() {
        let read_side = check_scan_budget(MAX_OPEN_SCAN_CHUNKS + 1).unwrap_err();
        let write_side =
            crate::container::file::write_budget_error_for_test(MAX_OPEN_SCAN_CHUNKS, 1);
        assert!(
            matches!(read_side, Error::ContainerTooLarge { .. })
                && matches!(write_side, Error::ContainerTooLarge { .. }),
            "read side said {read_side:?}, write side said {write_side:?}"
        );
        assert_eq!(format!("{read_side}"), format!("{write_side}"));
    }
}

#[cfg(test)]
mod hv12_cancel_reach_tests {
    /// Both fast-open phases must take the cancel token and poll it.
    ///
    /// A SOURCE check, and the reason is worth stating. Cancelling during a
    /// fast open produced the same OUTCOME either way — phase A returned, and
    /// the selective scan's own poll surfaced the cancel a moment later. What
    /// changed was how long the caller waited: up to `REVERSE_SCAN_BUDGET`
    /// reads plus a `MAX_CHECKPOINT_CHAIN` walk, each a read and a
    /// trial-decrypt. On the machine that runs this suite that is
    /// milliseconds, so a timing assertion here would measure nothing and
    /// would be flaky when it did; the promise is about a phone with a slow
    /// disk (report9 HV-12).
    ///
    /// What can rot is the wiring: a phase that stops taking the token, or
    /// takes it and never looks. That is a fact about this file.
    #[test]
    fn the_fast_open_phases_take_and_poll_the_cancel_token() {
        let source = include_str!("mod.rs");
        for name in [
            "fn find_latest_superblock_reverse(",
            "fn read_checkpoint_chain(",
        ] {
            let start = source
                .find(name)
                .unwrap_or_else(|| panic!("{name} moved — this guard no longer watches it"));
            let body = &source[start..];
            let end = body[1..].find("\nfn ").map_or(body.len(), |i| i + 1);
            let body = &body[..end];
            assert!(
                body.contains("cancel: Option<&CancelToken>"),
                "{name} no longer takes a cancel token, so a fast open cannot \
                 be interrupted while it runs"
            );
            assert!(
                body.contains("token.check()?"),
                "{name} takes a cancel token and never polls it — the caller \
                 waits out the whole phase"
            );
        }
    }
}
