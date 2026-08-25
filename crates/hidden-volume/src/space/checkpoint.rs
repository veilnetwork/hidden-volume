//! Open-scan acceleration checkpoint (the "fast-open" optimization).
//!
//! The discovery scan ([`crate::open`]) is O(total slots): it
//! trial-decrypts every slot to find the ones this space owns. A
//! long-history / low-utilization container (a messenger store bloated
//! by per-commit padding, say) makes every unlock pay a full sweep.
//!
//! A **checkpoint** is a chain of [`crate::chunk::ChunkKind::Checkpoint`]
//! chunks that records the *complete* set of slots this space owned as
//! of a past open (post-vacuum). A later open can then trial-decrypt
//! only that recorded working set plus the tail appended since
//! (`[cp_high_water, slot_count)`), instead of every slot — an
//! O(working-set + tail) open. See [`crate::open`] for the reader.
//!
//! **It is an optimization hint, never a correctness-bearing
//! structure.** A reader that ignores the checkpoint, or that finds it
//! unreadable, always falls back to the full scan and is correct.
//!
//! **Completeness is guaranteed by induction over honest writes.** The
//! reconstructed `owned_slots` equals a full scan's whenever the
//! checkpoint's recorded owned set is itself complete, and the honest
//! writer always produces a complete one:
//! - *Base case.* The first checkpoint can only be written when none
//!   exists (`old_head == NO_RECORD`), which means this open's
//!   fast-path declined and a **full scan** produced the authoritative
//!   owned set that is snapshotted — complete by construction.
//! - *Inductive step.* A fast open trial-decrypts every slot the
//!   checkpoint recorded below `cp_high_water` (re-validating each, so a
//!   slot scrubbed since is dropped exactly as a full scan would drop
//!   it) and scans the tail `[cp_high_water, total)` in full. Since
//!   appends-only + scrub-only-removes-ownership mean no slot below the
//!   high-water becomes *newly* owned after the checkpoint, a complete
//!   predecessor yields a complete successor.
//!
//! So under honest operation forward-secrecy (`vacuum_orphans` /
//! `vacuum_data_batches` iterate the full `owned_slots`) and
//! `commit_history` are preserved bit-for-bit.
//!
//! **Trust boundary.** The recorded owned set is a *key-authenticated
//! trusted cache*: the reader drops recorded slots that fail
//! re-validation but cannot detect an *omitted* slot without the very
//! full scan it is avoiding. A checkpoint that omits a genuinely-owned
//! slot below `cp_high_water` — only producible by a key-holder
//! deliberately forging one (self-harm), never by the honest writer
//! above, and unreachable by any keyless adversary — would make vacuum
//! miss that orphan (a forward-secrecy degradation), but never affects
//! the winning superblock or any committed data (reads follow
//! `superblock.root_slot`, not `owned_slots`). This is the same trust
//! model the superblock's persisted `root_slot` / `root_hash` already
//! rely on (and `verify_integrity` cross-checks the Merkle root). The
//! `fast_path_matches_full_scan_and_engages` test guards the
//! owned-tracking regression class.
//!
//! **Lazy self-heal, never per-commit.** `commit_tx` never writes a
//! checkpoint (zero per-commit overhead — it only carries the pointer
//! forward). The checkpoint is (re)written at most once per open, and
//! only when it actually helps: the container is large enough that a
//! full scan is slow, and the un-checkpointed tail has grown past the
//! working set. This amortizes checkpoint writes and honors the "don't
//! thrash the disk" constraint.
//!
//! **Deniability.** Each checkpoint chunk is AEAD-sealed under the same
//! per-space key as every other chunk (opaque random bytes to a
//! foreign adversary) and is the same `CHUNK_SIZE` as every other
//! chunk, so it adds no size/structure signal beyond the appends/
//! in-place-rewrites that commit + padding + vacuum already produce.
//! Checkpoints are per-space only — never aggregated across spaces.

use byteorder::{ByteOrder, LittleEndian};

use crate::chunk::ChunkKind;
use crate::chunk::format::PAYLOAD_CAP;
use crate::{Error, Result};

use super::Space;
use super::superblock::{NO_RECORD, Superblock};

/// Fixed header bytes of a checkpoint chunk's payload, before the two
/// slot lists: `cp_seq (8) ‖ cp_high_water (8) ‖ next_slot (8) ‖
/// owned_count (4) ‖ pool_count (4)`.
const CP_HEADER_LEN: usize = 8 + 8 + 8 + 4 + 4;

/// Slot entries (each a `u64` LE) that fit in one checkpoint chunk after
/// its header. The owned list and the pool list share this budget — a
/// chunk carries `owned.len() + pool.len() <= CP_ENTRIES_PER_CHUNK`.
pub(crate) const CP_ENTRIES_PER_CHUNK: usize = (PAYLOAD_CAP - CP_HEADER_LEN) / 8;

// Compile-time guarantees: at least one entry fits, and a full chunk's
// header + entry list never exceeds the per-chunk payload cap.
const _: () = assert!(CP_ENTRIES_PER_CHUNK > 0);
const _: () = assert!(CP_HEADER_LEN + CP_ENTRIES_PER_CHUNK * 8 <= PAYLOAD_CAP);

/// Below this total slot count a full scan is already fast (≈ tens of
/// ms), so the self-heal writer skips checkpointing entirely — keeping
/// small containers byte-for-byte free of checkpoint chunks (and so
/// forward-compatible with a pre-checkpoint reader). `4096` chunks ≈
/// 16 MiB.
pub(crate) const CHECKPOINT_MIN_TOTAL: u64 = 4096;

/// The self-heal writer refreshes the checkpoint when the
/// un-checkpointed tail has grown past `max(owned_count,
/// CHECKPOINT_MIN_TAIL_REFRESH)`. The floor keeps tiny tails from
/// triggering a rewrite on every open.
pub(crate) const CHECKPOINT_MIN_TAIL_REFRESH: u64 = 2048;

/// The self-heal writer also refreshes when the decoy pool's membership
/// has drifted by this many slots since it was last recorded (DESIGN
/// §9.1).
///
/// Without this trigger the reuse work would have shipped with a
/// mechanism that cannot persist: reuse is what stops the file growing,
/// the growth of the un-checkpointed tail is what the other trigger
/// measures, and so the better reuse works the less often the pool that
/// enables it gets written down. A container that reused perfectly would
/// checkpoint exactly once and then lose every slot it freed on the next
/// close.
///
/// `256` is one bucket of the recommended `BucketGrowth { 256 }` padding
/// preset — the granularity the file already moves in — so a refresh
/// costs a chain write about as often as the pre-reuse design paid for a
/// megabyte of padding.
pub(crate) const CHECKPOINT_MIN_POOL_DRIFT: u64 = 256;

/// Upper bound on checkpoint-chain hops while reading or scrubbing,
/// defending against an adversarial/buggy cyclic or over-long chain.
/// `MAX_OPEN_SCAN_CHUNKS` entries / `CP_ENTRIES_PER_CHUNK` per chunk,
/// plus slack.
pub(crate) const MAX_CHECKPOINT_CHAIN: u64 =
    crate::open::MAX_OPEN_SCAN_CHUNKS / (CP_ENTRIES_PER_CHUNK as u64) + 2;

/// One decoded checkpoint chunk: the shared header plus this chunk's
/// slice of the owned-slot list and the pointer to the next chunk in
/// the chain (or [`NO_RECORD`] at the tail).
#[derive(Debug, Clone)]
pub(crate) struct CheckpointChunk {
    /// Superblock seq this checkpoint was published under (the
    /// checkpoint "commit"). Same value in every chunk of one chain.
    pub cp_seq: u64,
    /// Slot count at checkpoint-write time. Every recorded owned slot
    /// is `< cp_high_water`; the reader scans `[cp_high_water, total)`
    /// fresh. Same value in every chunk of one chain.
    pub cp_high_water: u64,
    /// Slot of the next checkpoint chunk in the chain, or [`NO_RECORD`].
    pub next_slot: u64,
    /// This chunk's slice of the sorted owned-slot list.
    pub owned: Vec<u64>,
    /// This chunk's slice of the sorted **decoy-pool** list — slots this
    /// space has retired and may rewrite (DESIGN §9.1). Recorded here
    /// rather than in its own structure because it needs exactly what the
    /// owned list needs: one chain, published atomically with a
    /// superblock, sealed under the same per-space key.
    ///
    /// The reader treats it as a hint and subtracts the scan's owned set
    /// from it — see [`super::pool::DecoyPool`]. That is what lets this
    /// list be refreshed as lazily as the rest of the checkpoint without
    /// ever naming a slot that has since gone live.
    pub pool: Vec<u64>,
}

/// The pool half of a record: this session's live pool, plus whatever was
/// carried from the record being superseded.
///
/// Merged rather than substituted — a session that never loaded a pool can
/// still have freed slots into one (every commit's garbage padding does), and
/// those are as real as the carried ones.
///
/// Both halves are filtered against THIS era's owned set and high-water, so
/// the two halves of the record stay complementary. That filter is
/// defence-in-depth rather than a live correction: the reader subtracts its
/// scan's owned set from the recorded pool anyway (see `crate::open`), and a
/// session with no pool cannot have written to a carried slot in the first
/// place. It is here so that the record is true on its own terms, not only
/// after a reader repairs it.
///
/// Merged ON the carried bitmap rather than into a third `Vec`. The eight
/// bytes per slot the record is encoded from are unavoidable once, and this
/// path used to pay them four times over — the live pool as a `Vec`, the
/// carried one as a second, the concatenation of both as a third, and the
/// sort that ordered what two sets already had in order.
fn merge_carried_pool(
    live: &crate::space::pool::DecoyPool,
    mut carried: crate::space::pool::DecoyPool,
    owned: &crate::space::slots::OwnedSet,
    high_water: u64,
) -> Result<Vec<u64>> {
    // Fallible for the reason `owned` is: this is the other 128-MiB-at-the-
    // ceiling allocation on the checkpoint path, and `panic = "abort"` makes
    // a refusal from the allocator process death (report14 HV14-M5).
    let too_big = |_| Error::Internal("checkpoint pool does not fit in memory");
    if carried.is_empty() {
        return live.try_sorted().map_err(too_big);
    }
    for slot in live.iter() {
        carried.record(slot);
    }
    carried.retain_below_and_unowned(high_water, owned);
    carried.try_sorted().map_err(too_big)
}

impl CheckpointChunk {
    /// Encode to the checkpoint payload bytes (header ‖ owned u64 LE list
    /// ‖ pool u64 LE list). Errors if the two lists together exceed
    /// [`CP_ENTRIES_PER_CHUNK`].
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        let entries = self.owned.len() + self.pool.len();
        if entries > CP_ENTRIES_PER_CHUNK {
            return Err(Error::Internal("checkpoint chunk overfull"));
        }
        let mut buf = Vec::with_capacity(CP_HEADER_LEN + entries * 8);
        let mut hdr = [0u8; CP_HEADER_LEN];
        LittleEndian::write_u64(&mut hdr[0..8], self.cp_seq);
        LittleEndian::write_u64(&mut hdr[8..16], self.cp_high_water);
        LittleEndian::write_u64(&mut hdr[16..24], self.next_slot);
        LittleEndian::write_u32(&mut hdr[24..28], self.owned.len() as u32);
        LittleEndian::write_u32(&mut hdr[28..32], self.pool.len() as u32);
        buf.extend_from_slice(&hdr);
        for &s in self.owned.iter().chain(self.pool.iter()) {
            let mut b = [0u8; 8];
            LittleEndian::write_u64(&mut b, s);
            buf.extend_from_slice(&b);
        }
        Ok(buf)
    }

    /// Decode a checkpoint payload. Strict on length: the trailing slot
    /// lists must be exactly `(owned_count + pool_count) * 8` bytes (no
    /// trailing slack), and the two counts together must fit one chunk.
    /// Errors as [`Error::Malformed`] otherwise — the reader treats any
    /// error as "no usable checkpoint" and falls back to the full scan.
    pub(crate) fn decode(payload: &[u8]) -> Result<Self> {
        if payload.len() < CP_HEADER_LEN {
            return Err(Error::Malformed("checkpoint chunk shorter than header"));
        }
        let cp_seq = LittleEndian::read_u64(&payload[0..8]);
        let cp_high_water = LittleEndian::read_u64(&payload[8..16]);
        let next_slot = LittleEndian::read_u64(&payload[16..24]);
        let owned_count = LittleEndian::read_u32(&payload[24..28]) as usize;
        let pool_count = LittleEndian::read_u32(&payload[28..32]) as usize;
        // Checked as a SUM, and before it is used to size anything: the two
        // counts share one chunk's budget, so a pair that each pass a
        // per-list bound can still describe twice a chunk's worth of
        // entries. `saturating_add` because both are attacker-supplied
        // u32s widened to usize.
        let entries = owned_count.saturating_add(pool_count);
        if entries > CP_ENTRIES_PER_CHUNK {
            return Err(Error::Malformed(
                "checkpoint count exceeds per-chunk capacity",
            ));
        }
        let need = CP_HEADER_LEN + entries * 8;
        if payload.len() != need {
            return Err(Error::Malformed("checkpoint chunk length mismatch"));
        }
        let read_at = |i: usize| LittleEndian::read_u64(&payload[i * 8..i * 8 + 8]);
        let base = CP_HEADER_LEN / 8;
        let mut owned = Vec::with_capacity(owned_count);
        for i in 0..owned_count {
            owned.push(read_at(base + i));
        }
        let mut pool = Vec::with_capacity(pool_count);
        for i in 0..pool_count {
            pool.push(read_at(base + owned_count + i));
        }
        Ok(Self {
            cp_seq,
            cp_high_water,
            next_slot,
            owned,
            pool,
        })
    }
}

impl<'f> Space<'f> {
    /// Lazily (re)write this space's open-scan checkpoint so the next
    /// open is O(working-set). Returns `true` if a checkpoint was
    /// written.
    ///
    /// Called once per open, AFTER `vacuum_orphans` (so the recorded
    /// owned set reflects the post-vacuum truth), on writable handles
    /// only. No-op when:
    /// - the handle is read-only (forward-secrecy / checkpoint writes
    ///   are writer-only),
    /// - the container is smaller than [`CHECKPOINT_MIN_TOTAL`] (a full
    ///   scan is already fast; keep small containers checkpoint-free),
    /// - a checkpoint already covers all but a small tail (no churn).
    ///
    /// The write is published like a tiny no-data commit: the owned
    /// set is recorded in a fresh checkpoint chain, then a superblock
    /// with a **bumped seq** (same `root_slot` / `root_hash`, new
    /// `checkpoint_slot`) is appended so the next open's max-seq
    /// superblock points at the new chain. Seq is bumped (not reused)
    /// to preserve the same-seq-replicas-are-bit-equal invariant.
    pub(crate) fn maybe_self_heal_checkpoint(&mut self) -> Result<bool> {
        if !self.file.lock_mode.allows_writes() {
            return Ok(false);
        }
        let total = self.file.slot_count();
        if total < CHECKPOINT_MIN_TOTAL {
            return Ok(false);
        }

        let old_head = self.state.superblock.checkpoint_slot;
        // Existing checkpoint's coverage (its high-water). Unreadable /
        // absent ⇒ treat as zero coverage so we (re)write.
        let existing_high_water = if old_head == NO_RECORD {
            0
        } else {
            // Unreadable / absent head ⇒ zero coverage ⇒ (re)write.
            self.read_checkpoint_head_high_water(old_head)
                .unwrap_or_default()
        };
        let tail = total.saturating_sub(existing_high_water);
        let owned_count = self.state.owned_slots.len() as u64;
        let refresh = old_head == NO_RECORD
            || tail > owned_count.max(CHECKPOINT_MIN_TAIL_REFRESH)
            // The pool's own trigger. Reuse suppresses tail growth, which
            // is what the clause above measures, so on a container that
            // reuses well this is the only clause that ever fires — see
            // `CHECKPOINT_MIN_POOL_DRIFT`.
            || self.state.pool.drift() >= CHECKPOINT_MIN_POOL_DRIFT;
        if !refresh {
            return Ok(false);
        }

        self.write_self_heal_checkpoint()?;
        Ok(true)
    }

    /// The checkpoint write itself, independent of the size/refresh
    /// policy in [`Self::maybe_self_heal_checkpoint`]. Scrubs the chain
    /// it supersedes, snapshots the (post-vacuum) owned set, writes a
    /// fresh chain, and publishes a bumped-seq superblock pointing at
    /// it. Returns [`Error::ReadOnly`] on a shared-locked handle.
    pub(crate) fn write_self_heal_checkpoint(&mut self) -> Result<()> {
        if !self.file.lock_mode.allows_writes() {
            return Err(Error::ReadOnly);
        }
        // This episode reuses nothing. `commit_tx` is the only caller of
        // `churn_decoys`, so a slot this path took out of the pool — the
        // Superblock replicas below; the chain itself is `Checkpoint` and
        // never reuses — would be a reused slot no churn ever covered, which
        // is the snapshot oracle DESIGN §9.1 denies. The budget is declared
        // here rather than inherited: `commit_tx` leaves its own floor
        // standing, and a floor a later, growing pool has climbed back over
        // would quietly re-permit exactly that.
        self.state.reuse_floor = usize::MAX;

        let total = self.file.slot_count();
        let old_head = self.state.superblock.checkpoint_slot;

        // What the chain we are about to supersede recorded, read BEFORE the
        // scrub below destroys it.
        //
        // A session that never loaded the pool would otherwise record an EMPTY
        // one over the accumulated set, and that loss is permanent — every
        // later open starts append-only until the pool rebuilds. The session
        // that does this is the constant-time open: it takes the full-scan
        // path by design (the fast path's chunk count distinguishes a right
        // password from a wrong one), and the pool is only recoverable from a
        // checkpoint. Measured on a fixture: 46 recorded slots became 1
        // (report9 HV-14).
        //
        // Only when this session never LOADED the record. A session that did
        // holds the authoritative set — it knows both what the record said and
        // what it has since consumed, and carrying anything forward there
        // would resurrect a slot it deliberately dropped.
        //
        // Emptiness is the wrong test for that: this session's pool is empty
        // only until the first commit frees a slot into it, after which one
        // slot would be recorded over the accumulated forty.
        let carried_pool = if !self.state.pool_recovered && old_head != NO_RECORD {
            let container_id = self.state.keys.container_id;
            let keys = self.state.keys.clone();
            crate::open::read_checkpoint_chain(
                self.file,
                &keys,
                &container_id,
                old_head,
                total,
                None,
                false,
            )
            .ok()
            .flatten()
            .map(|recorded| recorded.pool)
            .unwrap_or_default()
        } else {
            crate::space::pool::DecoyPool::default()
        };

        // Scrub the chain we are about to supersede *first*, so the
        // fresh owned snapshot does not record the soon-dead chunks.
        // Crash-safe: if we die before publishing the new superblock,
        // the on-disk superblock still points at the (now-scrubbed)
        // old head, so the next open's fast-path read fails and falls
        // back to a full scan + re-heal. No data is referenced through
        // a checkpoint, so a dangling pointer only costs one slow open.
        if old_head != NO_RECORD {
            self.scrub_checkpoint_chain(old_head)?;
        }

        // cp_high_water = current slot count: every slot now on disk is
        // < total, so the reader scans nothing twice. Scrubbing above
        // does not change slot_count (in-place overwrite), so `total`
        // sampled before the scrub is still the high-water.
        let cp_high_water = total;
        // The one place the set is materialized as eight bytes per slot: the
        // record is encoded from it. Already ascending and duplicate-free by
        // the set's construction, which is what the sort and dedup here used
        // to guarantee.
        // Fallibly: eight bytes per slot is 128 MiB at the supported ceiling,
        // and this crate builds with `panic = "abort"`, so an allocation the
        // allocator cannot serve ENDS THE PROCESS rather than unwinding. A
        // checkpoint is an optimisation hint — refusing to write one costs the
        // next open a full scan, and that is a trade worth making against
        // taking the caller down with it (report14 HV14-M5).
        let owned: Vec<u64> = self
            .state
            .owned_slots
            .try_to_sorted_vec()
            .map_err(|_| Error::Internal("checkpoint owned set does not fit in memory"))?;
        debug_assert!(
            owned.last().map(|&s| s < cp_high_water).unwrap_or(true),
            "owned slots must be below the checkpoint high-water"
        );
        // The pool travels with the owned set, and it must be recorded from
        // the SAME moment: the two are complementary halves of "what this
        // space has below the high-water", and a reader that mixed one
        // era's owned set with another's pool could see a slot in neither.
        let pool: Vec<u64> = merge_carried_pool(
            &self.state.pool,
            carried_pool,
            &self.state.owned_slots,
            cp_high_water,
        )?;
        debug_assert!(
            pool.last().map(|&s| s < cp_high_water).unwrap_or(true),
            "pool slots must be below the checkpoint high-water"
        );

        // Same rule as `commit_tx`: never re-use a seq whose replica may
        // already be on disk from a failed publish. Publishing a checkpoint
        // bumps and publishes the superblock `seq`, so this path carries
        // correctness state despite being "an optimisation hint".
        let cp_seq = self
            .state
            .attempted_seq
            .max(self.state.superblock.seq)
            .checked_add(1)
            .ok_or(Error::Internal("checkpoint seq overflow"))?;

        let head = self.write_checkpoint_chain(cp_seq, cp_high_water, &owned, &pool)?;
        self.file.fsync()?;

        // Publish: new superblock, bumped seq, unchanged root, pointing
        // at the new checkpoint head. Replicas are bit-equal (same seq,
        // same payload) so the open-scan dedup invariant holds.
        let new_sb = Superblock {
            seq: cp_seq,
            root_slot: self.state.superblock.root_slot,
            root_hash: self.state.superblock.root_hash,
            checkpoint_slot: head,
        };
        // Same window as `commit_tx`, same answer: past this call the seq is
        // burnt and a replica may be on the disk, so a failure is not "the
        // checkpoint write failed, carry on" but "this handle may be behind the
        // file, reopen" (report8 H-09). A checkpoint is an optimisation hint,
        // but PUBLISHING one bumps the superblock seq, and that half is
        // correctness state like any other era transition.
        self.publish_superblock(&new_sb, "checkpointing")?;
        self.state.superblock = new_sb;
        // The recorded pool is now current. Cleared only after the publish
        // succeeded: a failed publish leaves the on-disk chain unnamed, so
        // the drift that motivated this write is still owed.
        self.state.pool.clear_drift();
        // cp_seq is strictly greater than every prior entry (bumped from
        // the max), so push preserves sort + uniqueness.
        self.state.commit_history.push(cp_seq);
        Ok(())
    }

    /// Read the head checkpoint chunk and return its `cp_high_water`,
    /// or `None` if it is unreadable / not a checkpoint. Used only for
    /// the refresh-decision heuristic (the authoritative read is on the
    /// open path).
    fn read_checkpoint_head_high_water(&mut self, head: u64) -> Option<u64> {
        if head >= self.file.slot_count() {
            return None;
        }
        let pt = self.read_owned_chunk(head).ok()?;
        if pt.kind != ChunkKind::Checkpoint {
            return None;
        }
        CheckpointChunk::decode(&pt.payload)
            .ok()
            .map(|c| c.cp_high_water)
    }

    /// Write `owned` and `pool` (both sorted, all `< cp_high_water`) as a
    /// fresh checkpoint chain, returning the head slot. The chain is
    /// written tail-first so each chunk's `next_slot` is known before it
    /// is sealed. Empty lists still write one (empty) chunk so the
    /// pointer is always valid.
    ///
    /// The two lists share each chunk's entry budget and are packed
    /// end-to-end — owned first, then pool — so a chain holding `N` slots
    /// in total costs the same chunks whichever list they came from.
    fn write_checkpoint_chain(
        &mut self,
        cp_seq: u64,
        cp_high_water: u64,
        owned: &[u64],
        pool: &[u64],
    ) -> Result<u64> {
        // Groups of at most CP_ENTRIES_PER_CHUNK entries, in forward
        // order. Empty lists ⇒ a single empty group.
        let mut groups: Vec<(&[u64], &[u64])> = Vec::new();
        let (mut o, mut p) = (owned, pool);
        loop {
            let take_o = o.len().min(CP_ENTRIES_PER_CHUNK);
            let take_p = (CP_ENTRIES_PER_CHUNK - take_o).min(p.len());
            groups.push((&o[..take_o], &p[..take_p]));
            o = &o[take_o..];
            p = &p[take_p..];
            if o.is_empty() && p.is_empty() {
                break;
            }
        }
        let mut next = NO_RECORD;
        // Write last group first so `next` always points at an
        // already-written successor; after the reverse walk `next` is
        // the first group's slot = the chain head.
        for (group_owned, group_pool) in groups.iter().rev() {
            let cc = CheckpointChunk {
                cp_seq,
                cp_high_water,
                next_slot: next,
                owned: group_owned.to_vec(),
                pool: group_pool.to_vec(),
            };
            let payload = cc.encode()?;
            next = self.place_chunk(ChunkKind::Checkpoint, cp_seq, &payload)?;
        }
        Ok(next)
    }

    /// Scrub (overwrite with random) every chunk of the checkpoint
    /// chain rooted at `head`, removing them from `owned_slots`. Stops
    /// at the first unreadable / non-checkpoint hop (a partially
    /// scrubbed chain from a prior crash) and is bounded by
    /// [`MAX_CHECKPOINT_CHAIN`]. Best-effort cleanup of a superseded
    /// chain — not correctness-bearing (orphan checkpoint chunks left
    /// by a crash are reclaimed by the next `compact_known`).
    fn scrub_checkpoint_chain(&mut self, head: u64) -> Result<()> {
        let mut cur = head;
        let mut scrubbed: Vec<u64> = Vec::new();
        let mut hops = 0u64;
        while cur != NO_RECORD && hops < MAX_CHECKPOINT_CHAIN {
            hops += 1;
            if cur >= self.file.slot_count() {
                break;
            }
            let pt = match self.read_owned_chunk(cur) {
                Ok(p) => p,
                // Already scrubbed / not ours — stop walking.
                Err(Error::AuthFailed) => break,
                Err(other) => return Err(other),
            };
            if pt.kind != ChunkKind::Checkpoint {
                break;
            }
            let next = match CheckpointChunk::decode(&pt.payload) {
                Ok(c) => c.next_slot,
                Err(_) => NO_RECORD,
            };
            self.file.scrub_slot(cur)?;
            scrubbed.push(cur);
            cur = next;
        }
        if !scrubbed.is_empty() {
            self.file.fsync()?;
            let drop: std::collections::HashSet<u64> = scrubbed.into_iter().collect();
            self.state.owned_slots.retain(|s| !drop.contains(&s));
            // A superseded chain is retired the same way a vacuumed orphan
            // is, so it joins the pool the same way (DESIGN §9.1). The
            // chain the caller is about to write does NOT come out of the
            // pool — see `Space::place_chunk` on why checkpoint chunks
            // alone are append-only.
            for slot in drop {
                self.state.pool.insert(slot);
            }
        }
        Ok(())
    }
}

/// The on-disk checkpoint header, and the documents that describe it.
///
/// report9 HV-08: `docs/{en,ru}/reference/format.md` carried a 28-byte header
/// with one list long after the pool list and `pool_count` had arrived with
/// slot reuse. Nothing was wrong with the code; the format reference is the
/// contract an independent implementation is written against, and an
/// implementation written against that one mis-parsed every checkpoint this
/// writer produces.
///
/// Checked against the docs rather than only stated here, because a comment
/// beside the constant is exactly what was already there while the reference
/// said something else.
#[cfg(test)]
mod format_doc_agreement_tests {
    use super::CP_HEADER_LEN;

    fn doc(path: &str) -> String {
        let full = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("{full}: {e}"))
    }

    #[test]
    fn the_header_is_thirty_two_bytes() {
        assert_eq!(
            CP_HEADER_LEN, 32,
            "the header changed size — every offset in format.md moved with it"
        );
    }

    #[test]
    fn both_format_references_describe_the_header_that_is_written() {
        for path in ["docs/en/reference/format.md", "docs/ru/reference/format.md"] {
            let text = doc(path);
            for needle in [
                "offset 24..28   owned_count",
                "offset 28..32   pool_count",
                "offset 32..",
            ] {
                assert!(
                    text.contains(needle),
                    "{path} does not describe `{needle}` — an implementation \
                     written from it will mis-parse every checkpoint this \
                     writer produces (report9 HV-08)"
                );
            }
            assert!(
                !text.contains("offset 28..     owned["),
                "{path} still carries the pre-pool 28-byte header"
            );
        }
    }
}

#[cfg(test)]
mod tests {

    /// A checkpoint that does not fit in memory is REFUSED, not fatal.
    ///
    /// Eight bytes per slot is 128 MiB at the supported ceiling, and this
    /// crate builds with `panic = "abort"` — so an allocation the allocator
    /// cannot serve does not unwind, it ends the process. A checkpoint is an
    /// optimisation hint: refusing to write one costs the next open a full
    /// scan, and that is the trade (report14 HV14-M5).
    ///
    /// The refusal is exercised through the same fallible path the writer
    /// takes, with a length no allocator will serve.
    #[test]
    fn a_slot_list_too_large_to_hold_is_refused_rather_than_fatal() {
        use crate::space::slots::OwnedSet;

        // An honest set first, or the refusal below is about nothing.
        let mut small = OwnedSet::default();
        for slot in [1u64, 5, 9] {
            small.insert(slot);
        }
        assert_eq!(small.try_to_sorted_vec().unwrap(), vec![1, 5, 9]);

        // `try_reserve_exact` refuses a request past what the allocator can
        // serve — `isize::MAX` bytes is the hard ceiling for any allocation,
        // so this is refused on every platform rather than attempted.
        let mut v: Vec<u64> = Vec::new();
        assert!(
            v.try_reserve_exact(usize::MAX / 8).is_err(),
            "the fixture's premise is that an over-large reserve FAILS"
        );

        // And the pool half answers the same way.
        let pool = crate::space::pool::DecoyPool::default();
        assert!(pool.try_sorted().is_ok());
    }

    /// The claim that lets `open` swallow a self-heal failure, put to the file.
    ///
    /// `open_space_with_keys_inner_opts` ends with
    /// `let _ = space.maybe_self_heal_checkpoint()`, on the grounds that the
    /// checkpoint is an optimisation hint and the next open re-tries. The
    /// failure it drops can leave a half-written chain behind, and nothing in
    /// this crate reports it — there is no logging channel here at all, which
    /// for a deniable store is a decision rather than an omission.
    ///
    /// So the guarantee has to be the reader's, and this is it: a chain whose
    /// head is unreadable costs the fast path and nothing else. The data comes
    /// back, through a full scan.
    ///
    /// The failure itself cannot be forced from a test — the paths that fail
    /// are I/O and there is no fault injection under the file — so what is
    /// pinned is the property that makes swallowing it defensible.
    #[test]
    fn an_unreadable_checkpoint_head_costs_the_fast_path_and_nothing_else() {
        use crate::container::{Container, ContainerOptions};
        use crate::crypto::kdf::Argon2Params;
        use crate::padding::PaddingPolicy;
        use crate::space::index::Namespace;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.hv");
        // Past CHECKPOINT_MIN_TOTAL by construction rather than by writing
        // sixteen megabytes of real records.
        let opts = ContainerOptions {
            argon2: Argon2Params::MIN,
            initial_garbage_chunks: CHECKPOINT_MIN_TOTAL + 128,
            padding_policy: PaddingPolicy::None,
            superblock_replicas: 1,
        };
        {
            let mut c = Container::create_with_options(&path, opts).unwrap();
            let mut sp = c.create_space(b"pw").unwrap();
            let mut tx = sp.begin_tx();
            tx.put(Namespace::CONTACTS, b"k", b"the value that must survive")
                .unwrap();
            tx.commit().unwrap();
        }

        // The open that writes the checkpoint, and the slot it put it at.
        let head = {
            let mut c = Container::open(&path).unwrap();
            let sp = c.open_space(b"pw").unwrap();
            sp.state.superblock.checkpoint_slot
        };
        assert_ne!(
            head, NO_RECORD,
            "the fixture needs a checkpoint before it can break one",
        );

        // A head that will not decrypt: the shape a write interrupted part
        // way through leaves, from the reader's side.
        let before = std::fs::metadata(&path).unwrap().len();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            let offset = (1 + head) * crate::CHUNK_SIZE as u64;
            f.seek(SeekFrom::Start(offset)).unwrap();
            f.write_all(&[0xA5u8; 256]).unwrap();
            f.sync_all().unwrap();
        }
        // Vacuity guard: a seek past the end would have GROWN the file and
        // scribbled on nothing, and the assertion below would then pass
        // because the checkpoint was never touched.
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            before,
            "the scribble landed outside the container",
        );

        let mut c = Container::open(&path).unwrap();
        let mut sp = c.open_space(b"pw").unwrap();
        assert_eq!(
            sp.get(Namespace::CONTACTS, b"k").unwrap().as_deref(),
            Some(&b"the value that must survive"[..]),
            "a broken checkpoint must cost the fast path, not the data",
        );
    }

    /// A pool holding exactly these slots, sized past the largest of them.
    fn pool_of(slots: &[u64]) -> crate::space::pool::DecoyPool {
        let mut p = crate::space::pool::DecoyPool::default();
        for &s in slots {
            p.record(s);
        }
        p
    }

    /// The carried half must never name a slot this era owns.
    ///
    /// Defence-in-depth, and the only place it can be exercised: a session
    /// with no pool cannot write to a carried slot, so no fixture at the
    /// container level can produce the collision. Tested here because the
    /// filter is what makes the record true on its own terms rather than only
    /// after a reader subtracts its own scan.
    #[test]
    fn a_carried_slot_this_era_owns_is_not_recorded_as_reusable() {
        let owned = [5u64, 9].into_iter().collect();
        let pool =
            super::merge_carried_pool(&pool_of(&[2]), pool_of(&[5, 7, 9]), &owned, 100).unwrap();
        assert_eq!(pool, vec![2, 7], "a live slot was recorded as reusable");
    }

    /// And past the high-water: the record summarizes only what is below it.
    #[test]
    fn a_carried_slot_above_the_high_water_is_not_recorded() {
        let pool =
            super::merge_carried_pool(&pool_of(&[1]), pool_of(&[3, 42]), &Default::default(), 10)
                .unwrap();
        assert_eq!(pool, vec![1, 3]);
    }

    /// Merged, not substituted, and deduplicated across the two halves.
    #[test]
    fn the_live_pool_and_the_carried_one_are_both_kept() {
        let pool =
            super::merge_carried_pool(&pool_of(&[4, 1]), pool_of(&[1, 6]), &Default::default(), 10)
                .unwrap();
        assert_eq!(pool, vec![1, 4, 6]);
    }
    use super::*;

    #[test]
    fn checkpoint_chunk_roundtrip() {
        let cc = CheckpointChunk {
            cp_seq: 5,
            cp_high_water: 1000,
            next_slot: 42,
            owned: vec![1, 7, 9, 900],
            pool: vec![2, 400],
        };
        let enc = cc.encode().unwrap();
        let dec = CheckpointChunk::decode(&enc).unwrap();
        assert_eq!(dec.cp_seq, 5);
        assert_eq!(dec.cp_high_water, 1000);
        assert_eq!(dec.next_slot, 42);
        assert_eq!(dec.owned, vec![1, 7, 9, 900]);
        assert_eq!(dec.pool, vec![2, 400]);
    }

    /// The two lists are packed end-to-end with only their counts to say
    /// where the boundary is, so an off-by-one in either count silently
    /// re-attributes slots from one list to the other — and a slot that
    /// moves from `owned` to `pool` is a live slot offered to the
    /// allocator. Asymmetric lengths and disjoint values pin the split.
    #[test]
    fn the_two_lists_do_not_bleed_into_each_other() {
        let cc = CheckpointChunk {
            cp_seq: 3,
            cp_high_water: 100,
            next_slot: NO_RECORD,
            owned: vec![10, 11, 12, 13, 14],
            pool: vec![90],
        };
        let dec = CheckpointChunk::decode(&cc.encode().unwrap()).unwrap();
        assert_eq!(dec.owned, vec![10, 11, 12, 13, 14]);
        assert_eq!(dec.pool, vec![90]);

        // ...and with the lengths the other way round.
        let cc = CheckpointChunk {
            cp_seq: 3,
            cp_high_water: 100,
            next_slot: NO_RECORD,
            owned: vec![7],
            pool: vec![80, 81, 82, 83],
        };
        let dec = CheckpointChunk::decode(&cc.encode().unwrap()).unwrap();
        assert_eq!(dec.owned, vec![7]);
        assert_eq!(dec.pool, vec![80, 81, 82, 83]);
    }

    #[test]
    fn checkpoint_chunk_empty_owned() {
        let cc = CheckpointChunk {
            cp_seq: 1,
            cp_high_water: 0,
            next_slot: NO_RECORD,
            owned: vec![],
            pool: vec![],
        };
        let enc = cc.encode().unwrap();
        assert_eq!(enc.len(), CP_HEADER_LEN);
        let dec = CheckpointChunk::decode(&enc).unwrap();
        assert!(dec.owned.is_empty());
        assert!(dec.pool.is_empty());
        assert_eq!(dec.next_slot, NO_RECORD);
    }

    #[test]
    fn checkpoint_chunk_rejects_trailing_slack() {
        let mut enc = CheckpointChunk {
            cp_seq: 1,
            cp_high_water: 10,
            next_slot: NO_RECORD,
            owned: vec![3],
            pool: vec![4],
        }
        .encode()
        .unwrap();
        enc.push(0); // one trailing byte
        assert!(CheckpointChunk::decode(&enc).is_err());
    }

    #[test]
    fn checkpoint_chunk_rejects_overlarge_count() {
        let mut enc = CheckpointChunk {
            cp_seq: 1,
            cp_high_water: 10,
            next_slot: NO_RECORD,
            owned: vec![3],
            pool: vec![],
        }
        .encode()
        .unwrap();
        // Force count to a huge value without supplying the bytes.
        LittleEndian::write_u32(&mut enc[24..28], u32::MAX);
        assert!(CheckpointChunk::decode(&enc).is_err());
    }

    /// The capacity check is on the SUM, so two counts that each look
    /// sane must still be rejected together. Held to literals rather than
    /// to `CP_ENTRIES_PER_CHUNK`: pinning the numbers to the constant
    /// would let a change to the constant move the test with it, and the
    /// point is that one chunk cannot describe two chunks' worth of
    /// slots.
    #[test]
    fn checkpoint_chunk_rejects_two_counts_that_only_overflow_together() {
        assert_eq!(
            CP_ENTRIES_PER_CHUNK, 501,
            "the payload budget moved; recheck the literals below"
        );
        let mut enc = CheckpointChunk {
            cp_seq: 1,
            cp_high_water: 10,
            next_slot: NO_RECORD,
            owned: vec![3],
            pool: vec![],
        }
        .encode()
        .unwrap();
        // 300 + 300 = 600 > 501, but neither alone exceeds the budget.
        LittleEndian::write_u32(&mut enc[24..28], 300);
        LittleEndian::write_u32(&mut enc[28..32], 300);
        assert!(CheckpointChunk::decode(&enc).is_err());
    }

    // --- End-to-end fast-open behavior (uses the public Container API
    //     plus in-crate test seams in `crate::open::test_hooks`). ---

    use crate::Container;
    use crate::crypto::kdf::Argon2Params;
    use crate::open::test_hooks;
    use crate::space::index::Namespace;

    fn scratch_path() -> std::path::PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
    }

    /// Reconstructed-state fingerprint for fast-vs-full equivalence.
    #[derive(PartialEq, Debug)]
    struct StateSnap {
        owned: Vec<u64>,
        history: Vec<u64>,
        seq: u64,
        root_slot: u64,
        present: Vec<(u32, Vec<u8>)>,
    }

    const N_KEYS: u32 = 40;
    const DELETED: [u32; 3] = [5, 17, 33];

    /// Build a container: write `N_KEYS` settings KV entries (one commit
    /// each, so each commit supersedes the prior index → orphan
    /// IndexNodes accumulate), delete a few, then force-write a
    /// checkpoint. Leaves the file closed and ready to reopen.
    fn build_with_checkpoint(path: &std::path::Path) {
        let mut c = Container::create(path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..N_KEYS {
            let mut tx = s.begin_tx();
            tx.put(
                Namespace::SETTINGS,
                format!("k{i}").as_bytes(),
                format!("v{i}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        for &d in &DELETED {
            let mut tx = s.begin_tx();
            tx.delete(Namespace::SETTINGS, format!("k{d}").as_bytes())
                .unwrap();
            tx.commit().unwrap();
        }
        // Force the checkpoint regardless of the size threshold so the
        // mechanism is exercised on a small (fast) container.
        s.write_self_heal_checkpoint().unwrap();
        assert_ne!(
            s.state.superblock.checkpoint_slot, NO_RECORD,
            "checkpoint pointer must be set after a forced write"
        );
    }

    /// Open read-only (no vacuum, no mutation, sequential scan) and
    /// fingerprint the reconstructed state + the live KV data.
    fn snapshot_readonly(path: &std::path::Path) -> StateSnap {
        let mut c = Container::open_readonly(path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        let mut owned = s.state.owned_slots.to_sorted_vec();
        owned.sort_unstable();
        let history = s.state.commit_history.clone();
        let seq = s.state.superblock.seq;
        let root_slot = s.state.superblock.root_slot;
        let mut present = Vec::new();
        for i in 0..N_KEYS {
            if let Some(v) = s
                .get(Namespace::SETTINGS, format!("k{i}").as_bytes())
                .unwrap()
            {
                present.push((i, v));
            }
        }
        StateSnap {
            owned,
            history,
            seq,
            root_slot,
            present,
        }
    }

    /// The fast-open scan must reconstruct byte-for-byte the same state
    /// (owned_slots, commit_history, superblock, live data) as a full
    /// scan — and must actually engage.
    #[test]
    fn fast_path_matches_full_scan_and_engages() {
        let path = scratch_path();
        build_with_checkpoint(&path);

        test_hooks::set_disable(false);
        test_hooks::reset_hits();
        let fast = snapshot_readonly(&path);
        assert!(
            test_hooks::hits() >= 1,
            "fast path must engage when a checkpoint is present"
        );

        test_hooks::set_disable(true);
        let full = snapshot_readonly(&path);
        test_hooks::set_disable(false);

        assert_eq!(fast, full, "fast-open state must equal the full scan");
        let expected: usize = (N_KEYS as usize) - DELETED.len();
        assert_eq!(fast.present.len(), expected);
        for (i, v) in &fast.present {
            assert!(!DELETED.contains(i));
            assert_eq!(v.as_slice(), format!("v{i}").as_bytes());
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A corrupt (scrubbed) checkpoint head must make the fast-path
    /// decline and fall back to the full scan — with all data intact.
    #[test]
    fn corrupt_checkpoint_falls_back_to_full_scan() {
        let path = scratch_path();
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            for i in 0..N_KEYS {
                let mut tx = s.begin_tx();
                tx.put(
                    Namespace::SETTINGS,
                    format!("k{i}").as_bytes(),
                    format!("v{i}").as_bytes(),
                )
                .unwrap();
                tx.commit().unwrap();
            }
            s.write_self_heal_checkpoint().unwrap();
            let head = s.state.superblock.checkpoint_slot;
            assert_ne!(head, NO_RECORD);
            s.file.scrub_slot(head).unwrap();
            s.file.fsync().unwrap();
        }
        test_hooks::set_disable(false);
        test_hooks::reset_hits();
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            test_hooks::hits(),
            0,
            "an unreadable checkpoint must fall back to the full scan"
        );
        for i in 0..N_KEYS {
            assert_eq!(
                s.get(Namespace::SETTINGS, format!("k{i}").as_bytes())
                    .unwrap()
                    .as_deref(),
                Some(format!("v{i}").as_bytes()),
                "key k{i} must survive the fallback"
            );
        }
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    /// Opening through the fast path then vacuuming must scrub exactly
    /// the orphans a full-scan-driven vacuum would (forward secrecy is
    /// not weakened by the reduced scan): the post-vacuum owned-chunk
    /// count is identical via either scan path. Compared on two copies
    /// of the same file so the only difference is the scan.
    #[test]
    fn fast_path_open_drives_complete_vacuum() {
        let path = scratch_path();
        build_with_checkpoint(&path);
        let path_fast = scratch_path();
        let path_full = scratch_path();
        std::fs::copy(&path, &path_fast).unwrap();
        std::fs::copy(&path, &path_full).unwrap();

        let fast_owned = {
            test_hooks::set_disable(false);
            test_hooks::reset_hits();
            let mut c = Container::open(&path_fast).unwrap();
            let s = c.open_space(b"pw").unwrap();
            assert!(test_hooks::hits() >= 1, "fast path must engage");
            s.audit_owned_chunk_count()
        };
        let full_owned = {
            test_hooks::set_disable(true);
            let mut c = Container::open(&path_full).unwrap();
            let s = c.open_space(b"pw").unwrap();
            s.audit_owned_chunk_count()
        };
        test_hooks::set_disable(false);
        assert_eq!(
            fast_owned, full_owned,
            "fast-path-driven vacuum must reclaim the same orphans as full-scan-driven vacuum"
        );
        for p in [&path, &path_fast, &path_full] {
            let _ = std::fs::remove_file(p);
        }
    }

    /// The constant-time open path must NOT engage the fast path — and must
    /// still return all data.
    ///
    /// This test previously asserted the opposite, and that was the bug: the
    /// selective scan visits a working set instead of every slot, so its
    /// duration is a function of what the space CONTAINS. A correct password
    /// then finishes quickly while a wrong one pays the full O(total) scan,
    /// and an observer of unlock wall-clock learns both that something opened
    /// and roughly how much is in it. Equalising per-chunk work cannot fix a
    /// signal carried by the NUMBER of chunks visited.
    ///
    /// That trade is fine on the default path, where speed is the point.
    /// `open_space_constant_time` is the opt-in API whose published contract
    /// is that the host's timing "can't leak which space (or none) matched",
    /// and whose docs already warn it roughly doubles open time — its callers
    /// bought equal timing and were being handed back the speed instead.
    #[test]
    fn constant_time_open_does_not_engage_the_fast_path() {
        let path = scratch_path();
        build_with_checkpoint(&path);
        test_hooks::set_disable(false);
        test_hooks::reset_hits();
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space_constant_time(b"pw").unwrap();
        assert_eq!(
            test_hooks::hits(),
            0,
            "constant-time open took the checkpoint fast path; its duration \
             now reflects the working set, which is what that API exists to \
             hide"
        );
        for i in 0..N_KEYS {
            let want = if DELETED.contains(&i) {
                None
            } else {
                Some(format!("v{i}").into_bytes())
            };
            assert_eq!(
                s.get(Namespace::SETTINGS, format!("k{i}").as_bytes())
                    .unwrap(),
                want
            );
        }
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    /// A wrong password must NOT engage the fast path (it cannot decrypt
    /// the checkpoint), so it pays a full scan and fails with
    /// AuthFailed — the post-authentication property that keeps the
    /// fast-vs-slow timing from being a password oracle.
    #[test]
    fn wrong_password_does_not_engage_fast_path() {
        let path = scratch_path();
        build_with_checkpoint(&path);
        test_hooks::set_disable(false);
        test_hooks::reset_hits();
        let mut c = Container::open(&path).unwrap();
        let err = c.open_space(b"WRONG").err();
        assert!(matches!(err, Some(crate::Error::AuthFailed)));
        assert_eq!(
            test_hooks::hits(),
            0,
            "a wrong password must never engage the (post-auth) fast path"
        );
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    /// Re-running the self-heal scrubs the chain it supersedes, so the
    /// owned-chunk count does not grow by a whole chain on each refresh.
    #[test]
    fn refresh_scrubs_old_checkpoint_chain() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..N_KEYS {
            let mut tx = s.begin_tx();
            tx.put(
                Namespace::SETTINGS,
                format!("k{i}").as_bytes(),
                format!("v{i}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        s.write_self_heal_checkpoint().unwrap();
        let after_first = s.audit_owned_chunk_count();
        // A second self-heal with no new data appends one fresh chain +
        // replicas and scrubs the old chain, so net growth is small.
        s.write_self_heal_checkpoint().unwrap();
        let after_second = s.audit_owned_chunk_count();
        let replicas = 8usize; // generous upper bound on replica count
        assert!(
            after_second <= after_first + replicas,
            "refresh must scrub the superseded chain (was {after_first}, now {after_second})"
        );
        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
    }

    /// Links from two DIFFERENT checkpoints are refused, not folded into one
    /// recorded state.
    ///
    /// `CheckpointChunk` promises "same value in every chunk of one chain" for
    /// both `cp_seq` and `cp_high_water`; only the second was ever enforced,
    /// and the fix that added the first shipped saying it had no test, because
    /// reaching the reader "needs a real container with a multi-chunk chain and
    /// then a forged link, which nothing in the suite builds".
    ///
    /// It does not need the writer. `place_chunk` takes the authenticated seq
    /// and `CheckpointChunk` carries `next_slot`, so a chain can be laid down
    /// link by link with whatever seq each one claims — which is exactly the
    /// faulty-or-key-holding writer this guard is aimed at. AEAD keeps everyone
    /// else out.
    #[test]
    fn a_chain_whose_links_disagree_about_their_checkpoint_is_refused() {
        const SEQ_A: u64 = 41;
        const SEQ_B: u64 = 42;

        // Two links laid down by hand, differing ONLY in the checkpoint they
        // claim; `head` points at `tail`, so a reader that does not compare
        // the field walks both and folds two eras together.
        fn lay_chain(s: &mut crate::space::Space<'_>, head_seq: u64, tail_seq: u64) -> (u64, u64) {
            let hw = s.file.slot_count();
            let tail = CheckpointChunk {
                cp_seq: tail_seq,
                cp_high_water: hw,
                next_slot: NO_RECORD,
                owned: vec![1],
                pool: Vec::new(),
            };
            let tail_slot = s
                .place_chunk(ChunkKind::Checkpoint, tail_seq, &tail.encode().unwrap())
                .unwrap();
            let head = CheckpointChunk {
                cp_seq: head_seq,
                cp_high_water: hw,
                next_slot: tail_slot,
                owned: vec![2],
                pool: Vec::new(),
            };
            let head_slot = s
                .place_chunk(ChunkKind::Checkpoint, head_seq, &head.encode().unwrap())
                .unwrap();
            // AFTER placing: the reader refuses any hop at or past `total`, and
            // these chunks were appended beyond the count taken above.
            (head_slot, s.file.slot_count())
        }

        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..8u32 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }

        let keys = s.state.keys.clone();
        let container_id = s.state.keys.container_id;

        // Vacuity guard FIRST: the same shape with ONE checkpoint must be
        // accepted, or the refusal below is about the fixture rather than the
        // disagreement.
        let (agreeing_head, total) = lay_chain(&mut s, SEQ_A, SEQ_A);
        let agreed = crate::open::read_checkpoint_chain(
            s.file,
            &keys,
            &container_id,
            agreeing_head,
            total,
            None,
            false,
        )
        .unwrap();
        assert!(
            agreed.is_some(),
            "a two-link chain that agrees about its checkpoint must be read, \
             or this test proves nothing about the disagreement"
        );

        let (forged_head, total) = lay_chain(&mut s, SEQ_A, SEQ_B);
        let forged = crate::open::read_checkpoint_chain(
            s.file,
            &keys,
            &container_id,
            forged_head,
            total,
            None,
            false,
        )
        .unwrap();
        assert!(
            forged.is_none(),
            "links from two different checkpoints were folded into one state"
        );

        drop(s);
        drop(c);
        let _ = std::fs::remove_file(&path);
    }
}
