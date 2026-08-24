//! The decoy pool: the slots this space is allowed to rewrite.
//!
//! ## Why a pool, and not "any garbage-looking slot"
//!
//! A writer of space A cannot tell a garbage chunk from space B's live
//! chunk — that indistinguishability is the product (DESIGN §9). So
//! "re-randomize the garbage" is not an operation this format can
//! express: every slot A did not write is a slot A must not touch.
//!
//! What A *can* prove it owns and has retired is exactly two things:
//!
//! 1. slots A scrubbed — orphan `IndexNode` / `DataBatch` chunks
//!    reclaimed by [`Space::vacuum_orphans`][crate::Space::vacuum_orphans]
//!    / [`vacuum_data_batches`][crate::Space::vacuum_data_batches], and
//!    superseded checkpoint chains;
//! 2. garbage A itself appended as post-commit padding, whose slot range
//!    A knows at the moment it writes it.
//!
//! Their union is the **decoy pool**. Every slot in it is dead by
//! construction, so both operations the churn design needs — allocate a
//! real chunk into it, or re-randomize it — are safe, and are safe for
//! the same reason.
//!
//! ## The pool is a hint; ownership is the authority
//!
//! The pool is persisted in the checkpoint chain (see
//! [`super::checkpoint`]), which is refreshed lazily. A recorded pool can
//! therefore be *stale* — it may still name a slot that a later commit
//! has already reused. That is not a hazard, because the open path
//! subtracts the scan's answer:
//!
//! ```text
//! pool_effective = pool_recorded \ owned_slots
//! ```
//!
//! A reused slot is AEAD-decryptable under this space's key again, so it
//! is *owned*, so it leaves the pool automatically. The recorded pool is
//! allowed to under-report (the cost is leaked disk, reclaimed by the
//! next `compact_known`) and cannot over-report for an honest writer,
//! since only this space's own scrubs and paddings ever enter it.
//!
//! Cross-space disjointness holds by construction: a slot enters A's pool
//! only by A scrubbing a slot A owned, or by A appending padding past the
//! end of the file. Neither can name a slot another space ever wrote.
//!
//! ## Uniform draws, deliberately
//!
//! Both users of the pool draw **uniformly at random** — allocation via
//! [`DecoyPool::take`], churn via [`DecoyPool::sample_distinct`]. This is
//! not incidental: it is what makes the two indistinguishable. A FIFO or
//! lowest-index-first allocator would give real writes an index-locality
//! signature that a uniformly-drawn churn does not share, and the
//! adversary would separate them by *where* rather than by *how often*.
//! See DESIGN §9.1.
//!
//! ## One bit per slot, for the same reason `SlotSet` is
//!
//! A `Vec<u64>` of retired slots costs 8 bytes per retired slot, and a
//! heavy-delete container retires most of itself: at
//! [`crate::MAX_OPEN_SCAN_CHUNKS`] that is 128 MiB of pool, live for the
//! whole session, on a phone. The audit-HV-03 argument against exactly
//! this shape in `vacuum_orphans` applies here word for word — a pool
//! that cannot be allocated is a container that cannot be opened, with
//! no adversary involved — and the `vacuum_peak_does_not_scale_with_the_
//! owned_slot_count` regression test caught the `Vec` version of this
//! module. One bit per slot is 2 MiB at that same ceiling.

use crate::Result;

/// Slots this space may rewrite, as a bitmap over slot indices.
///
/// The bitmap grows on demand: the pool is seeded at open from the
/// checkpoint (so its capacity starts at the file's slot count) and then
/// takes padding slots appended during the session, which sit past it.
#[derive(Debug, Default, Clone)]
pub(crate) struct DecoyPool {
    words: Vec<u64>,
    len: usize,
    /// Membership changes since the pool was last written to a
    /// checkpoint. See [`Self::drift`].
    drift: u64,
}

impl DecoyPool {
    /// Build from a recorded list, dropping anything at or past `total`
    /// (a pool entry always names a slot that exists). Duplicates
    /// collapse for free — this is a set.
    ///
    /// The bitmap is sized from the entries that survive the filter, not
    /// from `total`. `total` is a bound on what may be *recorded*, and
    /// callers with no pool to recover pass `u64::MAX` to mean "no
    /// filter" — sizing on it allocated 2 EiB and aborted the process
    /// (every `hv` CLI test died on it, which is how this is here in
    /// words rather than in a bug report).
    #[cfg(test)]
    pub(crate) fn from_recorded(slots: Vec<u64>, total: u64) -> Self {
        let mut p = Self::default();
        for s in slots {
            if s < total {
                p.set(s);
            }
        }
        p.drift = 0;
        p
    }

    /// Room for slots `0..capacity` without reallocating, for the reader
    /// that fills the pool one recorded entry at a time.
    ///
    /// `capacity` must already be bounded by the file — see
    /// [`Self::record`]. It is a hint only; [`Self::insert`] still grows past
    /// it for the padding slots a session appends after the open.
    pub(crate) fn with_capacity(capacity: u64) -> Self {
        Self {
            words: vec![0u64; capacity.div_ceil(64) as usize],
            len: 0,
            drift: 0,
        }
    }

    /// Record a slot read off a checkpoint, leaving [`Self::drift`] alone.
    ///
    /// The difference from [`Self::insert`] is the whole point: drift asks
    /// "how far has the pool moved since it was last written down", so
    /// replaying what is written down must answer zero. A recovered pool that
    /// counted its own recovery would make the first open of every container
    /// rewrite the checkpoint it just read.
    pub(crate) fn record(&mut self, slot: u64) {
        self.set(slot);
    }

    /// Ascending iteration over the slots in the pool.
    ///
    /// The bitmap's own order, without the eight-bytes-per-slot `Vec`
    /// [`Self::sorted`] hands the checkpoint encoder.
    pub(crate) fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(w, &word)| super::slots::slots_in_word(w, word))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Drop every slot at or past `high_water`, and every slot in `owned`.
    ///
    /// The filter the checkpoint writer applies before recording, expressed
    /// word-wise on the bitmap so that merging a carried record costs no
    /// second copy of either half.
    pub(crate) fn retain_below_and_unowned(
        &mut self,
        high_water: u64,
        owned: &super::slots::OwnedSet,
    ) {
        let mut len = 0usize;
        for (w, word) in self.words.iter_mut().enumerate() {
            // The owned set is grown by `place_chunk` as the file does, so it
            // can be WIDER than the pool as well as narrower; `word` answers
            // zero past its end rather than panicking.
            let mut kept = *word & !owned.word(w);
            let base = (w as u64) * 64;
            if base + 64 > high_water {
                let cutoff = high_water.saturating_sub(base);
                kept &= if cutoff >= 64 {
                    u64::MAX
                } else {
                    (1u64 << cutoff) - 1
                };
            }
            *word = kept;
            len += kept.count_ones() as usize;
        }
        self.len = len;
    }

    /// How many slots have entered or left since the last
    /// [`Self::clear_drift`] — the checkpoint writer's refresh signal.
    ///
    /// Size alone will not do. Reuse consumes and vacuum replenishes, so a
    /// pool can turn over completely and come back to the same length; a
    /// checkpoint refreshed on length would then persist an ever-staler
    /// membership. It costs nothing to be exact here.
    pub(crate) fn drift(&self) -> u64 {
        self.drift
    }

    pub(crate) fn clear_drift(&mut self) {
        self.drift = 0;
    }

    /// Number of slots currently in the pool. This is the anonymity set
    /// for a reused slot — see DESIGN §9.1.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Record `slot` as retired. Idempotent; grows the bitmap as needed.
    pub(crate) fn insert(&mut self, slot: u64) {
        if self.set(slot) {
            self.drift = self.drift.saturating_add(1);
        }
    }

    /// Drop every slot in `owned` from the pool.
    ///
    /// This is the correction that makes a stale recorded pool safe: a
    /// slot that decrypts under our key is live-or-orphaned data, not a
    /// decoy, whatever the checkpoint said. Called once at open, with the
    /// scan's authoritative owned set.
    pub(crate) fn subtract_owned(&mut self, owned: &super::slots::OwnedSet) {
        for s in owned.iter() {
            self.clear(s);
        }
    }

    /// The pool's slots, sorted ascending — the form the checkpoint
    /// records. O(capacity); called once per checkpoint write.
    pub(crate) fn sorted(&self) -> Vec<u64> {
        let mut out = Vec::with_capacity(self.len);
        for (w, &word) in self.words.iter().enumerate() {
            let mut word = word;
            while word != 0 {
                let bit = word.trailing_zeros() as u64;
                out.push(w as u64 * 64 + bit);
                word &= word - 1;
            }
        }
        out
    }

    /// Remove and return a uniformly-drawn slot, or `None` when empty.
    pub(crate) fn take(&mut self) -> Result<Option<u64>> {
        if self.len == 0 {
            return Ok(None);
        }
        let rank = uniform_below(self.len)?;
        let slot = self.select(rank).expect("rank < len");
        self.clear(slot);
        self.drift = self.drift.saturating_add(1);
        Ok(Some(slot))
    }

    /// Up to `n` **distinct** uniformly-drawn slots, left in the pool.
    ///
    /// The churn's victim picker, and distinct is the load-bearing word.
    /// Drawing with replacement looks fair and is not: two draws that
    /// land on one offset produce ONE changed offset in a snapshot diff,
    /// so a churn asked for `k` victims would deliver fewer than `k`
    /// whenever the pool is small — precisely when the anonymity set is
    /// already thin. The reuse it is meant to balance never repeats,
    /// because [`Self::take`] removes.
    ///
    /// Partial Fisher-Yates over the drawn prefix, undone by restoring
    /// the bits, so pool membership and [`Self::drift`] are unchanged:
    /// churn retires nothing.
    pub(crate) fn sample_distinct(&mut self, n: usize) -> Result<Vec<u64>> {
        let k = n.min(self.len);
        let mut out = Vec::with_capacity(k);
        // The failure is REMEMBERED rather than returned, because a `?` here
        // would return between the clearing and the restoring below — and the
        // slots drawn so far would stay cleared. Gone from `len`, never
        // allocated, never churned: decoys that stop existing because a draw
        // failed, which is the anonymity set shrinking for a reason nothing
        // reports. The pool is also what the reuse budget is computed from.
        let mut failure = None;
        for _ in 0..k {
            match uniform_below(self.len) {
                Ok(rank) => {
                    let slot = self.select(rank).expect("rank < len");
                    self.clear(slot);
                    out.push(slot);
                },
                Err(e) => {
                    failure = Some(e);
                    break;
                },
            }
        }
        for &s in &out {
            self.set(s);
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }

    // --- bitmap internals ---

    /// Set `slot`'s bit, growing the bitmap if it is past the end.
    /// Returns whether the bit was newly set.
    fn set(&mut self, slot: u64) -> bool {
        let w = (slot / 64) as usize;
        if w >= self.words.len() {
            self.words.resize(w + 1, 0);
        }
        let bit = 1u64 << (slot % 64);
        if self.words[w] & bit != 0 {
            return false;
        }
        self.words[w] |= bit;
        self.len += 1;
        true
    }

    fn clear(&mut self, slot: u64) {
        let w = (slot / 64) as usize;
        if w >= self.words.len() {
            return;
        }
        let bit = 1u64 << (slot % 64);
        if self.words[w] & bit != 0 {
            self.words[w] &= !bit;
            self.len -= 1;
        }
    }

    /// The `rank`-th set bit (0-based), or `None` if there are fewer.
    ///
    /// A linear scan from word zero, so a draw costs O(capacity in words) and
    /// not O(pool size) — the cost is set by how WIDE the file is, not by how
    /// much is in the pool. report9 HV-05 reads that as a denial-of-service
    /// surface; it is bounded, and the bound is small enough to leave alone:
    ///
    /// | slots (file size) | per draw | 64 draws |
    /// |---|---|---|
    /// | 100 K (≈400 MiB) | 1.4 µs | 0.09 ms |
    /// | 1 M (≈4 GiB) | 3.2 µs | 0.21 ms |
    /// | 16 M (64 GiB, `MAX_OPEN_SCAN_CHUNKS`) | 40 µs | 2.5 ms |
    ///
    /// Re-measured 2026-08-18 on an Apple-silicon laptop; the previous row of
    /// numbers (2.6 / 6.8 / 84 µs) was about twice these and came from other
    /// hardware. Both are recorded because the ratio between the rows is the
    /// durable part — the cost is linear in the file's WIDTH — and the
    /// absolute microseconds are not.
    ///
    /// Reproduced 2026-08-24 against audit report12 HV-M3, which asks for the
    /// hierarchical index this doc declines: 3.3 µs/draw at 1 M slots,
    /// 9.5 µs at 4 M, 40.7 µs at 16.8 M — the table above, within noise. The
    /// degenerate single transaction it prices (12,500 draws at the hard cap)
    /// came to 508 ms. Run it with
    /// `cargo test -p hidden-volume --release measure_sample_distinct --
    /// --ignored --nocapture`; the decision below is unchanged, and the
    /// measurement is what makes it a decision rather than an assumption.
    ///
    /// Sixty-four draws is one ILLUSTRATIVE commit — one that reuses
    /// thirty-two slots and churns thirty-two. It is not a worst case, and
    /// nothing caps a commit at sixty-four draws. The real bound, traced
    /// through the two call sites that draw:
    ///
    /// - One `select` per chunk placed through [`Self::take`], gated
    ///   by `Space::reuse_budget_available` (`space/mod.rs`), which is
    ///   `pool.len() > state.reuse_floor`.
    /// - `reuse_floor` is re-armed once per commit from
    ///   [`super::reuse_floor_for`] (called at the top of `commit_tx` in
    ///   `space/commit.rs`), i.e. `pool_len - pool_len / (1 + CHURN_PER_REUSE)`.
    /// - Then `reused * CHURN_PER_REUSE` further draws, one `select` each,
    ///   through [`Self::sample_distinct`] — `commit_tx` calls
    ///   `churn_decoys(reused * CHURN_PER_REUSE)` after the placements.
    ///
    /// So, with [`super::CHURN_PER_REUSE`] `= 1`:
    ///
    /// ```text
    /// draws_per_commit = (1 + CHURN_PER_REUSE) * reused = 2 * reused
    /// reused           <= min(pool_len / 2, chunks_placed)
    /// ```
    ///
    /// `pool_len / 2` is integer division: reuse proceeds while
    /// `pool.len() > reuse_floor`, and each `take` drops the length by one,
    /// so a pool of `P` funds exactly `P - reuse_floor_for(P)` = `P / 2`
    /// reuses. `sample_distinct` restores every bit it drew, so churn does
    /// not shrink the pool and does not feed back into the budget.
    ///
    /// The cost therefore scales with the POOL, not with a constant, and
    /// the table above is what to multiply. A realistic container is the
    /// number that matters: 1 GiB at `CHUNK_SIZE` 4096 is 262,144 slots,
    /// between the first two rows (≈3.4 µs/draw interpolated), so the
    /// illustrative 32-reuse/32-churn commit costs about 0.2 ms. Even the
    /// degenerate commit — one that places enough chunks to exhaust the
    /// budget on a pool spanning a container at the hard cap — is priced by
    /// the same 84 µs/draw row, and it takes `pool_len / 2` chunks in ONE
    /// transaction to reach it.
    ///
    /// A hierarchical popcount index would cut that by a factor of sixty, and
    /// it would put a second, derived copy of the membership beside the
    /// bitmap. This is the structure where a wrong answer means the allocator
    /// hands out a LIVE slot — data loss, silently, on the next commit. Two
    /// tenths of a millisecond on a realistic container is not worth that
    /// trade. Re-measure with `measure_select_cost` before revisiting.
    ///
    /// ## What "a large commit holds the lock for seconds" needs
    ///
    /// Raised a second time as report13 HV13-M5, and the arithmetic above is
    /// the answer: at the re-measured 40 µs a whole second of draws is 25,000
    /// of them, so 12,500 reuses, so a single transaction placing 12,500
    /// chunks — about 50 MiB of data in one `commit_tx` — on a container at
    /// the format's 64 GiB hard cap. The same transaction on a 1 GiB
    /// container costs 42 ms. It is bounded, and the bound needs both
    /// extremes at once.
    ///
    /// The three cheaper remedies were considered and refused, each for the
    /// same reason the linear scan is here in the first place:
    ///
    /// - **Cap the draws per commit.** Unbiased in itself — the draws that
    ///   still happen are still uniform — but past the cap the commit appends
    ///   instead, which puts file growth back on exactly the commits reuse
    ///   exists to keep flat. That is a deniability cost paid to save
    ///   milliseconds, and there is no principled place to put the cap.
    /// - **Resume the scan where the last one stopped.** The cursor has to
    ///   carry the cumulative popcount at its position to answer the next
    ///   rank correctly, and every `set` / `clear` below it invalidates that
    ///   number. A stale cursor does not return a slower answer, it returns
    ///   the WRONG slot — a live one. Same hazard as the index above, at a
    ///   fraction of the benefit, since ranks arrive in no order.
    /// - **One-pass sequential sampling in [`Self::sample_distinct`].** This
    ///   one is exactly unbiased over subsets and would halve a commit's draw
    ///   cost. It yields the subset ASCENDING, though, where the reuse half
    ///   writes in placement order — so an observer of the live I/O sequence,
    ///   rather than of two snapshots, would have the reuse/churn
    ///   distinguisher §9.1 exists to deny. Restoring random order costs a
    ///   shuffle, and what is left is a rewrite of the deniability-bearing
    ///   sampler for a factor of two, guarded by tests that pin distinctness
    ///   and coverage but not the distribution.
    fn select(&self, mut rank: usize) -> Option<u64> {
        for (w, &word) in self.words.iter().enumerate() {
            let count = word.count_ones() as usize;
            if rank < count {
                let mut word = word;
                for _ in 0..rank {
                    word &= word - 1; // drop the lowest set bit
                }
                return Some(w as u64 * 64 + word.trailing_zeros() as u64);
            }
            rank -= count;
        }
        None
    }
}

/// A uniform integer in `[0, n)` from the system CSPRNG, `n > 0`.
///
/// Rejection-sampled rather than `% n`. The modulo bias here would be
/// around `n / 2^64` and thus unmeasurable, but the pool's whole job is
/// that the allocator's and the churn's draws come from the *same*
/// distribution, and a biased draw is a distribution with a shape
/// somebody could in principle fit. The expected number of retries is
/// below 2 for every `n`.
fn uniform_below(n: usize) -> Result<usize> {
    debug_assert!(n > 0, "caller must exclude the empty case");
    let n = n as u64;
    // Largest multiple of `n` that fits in u64; draws at or above it
    // would land in the short final bucket.
    let limit = u64::MAX - (u64::MAX % n);
    loop {
        let v = u64::from_le_bytes(crate::crypto::rng::random_array::<8>()?);
        if v < limit {
            return Ok((v % n) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A draw that fails partway must leave the pool exactly as it found it.
    ///
    /// `sample_distinct` clears each drawn bit as its sampling device and puts
    /// every one of them back at the end — churn retires nothing. A `?` on the
    /// CSPRNG used to return between those two halves, so the slots drawn
    /// before the failure stayed cleared: gone from `len`, never handed to the
    /// allocator, never churned again. Decoys that quietly stop existing are
    /// the anonymity set shrinking for a reason nothing reports, and the pool
    /// is also the accounting the reuse budget is computed from.
    ///
    /// Armed at the SECOND fill so at least one draw has already cleared a
    /// bit — otherwise there would be nothing to restore and the assertion
    /// below would hold against the broken version too. With eight slots the
    /// rejection loop in `uniform_below` retries with probability about
    /// 2^-61, so the second fill is the second draw.
    #[test]
    fn a_failed_draw_leaves_the_pool_whole() {
        let slots = vec![1u64, 3, 5, 7, 9, 11, 13, 15];
        let mut p = DecoyPool::from_recorded(slots.clone(), 64);

        // The same call succeeds without the fault, so the failure below is
        // the fault and not the fixture.
        assert_eq!(p.sample_distinct(4).unwrap().len(), 4);
        assert_eq!(p.sorted(), slots, "sampling is not supposed to retire");

        let _fault = crate::crypto::rng::ForcedRngFailure::arm(2);
        let err = p.sample_distinct(4);
        assert!(err.is_err(), "the armed CSPRNG failure never fired");
        assert_eq!(
            p.sorted(),
            slots,
            "a failed draw kept the slots it had already drawn — they are \
             gone from the pool for the life of the container"
        );
        assert_eq!(p.len(), slots.len(), "len disagrees with membership");
    }

    /// What a draw costs at the capacities this format allows — the evidence
    /// behind the table on [`DecoyPool::select`], kept runnable rather than
    /// only written down.
    ///
    /// `#[ignore]`d because it is a measurement and not an assertion: timings
    /// on a shared CI runner make terrible gates, and a flaky red is worse
    /// than a number nobody reads. Run it with
    /// `cargo test -p hidden-volume --release measure_select_cost -- --ignored --nocapture`
    /// before changing the cap, the bitmap, or the draw.
    #[test]
    #[ignore]
    fn measure_select_cost() {
        for (capacity, entries) in [
            (100_000u64, 5_000usize),
            (1_000_000, 20_000),
            (16_000_000, 20_000),
            (16_000_000, 1_000_000),
        ] {
            let step = capacity / entries as u64;
            let slots: Vec<u64> = (0..entries as u64).map(|i| i * step).collect();
            let mut p = DecoyPool::from_recorded(slots, capacity);
            let t = std::time::Instant::now();
            // 64 draws: a commit reusing 32 slots and churning 32.
            let mut sink = 0u64;
            for _ in 0..64 {
                sink ^= p.sample_distinct(1).unwrap()[0];
            }
            let dt = t.elapsed();
            println!(
                "capacity={capacity} entries={entries} words={} 64 draws in {:?} ({:?}/draw) sink={sink}",
                (capacity / 64) as usize,
                dt,
                dt / 64
            );
        }
    }

    /// The checkpoint writer's filter, across word boundaries.
    ///
    /// It is a per-word `AND` with a mask, and both halves have an off-by-one
    /// that only shows up away from word zero: the owned set may be WIDER or
    /// narrower than the pool, and the high-water cuts a word in half at an
    /// arbitrary bit. Every existing caller-level test sits in word 0, where
    /// a wrong `base` and a right one agree.
    #[test]
    fn the_writer_filter_cuts_on_the_right_bit_in_every_word() {
        let mut p = DecoyPool::default();
        for s in [1u64, 63, 64, 127, 128, 200, 255, 256, 4096] {
            p.record(s);
        }
        // High-water inside word 3 (slots 192..256): 200 is above it, 128 and
        // 127 are below. The owned set names one slot in word 1 and one past
        // the end of the pool's own words.
        let owned: crate::space::slots::OwnedSet = [64u64, 1 << 20].into_iter().collect();
        p.retain_below_and_unowned(200, &owned);
        assert_eq!(p.sorted(), vec![1, 63, 127, 128]);
        assert_eq!(p.len(), 4, "len disagrees with membership");
    }

    /// A high-water exactly on a word boundary keeps the last slot below it
    /// and drops the first slot at it — `1u64 << 64` is the shift that would
    /// take the whole mask out.
    #[test]
    fn a_high_water_on_a_word_boundary_keeps_the_slot_below_it() {
        let mut p = DecoyPool::default();
        for s in [63u64, 64, 65] {
            p.record(s);
        }
        p.retain_below_and_unowned(64, &Default::default());
        assert_eq!(p.sorted(), vec![63]);
    }

    #[test]
    fn recorded_entries_past_the_end_are_dropped() {
        let p = DecoyPool::from_recorded(vec![1, 5, 9, 12], 10);
        assert_eq!(p.sorted(), vec![1, 5, 9]);
    }

    #[test]
    fn duplicates_collapse() {
        let mut p = DecoyPool::from_recorded(vec![3, 3, 3, 7], 100);
        assert_eq!(p.sorted(), vec![3, 7]);
        p.insert(3);
        p.insert(11);
        assert_eq!(p.sorted(), vec![3, 7, 11]);
        assert_eq!(p.len(), 3);
    }

    /// A slot appended after the pool was seeded (post-commit padding)
    /// sits past the bitmap's capacity. Dropping it would silently make
    /// every padding chunk unusable as a decoy — the churn's whole
    /// supply.
    #[test]
    fn a_slot_past_the_seeded_capacity_is_kept() {
        let mut p = DecoyPool::from_recorded(vec![1], 8);
        p.insert(4096);
        assert_eq!(p.sorted(), vec![1, 4096]);
        assert_eq!(p.len(), 2);
    }

    /// The correction that makes a stale recorded pool safe.
    #[test]
    fn owned_slots_leave_the_pool() {
        let mut p = DecoyPool::from_recorded(vec![1, 2, 3, 4, 5], 100);
        p.subtract_owned(&[4u64, 2].into_iter().collect());
        assert_eq!(p.sorted(), vec![1, 3, 5]);
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn take_removes_and_sampling_does_not() {
        let mut p = DecoyPool::from_recorded(vec![8], 100);
        assert_eq!(p.sample_distinct(1).unwrap(), vec![8]);
        assert_eq!(p.len(), 1, "sampling must leave the slot in the pool");
        assert_eq!(p.take().unwrap(), Some(8));
        assert_eq!(p.len(), 0);
        assert_eq!(p.take().unwrap(), None);
        assert!(p.sample_distinct(3).unwrap().is_empty());
    }

    /// The churn must dirty `n` DISTINCT offsets, because `n` draws that
    /// collide produce fewer changed offsets than that — and it is
    /// exactly when the pool is small, i.e. when the anonymity set is
    /// already thin, that collisions are likely.
    #[test]
    fn sampling_never_repeats_a_slot() {
        let mut p = DecoyPool::from_recorded(vec![10, 11, 12], 100);
        for _ in 0..500 {
            let got = p.sample_distinct(3).unwrap();
            let uniq: std::collections::BTreeSet<u64> = got.iter().copied().collect();
            assert_eq!(uniq.len(), 3, "sample repeated a slot: {got:?}");
            assert_eq!(p.len(), 3, "sampling changed pool membership");
        }
        // More than the pool holds: capped, still distinct.
        let got = p.sample_distinct(9).unwrap();
        assert_eq!(got.len(), 3);
    }

    /// Every element must be reachable by a draw. A draw that could only
    /// ever return one end of the pool would give reuse an index
    /// signature churn does not share — the exact failure the uniform
    /// draw exists to prevent.
    #[test]
    fn draws_cover_the_whole_pool() {
        let mut p = DecoyPool::from_recorded((0..16).collect(), 100);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..2000 {
            seen.extend(p.sample_distinct(1).unwrap());
        }
        assert_eq!(
            seen.len(),
            16,
            "some pool slots are unreachable by a draw: {seen:?}"
        );
    }

    /// `select` has to walk words and then bits; an off-by-one in either
    /// half silently biases the draw. Checked against the sorted list at
    /// every rank, across a bitmap wide enough to span several words.
    #[test]
    /// MEASUREMENT, not an assertion about speed: what one churn's victim
    /// draw actually costs on a pool the size the report is about. Printed so
    /// the number decides whether a hierarchical rank-select is worth its
    /// invariants.
    #[test]
    #[ignore = "measurement"]
    fn measure_sample_distinct_cost() {
        for &(slots, n) in &[
            (1_000_000u64, 100usize),
            (4_000_000, 1_000),
            (16_777_216, 12_500),
        ] {
            // A pool holding every other slot: half the bitmap set, which is
            // the worst realistic density for a linear scan.
            let recorded: Vec<u64> = (0..slots).step_by(2).collect();
            let mut p = DecoyPool::from_recorded(recorded, slots);
            let t0 = std::time::Instant::now();
            let got = p.sample_distinct(n).unwrap();
            let dt = t0.elapsed();
            println!(
                "MEASURED slots={slots} pool={} draws={n} -> {:?} ({:?}/draw)",
                p.len(),
                dt,
                dt / n as u32,
            );
            assert_eq!(got.len(), n);
        }
    }

    fn select_agrees_with_the_sorted_order() {
        let slots: Vec<u64> = vec![0, 1, 63, 64, 65, 127, 128, 200, 511];
        let p = DecoyPool::from_recorded(slots.clone(), 512);
        for (rank, &want) in slots.iter().enumerate() {
            assert_eq!(p.select(rank), Some(want), "rank {rank}");
        }
        assert_eq!(p.select(slots.len()), None);
    }

    #[test]
    fn uniform_below_stays_in_range() {
        for n in [1usize, 2, 3, 7, 1000] {
            for _ in 0..200 {
                assert!(uniform_below(n).unwrap() < n);
            }
        }
    }
}
