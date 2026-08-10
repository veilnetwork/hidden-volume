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
    /// | 100 K (≈400 MiB) | 2.6 µs | 0.17 ms |
    /// | 1 M (≈4 GiB) | 6.8 µs | 0.43 ms |
    /// | 16 M (64 GiB, `MAX_OPEN_SCAN_CHUNKS`) | 84 µs | 5.4 ms |
    ///
    /// Sixty-four draws is a commit that reuses thirty-two slots and churns
    /// thirty-two. So the worst case this format can be pushed to costs a
    /// commit about five milliseconds, on a container at the hard cap.
    ///
    /// A hierarchical popcount index would cut that by a factor of sixty, and
    /// it would put a second, derived copy of the membership beside the
    /// bitmap. This is the structure where a wrong answer means the allocator
    /// hands out a LIVE slot — data loss, silently, on the next commit. Five
    /// milliseconds on a 64 GiB container is not worth that trade. Re-measure
    /// with `measure_select_cost` before revisiting.
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
