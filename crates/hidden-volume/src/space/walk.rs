//! Shared traversal guard for every B+ tree walker in this module.
//!
//! A walk follows a list of `(child_slot, child_hash)` pointers decoded
//! out of an `IndexNode` chunk. Nothing in the encoding forces those
//! pointers to be distinct, to point downwards, or to bottom out — the
//! input to a reader is whatever a key-holder (or a writer-bug
//! regression) put on the disk, and every shape below is AEAD-valid and
//! Merkle-consistent. The guard is what makes each of them a named,
//! bounded failure rather than unbounded work:
//!
//! - **A DAG.** An `InternalNode` whose ~90 children all name the
//!   *same* next `InternalNode`. Without `visited` a 4-level fan-out
//!   costs `90³ ≈ 7.3 × 10⁵` chunk reads (an AEAD-decrypt plus a
//!   BLAKE3 each) out of four distinct chunks — an amplification DoS
//!   from a container of a few KiB.
//! - **A cycle.** A node reachable from itself: unbounded work from a
//!   finite container.
//! - **A chain.** `Internal → Internal → …`, one child each, as deep as
//!   the container has chunks. Every walker here recurses, so unbounded
//!   depth is a stack overflow — an abort, not an error.
//!
//! ## The three halves of the guard
//!
//! - **`visited`** makes the DAG (and the cycle, which is a DAG that
//!   closes) a named failure instead of quiet work. A well-formed index
//!   *is* a tree: each chunk is reachable by exactly one path, from
//!   exactly one parent, in exactly one namespace. So a second visit to
//!   a slot is a structural violation to report, not a duplicate to
//!   silently skip. This also covers the narrower "two children of one
//!   node share a `child_slot`" case without a separate per-node check.
//!   A slot at or past the file's own slot count is refused here too:
//!   the reader would refuse the same pointer a line later
//!   (`ContainerFile::read_slot`), and refusing it in the guard is what
//!   lets the set be an array indexed by slot — see below.
//! - **`budget`** bounds total chunk reads independently of the shape
//!   of the input, so the walk stays finite even if a future refactor
//!   loosens the visited check. The ceiling is the number of chunks
//!   the space owns ([`super::SpaceState::owned_slots`]): every chunk
//!   a walker can legitimately read decrypts under this space's key,
//!   and the open scan enumerates every such slot (a container whose
//!   slot count exceeds [`crate::MAX_OPEN_SCAN_CHUNKS`] is rejected at
//!   open, so the enumeration is never truncated). A walk that wants
//!   to read more chunks than the space owns is asking for a chunk
//!   that is not there.
//! - **`max_depth`** bounds recursion, which the budget alone does not:
//!   16 M chunks of budget is 16 M stack frames. It is *derived* from
//!   the budget rather than fixed — see [`max_depth_for_budget`].
//!
//! ## Why the depth bound is derived and not a constant
//!
//! It used to be `MAX_TREE_DEPTH = 3`, back when the writer emitted at
//! most one Internal node over a row of Leaves. That constant was also
//! the namespace's capacity ceiling: ~79 entries of 2 KiB values, and
//! `Error::IndexFull` past it. The writer now grows a new level
//! whenever the level below outgrows a single chunk, so there is no
//! constant to pick that does not re-impose a ceiling somewhere.
//!
//! The bound honest data actually obeys is the container's own: a
//! namespace cannot be deeper than the chunks it is made of. Each
//! level of a well-formed tree is at least
//! [`super::index::MIN_FULL_INTERNAL_FANOUT`] times wider than the one
//! above it, so a tree of depth `d` costs at least
//! `1 + Σₖ₌₁..d (fanout^(k-1) + 1)` chunks. Inverting that against the
//! chunks a space owns gives the deepest tree that space *could* hold —
//! honest data is never refused, and an attacker gains nothing, because
//! reaching depth `d` costs them the same chunks it would cost anyone.
//! At the largest container the format allows (`MAX_OPEN_SCAN_CHUNKS`,
//! 16 M chunks / 64 GiB) that bound is 12.
//!
//! **The fanout is a floor the writer enforces, not a statistic
//! (audit HV-16).** Node boundaries are content-defined: an internal
//! node ends where one of its children's boundary hashes says so, which
//! is what makes a tree's shape independent of the order it was built
//! in. That gives ~40–70 children per node on average and *no* lower
//! bound on its own — a key-holder choosing keys whose hashes all fire
//! would get one-child nodes and arbitrary depth from a handful of
//! chunks. So the writer refuses to honour a boundary before
//! [`super::index::MIN_INTERNAL_CHILDREN`] children
//! ([`super::Space::update_tree`]'s sealer, checked again on every
//! seal), and *that* floor — not the average — is what the arithmetic
//! above uses. Trading the old greedy packing's fanout of 12 for a
//! guaranteed 4 moves the bound from 7 descents to 12; both are far
//! below what the recursion or the budget care about.
//!
//! ## What the visited set costs
//!
//! `visited` holds one entry per chunk the walk reads, and the walk can
//! legitimately read every chunk the space owns — a `verify_integrity`
//! or a `vacuum_orphans` over a healthy tree does exactly that. As a
//! `HashSet<u64>` that measured 18.9 bytes per member live and 28.3 at
//! the rehash that gets there (hashbrown rounds up to a power of two
//! buckets of nine bytes each), so a walk of a container at the
//! format's ceiling — [`crate::MAX_OPEN_SCAN_CHUNKS`], 16 M chunks —
//! held 302 MiB and peaked at 453. The workspace builds with
//! `panic = "abort"`, so failing to allocate that is not an error a
//! host app can report; it is the process going away on the open path,
//! for a container the format explicitly permits (audit HV13-M1).
//!
//! Slot indices are dense and bounded by the file, so the same
//! membership is one bit per slot — 2 MiB at that ceiling, whatever the
//! walk reads. That is [`super::slots::DenseSlotSet`], which the vacuum
//! already used for its own slot sets.
//!
//! **Why the set is not dense from the first slot.** A bitmap costs
//! `slot_count / 8` bytes whether it holds one member or all of them,
//! and most walks are small: `Space::get` descends to a leaf and reads
//! at most `max_depth + 1` chunks, and each one builds its own guard. A
//! set that was dense from the start would hand every point read on a
//! 64 GiB container a 2 MiB allocation to record thirteen slots — the
//! trade-off that left this set hashed when audit HV-03 shrank the
//! vacuum's. So it stays hashed while it is small and switches once, at
//! [`dense_threshold`], where the two representations cost about the
//! same. Small walks keep the allocation they had; a full walk is
//! bounded by the file rather than by its own length.
//!
//! ## Scope
//!
//! One `TreeWalk` covers one logical traversal, which may span several
//! namespace roots — `verify_integrity` walks every root under a
//! single guard, and `vacuum_orphans` collects the reachable set of
//! every root under a single guard. Roots of different namespaces
//! never share chunks (each `IndexNode` carries its namespace byte and
//! the readers cross-check it), so sharing one visited set across
//! roots is both safe and stricter than one set per root.

use std::collections::HashSet;

use crate::{Error, Result};

use super::slots::DenseSlotSet;

/// The deepest B+ tree a space owning `budget` chunks can hold.
///
/// Counts the minimum chunks each additional level costs and stops at
/// the last level that still fits. With
/// [`super::index::MIN_FULL_INTERNAL_FANOUT`] = 4 and the format's
/// 16 M-chunk ceiling the sequence is 3, 8, 25, 90, 347, 1 372, 5 469,
/// 21 854, 87 391, 349 536, 1 398 113, 5 592 418 chunks for depths
/// 1..12, so 12 is the deepest tree the format can express at all.
///
/// **Why the minimum is what it is.** Level 1 holds ≥ 2 nodes — with
/// one node the writer would have stopped there and made *it* the
/// root. Level `k+1` holds ≥ `fanout × (mₖ - 1) + 1` nodes, since every
/// node of level `k` but the last holds at least `fanout` children. By
/// induction level `k` holds at least `fanout^(k-1) + 1` nodes, and the
/// tree at least `1 + Σₖ₌₁..d (fanout^(k-1) + 1)` of them — every one a
/// distinct chunk the space owns.
///
/// Saturating throughout: `budget` is a `usize` read off a container,
/// and the running products exceed `u64` well before the loop would
/// otherwise stop.
pub(in crate::space) fn max_depth_for_budget(budget: usize) -> u8 {
    let fanout = super::index::MIN_FULL_INTERNAL_FANOUT as u128;
    let budget = budget as u128;
    // The root alone: a single Leaf, depth 0.
    let mut min_chunks: u128 = 1;
    // Nodes level 1 must hold; ×fanout for each level below it.
    let mut min_level: u128 = 1;
    let mut depth: u8 = 0;
    loop {
        // One more level admits at least `min_level + 1` more nodes
        // (the +1 for the last, possibly-underfull node of the level).
        let with_level = min_chunks.saturating_add(min_level).saturating_add(1);
        if with_level > budget || depth == u8::MAX {
            return depth;
        }
        min_chunks = with_level;
        min_level = min_level.saturating_mul(fanout);
        depth += 1;
    }
}

/// One hashed member per this many slots of file is where
/// [`TreeWalk`]'s visited set stops hashing and starts indexing.
///
/// At the switch the hashed set holds `slot_count / 512` members of 18.9
/// bytes, which is 37 % of the `slot_count / 8` bytes the bitmap will
/// cost — both are live for the length of the copy, so the peak of the
/// switch is 1.4 bitmaps, and everything after it is exactly one. Any
/// walk that never reaches the ratio never allocates a bitmap at all,
/// which is every point read and every bounded page of leaves.
const SLOTS_PER_HASHED_MEMBER: u64 = 512;

/// Floor under that ratio, so a small container does not switch on its
/// second chunk. Below this many members the question is moot in both
/// directions — 32 hashed slots is under a kilobyte, and the bitmap of a
/// file small enough to make 32 the binding number is under 64 bytes.
const MIN_HASHED_SLOTS: usize = 32;

/// How many slots a walk over a `slot_count`-slot file may hash before
/// the bitmap is the cheaper of the two.
fn dense_threshold(slot_count: u64) -> usize {
    ((slot_count / SLOTS_PER_HASHED_MEMBER) as usize).max(MIN_HASHED_SLOTS)
}

/// The visited set in whichever of its two shapes currently fits.
///
/// See the module docs: hashed while the walk is small, one bit per slot
/// of file once it is not.
enum Visited {
    Hashed(HashSet<u64>),
    Dense(DenseSlotSet),
}

impl Visited {
    fn contains(&self, slot: u64) -> bool {
        match self {
            Visited::Hashed(h) => h.contains(&slot),
            Visited::Dense(d) => d.contains(slot),
        }
    }

    /// Record `slot`, which the caller has already checked is below
    /// `capacity`, switching representation once the hashed set reaches
    /// `promote_at`. Returns whether it was newly recorded.
    fn insert(&mut self, slot: u64, capacity: u64, promote_at: usize) -> bool {
        match self {
            Visited::Hashed(h) => {
                if !h.insert(slot) {
                    return false;
                }
                if h.len() >= promote_at {
                    let mut dense = DenseSlotSet::with_capacity(capacity);
                    for s in h.iter() {
                        // In range by the caller's check, so every
                        // member carries over — a dropped one would be a
                        // chunk the walk could then read twice.
                        debug_assert!(*s < capacity);
                        dense.insert(*s);
                    }
                    *self = Visited::Dense(dense);
                }
                true
            },
            Visited::Dense(d) => {
                if d.contains(slot) {
                    return false;
                }
                d.insert(slot);
                true
            },
        }
    }
}

/// Per-traversal guard: which slots this walk has already read, how
/// many reads it has left, and how deep it may descend. See the module
/// docs for why all three are needed.
pub(super) struct TreeWalk {
    visited: Visited,
    /// The file's slot count: the first slot index no chunk can have,
    /// and the width of the bitmap `visited` switches to.
    capacity: u64,
    /// Hashed members at which that switch happens.
    promote_at: usize,
    budget: usize,
    max_depth: u8,
}

impl TreeWalk {
    /// New guard permitting at most `budget` distinct chunk reads, none
    /// of them at or past `slot_count`, and a descent no deeper than
    /// `budget` chunks could hold. Callers pass the space's owned-chunk
    /// count and its file's slot count
    /// ([`super::Space::new_tree_walk`]).
    pub(super) fn new(budget: usize, slot_count: u64) -> Self {
        Self {
            visited: Visited::Hashed(HashSet::new()),
            capacity: slot_count,
            promote_at: dense_threshold(slot_count),
            budget,
            max_depth: max_depth_for_budget(budget),
        }
    }

    /// Admit `slot`, reached after `depth` descents from the root, into
    /// this walk. Violations are reported through [`Error::Malformed`]
    /// — the shape the non-verify walkers (`collect_leaves`,
    /// `count_leaves`, the `log_iter` family,
    /// `collect_tree_chunks_into_set`) already use for structural
    /// rejects.
    pub(super) fn admit(&mut self, slot: u64, depth: u8) -> Result<()> {
        self.check(slot, depth).map_err(Error::Malformed)
    }

    /// Admit `slot` into this walk, reporting a violation through
    /// [`Error::IntegrityFailure`] — the integrity walk's contract is
    /// that a structural problem names the slot it was found at.
    pub(super) fn admit_for_verify(&mut self, slot: u64, depth: u8) -> Result<()> {
        self.check(slot, depth)
            .map_err(|detail| Error::IntegrityFailure { detail, slot })
    }

    /// Whether this walk has already read `slot`.
    ///
    /// The visited set is a reachability record as much as a guard, and
    /// [`super::Space::vacuum_orphans`] reads it as one: after walking
    /// every namespace root, "admitted" and "reachable from the current
    /// commit" name the same slots, so the vacuum asks here instead of
    /// building a second set beside this one (audit HV-03).
    pub(super) fn has_visited(&self, slot: u64) -> bool {
        self.visited.contains(slot)
    }

    /// Bytes the visited set holds on the heap. Hashed capacity is
    /// hashbrown's own layout — buckets, at `size_of::<u64>()` plus one
    /// control byte each, at the 7/8 load factor `capacity()` reports
    /// against.
    #[cfg(test)]
    fn visited_heap_bytes(&self) -> usize {
        match &self.visited {
            Visited::Hashed(h) => h.capacity() * (std::mem::size_of::<u64>() + 1) * 8 / 7,
            Visited::Dense(d) => d.heap_bytes(),
        }
    }

    fn check(&mut self, slot: u64, depth: u8) -> std::result::Result<(), &'static str> {
        if depth > self.max_depth {
            return Err("tree deeper than this space's chunk count can hold");
        }
        if self.budget == 0 {
            return Err("tree walk exceeded its traversal budget");
        }
        // Ahead of the read that would refuse it anyway, because the
        // visited set is indexed by slot and cannot hold what the file
        // cannot hold.
        if slot >= self.capacity {
            return Err("chunk pointer outside the container");
        }
        self.budget -= 1;
        if !self.visited.insert(slot, self.capacity, self.promote_at) {
            return Err("chunk reachable more than once in one tree walk");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_visit_to_a_slot_is_rejected() {
        let mut w = TreeWalk::new(16, 4096);
        w.admit(7, 0).unwrap();
        w.admit(8, 1).unwrap();
        let err = w.admit(7, 2).unwrap_err();
        assert!(matches!(err, Error::Malformed(d) if d.contains("more than once")));
    }

    #[test]
    fn the_budget_permits_exactly_its_count_then_stops() {
        let mut w = TreeWalk::new(2, 4096);
        w.admit(1, 0).unwrap();
        w.admit(2, 0).unwrap();
        let err = w.admit(3, 0).unwrap_err();
        assert!(matches!(err, Error::Malformed(d) if d.contains("traversal budget")));
    }

    /// A zero budget is what an empty space would hand out; it must not
    /// admit a first read rather than underflowing to `usize::MAX`.
    #[test]
    fn a_zero_budget_admits_nothing() {
        let mut w = TreeWalk::new(0, 4096);
        assert!(w.admit(1, 0).is_err());
        assert!(w.admit(2, 0).is_err());
    }

    /// The verify variant reports the same violations through the
    /// integrity error shape, naming the offending slot.
    #[test]
    fn the_verify_variant_names_the_slot() {
        let mut w = TreeWalk::new(4, 4096);
        w.admit_for_verify(9, 0).unwrap();
        let err = w.admit_for_verify(9, 0).unwrap_err();
        match err {
            Error::IntegrityFailure { detail, slot } => {
                assert_eq!(slot, 9);
                assert!(detail.contains("more than once"));
            },
            other => panic!("expected IntegrityFailure, got {other:?}"),
        }
    }

    /// The depth bound tracks the budget: a walk cannot descend deeper
    /// than the chunks it is allowed to read could possibly be arranged
    /// into. Distinct slots and spare budget do not buy extra depth.
    #[test]
    fn depth_is_bounded_by_what_the_budget_could_hold() {
        // 3 chunks is exactly a depth-1 tree (root + 2 leaves).
        let mut w = TreeWalk::new(3, 4096);
        w.admit(1, 0).unwrap();
        w.admit(2, 1).unwrap();
        let err = w.admit(3, 2).unwrap_err();
        assert!(
            matches!(err, Error::Malformed(d) if d.contains("deeper than")),
            "a 3-chunk space cannot hold a depth-2 tree"
        );
    }

    /// The other side of the same coin: enough chunks, and the walk is
    /// allowed down. Nothing but the budget decides this.
    #[test]
    fn a_bigger_budget_buys_the_depth_it_pays_for() {
        let mut w = TreeWalk::new(16, 4096);
        for depth in 0..=2 {
            w.admit(depth as u64 + 100, depth).unwrap();
        }
        let err = w.admit(200, 3).unwrap_err();
        assert!(matches!(err, Error::Malformed(d) if d.contains("deeper than")));
    }

    /// A child pointer naming a slot the file does not have is a
    /// structural failure, not a read to attempt. `ContainerFile` says
    /// the same thing one line later; saying it here is what lets the
    /// visited set be indexed by slot.
    #[test]
    fn a_pointer_past_the_end_of_the_file_is_refused() {
        let mut w = TreeWalk::new(64, 64);
        let err = w.admit(64, 0).unwrap_err();
        assert!(matches!(err, Error::Malformed(d) if d.contains("outside the container")));
        // The last slot the file DOES have is still admitted.
        w.admit(63, 0).unwrap();

        let mut v = TreeWalk::new(64, 64);
        match v.admit_for_verify(u64::MAX, 0).unwrap_err() {
            Error::IntegrityFailure { detail, slot } => {
                assert_eq!(slot, u64::MAX);
                assert!(detail.contains("outside the container"));
            },
            other => panic!("expected IntegrityFailure, got {other:?}"),
        }
    }

    /// The visited set's footprint is a function of the CONTAINER, not
    /// of the walk (audit HV13-M1). A `verify_integrity` or an
    /// auto-`vacuum_orphans` over a healthy tree reads every chunk the
    /// space owns, and at the format's ceiling a hashed `u64` each
    /// measured 18.9 bytes live — 302 MiB, peaking at 453 through the
    /// rehash — under `panic = "abort"`, on the open path.
    #[test]
    fn the_visited_set_is_sized_by_the_file_not_by_the_walk() {
        let slots = crate::MAX_OPEN_SCAN_CHUNKS;
        let promote_at = dense_threshold(slots) as u64;
        let mut w = TreeWalk::new(slots as usize, slots);
        for slot in 0..promote_at * 4 {
            w.admit(slot, 0).unwrap();
        }
        let bytes = w.visited_heap_bytes();
        assert_eq!(
            bytes,
            (slots / 8) as usize,
            "one bit per slot of file and nothing else"
        );
        // Four times the chunks again, and not one byte more.
        for slot in promote_at * 4..promote_at * 16 {
            w.admit(slot, 0).unwrap();
        }
        assert_eq!(w.visited_heap_bytes(), bytes);

        // Measured against the system allocator, `HashSet<u64>` held
        // this many bytes per member once it had stopped rehashing.
        const HASHED_BYTES_PER_MEMBER: usize = 18;
        assert!(
            bytes * 100 < HASHED_BYTES_PER_MEMBER * slots as usize,
            "a full walk of a {slots}-slot container holds {bytes} bytes; \
             hashed it would be {}",
            HASHED_BYTES_PER_MEMBER * slots as usize
        );
    }

    /// The other side of the same trade. `Space::get` builds a guard to
    /// read one chunk per level of the tree and throws it away, so a set
    /// that was dense from the first slot would charge every point read
    /// on a 64 GiB container 2 MiB to record thirteen slots.
    #[test]
    fn a_point_read_does_not_allocate_the_container() {
        let slots = crate::MAX_OPEN_SCAN_CHUNKS;
        let mut w = TreeWalk::new(slots as usize, slots);
        for depth in 0..=max_depth_for_budget(slots as usize) {
            w.admit(u64::from(depth) + 1, depth).unwrap();
        }
        let bytes = w.visited_heap_bytes();
        assert!(
            bytes < 1024,
            "a descent of {} chunks held {bytes} bytes; this container's \
             bitmap is {}",
            max_depth_for_budget(slots as usize) + 1,
            slots / 8
        );
    }

    /// The switch between the two representations is invisible to every
    /// caller: a slot dropped on the way across is a chunk the walk
    /// would then happily read a second time.
    #[test]
    fn the_switch_to_a_bitmap_keeps_every_slot_it_had() {
        // Small enough that the floor is the binding threshold, so the
        // switch lands inside a walk this test can enumerate.
        let slots: u64 = 4096;
        let promote_at = dense_threshold(slots) as u64;
        assert_eq!(promote_at, MIN_HASHED_SLOTS as u64);

        let mut w = TreeWalk::new(slots as usize, slots);
        for slot in 0..promote_at + 8 {
            w.admit(slot, 0).unwrap();
        }
        assert!(
            matches!(w.visited, Visited::Dense(_)),
            "{} admitted slots should have crossed the {promote_at}-slot threshold",
            promote_at + 8
        );
        for slot in 0..promote_at + 8 {
            assert!(w.has_visited(slot), "slot {slot} was lost in the switch");
            let err = w.admit(slot, 0).unwrap_err();
            assert!(
                matches!(err, Error::Malformed(d) if d.contains("more than once")),
                "slot {slot} was admitted twice"
            );
        }
    }

    /// The threshold tracks the file: one hashed member per 512 slots,
    /// with a floor small containers sit under.
    #[test]
    fn the_threshold_follows_the_file_size() {
        assert_eq!(dense_threshold(0), MIN_HASHED_SLOTS);
        assert_eq!(
            dense_threshold(512 * MIN_HASHED_SLOTS as u64),
            MIN_HASHED_SLOTS
        );
        assert_eq!(dense_threshold(1 << 20), (1 << 20) / 512);
        // At the switch the hashed set is a fraction of the bitmap it
        // makes way for, so the peak of the switch is not a multiple of
        // the steady state.
        let slots = crate::MAX_OPEN_SCAN_CHUNKS;
        let hashed_at_switch = dense_threshold(slots) * 28;
        assert!(
            hashed_at_switch < (slots / 8) as usize,
            "the hashed set costs {hashed_at_switch} bytes at the switch, \
             over the {} the bitmap costs",
            slots / 8
        );
    }

    /// The minimum-chunks sequence the doc comment claims, checked
    /// against the function on both sides of every step. A regression
    /// here means either honest containers get refused (bound too low)
    /// or a hostile chain gets more stack frames than it should.
    #[test]
    fn the_depth_bound_matches_the_minimum_tree_that_fits() {
        // depth -> minimum chunks, per `1 + Σ (fanout^(k-1) + 1)` with
        // MIN_FULL_INTERNAL_FANOUT = 4.
        let steps: [(u8, usize); 12] = [
            (1, 3),
            (2, 8),
            (3, 25),
            (4, 90),
            (5, 347),
            (6, 1_372),
            (7, 5_469),
            (8, 21_854),
            (9, 87_391),
            (10, 349_536),
            (11, 1_398_113),
            (12, 5_592_418),
        ];
        assert_eq!(max_depth_for_budget(0), 0);
        assert_eq!(max_depth_for_budget(1), 0);
        for (depth, min_chunks) in steps {
            assert_eq!(
                max_depth_for_budget(min_chunks),
                depth,
                "{min_chunks} chunks is exactly a depth-{depth} tree"
            );
            assert_eq!(
                max_depth_for_budget(min_chunks - 1),
                depth - 1,
                "one chunk short of a depth-{depth} tree"
            );
        }
        // The largest container the format permits.
        assert_eq!(
            max_depth_for_budget(crate::MAX_OPEN_SCAN_CHUNKS as usize),
            12,
            "64 GiB of container is a depth-12 tree at the very most"
        );
        // And no input can make it unbounded: even a budget no container
        // could reach stays inside what the recursion can pay for.
        assert!(max_depth_for_budget(usize::MAX) < 40);
    }
}
