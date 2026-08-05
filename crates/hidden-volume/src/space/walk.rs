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

/// Per-traversal guard: which slots this walk has already read, how
/// many reads it has left, and how deep it may descend. See the module
/// docs for why all three are needed.
pub(super) struct TreeWalk {
    visited: HashSet<u64>,
    budget: usize,
    max_depth: u8,
}

impl TreeWalk {
    /// New guard permitting at most `budget` distinct chunk reads, and
    /// a descent no deeper than that many chunks could hold. Callers
    /// pass the space's owned-chunk count
    /// ([`super::Space::new_tree_walk`]).
    pub(super) fn with_budget(budget: usize) -> Self {
        Self {
            visited: HashSet::new(),
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
        self.visited.contains(&slot)
    }

    fn check(&mut self, slot: u64, depth: u8) -> std::result::Result<(), &'static str> {
        if depth > self.max_depth {
            return Err("tree deeper than this space's chunk count can hold");
        }
        if self.budget == 0 {
            return Err("tree walk exceeded its traversal budget");
        }
        self.budget -= 1;
        if !self.visited.insert(slot) {
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
        let mut w = TreeWalk::with_budget(16);
        w.admit(7, 0).unwrap();
        w.admit(8, 1).unwrap();
        let err = w.admit(7, 2).unwrap_err();
        assert!(matches!(err, Error::Malformed(d) if d.contains("more than once")));
    }

    #[test]
    fn the_budget_permits_exactly_its_count_then_stops() {
        let mut w = TreeWalk::with_budget(2);
        w.admit(1, 0).unwrap();
        w.admit(2, 0).unwrap();
        let err = w.admit(3, 0).unwrap_err();
        assert!(matches!(err, Error::Malformed(d) if d.contains("traversal budget")));
    }

    /// A zero budget is what an empty space would hand out; it must not
    /// admit a first read rather than underflowing to `usize::MAX`.
    #[test]
    fn a_zero_budget_admits_nothing() {
        let mut w = TreeWalk::with_budget(0);
        assert!(w.admit(1, 0).is_err());
        assert!(w.admit(2, 0).is_err());
    }

    /// The verify variant reports the same violations through the
    /// integrity error shape, naming the offending slot.
    #[test]
    fn the_verify_variant_names_the_slot() {
        let mut w = TreeWalk::with_budget(4);
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
        let mut w = TreeWalk::with_budget(3);
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
        let mut w = TreeWalk::with_budget(16);
        for depth in 0..=2 {
            w.admit(depth as u64 + 100, depth).unwrap();
        }
        let err = w.admit(200, 3).unwrap_err();
        assert!(matches!(err, Error::Malformed(d) if d.contains("deeper than")));
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
