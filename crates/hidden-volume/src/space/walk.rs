//! Shared traversal guard for every B+ tree walker in this module.
//!
//! ## What the depth cap does not cover
//!
//! [`super::index::MAX_TREE_DEPTH`] bounds how *deep* a walk descends.
//! It says nothing about how *wide* it fans out, and nothing about
//! whether the thing being walked is a tree at all.
//!
//! What a walker actually follows is a list of `(child_slot,
//! child_hash)` pointers decoded out of an `IndexNode` chunk. Nothing
//! in the encoding forces those pointers to be distinct. A key-holder
//! — or a writer-bug regression — can emit an `InternalNode` whose ~90
//! children all name the *same* next `InternalNode` chunk. Every link
//! is AEAD-valid, every Merkle hash matches its parent's record, every
//! node decodes: the structure is simply a DAG instead of a tree. At
//! `MAX_TREE_DEPTH` that costs `90³ ≈ 7.3 × 10⁵` chunk reads (an
//! AEAD-decrypt plus a BLAKE3 each) out of four distinct chunks — an
//! amplification DoS from a container of a few KiB.
//!
//! ## The two halves of the guard
//!
//! - **`visited`** makes the DAG a named failure instead of quiet
//!   work. A well-formed index *is* a tree: each chunk is reachable by
//!   exactly one path, from exactly one parent, in exactly one
//!   namespace. So a second visit to a slot is a structural violation
//!   to report, not a duplicate to silently skip. This also covers the
//!   narrower "two children of one node share a `child_slot`" case
//!   without a separate per-node check.
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

/// Per-traversal guard: which slots this walk has already read, and how
/// many reads it has left. See the module docs for why both are needed.
pub(super) struct TreeWalk {
    visited: HashSet<u64>,
    budget: usize,
}

impl TreeWalk {
    /// New guard permitting at most `budget` distinct chunk reads.
    /// Callers pass the space's owned-chunk count
    /// ([`super::Space::new_tree_walk`]).
    pub(super) fn with_budget(budget: usize) -> Self {
        Self {
            visited: HashSet::new(),
            budget,
        }
    }

    /// Admit `slot` into this walk, reporting a violation through
    /// [`Error::Malformed`] — the shape the non-verify walkers
    /// (`collect_leaves`, `count_leaves`, the `log_iter` family,
    /// `collect_tree_chunks_into_set`) already use for structural
    /// rejects.
    pub(super) fn admit(&mut self, slot: u64) -> Result<()> {
        self.check(slot).map_err(Error::Malformed)
    }

    /// Admit `slot` into this walk, reporting a violation through
    /// [`Error::IntegrityFailure`] — the integrity walk's contract is
    /// that a structural problem names the slot it was found at.
    pub(super) fn admit_for_verify(&mut self, slot: u64) -> Result<()> {
        self.check(slot)
            .map_err(|detail| Error::IntegrityFailure { detail, slot })
    }

    fn check(&mut self, slot: u64) -> std::result::Result<(), &'static str> {
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
        w.admit(7).unwrap();
        w.admit(8).unwrap();
        let err = w.admit(7).unwrap_err();
        assert!(matches!(err, Error::Malformed(d) if d.contains("more than once")));
    }

    #[test]
    fn the_budget_permits_exactly_its_count_then_stops() {
        let mut w = TreeWalk::with_budget(2);
        w.admit(1).unwrap();
        w.admit(2).unwrap();
        let err = w.admit(3).unwrap_err();
        assert!(matches!(err, Error::Malformed(d) if d.contains("traversal budget")));
    }

    /// A zero budget is what an empty space would hand out; it must not
    /// admit a first read rather than underflowing to `usize::MAX`.
    #[test]
    fn a_zero_budget_admits_nothing() {
        let mut w = TreeWalk::with_budget(0);
        assert!(w.admit(1).is_err());
        assert!(w.admit(2).is_err());
    }

    /// The verify variant reports the same violations through the
    /// integrity error shape, naming the offending slot.
    #[test]
    fn the_verify_variant_names_the_slot() {
        let mut w = TreeWalk::with_budget(4);
        w.admit_for_verify(9).unwrap();
        let err = w.admit_for_verify(9).unwrap_err();
        match err {
            Error::IntegrityFailure { detail, slot } => {
                assert_eq!(slot, 9);
                assert!(detail.contains("more than once"));
            },
            other => panic!("expected IntegrityFailure, got {other:?}"),
        }
    }
}
