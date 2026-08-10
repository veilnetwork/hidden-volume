//! The set of slots a space owns, as a bitmap.
//!
//! ## Why not `Vec<u64>`
//!
//! `owned_slots` was a sorted `Vec<u64>` — eight bytes per owned chunk, held
//! for the life of the handle and built by `push` during the open scan, so
//! its growth doubling briefly holds one and a half copies. Measured (see
//! `tests/open_peak_memory.rs`), the open peaked at 27.5 bytes per owned slot,
//! which at [`crate::MAX_OPEN_SCAN_CHUNKS`] is 440 MiB — for a container the
//! format explicitly permits and a phone cannot open (report9 HV-13).
//!
//! A bitmap costs one bit per slot in the file rather than 64 bits per owned
//! slot, so it is smaller than the vector at any density above one owned slot
//! in sixty-four. Every real container is far denser than that: an open that
//! found almost nothing owned had almost nothing to hold either.
//!
//! ## Why this is not `vacuum::SlotSet`
//!
//! Vacuum's bitmap is sized to the file and REFUSES a slot beyond it, which is
//! right there — it is fed arbitrary 8-byte KV values that need not name a
//! real slot, and a value that names no slot can match no owned slot either.
//!
//! This set is written to by `place_chunk` as the file grows, so a slot beyond
//! the current capacity is not a stray value but the next append. Refusing it
//! would silently forget a live chunk, which is the failure mode that ends in
//! a vacuum scrubbing data. It grows instead.

/// A set of slot indices, one bit each.
///
/// Iteration is ascending, which is what the previous sorted `Vec` gave every
/// caller that relied on order (the checkpoint record encodes ascending; the
/// fast-open comparison in `tests/streaming_open.rs` compares sorted).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct OwnedSet {
    words: Vec<u64>,
    len: usize,
}

impl OwnedSet {
    /// Room for slots `0..capacity` without reallocating. The capacity is a
    /// hint only — [`Self::insert`] grows past it.
    pub(crate) fn with_capacity(capacity: u64) -> Self {
        Self {
            words: vec![0u64; capacity.div_ceil(64) as usize],
            len: 0,
        }
    }

    /// Add `slot`, growing to fit it. Returns whether it was newly added.
    pub(crate) fn insert(&mut self, slot: u64) -> bool {
        let word_idx = (slot / 64) as usize;
        if word_idx >= self.words.len() {
            self.words.resize(word_idx + 1, 0);
        }
        let bit = 1u64 << (slot % 64);
        let word = &mut self.words[word_idx];
        if *word & bit != 0 {
            return false;
        }
        *word |= bit;
        self.len += 1;
        true
    }

    pub(crate) fn contains(&self, slot: u64) -> bool {
        let word_idx = (slot / 64) as usize;
        word_idx < self.words.len() && self.words[word_idx] & (1u64 << (slot % 64)) != 0
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Keep only the slots `f` accepts.
    pub(crate) fn retain(&mut self, mut f: impl FnMut(u64) -> bool) {
        let mut len = 0;
        for (w, word) in self.words.iter_mut().enumerate() {
            let mut bits = *word;
            let mut kept = 0u64;
            while bits != 0 {
                let b = bits.trailing_zeros() as u64;
                bits &= bits - 1;
                let slot = (w as u64) * 64 + b;
                if f(slot) {
                    kept |= 1u64 << b;
                    len += 1;
                }
            }
            *word = kept;
        }
        self.len = len;
    }

    /// How many 64-slot words the set spans, and the bits of one of them.
    ///
    /// For callers that must hold `&mut` on the owner while they walk the
    /// set — vacuum reads and scrubs each slot as it goes. Iterating a
    /// borrowed view is impossible there, and materializing the slot list is
    /// the eight-bytes-per-slot copy audit HV-03 removed. One word at a time
    /// is neither: 64 slots per `u64` of stack.
    ///
    /// Word count only ever grows (`insert` resizes, nothing shrinks), so an
    /// index taken before a mutation stays in range after it.
    pub(crate) fn word_count(&self) -> usize {
        self.words.len()
    }

    pub(crate) fn word(&self, index: usize) -> u64 {
        self.words.get(index).copied().unwrap_or(0)
    }

    /// Ascending iteration over the slots in the set.
    pub(crate) fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.words.iter().enumerate().flat_map(|(w, word)| {
            let mut bits = *word;
            std::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let b = bits.trailing_zeros() as u64;
                bits &= bits - 1;
                Some((w as u64) * 64 + b)
            })
        })
    }

    /// The set as an ascending `Vec`, which is the form the checkpoint record
    /// is encoded from. Allocates the eight-bytes-per-slot this type exists to
    /// avoid holding, so it is for the writer that needs it and not for
    /// convenience at a call site that could iterate.
    pub(crate) fn to_sorted_vec(&self) -> Vec<u64> {
        let mut v = Vec::with_capacity(self.len);
        v.extend(self.iter());
        v
    }

    /// Absorb `other`. Used by the parallel scan's reduce, where the two
    /// halves are disjoint by construction (each work item owns a slot range).
    ///
    /// Gated exactly as its one caller is. `parallel-scan` is off by default —
    /// mobile does not want six megabytes of rayon for a scan that is already
    /// AEAD-bound — so on a default build this method has no callers at all,
    /// and the Android cross-compile gate builds with `-D warnings`.
    #[cfg(all(feature = "parallel-scan", unix))]
    pub(crate) fn union_from(&mut self, other: &Self) {
        if other.words.len() > self.words.len() {
            self.words.resize(other.words.len(), 0);
        }
        let mut len = 0;
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a |= *b;
        }
        for w in &self.words {
            len += w.count_ones() as usize;
        }
        self.len = len;
    }
}

/// The slots named by one word of a bitmap, ascending.
///
/// Companion to [`OwnedSet::word`] — free rather than a method so a caller
/// can walk the set while holding `&mut` on whatever owns it.
pub(crate) fn slots_in_word(index: usize, mut bits: u64) -> impl Iterator<Item = u64> {
    std::iter::from_fn(move || {
        if bits == 0 {
            return None;
        }
        let b = bits.trailing_zeros() as u64;
        bits &= bits - 1;
        Some((index as u64) * 64 + b)
    })
}

impl FromIterator<u64> for OwnedSet {
    fn from_iter<I: IntoIterator<Item = u64>>(iter: I) -> Self {
        let mut set = Self::default();
        for slot in iter {
            set.insert(slot);
        }
        set
    }
}

impl std::fmt::Debug for OwnedSet {
    /// Count only. The slot indices a space owns are exactly what a
    /// `Debug` on `SpaceState` must not leak (see `redacted_debug!`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OwnedSet({} slots)", self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::OwnedSet;

    #[test]
    fn a_slot_past_the_capacity_grows_the_set() {
        // The difference from `vacuum::SlotSet`, and the one that matters:
        // `place_chunk` appends past the slot count the open saw. A set that
        // refused would forget a live chunk, and the next vacuum would scrub
        // it as an orphan.
        let mut s = OwnedSet::with_capacity(64);
        assert!(s.insert(1_000_000));
        assert!(s.contains(1_000_000));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn inserting_twice_counts_once() {
        let mut s = OwnedSet::with_capacity(64);
        assert!(s.insert(7));
        assert!(!s.insert(7));
        assert_eq!(s.len(), 1);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn iteration_is_ascending_and_complete() {
        let slots = [0u64, 1, 63, 64, 65, 4095, 4096];
        let s: OwnedSet = slots.iter().copied().collect();
        assert_eq!(s.to_sorted_vec(), slots);
        assert_eq!(s.len(), slots.len());
    }

    #[test]
    fn retain_keeps_the_count_honest() {
        let mut s: OwnedSet = (0u64..200).collect();
        s.retain(|slot| slot % 2 == 0);
        assert_eq!(s.len(), 100);
        assert!(s.contains(198));
        assert!(!s.contains(199));
        assert_eq!(s.to_sorted_vec().len(), 100);
    }

    #[cfg(all(feature = "parallel-scan", unix))]
    #[test]
    fn a_union_counts_the_overlap_once() {
        let mut a: OwnedSet = [1u64, 2, 3].into_iter().collect();
        let b: OwnedSet = [3u64, 300].into_iter().collect();
        a.union_from(&b);
        assert_eq!(a.to_sorted_vec(), vec![1, 2, 3, 300]);
        assert_eq!(a.len(), 4);
    }

    #[test]
    fn walking_by_word_sees_every_slot() {
        // The vacuum path: same slots as `iter`, in the same order, without
        // a borrow on the set.
        let s: OwnedSet = [0u64, 63, 64, 130, 4097].into_iter().collect();
        let mut walked = Vec::new();
        for w in 0..s.word_count() {
            walked.extend(super::slots_in_word(w, s.word(w)));
        }
        assert_eq!(walked, s.to_sorted_vec());
    }

    #[test]
    fn debug_does_not_name_the_slots() {
        let s: OwnedSet = [17u64, 4242].into_iter().collect();
        let shown = format!("{s:?}");
        assert!(!shown.contains("17"), "{shown}");
        assert!(!shown.contains("4242"), "{shown}");
        assert!(shown.contains('2'), "{shown} should still carry the count");
    }
}
