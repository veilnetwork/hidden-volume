//! `Redacted<T>` — the wrapper every plaintext-bearing struct field wears.
//!
//! # Why a type and not another hand-written `Debug`
//!
//! Audit HV-01 was created by the fix for its own predecessor. That pass
//! redacted `Debug` on the four types that *hold* a key, a value or a log
//! payload — `KvOp`, `WriteOp`, `LogEntry`, `Plaintext` — and left the
//! structs that hold *those* alone. `Tx`, `LeafNode`, `ChildPointer`,
//! `SpaceState` and `Space` still derived `Debug`, so one `format!("{tx:?}")`
//! still put a contact record or a message body into whatever log, panic
//! message or CI transcript the string flowed into. A per-type list is only
//! as complete as the memory of whoever last extended it, and the on-disk
//! node types are extended whenever the format is.
//!
//! `Zeroizing` is not a redaction primitive either: the upstream crate
//! derives `Debug` on it, so `Zeroizing<Vec<u8>>` prints its bytes verbatim.
//! It scrubs on drop and says nothing about formatting.
//!
//! # The two rules this module enforces
//!
//! 1. **A plaintext-bearing field is typed `Redacted<T>`.** Its `Debug`
//!    prints counts, never content, so the field is safe even under
//!    `#[derive(Debug)]`, safe when printed on its own, and safe when a
//!    future author pulls it into a `debug_struct` by hand. `T: Secret` is
//!    a compile-time obligation: a new field cannot be wrapped without
//!    saying how to count and how to scrub it.
//! 2. **Its carrier's `Debug` is an allow-list**, written by the
//!    crate-private `redacted_debug!` macro, which ends in
//!    `finish_non_exhaustive()`. A field
//!    added later is not printed *at all* until someone names it — so
//!    forgetting is the safe direction, and exposure takes a deliberate
//!    edit.
//!
//! Together they mean a newly added secret field is redacted by
//! construction rather than by recall. `tests/debug_redaction.rs` holds a
//! sentinel that adds one and proves it.
//!
//! # What the scrub does and does not promise (audit HV-07)
//!
//! Dropping a `Redacted<T>` overwrites the plaintext bytes `T` owns *at
//! that moment*. That bounds how long this crate's **internal** copies of a
//! decrypted key, value or payload stay readable in the heap: they do not
//! outlive the operation that built them.
//!
//! It is **not** a promise that a plaintext is gone from the process. A
//! `Vec` that grew during construction left its earlier allocation behind
//! unscrubbed; the value this crate *returns* is owned by the caller and
//! across UniFFI it is copied into a foreign heap this crate never sees.
//! Those copies are the host application's to manage.

use core::fmt;
use core::ops::{Deref, DerefMut};
use std::collections::BTreeMap;

use zeroize::Zeroize;

/// The only thing a [`Redacted`] value is allowed to say about itself in
/// `{:?}`: how many secrets it holds and how many plaintext bytes they add
/// up to. Both are the kind of number a diagnostic actually needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecretShape {
    /// How many distinct secrets the value holds (entries, ops, records).
    pub items: usize,
    /// Total plaintext bytes across those secrets.
    pub bytes: usize,
}

/// Decrypted user data — a key, a value, a log payload — or a container of
/// them.
///
/// Implemented per *container shape* rather than per field, and required by
/// [`Redacted`]: a field cannot be wrapped without an implementation, and an
/// implementation cannot be written without deciding how the value is
/// counted and how it is scrubbed.
pub trait Secret {
    /// Counts only. Must never derive its result from secret *content*.
    fn secret_shape(&self) -> SecretShape;

    /// Overwrite every plaintext byte this value currently owns and drop it
    /// to an empty state. Reachable earlier allocations (a `Vec` that grew)
    /// are out of reach here — see the module docs.
    fn scrub_secret(&mut self);
}

/// A field holding decrypted user data.
///
/// Redacts under `{:?}` (see [`SecretShape`]) and scrubs on drop. Derefs to
/// `T`, so read and mutate call sites are unchanged; taking the value back
/// out is the explicit [`Redacted::into_inner`].
pub struct Redacted<T: Secret> {
    inner: T,
}

impl<T: Secret> Redacted<T> {
    /// Wrap a plaintext-bearing value.
    pub const fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Borrow the wrapped value. `&*redacted` does the same via [`Deref`];
    /// this exists for the places where inference needs the type named.
    pub const fn as_inner(&self) -> &T {
        &self.inner
    }
}

impl<T: Secret + Default> Redacted<T> {
    /// Move the plaintext out, handing ownership — and responsibility for
    /// its lifetime — to the caller. The wrapper is left holding
    /// `T::default()`, which is what its drop then scrubs.
    ///
    /// Deliberately explicit: every call site is a place where plaintext
    /// leaves this crate's redaction discipline.
    pub fn into_inner(mut self) -> T {
        core::mem::take(&mut self.inner)
    }
}

/// One item a [`SecretItems`] can scrub when nobody takes it.
///
/// A trait rather than a hard-coded pair type so the drop behaviour can be
/// OBSERVED in a test: reading a freed allocation is not available, but a
/// fixture that counts its own scrubs is.
pub trait Scrubbable {
    /// Overwrite every plaintext byte this item owns.
    fn scrub(&mut self);
}

impl Scrubbable for (Vec<u8>, Vec<u8>) {
    fn scrub(&mut self) {
        self.0.zeroize();
        self.1.zeroize();
    }
}

/// Items being consumed one at a time, whose remainder is scrubbed on drop.
///
/// [`Redacted::into_inner`] hands the plaintext over and stops protecting it,
/// which is right for a caller that asked for it — and wrong for a walk that
/// takes the keys and discards the values, or stops at a page limit and
/// abandons the tail. `list_keys` did exactly that: every value it decoded,
/// and every key past the cursor or the limit, left through an ordinary drop
/// (report17 HV17-M6).
///
/// This is the shape that CONSUMES rather than releases: whatever the loop did
/// not take is still scrubbed.
pub struct SecretItems<T: Scrubbable> {
    inner: std::vec::IntoIter<T>,
}

impl<T: Scrubbable> fmt::Debug for SecretItems<T> {
    /// Counts, never content — the same rule [`Redacted`] follows.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretItems")
            .field("remaining", &self.inner.len())
            .finish()
    }
}

impl<T: Scrubbable> Iterator for SecretItems<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<T: Scrubbable> Drop for SecretItems<T> {
    fn drop(&mut self) {
        // Whatever the consumer stopped short of — a page limit reached, an
        // error raised mid-walk, a `break`.
        for mut item in self.inner.by_ref() {
            item.scrub();
        }
    }
}

/// Key-value pairs being consumed, whose remainder is scrubbed on drop.
pub type SecretPairs = SecretItems<(Vec<u8>, Vec<u8>)>;

impl Redacted<Vec<(Vec<u8>, Vec<u8>)>> {
    /// Consume the pairs one at a time, scrubbing whatever is left behind.
    ///
    /// The item handed to the loop is the caller's to deal with — a key it
    /// keeps, a value it should scrub — but the REMAINDER never becomes
    /// anybody's problem, which is the difference from [`Self::into_inner`].
    pub fn into_secret_pairs(self) -> SecretPairs {
        SecretItems {
            inner: self.into_inner().into_iter(),
        }
    }
}

impl<T: Secret> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let shape = self.inner.secret_shape();
        f.debug_struct("Redacted")
            .field("items", &shape.items)
            .field("bytes", &shape.bytes)
            .finish()
    }
}

impl<T: Secret> Deref for Redacted<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: Secret> DerefMut for Redacted<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Secret> Drop for Redacted<T> {
    fn drop(&mut self) {
        self.inner.scrub_secret();
    }
}

impl<T: Secret + Clone> Clone for Redacted<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: Secret + Default> Default for Redacted<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Secret + PartialEq> PartialEq for Redacted<T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<T: Secret + Eq> Eq for Redacted<T> {}

impl<T: Secret> From<T> for Redacted<T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

// =====================================================================
// `Secret` for the container shapes this crate stores plaintext in.
//
// The set is small on purpose and the compiler keeps it honest: a field
// typed `Redacted<T>` does not build until `T: Secret` exists.
// =====================================================================

/// One byte string: a KV key, an internal node's `first_key`, a decrypted
/// commit payload.
impl Secret for Vec<u8> {
    fn secret_shape(&self) -> SecretShape {
        SecretShape {
            items: 1,
            bytes: self.len(),
        }
    }

    fn scrub_secret(&mut self) {
        self.zeroize();
    }
}

/// One Tx's operations against one namespace, collapsed to one entry per
/// key: `key → Some(value)` for a put, `key → None` for a delete. Both
/// halves are user plaintext, and this map is a **full copy** of the
/// transaction's — built by `space::commit` from `KvOp`s that are already
/// `Redacted`, so leaving it bare made the copy outlive the discipline
/// its source was held to (report7 P3).
impl Secret for BTreeMap<Vec<u8>, Option<Vec<u8>>> {
    fn secret_shape(&self) -> SecretShape {
        SecretShape {
            items: self.len(),
            bytes: self
                .iter()
                .map(|(k, v)| k.len() + v.as_ref().map_or(0, Vec::len))
                .sum(),
        }
    }

    fn scrub_secret(&mut self) {
        // The keys of a `BTreeMap` are not reachable as `&mut`, so they
        // cannot be zeroized in place: drain the map instead, scrub each
        // pair as it comes out, and let the owned copies drop.
        for (mut k, v) in core::mem::take(self) {
            k.zeroize();
            if let Some(mut v) = v {
                v.zeroize();
            }
        }
    }
}

/// Leaf entries: `(key, value)` pairs, both halves user plaintext.
impl Secret for Vec<(Vec<u8>, Vec<u8>)> {
    fn secret_shape(&self) -> SecretShape {
        SecretShape {
            items: self.len(),
            bytes: self.iter().map(|(k, v)| k.len() + v.len()).sum(),
        }
    }

    fn scrub_secret(&mut self) {
        for (k, v) in self.iter_mut() {
            k.zeroize();
            v.zeroize();
        }
        self.clear();
    }
}

/// One namespace's coalesced log records, `[(log_id, payload)]`.
///
/// The payloads scrub themselves, so the wrapper's own scrub only has to
/// empty the vector — but it is still a `Secret`, because what `{:?}` must not
/// print is as true here as anywhere (report17 HV17-M6).
impl Secret for Vec<(u64, zeroize::Zeroizing<Vec<u8>>)> {
    fn secret_shape(&self) -> SecretShape {
        SecretShape {
            items: self.len(),
            bytes: self.iter().map(|(_, payload)| payload.len()).sum(),
        }
    }

    fn scrub_secret(&mut self) {
        // `clear` drops each payload, and each payload scrubs itself on drop.
        self.clear();
    }
}

/// A transaction's pending log appends, `namespace → [(log_id, payload)]`.
/// The `log_id` is the caller's own index, not plaintext; the payload is.
impl Secret for crate::tx::PendingLog {
    fn secret_shape(&self) -> SecretShape {
        SecretShape {
            items: self.values().map(Vec::len).sum(),
            bytes: self
                .values()
                .flat_map(|records| records.iter())
                .map(|(_, payload)| payload.len())
                .sum(),
        }
    }

    fn scrub_secret(&mut self) {
        for records in self.values_mut() {
            for (_, payload) in records.iter_mut() {
                payload.zeroize();
            }
            records.clear();
        }
        self.clear();
    }
}

/// Write a `Debug` that prints **only** the fields named here and ends in
/// `finish_non_exhaustive()`.
///
/// The point is the omission. A field added to the struct later prints
/// nothing until someone adds it to this list, so a new plaintext-bearing
/// field is invisible by default and exposing one is a deliberate edit
/// rather than an oversight. Name the redacted fields freely — a
/// [`Redacted`] field prints its [`SecretShape`], not its contents.
macro_rules! redacted_debug {
    ($ty:ident $(< $($lt:lifetime),+ >)? { $($field:ident),* $(,)? }) => {
        impl $(< $($lt),+ >)? core::fmt::Debug for $ty $(< $($lt),+ >)? {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($ty))
                    $(.field(stringify!($field), &self.$field))*
                    .finish_non_exhaustive()
            }
        }
    };
}

pub(crate) use redacted_debug;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_counts_not_content() {
        let r = Redacted::new(b"super-secret".to_vec());
        let s = format!("{r:?}");
        assert!(!s.contains("secret"), "content leaked: {s}");
        assert!(!s.contains("115"), "byte rendering leaked: {s}");
        assert!(s.contains("bytes: 12"), "shape missing: {s}");
    }

    #[test]
    fn entries_shape_counts_both_halves() {
        let r = Redacted::new(vec![(b"ab".to_vec(), b"cde".to_vec())]);
        let shape = r.secret_shape();
        assert_eq!(shape.items, 1);
        assert_eq!(shape.bytes, 5);
    }

    #[test]
    fn scrub_clears_the_container() {
        let mut v = vec![(b"ab".to_vec(), b"cde".to_vec())];
        v.scrub_secret();
        assert!(v.is_empty());
    }

    /// The collapsed key-ops map — `space::tree::KeyOps` — is a full copy
    /// of a transaction's plaintext and gets the same treatment as the
    /// `KvOp`s it is built from (report7 P3).
    /// The KV walks consume their leaves rather than releasing them.
    ///
    /// The behaviour cannot be observed from outside — a walk that scrubs and
    /// one that does not return the same keys — so this asserts the call each
    /// walk makes. `l.entries.into_inner()` hands a leaf's plaintext over with
    /// no owner; `into_secret_pairs()` scrubs whatever the walk does not take.
    ///
    /// Bounded to the three functions BY NAME. The first version of this test
    /// cut each file at its first `#[cfg(test)]` and searched what was left —
    /// and in `space/mod.rs` that attribute is on line 15, so it searched
    /// almost nothing and passed against a build with the fix removed.
    /// Measured green on that build before it was rewritten.
    ///
    /// The LOG walks are deliberately absent: their leaf values are batch-slot
    /// pointers, not user plaintext, and the payloads they point at are
    /// handled where they are decoded (HV17-M5). So is `collect_leaves_at`,
    /// whose every pair goes to the caller.
    #[test]
    fn the_kv_leaf_walks_do_not_release_their_leaves() {
        fn body<'a>(source: &'a str, name: &str) -> &'a str {
            let at = source
                .find(name)
                .unwrap_or_else(|| panic!("{name} moved or was renamed"));
            let rest = &source[at..];
            // To the function's closing brace at its own indentation.
            let end = rest.find("\n    }\n").unwrap_or(rest.len());
            &rest[..end]
        }

        let space = include_str!("space/mod.rs");
        let tree = include_str!("space/tree.rs");

        for (name, source) in [
            ("fn collect_leaf_keys_after_at", space),
            ("fn collect_leaf_pairs_after_at", space),
            ("fn update_tree", tree),
        ] {
            let body = body(source, name);
            assert!(
                !body.contains("entries.into_inner()"),
                "{name} releases a leaf's plaintext instead of consuming it: \
                 every value a keys-only walk decodes, and every pair past a \
                 cursor or a limit, is then dropped in the clear"
            );
            assert!(
                body.contains("into_secret_pairs()"),
                "{name} no longer consumes its leaves at all, so the check \
                 above is about nothing"
            );
        }
    }

    /// report17 HV17-M6 — what a consumer does NOT take is still scrubbed.
    ///
    /// `into_inner` hands the plaintext over and stops protecting it, which is
    /// right for a caller that asked for it. A walk that takes the keys and
    /// discards the values, or stops at a page limit and abandons the tail,
    /// asked for none of what it leaves behind — and that used to leave
    /// through an ordinary drop.
    ///
    /// Observed rather than assumed: reading a freed allocation is not
    /// available, so the fixture counts its own scrubs. That is why
    /// `SecretItems` is generic over [`Scrubbable`] instead of hard-coding the
    /// pair type — a version of this test that could only watch `Vec<u8>` had
    /// nothing to assert and passed on anything.
    /// And the pair impl actually wipes the bytes, not just the lengths.
    ///
    /// The two checks above hold up the MECHANISM: one reads the walk bodies
    /// for `into_secret_pairs`, the other counts scrubs through a fixture that
    /// implements [`Scrubbable`] itself. Neither touches the impl that carries
    /// the user's plaintext, and emptying that impl to `fn scrub(&mut self) {}`
    /// left every test in the crate green — a wipe nobody was checking.
    ///
    /// Read back through the allocation rather than through the `Vec`:
    /// `zeroize` truncates the length as well, so a `clear()` that left the
    /// bytes in place would satisfy anything that only asked whether the
    /// vector looks empty.
    #[test]
    fn the_pair_impl_wipes_the_bytes_and_not_only_the_lengths() {
        let mut pair = (vec![0xAAu8; 48], vec![0xBBu8; 64]);
        let (key_ptr, key_cap) = (pair.0.as_ptr(), pair.0.capacity());
        let (val_ptr, val_cap) = (pair.1.as_ptr(), pair.1.capacity());

        // SAFETY: `pair` owns both allocations and they are fully initialised.
        let before = unsafe { std::slice::from_raw_parts(key_ptr, key_cap) };
        assert!(
            before.iter().any(|b| *b != 0),
            "premise: the buffer holds something to wipe"
        );

        pair.scrub();

        // SAFETY: `zeroize` sets the length to zero without freeing, so both
        // allocations are still owned by `pair` and still ours to read.
        let key = unsafe { std::slice::from_raw_parts(key_ptr, key_cap) };
        let value = unsafe { std::slice::from_raw_parts(val_ptr, val_cap) };
        assert!(
            key.iter().all(|b| *b == 0),
            "the key's bytes survived the scrub: {key:02x?}"
        );
        assert!(
            value.iter().all(|b| *b == 0),
            "the value's bytes survived the scrub: {value:02x?}"
        );
    }

    #[test]
    fn an_abandoned_tail_is_scrubbed_rather_than_dropped() {
        use std::cell::Cell;
        use std::rc::Rc;

        struct Counted(Rc<Cell<usize>>);
        impl super::Scrubbable for Counted {
            fn scrub(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let scrubs = Rc::new(Cell::new(0));
        let items: Vec<Counted> = (0..5).map(|_| Counted(Rc::clone(&scrubs))).collect();

        let taken = {
            let mut drain = super::SecretItems {
                inner: items.into_iter(),
            };
            // Take two, abandon three — the page-limit shape.
            let a = drain.next().expect("a first item");
            let b = drain.next().expect("a second item");
            assert_eq!(
                scrubs.get(),
                0,
                "taking an item scrubbed it: the consumer would get an empty one"
            );
            vec![a, b]
            // `drain` drops here, with three items left in it.
        };

        assert_eq!(
            scrubs.get(),
            3,
            "the abandoned tail was dropped without being scrubbed"
        );
        assert_eq!(taken.len(), 2, "the taken items did not survive");
    }

    #[test]
    fn key_ops_map_is_redacted_and_scrubbed() {
        let mut m: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        m.insert(b"contact-id".to_vec(), Some(b"alice@example".to_vec()));
        m.insert(b"gone".to_vec(), None);

        // Counts both halves, and counts a delete as its key alone.
        let shape = m.secret_shape();
        assert_eq!(shape.items, 2);
        assert_eq!(
            shape.bytes,
            b"contact-id".len() + b"alice@example".len() + b"gone".len()
        );

        // `{:?}` says how much, never what.
        let r = Redacted::new(m);
        let printed = format!("{r:?}");
        assert!(!printed.contains("alice"), "value leaked: {printed}");
        assert!(!printed.contains("contact-id"), "key leaked: {printed}");

        // And the scrub empties it. Keys of a `BTreeMap` are not
        // reachable as `&mut`, so this drains rather than iterating —
        // an implementation that skipped the keys would leave them here.
        let mut m = r.into_inner();
        m.scrub_secret();
        assert!(m.is_empty(), "scrub left {} entries", m.len());
    }

    #[test]
    fn into_inner_hands_the_plaintext_over_intact() {
        let r = Redacted::new(b"payload".to_vec());
        assert_eq!(r.into_inner(), b"payload".to_vec());
    }
}
