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
