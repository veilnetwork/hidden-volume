//! Accumulators that clear themselves when they go.
//!
//! A `Vec` of plaintext freed by an ordinary drop leaves its bytes in the
//! allocator's hands. Every path that builds one of these pages has a way out
//! that is not the return value — an I/O error on a later chunk, a leaf that
//! does not decode, a cancel — and on that way out the entries gathered so far
//! were simply dropped (report24 HV24-03 for the repack's pages, report27 H02
//! for the index walk and the leaf decoder).
//!
//! Each type here is a plain newtype over the `Vec` the code already built, so
//! the accumulation is unchanged: the difference is that leaving early wipes
//! and returning normally does not. [`WipedPairs::take`] and its siblings are
//! what a success path calls — the contents move to the caller and the guard
//! is left holding nothing to clear.
//!
//! Living in one module rather than beside each user, because the first copy
//! covered the repack alone and the index walk went on returning bare `Vec`s
//! for three more audit passes.

use zeroize::Zeroize as _;

/// A page of KV pairs that clears itself when it goes.
pub(crate) struct WipedPairs(pub(crate) Vec<(Vec<u8>, Vec<u8>)>);

impl WipedPairs {
    /// An empty page, ready to accumulate into.
    pub(crate) fn new(v: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        Self(v)
    }

    /// Clear every byte still held. Separate from [`Drop`] so a test can watch
    /// it work on LIVE memory — reading a buffer back after it has been freed
    /// is undefined behaviour, which makes "did the drop wipe it" a question
    /// no safe test can ask directly.
    pub(crate) fn wipe(&mut self) {
        for (key, value) in self.0.iter_mut() {
            key.zeroize();
            value.zeroize();
        }
    }

    /// Hand the page to the caller. The guard keeps nothing, so the drop that
    /// follows has nothing to clear — this is the SUCCESS path, and wiping
    /// what we are about to return would be worse than not wiping at all.
    pub(crate) fn take(&mut self) -> Vec<(Vec<u8>, Vec<u8>)> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for WipedPairs {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// The same for a page of KEYS, which the index walk gathers on its own.
pub(crate) struct WipedKeys(pub(crate) Vec<Vec<u8>>);

impl WipedKeys {
    pub(crate) fn new(v: Vec<Vec<u8>>) -> Self {
        Self(v)
    }

    /// See [`WipedPairs::wipe`].
    pub(crate) fn wipe(&mut self) {
        for key in self.0.iter_mut() {
            key.zeroize();
        }
    }

    /// See [`WipedPairs::take`].
    pub(crate) fn take(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for WipedKeys {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// The same for a page of log payloads, which are read by reference and so are
/// never drained.
pub(crate) struct WipedLogPage(pub(crate) Vec<(u64, Vec<u8>)>);

impl WipedLogPage {
    /// See [`WipedPairs::wipe`].
    pub(crate) fn wipe(&mut self) {
        for (_, payload) in self.0.iter_mut() {
            payload.zeroize();
        }
    }
}

impl Drop for WipedLogPage {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_kv_page_clears_every_byte_it_still_holds() {
        let mut page = WipedPairs(vec![
            (b"key-one".to_vec(), b"secret-value".to_vec()),
            (b"key-two".to_vec(), b"another-secret".to_vec()),
        ]);

        page.wipe();

        for (key, value) in &page.0 {
            assert!(key.iter().all(|b| *b == 0), "key survived: {key:?}");
            assert!(value.iter().all(|b| *b == 0), "value survived: {value:?}");
        }
    }

    #[test]
    fn a_key_page_clears_every_byte_it_still_holds() {
        let mut page = WipedKeys(vec![b"contact:alice".to_vec(), b"contact:bob".to_vec()]);

        page.wipe();

        for key in &page.0 {
            assert!(key.iter().all(|b| *b == 0), "key survived: {key:?}");
        }
    }

    #[test]
    fn a_log_page_clears_its_payloads() {
        let mut page = WipedLogPage(vec![
            (1, b"a message body".to_vec()),
            (2, b"another one".to_vec()),
        ]);

        page.wipe();

        for (id, payload) in &page.0 {
            assert!(*id > 0, "ids are not secret and are left alone");
            assert!(
                payload.iter().all(|b| *b == 0),
                "payload survived: {payload:?}"
            );
        }
    }

    /// Handing the page over must not clear it on the way out.
    ///
    /// The guard's whole value is that leaving early wipes — and the success
    /// path leaves too. If `take` left the entries in the guard, or if the
    /// drop that follows reached what was returned, every successful `list`
    /// would answer with zeros. The wipe has to see an EMPTY page.
    #[test]
    fn taking_the_page_hands_it_over_intact_and_leaves_nothing_to_wipe() {
        let mut page = WipedPairs::new(vec![(b"k".to_vec(), b"v".to_vec())]);
        let taken = page.take();
        assert_eq!(taken, vec![(b"k".to_vec(), b"v".to_vec())]);
        assert!(
            page.0.is_empty(),
            "the guard still holds what it handed over"
        );
        drop(page);
        assert_eq!(
            taken,
            vec![(b"k".to_vec(), b"v".to_vec())],
            "the drop reached what had already been handed to the caller"
        );

        let mut keys = WipedKeys::new(vec![b"k".to_vec()]);
        let taken = keys.take();
        assert_eq!(taken, vec![b"k".to_vec()]);
        assert!(keys.0.is_empty());
    }

    /// Every page that is built up and can be abandoned uses one of these.
    ///
    /// The first copy of this guard covered the repack's pages alone, and the
    /// index walk went on accumulating plaintext into a bare `Vec` — through
    /// three audit passes — while every `?` in the tree walk below it dropped
    /// that `Vec` unwiped (report27 H02). Source-level because the question is
    /// "what does this function accumulate into", and because the answer it
    /// guards against cannot be observed at runtime: reading a buffer after it
    /// has been freed is undefined behaviour.
    #[test]
    fn the_accumulating_walks_gather_into_a_guarded_page() {
        /// One function's own body: from its signature to wherever the next
        /// one starts.
        ///
        /// A fixed-size window read PAST the end of `list_keys_after` into
        /// `list_after`, found that neighbour's guard, and passed on a
        /// `list_keys_after` restored to the defect — measured, not guessed.
        fn body<'a>(src: &'a str, file: &str, anchor: &str) -> &'a str {
            let at = src
                .find(anchor)
                .unwrap_or_else(|| panic!("{file}: `{anchor}` moved — this guard watches nothing"));
            let rest = &src[at + anchor.len()..];
            let end = rest
                .find("\n    pub fn ")
                .into_iter()
                .chain(rest.find("\n    fn "))
                .min()
                .unwrap_or(rest.len());
            &rest[..end]
        }

        let space = include_str!("space/mod.rs");
        let index = include_str!("space/index.rs");
        for (file, src, anchor) in [
            ("space/mod.rs", space, "pub fn list_keys_after("),
            ("space/mod.rs", space, "pub fn list_after("),
            // The leaf decoder, named by a line only it contains: three types
            // in that file decode, and the leaf is the one holding plaintext.
            (
                "space/index.rs",
                index,
                "\"leaf count exceeds payload bound\"",
            ),
        ] {
            let body = body(src, file, anchor);
            assert!(
                body.contains("WipedPairs::new") || body.contains("WipedKeys::new"),
                "{file}: `{anchor}` accumulates plaintext into a bare Vec — \
                 every early return below drops it unwiped"
            );
        }
    }
}
