//! Sentinel for the plaintext-redaction contract (audit HV-01, HV-07).
//!
//! Everything a `{:?}` can reach from a public type is formatted here with
//! recognisable markers as the key, the value and the log payload, and the
//! resulting strings are searched for those markers in every shape a
//! `Debug` impl could render them: as text, as the `[72, 86, ...]` byte
//! array a derived `Debug` on `Vec<u8>` produces, and as a bare
//! comma-separated tail (so a *truncated* print is caught too).
//!
//! The rule these tests exist to defend is in [`hidden_volume::redact`]:
//! plaintext-bearing fields are `Redacted<T>`, and their carriers' `Debug`
//! is an allow-list ending in `finish_non_exhaustive()`. The second half is
//! what makes a *newly added* field safe without anyone remembering to do
//! anything — see `new_field_on_a_carrier_is_invisible_by_default`, which
//! is the standing version of the break-check probe that added a real
//! plaintext field to `LeafNode` and confirmed it never appeared.

use hidden_volume::Container;
use hidden_volume::redact::Redacted;
use hidden_volume::space::index::{ChildPointer, IndexNode, InternalNode, LeafNode, Namespace};

mod common;
use common::fast_params;

const KEY: &[u8] = b"HVSENTINEL-KEY-a7f3";
const VALUE: &[u8] = b"HVSENTINEL-VALUE-91cc";
const PAYLOAD: &[u8] = b"HVSENTINEL-PAYLOAD-4b2d";

/// Every rendering of `secret` a `Debug` impl could plausibly emit.
///
/// The third entry is the numeric form of the marker's tail rather than the
/// whole of it: a print that stopped early — a truncating formatter, a
/// `{:.32?}`, a field that only carries the key's suffix — still trips the
/// assertion instead of sliding past a whole-string comparison.
fn renderings(secret: &[u8]) -> Vec<String> {
    let numeric: Vec<String> = secret.iter().map(u8::to_string).collect();
    vec![
        String::from_utf8(secret.to_vec()).expect("markers are ASCII"),
        format!("{secret:?}"),
        numeric[numeric.len() - 8..].join(", "),
    ]
}

/// The rendering of one field out of a `debug_struct` output, from
/// `"<field>: "` up to `", <next>: "`.
///
/// Needed because the marker-search above is only as good as the markers
/// *reaching* the field: `SpaceState::roots_payload_cache` holds a decrypted
/// `CommitPayload` — namespace bytes, slot numbers, Merkle hashes — and
/// never the caller's key or value. A leak there is invisible to a search
/// for `HVSENTINEL-*`, so that field is checked by shape instead. (The
/// break-check found exactly this: weakening `Redacted`'s `Debug` broke six
/// tests here and left the `Space` one green.)
#[track_caller]
fn debug_field<'a>(rendered: &'a str, field: &str, next_field: &str) -> &'a str {
    let head = format!("{field}: ");
    let start = rendered
        .find(&head)
        .unwrap_or_else(|| panic!("no `{field}` in: {rendered}"))
        + head.len();
    let tail = format!(", {next_field}: ");
    let len = rendered[start..]
        .find(&tail)
        .unwrap_or_else(|| panic!("no `{next_field}` after `{field}` in: {rendered}"));
    &rendered[start..start + len]
}

#[track_caller]
fn assert_no_plaintext(what: &str, rendered: &str) {
    for (name, secret) in [("key", KEY), ("value", VALUE), ("payload", PAYLOAD)] {
        for form in renderings(secret) {
            assert!(
                !rendered.contains(&form),
                "{what} leaked the {name} (as `{form}`): {rendered}"
            );
        }
    }
}

fn leaf_with_marker() -> LeafNode {
    LeafNode {
        namespace: Namespace::CONTACTS,
        entries: Redacted::new(vec![(KEY.to_vec(), VALUE.to_vec())]),
    }
}

fn child_with_marker() -> ChildPointer {
    ChildPointer {
        first_key: Redacted::new(KEY.to_vec()),
        child_slot: 7,
        child_hash: [0u8; 32],
    }
}

#[test]
fn leaf_node_debug_shows_counts_not_entries() {
    let leaf = leaf_with_marker();
    let rendered = format!("{leaf:?}");
    assert_no_plaintext("LeafNode", &rendered);
    // Still says the useful thing: one entry, key + value bytes.
    assert!(rendered.contains("items: 1"), "{rendered}");
    assert!(
        rendered.contains(&format!("bytes: {}", KEY.len() + VALUE.len())),
        "{rendered}"
    );
}

#[test]
fn child_pointer_debug_shows_counts_not_first_key() {
    let child = child_with_marker();
    let rendered = format!("{child:?}");
    assert_no_plaintext("ChildPointer", &rendered);
    assert!(
        rendered.contains(&format!("bytes: {}", KEY.len())),
        "{rendered}"
    );
}

#[test]
fn internal_node_debug_does_not_leak_through_its_children() {
    let node = InternalNode {
        namespace: Namespace::CONTACTS,
        children: vec![child_with_marker()],
    };
    assert_no_plaintext("InternalNode", &format!("{node:?}"));
    assert_no_plaintext(
        "IndexNode::Internal",
        &format!("{:?}", IndexNode::Internal(node)),
    );
}

#[test]
fn index_node_enum_does_not_leak_through_its_leaf() {
    assert_no_plaintext(
        "IndexNode::Leaf",
        &format!("{:?}", IndexNode::Leaf(leaf_with_marker())),
    );
}

#[test]
fn decoded_leaf_keeps_its_entries_wrapped() {
    // HV-07 at the type level, in the shape `tests/plaintext_hygiene.rs`
    // uses: if `decode` ever hands back a bare `Vec` again, this stops
    // compiling. The runtime half is that the decoded node — built from
    // freshly AEAD-opened bytes — is as redacted as a hand-built one.
    let bytes = leaf_with_marker().encode().unwrap();
    let decoded = LeafNode::decode(&bytes).unwrap();
    let _: &Redacted<Vec<(Vec<u8>, Vec<u8>)>> = &decoded.entries;
    assert_eq!(decoded.entries.len(), 1);
    assert_no_plaintext("decoded LeafNode", &format!("{decoded:?}"));
}

#[test]
fn tx_debug_shows_neither_pending_kv_nor_pending_log() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, KEY, VALUE).unwrap();
    tx.append_log(Namespace::MESSAGE_LOG, 1, PAYLOAD).unwrap();
    let rendered = format!("{tx:?}");
    assert_no_plaintext("Tx", &rendered);
    // The counts survive: one KV op, one log record.
    assert!(rendered.contains("pending_kv"), "{rendered}");
    assert!(rendered.contains("pending_log"), "{rendered}");
    assert!(
        rendered.contains(&format!("bytes: {}", KEY.len() + VALUE.len())),
        "{rendered}"
    );
    assert!(
        rendered.contains(&format!("bytes: {}", PAYLOAD.len())),
        "{rendered}"
    );
    tx.commit().unwrap();

    std::fs::remove_file(&path).ok();
}

#[test]
fn space_debug_does_not_leak_the_decrypted_roots_cache() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, KEY, VALUE).unwrap();
    tx.commit().unwrap();

    // Warms `SpaceState::roots_payload_cache` with a decrypted Commit
    // payload — the field that used to be a `Zeroizing<Vec<u8>>`, which
    // scrubs but derives `Debug` and therefore printed its bytes.
    assert_eq!(
        s.get(Namespace::CONTACTS, KEY).unwrap().as_deref(),
        Some(VALUE)
    );

    let rendered = format!("{s:?}");
    assert_no_plaintext("Space", &rendered);

    let cache = debug_field(&rendered, "roots_payload_cache", "attempted_seq");
    assert!(
        cache.starts_with("Some(("),
        "the cache must be warm or this test proves nothing: {cache}"
    );
    assert!(
        cache.contains("Redacted { items: 1, bytes: "),
        "roots cache is not rendered as a shape: {cache}"
    );
    assert!(
        !cache.contains('['),
        "roots cache rendered raw plaintext bytes: {cache}"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn new_field_on_a_carrier_is_invisible_by_default() {
    // The standing form of the "new secret field" probe. `redacted_debug!`
    // ends in `finish_non_exhaustive()`, so a carrier prints ONLY the
    // fields its allow-list names. This test pins the observable
    // consequence: `Space` has seven fields' worth of state behind it and
    // `Tx` has a `space` back-reference, and neither impl enumerates
    // everything it holds.
    //
    // The break-check that produced this test added a real
    // `probe: Vec<u8>` field carrying the marker to `LeafNode` and
    // confirmed it never reached the output; swapping the macro for
    // `#[derive(Debug)]` made the same field appear immediately.
    let leaf = leaf_with_marker();
    let rendered = format!("{leaf:?}");
    assert!(
        rendered.ends_with(".. }"),
        "carrier Debug must be non-exhaustive so unlisted fields stay unprinted: {rendered}"
    );

    let child = child_with_marker();
    assert!(format!("{child:?}").ends_with(".. }"));
}

/// A pending KV op must not be copyable out of the wrapper that wipes it.
///
/// `Tx::pending_kv` is a `Redacted<PendingKv>`, and what makes that wrapper
/// worth anything is its `Drop`: it scrubs the plaintext keys and values the
/// transaction is holding. A `KvOp` that could be cloned is a copy of that
/// plaintext living outside the wrapper, dropped by the ordinary `Vec` path
/// with nothing wiping it — and `Redacted<T>` is itself `Clone` whenever its
/// contents are, so the derive quietly made the whole pending map copyable.
///
/// Nothing cloned one; the derive was the capability alone (report17). This
/// reads the declaration rather than trying to call `.clone()`, because a test
/// that failed to compile would be a test nobody could run.
#[test]
fn a_pending_kv_op_is_not_cloneable() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tx/mod.rs"),
    )
    .expect("the transaction module");

    let at = source
        .find("pub(crate) enum KvOp {")
        .expect("KvOp moved; re-anchor this guard");

    // The ATTRIBUTE lines above the declaration, not the prose: the doc
    // comment right above it explains why the derive is gone, and a scan for
    // the word matched that explanation -- a guard reading its own reasoning.
    let attributes: Vec<&str> = source[..at]
        .lines()
        .rev()
        .take_while(|l| {
            let t = l.trim_start();
            t.starts_with("#[") || t.starts_with("///") || t.is_empty()
        })
        .filter(|l| l.trim_start().starts_with("#["))
        .collect();

    for attribute in &attributes {
        assert!(
            !attribute.contains("Clone") && !attribute.contains("Copy"),
            "KvOp is copyable again: {attribute}\n\
             a duplicated pending op is plaintext the Redacted wrapper never wipes"
        );
    }
}
