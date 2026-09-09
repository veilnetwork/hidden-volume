//! Two log branches that hold different messages must not share an anchor.
//!
//! `commit_history_with_roots` offers `(seq, root_hash)` as an exact identifier
//! of a branch, and the multi-device guide tells a reader to use it to tell a
//! clean continuation from a fork. It could not: the index tree for a log
//! namespace was built over values that held the batch's SLOT and nothing else,
//! so two copies of one container, appending records of the same shape, placed
//! their batch on the same slot and produced the same pair while holding
//! different messages (report24 HV24-01).
//!
//! The fixture is deliberately the honest case — two ordinary copies, no
//! forgery, no attacker — because that is the case the guide describes.

use hidden_volume::Container;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;

fn scratch(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "hv-log-branch-{tag}-{}-{:?}.bin",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

/// Append one log record with the given body and return the newest anchor.
fn append_and_anchor(path: &std::path::Path, body: &[u8]) -> (u64, [u8; 32]) {
    let mut c = Container::open(path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.append_log(Namespace::MESSAGE_LOG, 1, body).unwrap();
    tx.commit().unwrap();
    *s.commit_history_with_roots()
        .last()
        .expect("a commit leaves an anchor")
}

#[test]
fn two_branches_with_different_messages_have_different_anchors() {
    let a = scratch("a");
    let b = scratch("b");

    // One starting point, copied — the shape a second device has.
    {
        let mut c = Container::create(&a, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.append_log(Namespace::MESSAGE_LOG, 0, b"shared history")
            .unwrap();
        tx.commit().unwrap();
    }
    std::fs::copy(&a, &b).unwrap();

    // Each side appends its own message. Same id, same length, same shape:
    // everything except the bytes.
    let (seq_a, root_a) = append_and_anchor(&a, b"alice writes this");
    let (seq_b, root_b) = append_and_anchor(&b, b"bob writes another");

    assert_eq!(seq_a, seq_b, "premise: the branches are at the same seq");
    assert_ne!(
        root_a, root_b,
        "two branches holding different messages share an anchor, so a fork \
         reads as a clean continuation"
    );

    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
}

#[test]
fn the_same_message_on_both_sides_still_agrees() {
    // The control. An anchor that changed with every write regardless of
    // content would pass the test above and destroy the property it exists
    // for: two devices that did the SAME thing must agree.
    let a = scratch("same-a");
    let b = scratch("same-b");
    {
        let mut c = Container::create(&a, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.append_log(Namespace::MESSAGE_LOG, 0, b"shared history")
            .unwrap();
        tx.commit().unwrap();
    }
    std::fs::copy(&a, &b).unwrap();

    let (seq_a, root_a) = append_and_anchor(&a, b"the very same bytes");
    let (seq_b, root_b) = append_and_anchor(&b, b"the very same bytes");

    assert_eq!(seq_a, seq_b);
    assert_eq!(
        root_a, root_b,
        "the same append on two copies must produce the same anchor"
    );

    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
}
