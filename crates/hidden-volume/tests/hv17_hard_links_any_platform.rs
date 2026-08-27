//! report17 HV17-M3 — a second NAME for the container, on every platform that
//! has them.
//!
//! The hard-link half of report16 HV16-M3 lived in a test file gated
//! `#![cfg(unix)]`, next to the symlink half that genuinely needs Unix APIs.
//! So on Windows there was no test at all — and no behaviour either: the
//! link count was a hard-coded `1`, which is not "unknown", it is "there are
//! no other names". NTFS hard links exist. A rotation that left one behind
//! returned `Ok`, and the old password went on opening the container through
//! the other name.
//!
//! `std::fs::hard_link` works on both, so this asks the same question on both.
//! On a filesystem with no hard links the creation itself fails and the test
//! says so rather than passing on a link that was never made.

use hidden_volume::Container;
use hidden_volume::container::{ContainerOptions, RepackOptions};
use hidden_volume::space::index::Namespace;
use hidden_volume::{Error, Result};

mod common;
use common::{fast_params, scratch_path};

fn options() -> ContainerOptions {
    ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: hidden_volume::padding::PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

fn repack() -> RepackOptions {
    RepackOptions {
        argon2: Some(fast_params()),
        initial_garbage_chunks: 0,
        padding_policy: Some(hidden_volume::padding::PaddingPolicy::None),
        superblock_replicas: 1,
    }
}

fn seed(path: &std::path::Path, password: &[u8]) {
    let mut c = Container::create_with_options(path, options()).unwrap();
    let mut s = c.create_space(password).unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
    tx.commit().unwrap();
}

fn rotate(path: &std::path::Path, from: &[u8], to: &[u8]) -> Result<()> {
    Container::change_passwords(path, &[(from, to)], repack())
}

/// A rotation cannot revoke a name it was not given, and it must say so.
#[test]
fn a_rotation_with_another_name_pointing_at_it_says_so_on_this_platform() {
    let path = scratch_path();
    let sibling = scratch_path();
    let _ = std::fs::remove_file(&sibling);
    seed(&path, b"old");
    std::fs::hard_link(&path, &sibling)
        .expect("this filesystem has no hard links, so there is nothing to test here");

    let err = rotate(&path, b"old", b"new")
        .expect_err("a rotation that revoked one name of two reported success");
    assert!(
        matches!(err, Error::RenameVisibleAliasesNotRevoked(1)),
        "wrong outcome: {err:?}"
    );

    // The rewrite really did happen at the path that was named...
    let mut rotated = Container::open(&path).unwrap();
    assert!(
        rotated.open_space(b"old").is_err(),
        "the name was not rotated"
    );
    rotated
        .open_space(b"new")
        .expect("the new password opens the name that was rotated");
    drop(rotated);

    // ...and this is what the outcome is about: the other name did not move,
    // and the password somebody rotated because it leaked still opens it.
    let mut old = Container::open(&sibling).unwrap();
    old.open_space(b"old")
        .expect("premise: the other name still holds the pre-rotation container");
    drop(old);

    let _ = std::fs::remove_file(&sibling);
    let _ = std::fs::remove_file(&path);
}

/// CONTROL: with ONE name, the rotation is a plain success.
///
/// Without this, an implementation that answered `AliasesNotRevoked` for every
/// rotation would satisfy the test above — and rotation would be unusable.
#[test]
fn a_rotation_of_a_container_with_one_name_is_a_plain_success() {
    let path = scratch_path();
    seed(&path, b"old");

    rotate(&path, b"old", b"new").expect("an ordinary rotation must succeed");

    let mut c = Container::open(&path).unwrap();
    c.open_space(b"new").expect("the new password opens it");
    assert!(
        c.open_space(b"old").is_err(),
        "the old password still opens it"
    );
    drop(c);

    let _ = std::fs::remove_file(&path);
}
