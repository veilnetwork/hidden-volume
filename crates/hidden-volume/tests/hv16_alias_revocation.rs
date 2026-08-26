//! report16 HV16-H2 / HV16-M3 — a rewrite revokes the NAME it was given.
//!
//! `change_passwords` and `compact_known` write a sibling temp and `rename(2)`
//! it over the path. A rename replaces a lexical NAME, and a name is not the
//! same thing as a file.
//!
//! Through a symlink that difference is the whole operation: the rename
//! replaced the LINK with a new regular file and left the container the link
//! pointed at exactly as it was — same password, same spaces — while the call
//! returned `Ok`. Somebody rotating a leaked password was told the old one was
//! dead. Nothing downstream could catch it: the source was opened by following
//! the link, and the post-rename inode pin compared the new file against
//! itself.
//!
//! A hard link is the other half of the same fact and is not fixable by
//! refusing — the rewrite is correct for the name it was given, and the old
//! inode goes on answering under every other name. That is reported rather
//! than hidden.

#![cfg(unix)]

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

/// THE DEFECT, in one assertion.
#[test]
fn a_rotation_through_a_symlink_is_refused_rather_than_faked() {
    let real = scratch_path();
    let alias = scratch_path();
    let _ = std::fs::remove_file(&alias);
    seed(&real, b"old");
    std::os::unix::fs::symlink(&real, &alias).expect("symlink");

    let before = std::fs::read(&real).unwrap();
    let err = rotate(&alias, b"old", b"new")
        .expect_err("a rewrite that cannot revoke must not report success");

    assert!(
        matches!(err, Error::SourceIsNotARegularFile(_)),
        "refused for the wrong reason: {err:?}"
    );
    assert!(
        std::fs::symlink_metadata(&alias)
            .expect("the alias is still there")
            .file_type()
            .is_symlink(),
        "the alias was replaced by a regular file — which is the defect: the \
         container it pointed at keeps the old password"
    );
    assert_eq!(
        std::fs::read(&real).unwrap(),
        before,
        "the real container was touched"
    );

    // And the old password is still in force, which is what the caller now
    // knows instead of being told otherwise.
    let mut c = Container::open(&real).unwrap();
    c.open_space(b"old")
        .expect("the old password still opens it");
    drop(c);

    let _ = std::fs::remove_file(&alias);
    let _ = std::fs::remove_file(&real);
}

/// A hard link cannot be refused into correctness: the rewrite IS correct for
/// the name it was given. What must not happen is reporting plain success while
/// a second name still opens the pre-rotation container with the old password.
#[test]
fn a_rotation_with_another_name_pointing_at_it_says_so() {
    let path = scratch_path();
    let sibling = scratch_path();
    let _ = std::fs::remove_file(&sibling);
    seed(&path, b"old");
    std::fs::hard_link(&path, &sibling).expect("hard link");

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

    // ...and this is what the outcome is about: the other name did not move.
    let mut old = Container::open(&sibling).unwrap();
    old.open_space(b"old")
        .expect("premise: the other name still holds the pre-rotation container");
    drop(old);

    let _ = std::fs::remove_file(&sibling);
    let _ = std::fs::remove_file(&path);
}

/// Not only links: anything that is not a plain file cannot be rewritten in
/// place, and the caller is told which problem it is rather than being handed
/// whatever errno the open produced.
#[test]
fn a_path_that_is_not_a_file_at_all_is_refused_by_name() {
    let path = scratch_path();
    let _ = std::fs::remove_file(&path);
    std::fs::create_dir(&path).expect("a directory stands in for any non-file");

    let err = rotate(&path, b"old", b"new").expect_err("a directory is not a container");
    assert!(
        matches!(err, Error::SourceIsNotARegularFile(_)),
        "reported as raw I/O rather than as what it is: {err:?}"
    );

    let _ = std::fs::remove_dir(&path);
}

/// Vacuity guard. An ordinary container has one name and is not a link, so it
/// must rotate and report plain success — otherwise both assertions above are
/// satisfied by a library that refuses everything.
#[test]
fn an_ordinary_container_still_rotates_and_says_nothing_else() {
    let path = scratch_path();
    seed(&path, b"old");

    rotate(&path, b"old", b"new").expect("an ordinary rotation must succeed");

    let mut c = Container::open(&path).unwrap();
    assert!(c.open_space(b"old").is_err());
    c.open_space(b"new").expect("the new password works");
    drop(c);

    let _ = std::fs::remove_file(&path);
}

/// And the same rule holds for the other caller of the primitive.
#[test]
fn compaction_through_a_symlink_is_refused_too() {
    let real = scratch_path();
    let alias = scratch_path();
    let _ = std::fs::remove_file(&alias);
    seed(&real, b"keep");
    std::os::unix::fs::symlink(&real, &alias).expect("symlink");

    let err = Container::compact_known(&alias, &[b"keep".as_slice()], repack())
        .expect_err("compaction through an alias must be refused");
    assert!(
        matches!(err, Error::SourceIsNotARegularFile(_)),
        "refused for the wrong reason: {err:?}"
    );

    let _ = std::fs::remove_file(&alias);
    let _ = std::fs::remove_file(&real);
}
