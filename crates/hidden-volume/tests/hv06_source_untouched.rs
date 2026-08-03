//! Audit HV-06 — an abandoned in-place rewrite must leave the source
//! byte-identical.
//!
//! `compact_known` and `change_passwords` write a fresh container to a temp
//! path and `rename(2)` it over the original, and their contract says: "on any
//! failure the temp is removed and the original `path` is untouched".
//!
//! It was not. The primitive behind both opened the source with
//! `Container::open` — a read-WRITE handle — and the repack's `open_space`
//! then ran the maintenance every read-write open runs on its own initiative:
//! `vacuum_orphans` scrubs orphan IndexNode chunks, and the self-heal
//! checkpoint publishes a bumped-seq superblock. Both rewrite the file. A
//! rotation that failed at the very last step, or one the user cancelled, had
//! therefore already edited the file it promised not to touch.
//!
//! For a deniable container this is not a cosmetic difference. An observer who
//! holds a copy of the bytes from before an abandoned rotation and a copy from
//! after can see they differ, which is evidence that something ran — and the
//! caller was told the operation failed and nothing happened.
//!
//! Every assertion here compares CONTENT, not mtime or length: a scrub
//! overwrites a chunk in place, so length is unchanged and mtime is a property
//! of the filesystem, not of the promise.

use hidden_volume::Container;
use hidden_volume::container::{ContainerOptions, RepackOptions};
use hidden_volume::space::index::Namespace;

mod common;
use common::{fast_params, scratch_path};

fn fast_container_options(initial_garbage_chunks: u64) -> ContainerOptions {
    ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks,
        padding_policy: hidden_volume::padding::PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

fn fast_repack_options() -> RepackOptions {
    RepackOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: hidden_volume::padding::PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

/// Leave the container holding an orphan IndexNode that a writable open would
/// scrub: put an entry, commit, delete it, commit. The delete's commit is
/// append-only, so the put's IndexNode is still on disk and unreachable — and
/// no vacuum has run since, because the handle is dropped without reopening.
fn seed_with_a_pending_orphan(path: &std::path::Path, password: &[u8]) {
    let mut c = Container::create_with_options(path, fast_container_options(0)).unwrap();
    let mut s = c.create_space(password).unwrap();

    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
    tx.commit().unwrap();

    let mut tx = s.begin_tx();
    tx.delete(Namespace::CONTACTS, b"alice").unwrap();
    tx.commit().unwrap();
}

/// A compaction that fails AFTER the source has been opened must leave the
/// source byte-identical.
///
/// The failure is placed deliberately late: the first password opens its space
/// (which is where the old code ran the vacuum), the second does not exist, so
/// the repack errors on the second iteration of its loop. A wrong password in
/// FIRST position would fail before the source space was ever opened and would
/// prove nothing.
#[test]
fn a_failed_compaction_leaves_the_source_byte_identical() {
    let path = scratch_path();
    seed_with_a_pending_orphan(&path, b"keep");

    let before = std::fs::read(&path).unwrap();

    let err = Container::compact_known(
        &path,
        &[b"keep".as_slice(), b"no-such-space".as_slice()],
        fast_repack_options(),
    )
    .expect_err("the second password matches no space, so the repack must fail");

    let after = std::fs::read(&path).unwrap();
    assert_eq!(
        before.len(),
        after.len(),
        "the source changed SIZE during a failed compaction ({err:?})"
    );
    assert!(
        before == after,
        "the source changed CONTENT during a failed compaction ({err:?}): the \
         rewrite promised the original was untouched, and an observer holding \
         both copies can see that it was not"
    );

    // Nothing but the source is left in the directory either — the temp must
    // be gone, or the next operation inherits it.
    assert_no_stray_temp(&path);

    let _ = std::fs::remove_file(&path);
}

/// Same for `change_passwords`, the other caller of the primitive. Its stake is
/// higher: it is the path a user takes after a password leak.
#[test]
fn a_failed_rotation_leaves_the_source_byte_identical() {
    let path = scratch_path();
    seed_with_a_pending_orphan(&path, b"old");

    let before = std::fs::read(&path).unwrap();

    let err = Container::change_passwords(
        &path,
        &[
            (b"old".as_slice(), b"new".as_slice()),
            (b"no-such-space".as_slice(), b"whatever".as_slice()),
        ],
        fast_repack_options(),
    )
    .expect_err("the second pair matches no space, so the rotation must fail");

    let after = std::fs::read(&path).unwrap();
    assert!(
        before == after,
        "the source changed during a failed rotation ({err:?})"
    );

    // The old password must still work — a rotation that reports failure has
    // not rotated anything.
    let mut c = Container::open(&path).unwrap();
    c.open_space(b"old")
        .expect("a failed rotation must leave the original password in force");
    drop(c);

    let _ = std::fs::remove_file(&path);
}

/// The second maintenance path: the self-heal checkpoint.
///
/// `vacuum_orphans` only writes when there is an orphan to scrub, so a test
/// built on it alone would go green the day the vacuum's trigger changes. The
/// checkpoint has an independent trigger — a container at or above
/// `CHECKPOINT_MIN_TOTAL` (4096 slots) with no checkpoint yet — and publishes a
/// bumped-seq superblock, which is a write of a different shape in a different
/// place.
#[test]
fn a_failed_compaction_does_not_publish_a_checkpoint_into_the_source() {
    let path = scratch_path();

    {
        // 5000 garbage chunks puts the container over CHECKPOINT_MIN_TOTAL, so
        // a read-write open would self-heal a checkpoint into it.
        let mut c = Container::create_with_options(&path, fast_container_options(5000)).unwrap();
        let mut s = c.create_space(b"keep").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
        tx.commit().unwrap();
    }

    let before = std::fs::read(&path).unwrap();

    let err = Container::compact_known(
        &path,
        &[b"keep".as_slice(), b"no-such-space".as_slice()],
        fast_repack_options(),
    )
    .expect_err("the second password matches no space, so the repack must fail");

    let after = std::fs::read(&path).unwrap();
    assert_eq!(
        before.len(),
        after.len(),
        "a checkpoint was APPENDED to the source by a failed compaction ({err:?})"
    );
    assert!(
        before == after,
        "the source changed during a failed compaction ({err:?})"
    );

    let _ = std::fs::remove_file(&path);
}

/// The successful path must still do its job — the guard above must not have
/// been bought by making the rewrite a no-op.
#[test]
fn a_successful_rotation_still_rotates() {
    let path = scratch_path();
    seed_with_a_pending_orphan(&path, b"old");

    Container::change_passwords(
        &path,
        &[(b"old".as_slice(), b"new".as_slice())],
        fast_repack_options(),
    )
    .expect("a rotation with a matching password must succeed");

    let mut c = Container::open(&path).unwrap();
    assert!(
        c.open_space(b"old").is_err(),
        "the old password must be dead after a successful rotation"
    );
    drop(c);
    let mut c = Container::open(&path).unwrap();
    c.open_space(b"new")
        .expect("the new password must open the rotated container");

    let _ = std::fs::remove_file(&path);
}

/// The maintenance-free handle still takes the EXCLUSIVE lock. Dropping the
/// write permission must not have quietly downgraded it to a shared one — that
/// would reopen the lost-update race the primitive holds the lock to prevent.
#[test]
fn the_maintenance_free_handle_still_excludes_every_other_holder() {
    let path = scratch_path();
    seed_with_a_pending_orphan(&path, b"pw");

    let held = Container::open_exclusive_readonly(&path).unwrap();
    assert!(held.is_readonly(), "the handle must refuse writes");

    assert!(
        matches!(Container::open(&path), Err(hidden_volume::Error::Busy)),
        "a writer must be excluded while the maintenance-free handle lives"
    );
    assert!(
        matches!(
            Container::open_readonly(&path),
            Err(hidden_volume::Error::Busy)
        ),
        "a shared reader must be excluded too — the lock is LOCK_EX, not LOCK_SH"
    );

    drop(held);
    Container::open(&path).expect("the lock must be released on drop");

    let _ = std::fs::remove_file(&path);
}

/// Reading through the maintenance-free handle must not touch the file either.
/// This is the property in isolation, with no rewrite around it.
#[test]
fn opening_a_space_through_the_maintenance_free_handle_writes_nothing() {
    let path = scratch_path();
    seed_with_a_pending_orphan(&path, b"pw");

    let before = std::fs::read(&path).unwrap();
    {
        let mut c = Container::open_exclusive_readonly(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert!(
            s.get(Namespace::CONTACTS, b"alice").unwrap().is_none(),
            "the entry was deleted before the handle was dropped"
        );
        // An explicit maintenance call is refused rather than silently skipped.
        assert!(matches!(
            s.vacuum_orphans(),
            Err(hidden_volume::Error::ReadOnly)
        ));
    }
    let after = std::fs::read(&path).unwrap();
    assert!(
        before == after,
        "reading a space through the maintenance-free handle rewrote the file"
    );

    let _ = std::fs::remove_file(&path);
}

/// No `.<name>.hv-compact.*.tmp` / `.hv-rotate.*` sibling survives a failure.
fn assert_no_stray_temp(path: &std::path::Path) {
    let parent = path.parent().unwrap();
    let stem = path.file_name().unwrap().to_str().unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(&format!(".{stem}.")) && n.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed rewrite left its temp behind: {leftovers:?}"
    );
}
