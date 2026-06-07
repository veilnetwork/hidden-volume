//! Read-only / shared lock tests.
//!
//! Covers `Container::open_readonly` semantics: shared `flock(LOCK_SH)`,
//! multiple-reader concurrency, write rejection.

use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Error};

mod common;
use common::{fast_params, scratch_path};

fn populate_container(path: &std::path::Path) {
    let mut c = Container::create(path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
    tx.put(Namespace::CONTACTS, b"alice", b"a@x").unwrap();
    tx.commit().unwrap();
}

#[test]
fn readonly_open_succeeds_after_writer_closes() {
    let path = scratch_path();
    populate_container(&path);

    let c = Container::open_readonly(&path).unwrap();
    assert!(c.is_readonly());
    drop(c);
    std::fs::remove_file(&path).ok();
}

#[test]
fn readonly_can_read_data() {
    let path = scratch_path();
    populate_container(&path);

    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace::SETTINGS, b"theme").unwrap().as_deref(),
        Some(&b"dark"[..])
    );
    assert_eq!(
        s.get(Namespace::CONTACTS, b"alice").unwrap().as_deref(),
        Some(&b"a@x"[..])
    );

    drop(s);
    drop(c);
    std::fs::remove_file(&path).ok();
}

#[test]
fn multiple_readers_can_coexist() {
    let path = scratch_path();
    populate_container(&path);

    // Two simultaneous read-only handles — both succeed via shared lock.
    let r1 = Container::open_readonly(&path).unwrap();
    let r2 = Container::open_readonly(&path).unwrap();
    let r3 = Container::open_readonly(&path).unwrap();
    assert!(r1.is_readonly());
    assert!(r2.is_readonly());
    assert!(r3.is_readonly());

    drop(r1);
    drop(r2);
    drop(r3);
    std::fs::remove_file(&path).ok();
}

#[test]
fn writer_blocks_while_reader_active() {
    let path = scratch_path();
    populate_container(&path);

    let _reader = Container::open_readonly(&path).unwrap();
    // Reader holds shared lock → writer (exclusive) must fail with Busy.
    match Container::open(&path) {
        Err(Error::Busy) => {},
        other => panic!("expected Busy while reader active, got {other:?}"),
    }
    drop(_reader);

    // After reader drops, writer succeeds.
    let _writer = Container::open(&path).unwrap();
    drop(_writer);
    std::fs::remove_file(&path).ok();
}

#[test]
fn reader_blocks_while_writer_active() {
    let path = scratch_path();
    populate_container(&path);

    let _writer = Container::open(&path).unwrap();
    // Writer holds exclusive lock → reader (shared) must fail with Busy.
    match Container::open_readonly(&path) {
        Err(Error::Busy) => {},
        other => panic!("expected Busy while writer active, got {other:?}"),
    }
    drop(_writer);

    // After writer drops, reader succeeds.
    let _reader = Container::open_readonly(&path).unwrap();
    drop(_reader);
    std::fs::remove_file(&path).ok();
}

#[test]
fn create_space_on_readonly_returns_readonly_error() {
    let path = scratch_path();
    populate_container(&path);

    let mut c = Container::open_readonly(&path).unwrap();
    match c.create_space(b"new-password") {
        Err(Error::ReadOnly) => {},
        other => panic!("expected ReadOnly, got {other:?}"),
    }

    drop(c);
    std::fs::remove_file(&path).ok();
}

#[test]
fn commit_on_readonly_returns_readonly_error() {
    let path = scratch_path();
    populate_container(&path);

    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"new", b"value").unwrap();
    match tx.commit() {
        Err(Error::ReadOnly) => {},
        other => panic!("expected ReadOnly on commit, got {other:?}"),
    }

    drop(s);
    drop(c);
    std::fs::remove_file(&path).ok();
}

#[test]
fn set_padding_policy_on_readonly_returns_readonly_error() {
    let path = scratch_path();
    populate_container(&path);

    let mut c = Container::open_readonly(&path).unwrap();
    match c.set_padding_policy(PaddingPolicy::None) {
        Err(Error::ReadOnly) => {},
        other => panic!("expected ReadOnly, got {other:?}"),
    }
    match c.set_superblock_replicas(3) {
        Err(Error::ReadOnly) => {},
        other => panic!("expected ReadOnly, got {other:?}"),
    }

    drop(c);
    std::fs::remove_file(&path).ok();
}

/// Audit pass 10 (M1): `Space::set_padding_policy` must mirror
/// `Container::set_padding_policy`'s strict-RO behaviour. Previously
/// it silently mutated `ContainerFile::padding_policy` regardless of
/// the lock mode, which broke the strict-RO contract relied on by the
/// async + FFI wrappers (they reach the policy via `space_mut()`,
/// not via the Container method).
#[test]
fn set_padding_policy_on_readonly_space_returns_readonly_error() {
    let path = scratch_path();
    populate_container(&path);

    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    match s.set_padding_policy(PaddingPolicy::BucketGrowth { bucket_chunks: 64 }) {
        Err(Error::ReadOnly) => {},
        other => panic!("expected Err(ReadOnly), got {other:?}"),
    }
    // Policy must remain unchanged (default `None` from create-time).
    assert_eq!(s.padding_policy(), PaddingPolicy::None);

    drop(s);
    drop(c);
    std::fs::remove_file(&path).ok();
}

#[test]
fn open_space_on_readonly_skips_vacuum_and_explicit_call_errors() {
    // `open_space` normally calls `vacuum_orphans` (a write op).
    // On RO the auto-call is skipped (audit pass 7 L5) so that open
    // succeeds without privilege escalation. An EXPLICIT
    // `vacuum_orphans` call on the same handle now errors with
    // `Error::ReadOnly` — surfacing the failed privacy expectation
    // instead of silently no-op'ing.
    let path = scratch_path();
    populate_container(&path);

    // First create some orphan IndexNodes by replacing values.
    {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        for i in 0..5u8 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"theme", &[i]).unwrap();
            tx.commit().unwrap();
        }
    }

    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Reads still work.
    assert_eq!(
        s.get(Namespace::SETTINGS, b"theme").unwrap().as_deref(),
        Some(&[4u8][..])
    );
    // Explicit vacuum errors with ReadOnly (no longer silent).
    match s.vacuum_orphans() {
        Err(hidden_volume::Error::ReadOnly) => {},
        other => panic!("expected Err(ReadOnly), got {other:?}"),
    }

    drop(s);
    drop(c);
    std::fs::remove_file(&path).ok();
}

#[test]
fn readonly_open_after_writer_drop_works() {
    // Sequential pattern: writer closes, reader opens, reader closes,
    // writer opens. Common in messenger app / sync agent handoff.
    let path = scratch_path();

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"v", b"1").unwrap();
        tx.commit().unwrap();
    }

    {
        let mut c = Container::open_readonly(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.get(Namespace::SETTINGS, b"v").unwrap().as_deref(),
            Some(&b"1"[..])
        );
    }

    {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"v", b"2").unwrap();
        tx.commit().unwrap();
    }

    {
        let mut c = Container::open_readonly(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.get(Namespace::SETTINGS, b"v").unwrap().as_deref(),
            Some(&b"2"[..])
        );
    }

    std::fs::remove_file(&path).ok();
}
