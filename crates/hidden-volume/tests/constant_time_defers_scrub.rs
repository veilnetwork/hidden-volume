//! The constant-time open does no maintenance, and the maintenance still
//! happens when asked for (audit HV-01).
//!
//! `Container::open_space*_constant_time` equalizes the discovery scan so
//! the unlock's duration cannot say whether a password matched — and then
//! ran `vacuum_orphans` inline. That walk reads every non-visible chunk
//! among the reachable ones, overwrites the orphans and fsyncs:
//! milliseconds and disk writes, both proportional to how much history the
//! space has, and reached only on the success path, since a wrong password
//! returns from `open_constant_time` before that line. Whoever was
//! watching the process or the filesystem while the password was typed
//! could read the answer off it — the exact coercion setting the equalizer
//! exists for. It is the same finding `MultiSpace` closed one audit
//! earlier (`tests/multi_space.rs`), on a path that had no test at all.
//!
//! Both halves are pinned here, because removing the call is also how you
//! silently cancel forward secrecy for every caller:
//!
//! 1. the constant-time open must NOT reclaim, and
//! 2. `Space::vacuum_after_open` must — stated positively, so a "fix" that
//!    just deletes the maintenance fails this file rather than passing it.

use hidden_volume::Container;
use hidden_volume::container::ContainerOptions;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;

mod common;
use common::{fast_params, scratch_path};

fn fast_options() -> ContainerOptions {
    ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

/// Build a container that owes a scrub: write entries, then delete them.
/// The delete only unlinks — the index nodes holding the old values stay
/// on disk and stay decryptable with the password, which is what an
/// adversary holding an old snapshot goes after.
fn container_owing_a_scrub(path: &std::path::Path) {
    let mut c = Container::create_with_options(path, fast_options()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for i in 0..20u32 {
        tx.put(Namespace::SETTINGS, format!("k{i:02}").as_bytes(), b"v")
            .unwrap();
    }
    tx.commit().unwrap();
    let mut tx = s.begin_tx();
    for i in 0..20u32 {
        tx.delete(Namespace::SETTINGS, format!("k{i:02}").as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();
}

/// Half one: the open leaves the orphans alone. Half two: the explicit
/// call reclaims them.
#[test]
fn constant_time_open_defers_the_scrub_and_vacuum_after_open_performs_it() {
    let path = scratch_path();
    container_owing_a_scrub(&path);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space_constant_time(b"pw").unwrap();

    let after_open = s.audit_owned_chunk_count();
    assert!(
        after_open > 0,
        "precondition: the deleted entries' chunks must still be owned \
         right after a constant-time open — if they were already gone this \
         test would pass without the explicit vacuum doing anything"
    );

    let scrubbed = s.vacuum_after_open().unwrap();
    let after_vacuum = s.audit_owned_chunk_count();

    assert!(
        scrubbed > 0,
        "vacuum_after_open reclaimed nothing; the scrub the open deferred \
         is simply not happening any more, and every deleted value stays \
         readable to whoever later gets the password"
    );
    assert!(
        after_vacuum < after_open,
        "vacuum_after_open must reclaim what the deferred open left behind \
         ({after_open} -> {after_vacuum})"
    );

    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// The `SpaceKeys` entry point is the one the FFI master-space path takes,
/// so it gets the same pin rather than inheriting the password variant's.
#[test]
fn the_keys_variant_defers_it_too() {
    let path = scratch_path();
    container_owing_a_scrub(&path);
    let keys = {
        let c = Container::open(&path).unwrap();
        c.derive_space_keys(b"pw").unwrap()
    };

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space_with_keys_constant_time(keys).unwrap();
    let after_open = s.audit_owned_chunk_count();
    assert!(after_open > 0, "precondition: chunks still owned");
    assert!(
        s.vacuum_after_open().unwrap() > 0,
        "the keys variant's deferred scrub never happens"
    );
    assert!(s.audit_owned_chunk_count() < after_open);

    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// The contrast that makes the first assertion mean something: the DEFAULT
/// open is not the constant-time one and still scrubs inline. Without this
/// a fixture that simply had nothing to reclaim would look identical.
#[test]
fn the_ordinary_open_still_scrubs_inline() {
    let path = scratch_path();
    container_owing_a_scrub(&path);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.vacuum_after_open().unwrap(),
        0,
        "the default open path is supposed to have already scrubbed, so \
         there must be nothing left for an explicit call to reclaim"
    );

    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}

/// A read-only handle owes nothing and must not fail: hosts call this
/// unconditionally after every open, and a container someone mounted
/// read-only would otherwise break them. `Ok(0)` means "nothing could be
/// done", not "the scrub ran" — the same contract `MultiSpace::vacuum_hosted`
/// has.
#[test]
fn a_read_only_handle_answers_zero_rather_than_failing() {
    let path = scratch_path();
    container_owing_a_scrub(&path);

    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space_constant_time(b"pw").unwrap();
    assert_eq!(s.vacuum_after_open().unwrap(), 0);
    // The strict sibling still refuses, so the tolerance lives in the new
    // method and did not leak into the old one.
    assert!(matches!(
        s.vacuum_orphans(),
        Err(hidden_volume::Error::ReadOnly)
    ));

    drop(s);
    drop(c);
    let _ = std::fs::remove_file(&path);
}
