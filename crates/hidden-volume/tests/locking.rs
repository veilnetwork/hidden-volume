//! File locking tests — exclusive flock prevents concurrent
//! container holders from corrupting the append-only chunk grid.
//!
//! Lock semantics on Unix (Linux/macOS): `flock(LOCK_EX | LOCK_NB)`,
//! per-OFD (open file description). Two separate `File::open` calls
//! produce separate OFDs, so the second `try_lock_exclusive` returns
//! `WouldBlock` → mapped to [`Error::Busy`].
//!
//! Auto-release: lock is dropped when the last open file description
//! referencing it is closed (i.e., when [`Container`] is dropped).

use hidden_volume::{Container, Error};

mod common;
use common::{fast_params, scratch_path};

#[test]
fn create_holds_exclusive_lock() {
    let path = scratch_path();
    let _c1 = Container::create(&path, fast_params()).unwrap();
    // Second open must fail with Busy while _c1 is alive.
    match Container::open(&path).unwrap_err() {
        Error::Busy => {},
        other => panic!("expected Busy, got {other:?}"),
    }
    drop(_c1);
    std::fs::remove_file(&path).ok();
}

#[test]
fn open_holds_exclusive_lock() {
    let path = scratch_path();
    {
        let _ = Container::create(&path, fast_params()).unwrap();
    } // dropped, lock released

    let _c1 = Container::open(&path).unwrap();
    match Container::open(&path).unwrap_err() {
        Error::Busy => {},
        other => panic!("expected Busy, got {other:?}"),
    }
    drop(_c1);
    std::fs::remove_file(&path).ok();
}

#[test]
fn lock_releases_on_drop() {
    let path = scratch_path();
    {
        let _c1 = Container::create(&path, fast_params()).unwrap();
        // _c1 dropped at end of block.
    }
    // Now we can open again.
    let _c2 = Container::open(&path).unwrap();
    drop(_c2);
    std::fs::remove_file(&path).ok();
}

#[test]
fn create_then_open_sequentially_works() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(hidden_volume::space::index::Namespace::SETTINGS, b"k", b"v")
            .unwrap();
        tx.commit().unwrap();
    }

    {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.get(hidden_volume::space::index::Namespace::SETTINGS, b"k")
                .unwrap()
                .as_deref(),
            Some(&b"v"[..])
        );
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn create_existing_file_fails() {
    // create_new fails on existing file (separately from locking).
    let path = scratch_path();
    let _c1 = Container::create(&path, fast_params()).unwrap();
    match Container::create(&path, fast_params()) {
        Err(Error::Io(_)) => {}, // AlreadyExists from create_new
        Err(Error::Busy) => {},  // also acceptable if lock kicked in first
        other => panic!("expected Io/Busy on existing file, got {other:?}"),
    }
    drop(_c1);
    std::fs::remove_file(&path).ok();
}

#[test]
fn three_opens_in_sequence_each_takes_lock_in_turn() {
    let path = scratch_path();
    {
        let _ = Container::create(&path, fast_params()).unwrap();
    }
    for _ in 0..3 {
        let c = Container::open(&path).unwrap();
        // While c is alive, second open fails.
        assert!(matches!(Container::open(&path).unwrap_err(), Error::Busy));
        drop(c);
        // After drop, next iteration succeeds.
    }
    std::fs::remove_file(&path).ok();
}

#[test]
fn busy_error_is_distinct_from_other_errors() {
    let path = scratch_path();
    let _c1 = Container::create(&path, fast_params()).unwrap();

    // Confirm we get Busy, not Io / AuthFailed / etc.
    let err = Container::open(&path).unwrap_err();
    assert!(
        matches!(err, Error::Busy),
        "expected Error::Busy variant, got {err:?}"
    );
    assert_eq!(
        err.to_string(),
        "container file is locked by another holder"
    );
    drop(_c1);
    std::fs::remove_file(&path).ok();
}

#[test]
fn nonexistent_file_returns_io_not_busy() {
    let path = scratch_path();
    let _ = std::fs::remove_file(&path);
    match Container::open(&path).unwrap_err() {
        Error::Io(_) => {},
        other => panic!("expected Io for nonexistent file, got {other:?}"),
    }
}
