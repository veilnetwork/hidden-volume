//! Cooperative cancellation (v0.7).
//!
//! Coverage:
//! 1. Token starts not-cancelled; `cancel()` flips; clones share state.
//! 2. `check()` returns `Err(Cancelled)` after cancel.
//! 3. Pre-fired token: `open_space_cancellable` aborts before any scan
//!    work (post-Argon2 cancel point fires immediately).
//! 4. Mid-scan cancel: a separate thread fires cancel during scan;
//!    operation returns `Cancelled` without corrupting the file.
//! 5. Cancel is idempotent (multiple `cancel()` calls do nothing).
//! 6. Reusing a token after cancel: subsequent operations also abort.
//! 7. A NEW token after a cancelled one starts fresh (not pre-cancelled).
//! 8. Non-cancellable open paths are unaffected by an unrelated token.
//!
//! NB: Argon2id derivation itself isn't cancellable (RustCrypto is
//! uninterruptible), so tests use `Argon2Params::MIN` to keep the
//! pre-scan window negligible.

use hidden_volume::cancel::CancelToken;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Error};

mod common;
use common::{fast_params, scratch_path};

#[test]
fn token_starts_not_cancelled() {
    let t = CancelToken::new();
    assert!(!t.is_cancelled());
    assert!(t.check().is_ok());
}

#[test]
fn cancel_flips_flag_observable_via_clone() {
    let t = CancelToken::new();
    let t2 = t.clone();
    assert!(!t.is_cancelled());
    assert!(!t2.is_cancelled());
    t.cancel();
    assert!(t.is_cancelled());
    assert!(t2.is_cancelled(), "clone shares state via Arc");
    assert!(matches!(t.check(), Err(Error::Cancelled)));
    assert!(matches!(t2.check(), Err(Error::Cancelled)));
}

#[test]
fn cancel_is_idempotent() {
    let t = CancelToken::new();
    t.cancel();
    t.cancel();
    t.cancel();
    assert!(t.is_cancelled());
}

#[test]
fn fresh_token_after_cancelled_one_is_independent() {
    let cancelled = CancelToken::new();
    cancelled.cancel();
    let fresh = CancelToken::new();
    assert!(cancelled.is_cancelled());
    assert!(
        !fresh.is_cancelled(),
        "fresh tokens are not affected by old ones"
    );
}

#[test]
fn pre_fired_token_aborts_open_immediately() {
    // Build a real container so derive_keys + scan have something to do,
    // then fire cancel BEFORE calling open_space_cancellable.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }

    let token = CancelToken::new();
    token.cancel();

    let mut c = Container::open(&path).unwrap();
    let result = c.open_space_cancellable(b"pw", &token);
    match result {
        Err(Error::Cancelled) => {},
        other => panic!("expected Cancelled, got {other:?}"),
    }
}

#[test]
fn mid_scan_cancel_aborts_without_file_damage() {
    // Build a container with enough chunks that the scan loop iterates
    // many times. Fire cancel from a separate thread shortly after
    // open_space_cancellable starts.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..200u32 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, format!("k{i:03}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
    }

    let token = CancelToken::new();
    let cancel_arm = token.clone();
    let _h = std::thread::spawn(move || {
        // Tiny wait to land mid-scan. The 200-commit scan takes O(ms)
        // even on weak HW; firing immediately is fine — the post-Argon2
        // check or an early CANCEL_POLL_PERIOD checkpoint will catch it.
        std::thread::sleep(std::time::Duration::from_millis(1));
        cancel_arm.cancel();
    });

    let mut c = Container::open(&path).unwrap();
    let result = c.open_space_cancellable(b"pw", &token);
    match result {
        Err(Error::Cancelled) => {},
        // Race: scan may have completed before cancel fired (very fast
        // hardware). Tolerate Ok as long as we got a clean state.
        Ok(_) => { /* race won by scan */ },
        other => panic!("unexpected result: {other:?}"),
    }
    drop(c);

    // Reopen normally — file must still be intact and password works.
    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 201, "no file damage from cancelled scan");
}

#[test]
fn token_reuse_after_cancel_keeps_aborting() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }

    let token = CancelToken::new();
    token.cancel();

    let mut c = Container::open(&path).unwrap();
    assert!(matches!(
        c.open_space_cancellable(b"pw", &token),
        Err(Error::Cancelled)
    ));
    // Same already-cancelled token: still aborts.
    assert!(matches!(
        c.open_space_cancellable(b"pw", &token),
        Err(Error::Cancelled)
    ));
}

#[test]
fn unrelated_token_does_not_affect_normal_open() {
    // open_space (not _cancellable) ignores the token entirely.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    let stale = CancelToken::new();
    stale.cancel(); // pre-fired but irrelevant to non-cancellable API

    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 2);
    drop(s);
    // Token stays cancelled regardless.
    assert!(stale.is_cancelled());
}

#[test]
fn open_space_with_keys_cancellable_post_argon2_path() {
    // derive_space_keys + open_space_with_keys_cancellable separates
    // the (uninterruptible) Argon2 step from the cancellable scan.
    // Verify a pre-fired token aborts the scan after pre-derivation.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }

    let mut c = Container::open(&path).unwrap();
    let keys = c.derive_space_keys(b"pw").unwrap();

    let token = CancelToken::new();
    token.cancel();
    match c.open_space_with_keys_cancellable(keys, &token) {
        Err(Error::Cancelled) => {},
        other => panic!("expected Cancelled, got {other:?}"),
    }
}

// Async cancellation smoke test moved to crates/hidden-volume-async/tests/.
