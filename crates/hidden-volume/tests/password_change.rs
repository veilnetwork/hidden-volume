//! `Container::change_passwords` — in-place password rotation (v0.7.x).
//!
//! Coverage:
//! 1. Single-space rotation: old password stops working, new one works,
//!    KV/log state preserved.
//! 2. Multi-space, rotate one — others preserved verbatim.
//! 3. Multi-space, rotate two simultaneously.
//! 4. Wrong old password → `AuthFailed`, original file untouched.
//! 5. Two `write_as` collide in same mapping → `SpaceAlreadyExists`,
//!    temp removed, original untouched.
//! 6. Spaces NOT in mapping are dropped (matches `compact_known`
//!    semantics).
//! 7. No-op rotation (open_with == write_as for all entries) is
//!    behaviourally identical to `compact_known`.
//! 8. Cancellable variant: pre-fired token aborts before rename;
//!    temp removed, original untouched.

use hidden_volume::cancel::CancelToken;
use hidden_volume::container::RepackOptions;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Error};

mod common;
use common::{fast_params, scratch_path};

fn fast_repack_options() -> RepackOptions {
    RepackOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 3,
    }
}

fn build_single_space(path: &std::path::Path, password: &[u8], n_msgs: u64) {
    let mut c = Container::create(path, fast_params()).unwrap();
    let mut s = c.create_space(password).unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"username", b"alice").unwrap();
    tx.put(Namespace::CONTACTS, b"bob", b"@bob").unwrap();
    for id in 1..=n_msgs {
        tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id}").as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();
}

fn build_two_spaces(path: &std::path::Path, a_pw: &[u8], b_pw: &[u8]) {
    let mut c = Container::create(path, fast_params()).unwrap();
    {
        let mut s = c.create_space(a_pw).unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"who", b"alice").unwrap();
        tx.commit().unwrap();
    }
    {
        let mut s = c.create_space(b_pw).unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"who", b"bob").unwrap();
        tx.commit().unwrap();
    }
}

#[test]
fn single_space_rotation_succeeds() {
    let path = scratch_path();
    build_single_space(&path, b"old-pw", 20);

    let old: &[u8] = b"old-pw";
    let new: &[u8] = b"new-pw";
    Container::change_passwords(&path, &[(old, new)], fast_repack_options()).unwrap();

    // Old password no longer works.
    let mut c = Container::open(&path).unwrap();
    assert!(matches!(c.open_space(old), Err(Error::AuthFailed)));

    // New password works; KV/log state preserved.
    let mut s = c.open_space(new).unwrap();
    assert_eq!(
        s.get(Namespace::SETTINGS, b"username").unwrap().as_deref(),
        Some(&b"alice"[..])
    );
    let log = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
    assert_eq!(log.len(), 20);
}

#[test]
fn multi_space_rotate_one_preserve_other() {
    let path = scratch_path();
    build_two_spaces(&path, b"alice-old", b"bob-keep");

    let alice_old: &[u8] = b"alice-old";
    let alice_new: &[u8] = b"alice-new";
    let bob_keep: &[u8] = b"bob-keep";
    Container::change_passwords(
        &path,
        &[(alice_old, alice_new), (bob_keep, bob_keep)],
        fast_repack_options(),
    )
    .unwrap();

    let mut c = Container::open(&path).unwrap();
    // Alice: old fails, new works.
    assert!(matches!(c.open_space(alice_old), Err(Error::AuthFailed)));
    let mut a = c.open_space(alice_new).unwrap();
    assert_eq!(
        a.get(Namespace::SETTINGS, b"who").unwrap().as_deref(),
        Some(&b"alice"[..])
    );
    drop(a);
    // Bob: same password, state preserved.
    let mut b = c.open_space(bob_keep).unwrap();
    assert_eq!(
        b.get(Namespace::SETTINGS, b"who").unwrap().as_deref(),
        Some(&b"bob"[..])
    );
}

#[test]
fn rotate_both_spaces_at_once() {
    let path = scratch_path();
    build_two_spaces(&path, b"a-old", b"b-old");

    let a_old: &[u8] = b"a-old";
    let a_new: &[u8] = b"a-new";
    let b_old: &[u8] = b"b-old";
    let b_new: &[u8] = b"b-new";
    Container::change_passwords(
        &path,
        &[(a_old, a_new), (b_old, b_new)],
        fast_repack_options(),
    )
    .unwrap();

    let mut c = Container::open(&path).unwrap();
    assert!(matches!(c.open_space(a_old), Err(Error::AuthFailed)));
    assert!(matches!(c.open_space(b_old), Err(Error::AuthFailed)));
    assert!(c.open_space(a_new).is_ok());
    assert!(c.open_space(b_new).is_ok());
}

#[test]
fn wrong_old_password_returns_authfailed_and_leaves_original_intact() {
    let path = scratch_path();
    build_single_space(&path, b"actual-pw", 5);
    let tmp_path = path.with_extension("hv-rotate-tmp");

    let wrong: &[u8] = b"wrong-pw";
    let new: &[u8] = b"new-pw";
    let result = Container::change_passwords(&path, &[(wrong, new)], fast_repack_options());
    assert!(matches!(result, Err(Error::AuthFailed)));
    // Temp file was cleaned up.
    assert!(!tmp_path.exists());

    // Original still works with original password.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"actual-pw").unwrap();
    let log = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
    assert_eq!(log.len(), 5);
}

#[test]
fn two_write_as_collide_returns_space_already_exists() {
    let path = scratch_path();
    build_two_spaces(&path, b"a-old", b"b-old");
    let tmp_path = path.with_extension("hv-rotate-tmp");

    let a_old: &[u8] = b"a-old";
    let b_old: &[u8] = b"b-old";
    let same: &[u8] = b"collide";
    let result = Container::change_passwords(
        &path,
        &[(a_old, same), (b_old, same)],
        fast_repack_options(),
    );
    assert!(matches!(result, Err(Error::SpaceAlreadyExists)));
    assert!(!tmp_path.exists());

    // Original unchanged — both old passwords still work.
    let mut c = Container::open(&path).unwrap();
    assert!(c.open_space(a_old).is_ok());
    drop(c);
    let mut c = Container::open(&path).unwrap();
    assert!(c.open_space(b_old).is_ok());
}

#[test]
fn spaces_not_in_mapping_are_dropped() {
    // Same destructive semantics as compact_known.
    let path = scratch_path();
    build_two_spaces(&path, b"keep-this", b"drop-this");

    let keep: &[u8] = b"keep-this";
    Container::change_passwords(&path, &[(keep, keep)], fast_repack_options()).unwrap();

    let mut c = Container::open(&path).unwrap();
    // Dropped space is gone.
    assert!(matches!(c.open_space(b"drop-this"), Err(Error::AuthFailed)));
    // Kept space survives.
    assert!(c.open_space(keep).is_ok());
}

#[test]
fn noop_rotation_is_identical_to_compact_known() {
    // Two identical containers; one runs change_passwords with no-op
    // mapping, the other runs compact_known. Both must yield the same
    // observable state.
    let p1 = scratch_path();
    let p2 = scratch_path();
    build_single_space(&p1, b"pw", 15);
    build_single_space(&p2, b"pw", 15);

    let pw: &[u8] = b"pw";
    Container::change_passwords(&p1, &[(pw, pw)], fast_repack_options()).unwrap();
    Container::compact_known(&p2, &[pw], fast_repack_options()).unwrap();

    let log1 = {
        let mut c = Container::open(&p1).unwrap();
        let mut s = c.open_space(pw).unwrap();
        s.iter_log(Namespace::MESSAGE_LOG).unwrap()
    };
    let log2 = {
        let mut c = Container::open(&p2).unwrap();
        let mut s = c.open_space(pw).unwrap();
        s.iter_log(Namespace::MESSAGE_LOG).unwrap()
    };
    assert_eq!(log1, log2);
    assert_eq!(log1.len(), 15);
}

#[test]
fn cancellable_pre_fired_aborts_and_cleans_tmp() {
    let path = scratch_path();
    build_single_space(&path, b"old-pw", 5);
    let tmp_path = path.with_extension("hv-rotate-tmp");

    let token = CancelToken::new();
    token.cancel();

    let old: &[u8] = b"old-pw";
    let new: &[u8] = b"new-pw";
    let result = Container::change_passwords_cancellable(
        &path,
        &[(old, new)],
        fast_repack_options(),
        &token,
    );
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(!tmp_path.exists());

    // Original unchanged.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(old).unwrap();
    assert_eq!(s.iter_log(Namespace::MESSAGE_LOG).unwrap().len(), 5);
}
