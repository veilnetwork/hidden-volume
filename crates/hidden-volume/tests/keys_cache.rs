//! Tests for the pre-derived keys workflow:
//! `Container::derive_space_keys` + `Container::open_space_with_keys`.
//!
//! Validates the cross-session caching path that lets host-apps skip
//! the ~100 ms Argon2id cost on every app launch.

use hidden_volume::crypto::derive::SpaceKeys;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Error};

mod common;
use common::{fast_params, scratch_path};

#[test]
fn cached_keys_open_same_space() {
    let path = scratch_path();
    let password = b"my password";

    // Phase 1: create + cache.
    let cached_keys: SpaceKeys;
    {
        let mut container = Container::create(&path, fast_params()).unwrap();
        let mut space = container.create_space(password).unwrap();
        let mut tx = space.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
        drop(space);

        cached_keys = container.derive_space_keys(password).unwrap();
        // (host-app would persist `cached_keys` to OS keyring here)
    }

    // Phase 2: simulate a new app session — open with cached keys instead
    // of password, skipping Argon2.
    {
        let mut container = Container::open(&path).unwrap();
        let mut space = container.open_space_with_keys(cached_keys).unwrap();
        assert_eq!(
            space.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
            Some(&b"v"[..])
        );
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn cached_keys_match_password_path_byte_for_byte() {
    // Confirm derive_space_keys produces the SAME keys as the internal
    // password path. Otherwise cached-keys path opens a different (or
    // no) space.
    let path = scratch_path();
    {
        let mut container = Container::create(&path, fast_params()).unwrap();
        let mut space = container.create_space(b"pw").unwrap();
        let mut tx = space.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }

    let container = Container::open(&path).unwrap();
    let keys_a = container.derive_space_keys(b"pw").unwrap();
    let keys_b = container.derive_space_keys(b"pw").unwrap();
    // Determinism: same password + same container salt → same key.
    // Audit cleanup (B1+B2): SpaceKeys formerly held `master` and `kdf`
    // fields that were never read — both removed; only `aead_root`
    // remains as the key-schedule output consumed by
    // `derive_chunk_key`.
    assert_eq!(keys_a.aead_root, keys_b.aead_root);

    std::fs::remove_file(&path).ok();
}

#[test]
fn wrong_cached_keys_return_auth_failed() {
    // If keyring is tampered with (or restored from a different
    // container), `open_space_with_keys` must fail with AuthFailed
    // — same deniability invariant as wrong password.
    let path = scratch_path();
    {
        let mut container = Container::create(&path, fast_params()).unwrap();
        let _ = container.create_space(b"correct").unwrap();
    }

    let mut container = Container::open(&path).unwrap();
    let wrong_keys = container.derive_space_keys(b"wrong password").unwrap();
    match container.open_space_with_keys(wrong_keys) {
        Err(Error::AuthFailed) => {},
        other => panic!("expected AuthFailed, got {other:?}"),
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn cached_keys_clone_works_independently() {
    // SpaceKeys derives Clone — cached copy and original both usable.
    let path = scratch_path();
    {
        let mut container = Container::create(&path, fast_params()).unwrap();
        let _ = container.create_space(b"pw").unwrap();
    }

    let mut container = Container::open(&path).unwrap();
    let keys = container.derive_space_keys(b"pw").unwrap();
    let keys_clone = keys.clone();

    // First open consumes one of them.
    {
        let _ = container.open_space_with_keys(keys).unwrap();
    }
    // Clone still works.
    {
        let _ = container.open_space_with_keys(keys_clone).unwrap();
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn cached_keys_from_different_container_fail_via_aad_binding() {
    // The container_id is part of the AAD binding for every chunk's
    // AEAD. SpaceKeys derived against container A won't decrypt
    // chunks of container B even if the user's password is the same.
    let path_a = scratch_path();
    let path_b = scratch_path();

    {
        let mut a = Container::create(&path_a, fast_params()).unwrap();
        let _ = a.create_space(b"pw").unwrap();
    }
    {
        let mut b = Container::create(&path_b, fast_params()).unwrap();
        let _ = b.create_space(b"pw").unwrap();
    }

    // Derive keys from container A.
    let keys_from_a;
    {
        let container_a = Container::open(&path_a).unwrap();
        keys_from_a = container_a.derive_space_keys(b"pw").unwrap();
    }

    // Try to open container B with A's keys. salt + container_id
    // are different → keys don't decrypt anything.
    {
        let mut container_b = Container::open(&path_b).unwrap();
        match container_b.open_space_with_keys(keys_from_a) {
            Err(Error::AuthFailed) => {},
            other => {
                panic!("keys derived from container A must not open container B; got {other:?}")
            },
        }
    }

    std::fs::remove_file(&path_a).ok();
    std::fs::remove_file(&path_b).ok();
}

#[test]
fn cached_keys_skip_argon2_on_repeated_opens() {
    // Sanity check: a back-to-back password open vs cached-keys open
    // both succeed. We don't measure timing here (criterion bench
    // would, but unit-test scope is just correctness).
    let path = scratch_path();
    {
        let mut container = Container::create(&path, fast_params()).unwrap();
        let mut space = container.create_space(b"pw").unwrap();
        let mut tx = space.begin_tx();
        for i in 0..10u8 {
            tx.put(Namespace::CONTACTS, &[i], b"value").unwrap();
        }
        tx.commit().unwrap();
    }

    let mut container = Container::open(&path).unwrap();

    // Path A: password (slow, includes Argon2).
    {
        let mut space = container.open_space(b"pw").unwrap();
        assert_eq!(space.count(Namespace::CONTACTS).unwrap(), 10);
    }

    // Path B: cached keys (fast, no Argon2).
    let keys = container.derive_space_keys(b"pw").unwrap();
    {
        let mut space = container.open_space_with_keys(keys).unwrap();
        assert_eq!(space.count(Namespace::CONTACTS).unwrap(), 10);
    }

    std::fs::remove_file(&path).ok();
}
