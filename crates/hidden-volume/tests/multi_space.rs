//! `MultiSpace`: several spaces of one container open at once under a single
//! file lock, writes serialized in-core. The storage foundation for a host that
//! runs several identities simultaneously over one deniable container.

use hidden_volume::container::{Container, ContainerOptions};
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::{Error, MultiSpace};

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

#[test]
fn two_spaces_coexist_and_isolate_under_one_container() {
    let path = scratch_path();

    // Create a container holding two spaces, capture each space's keys.
    let (ka, kb) = {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        c.create_space(b"pa").unwrap();
        c.create_space(b"pb").unwrap();
        let ka = c.derive_space_keys(b"pa").unwrap();
        let kb = c.derive_space_keys(b"pb").unwrap();
        (ka, kb)
    }; // container dropped → exclusive lock released

    // Host BOTH spaces open at once under a single re-opened container/lock.
    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    let a = ms.open_space(ka).unwrap();
    let b = ms.open_space(kb).unwrap();
    assert_eq!(ms.len(), 2);

    // Interleave writes to A and B — both go through the one file lock.
    ms.with_space(a, |s| {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"who", b"alice").unwrap();
        tx.commit().unwrap();
    })
    .unwrap();
    ms.with_space(b, |s| {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"who", b"bob").unwrap();
        tx.commit().unwrap();
    })
    .unwrap();
    // A second write to A after B's write — proves the spaces stay independently
    // usable (no re-open) across interleaved operations.
    ms.with_space(a, |s| {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"city", b"riga").unwrap();
        tx.commit().unwrap();
    })
    .unwrap();

    // Each space reads back only its OWN data — full isolation.
    let who_a = ms
        .with_space(a, |s| s.get(Namespace::SETTINGS, b"who").unwrap())
        .unwrap();
    let who_b = ms
        .with_space(b, |s| s.get(Namespace::SETTINGS, b"who").unwrap())
        .unwrap();
    let city_a = ms
        .with_space(a, |s| s.get(Namespace::SETTINGS, b"city").unwrap())
        .unwrap();
    let city_b = ms
        .with_space(b, |s| s.get(Namespace::SETTINGS, b"city").unwrap())
        .unwrap();
    assert_eq!(who_a.as_deref(), Some(&b"alice"[..]));
    assert_eq!(who_b.as_deref(), Some(&b"bob"[..]));
    assert_eq!(city_a.as_deref(), Some(&b"riga"[..]));
    assert_eq!(city_b, None, "space B never wrote `city`");

    // Durability: drop the MultiSpace, reopen each space the classic way.
    drop(ms);
    let mut c = Container::open(&path).unwrap();
    let mut sa = c.open_space(b"pa").unwrap();
    assert_eq!(
        sa.get(Namespace::SETTINGS, b"who").unwrap().as_deref(),
        Some(&b"alice"[..])
    );
}

#[test]
fn open_space_with_wrong_keys_is_auth_failed() {
    let path = scratch_path();
    let kb = {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        c.create_space(b"pa").unwrap();
        c.derive_space_keys(b"pb").unwrap() // keys for a space that doesn't exist
    };
    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    match ms.open_space(kb) {
        Err(Error::AuthFailed) => {},
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

#[test]
fn with_space_rejects_unknown_id() {
    let path = scratch_path();
    {
        Container::create_with_options(&path, fast_options())
            .unwrap()
            .create_space(b"pa")
            .unwrap();
    }
    let mut ms = MultiSpace::new(Container::open(&path).unwrap());
    let ka = ms.derive_space_keys(b"pa").unwrap();
    ms.open_space(ka).unwrap();
    match ms.with_space(99, |s| s.commit_seq()) {
        Err(Error::Malformed(_)) => {},
        other => panic!("expected Malformed, got {other:?}"),
    }
}
