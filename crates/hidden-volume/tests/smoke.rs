//! End-to-end smoke tests using the public API surface only.
//!
//! v0.2 KV semantics: data is stored as `(namespace, key) → value`.
//! Tx accumulates put/delete ops, commit() applies atomically.

use hidden_volume::space::index::Namespace;
use hidden_volume::{Container, Error};

mod common;
use common::fast_params;

#[test]
fn create_space_put_reopen_get() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let password = b"correct horse battery staple";

    {
        let mut container = Container::create(&path, fast_params()).unwrap();
        let mut space = container.create_space(password).unwrap();
        assert_eq!(space.commit_seq(), 1);
        assert!(
            space
                .get(Namespace::SETTINGS, b"username")
                .unwrap()
                .is_none()
        );

        let mut tx = space.begin_tx();
        tx.put(Namespace::SETTINGS, b"username", b"alice").unwrap();
        tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
        tx.commit().unwrap();

        assert_eq!(
            space
                .get(Namespace::SETTINGS, b"username")
                .unwrap()
                .as_deref(),
            Some(&b"alice"[..])
        );
    }

    // Reopen + read.
    {
        let mut container = Container::open(&path).unwrap();
        let mut space = container.open_space(password).unwrap();
        assert_eq!(space.commit_seq(), 2);
        assert_eq!(
            space
                .get(Namespace::SETTINGS, b"username")
                .unwrap()
                .as_deref(),
            Some(&b"alice"[..])
        );
        assert_eq!(
            space.get(Namespace::SETTINGS, b"theme").unwrap().as_deref(),
            Some(&b"dark"[..])
        );
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn wrong_password_returns_auth_failed() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut container = Container::create(&path, fast_params()).unwrap();
        let mut space = container.create_space(b"real password").unwrap();
        let mut tx = space.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"secret").unwrap();
        tx.commit().unwrap();
    }

    let mut container = Container::open(&path).unwrap();

    match container.open_space(b"wrong password").unwrap_err() {
        Error::AuthFailed => {},
        other => panic!("expected AuthFailed, got {other:?}"),
    }

    let mut space = container.open_space(b"real password").unwrap();
    assert_eq!(
        space.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"secret"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn create_space_collision_rejected() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut container = Container::create(&path, fast_params()).unwrap();
    {
        let _s = container.create_space(b"pw").unwrap();
    }
    match container.create_space(b"pw").unwrap_err() {
        Error::SpaceAlreadyExists => {},
        other => panic!("expected SpaceAlreadyExists, got {other:?}"),
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn multi_tx_commits_increment_seq_and_persist() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut container = Container::create(&path, fast_params()).unwrap();
    let mut space = container.create_space(b"pw").unwrap();
    assert_eq!(space.commit_seq(), 1);

    for (i, k) in [b"k1", b"k2", b"k3", b"k4"].iter().enumerate() {
        let mut tx = space.begin_tx();
        tx.put(Namespace::CONTACTS, *k, format!("v{i}").as_bytes())
            .unwrap();
        tx.commit().unwrap();
        assert_eq!(space.commit_seq(), 2 + i as u64);
    }

    drop(space);
    drop(container);

    // Reopen — all 4 keys present.
    let mut container = Container::open(&path).unwrap();
    let mut space = container.open_space(b"pw").unwrap();
    assert_eq!(space.commit_seq(), 5);
    assert_eq!(space.count(Namespace::CONTACTS).unwrap(), 4);
    let list = space.list(Namespace::CONTACTS).unwrap();
    assert_eq!(list[0].0, b"k1");
    assert_eq!(list[3].1, b"v3");

    std::fs::remove_file(&path).ok();
}

#[test]
fn two_spaces_independent() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut container = Container::create(&path, fast_params()).unwrap();

        let mut a = container.create_space(b"alice").unwrap();
        let mut tx = a.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"alice").unwrap();
        tx.commit().unwrap();
        drop(a);

        let mut b = container.create_space(b"bob").unwrap();
        let mut tx = b.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"bob").unwrap();
        tx.commit().unwrap();
    }

    let mut container = Container::open(&path).unwrap();

    let mut a = container.open_space(b"alice").unwrap();
    assert_eq!(
        a.get(Namespace::SETTINGS, b"name").unwrap().as_deref(),
        Some(&b"alice"[..])
    );
    drop(a);

    let mut b = container.open_space(b"bob").unwrap();
    assert_eq!(
        b.get(Namespace::SETTINGS, b"name").unwrap().as_deref(),
        Some(&b"bob"[..])
    );
    drop(b);

    assert!(matches!(
        container.open_space(b"eve").unwrap_err(),
        Error::AuthFailed
    ));

    std::fs::remove_file(&path).ok();
}
