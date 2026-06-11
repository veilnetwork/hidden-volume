//! KV-level tests: namespace isolation, encoding bounds, get/list/count.

use hidden_volume::space::index::{MAX_KEY_LEN, MAX_VALUE_LEN, Namespace};
use hidden_volume::{Container, Error};

mod common;
use common::fast_params;

#[test]
fn namespaces_are_isolated() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"key", b"settings-value")
        .unwrap();
    tx.put(Namespace::CONTACTS, b"key", b"contacts-value")
        .unwrap();
    tx.put(Namespace::MEDIA, b"key", b"media-value").unwrap();
    tx.commit().unwrap();

    assert_eq!(
        s.get(Namespace::SETTINGS, b"key").unwrap().as_deref(),
        Some(&b"settings-value"[..])
    );
    assert_eq!(
        s.get(Namespace::CONTACTS, b"key").unwrap().as_deref(),
        Some(&b"contacts-value"[..])
    );
    assert_eq!(
        s.get(Namespace::MEDIA, b"key").unwrap().as_deref(),
        Some(&b"media-value"[..])
    );
    // Untouched namespace is empty.
    assert!(s.get(Namespace::MESSAGE_LOG, b"key").unwrap().is_none());

    std::fs::remove_file(&path).ok();
}

#[test]
fn list_returns_sorted_pairs() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    // Insert in non-sorted order.
    tx.put(Namespace::CONTACTS, b"zebra", b"3").unwrap();
    tx.put(Namespace::CONTACTS, b"alpha", b"1").unwrap();
    tx.put(Namespace::CONTACTS, b"middle", b"2").unwrap();
    tx.commit().unwrap();

    let list = s.list(Namespace::CONTACTS).unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].0, b"alpha");
    assert_eq!(list[1].0, b"middle");
    assert_eq!(list[2].0, b"zebra");

    std::fs::remove_file(&path).ok();
}

#[test]
fn put_with_zero_length_key_rejected() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    match tx.put(Namespace::SETTINGS, b"", b"v").unwrap_err() {
        Error::Malformed(_) => {},
        other => panic!("expected Malformed for empty key, got {other:?}"),
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn put_with_oversized_key_rejected() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    let big_key = vec![b'x'; MAX_KEY_LEN + 1];
    match tx.put(Namespace::SETTINGS, &big_key, b"v").unwrap_err() {
        Error::Malformed(_) => {},
        other => panic!("expected Malformed for oversized key, got {other:?}"),
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn put_with_oversized_value_rejected() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    let big_value = vec![0u8; MAX_VALUE_LEN + 1];
    match tx.put(Namespace::SETTINGS, b"k", &big_value).unwrap_err() {
        Error::PayloadTooLarge => {},
        other => panic!("expected PayloadTooLarge for oversized value, got {other:?}"),
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn reserved_namespace_zero_rejected() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    match tx.put(Namespace::RESERVED, b"k", b"v").unwrap_err() {
        Error::Malformed(_) => {},
        other => panic!("expected Malformed for reserved namespace, got {other:?}"),
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn many_keys_under_chunk_capacity_fit() {
    // Verify we can fit a realistic number of small entries in one
    // IndexNode chunk. 4040 - 3 (header) = 4037 bytes available.
    // Each entry = 2 + key + 4 + value. With 8-byte keys + 16-byte
    // values: 2+8+4+16 = 30 bytes. So ~134 fit.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for i in 0..100u32 {
        let k = format!("key{i:04}");
        let v = format!("value-data-{i:04}");
        tx.put(Namespace::CONTACTS, k.as_bytes(), v.as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();

    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 100);
    assert_eq!(
        s.get(Namespace::CONTACTS, b"key0042").unwrap().as_deref(),
        Some(&b"value-data-0042"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn delete_nonexistent_key_is_noop_for_commit() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    tx.delete(Namespace::SETTINGS, b"never-existed").unwrap();
    let new_seq = tx.commit().unwrap();
    assert_eq!(new_seq, 2, "Tx still bumps seq even when delete is a no-op");
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn coalesce_repeat_puts_in_same_tx() {
    // put(k, v1) followed by put(k, v2) in one tx -> final value is v2.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"first").unwrap();
    tx.put(Namespace::SETTINGS, b"k", b"second").unwrap();
    tx.put(Namespace::SETTINGS, b"k", b"third").unwrap();
    tx.commit().unwrap();

    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"third"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn delete_then_put_in_same_tx() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // Tx1: put.
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"v1").unwrap();
    tx.commit().unwrap();

    // Tx2: delete then put — the put wins.
    let mut tx = s.begin_tx();
    tx.delete(Namespace::SETTINGS, b"k").unwrap();
    tx.put(Namespace::SETTINGS, b"k", b"v2").unwrap();
    tx.commit().unwrap();

    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"v2"[..])
    );

    std::fs::remove_file(&path).ok();
}
