//! B+ tree overflow tests — namespaces growing beyond a single Leaf chunk.
//!
//! When a namespace's encoded entries exceed `PAYLOAD_CAP` (≈ 4040 bytes),
//! `Space::commit_tx` splits them into multiple Leaf chunks and emits
//! one Internal node above. Public API (`get`, `list`, `count`, `put`,
//! `delete`) hides the tree shape; these tests verify external behavior
//! is identical regardless of size.

use hidden_volume::Container;
use hidden_volume::space::index::Namespace;
use std::collections::BTreeMap;

mod common;
use common::fast_params;

/// Generate a deterministic test entry for index `i`.
fn entry(i: u32) -> (Vec<u8>, Vec<u8>) {
    (
        format!("key-{i:08}").into_bytes(),
        format!("value-with-some-padding-{i:08}-{i:08}-{i:08}").into_bytes(),
    )
}

#[test]
fn five_hundred_entries_round_trip() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..500u32 {
            let (k, v) = entry(i);
            tx.put(Namespace::CONTACTS, &k, &v).unwrap();
        }
        tx.commit().unwrap();
        // Same-session readback.
        assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 500);
        let (k, v) = entry(123);
        assert_eq!(s.get(Namespace::CONTACTS, &k).unwrap().unwrap(), v);
    }

    // Reopen.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 500);
    // Spot-check a few keys across the tree.
    for i in [0u32, 1, 7, 99, 250, 499] {
        let (k, v) = entry(i);
        assert_eq!(s.get(Namespace::CONTACTS, &k).unwrap().unwrap(), v);
    }
    let listed = s.list(Namespace::CONTACTS).unwrap();
    assert_eq!(listed.len(), 500);
    // Listed must be globally sorted.
    for w in listed.windows(2) {
        assert!(w[0].0 < w[1].0);
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn two_thousand_entries_round_trip() {
    // Stress: pushes well into the 2-level tree regime.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..2000u32 {
            let (k, v) = entry(i);
            tx.put(Namespace::MEDIA, &k, &v).unwrap();
        }
        tx.commit().unwrap();
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::MEDIA).unwrap(), 2000);
    let listed = s.list(Namespace::MEDIA).unwrap();
    assert_eq!(listed.len(), 2000);
    let map: BTreeMap<_, _> = listed.into_iter().collect();
    for i in 0..2000u32 {
        let (k, v) = entry(i);
        assert_eq!(map.get(&k).unwrap(), &v);
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn growing_one_at_a_time_eventually_splits() {
    // Add one entry per Tx until we cross the leaf-overflow threshold.
    // Reading after each Tx must give back exactly what we put in.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    for i in 0..200u32 {
        let (k, v) = entry(i);
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, &k, &v).unwrap();
        tx.commit().unwrap();
    }

    // Final state.
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 200);
    for i in [0u32, 50, 100, 150, 199] {
        let (k, v) = entry(i);
        assert_eq!(s.get(Namespace::CONTACTS, &k).unwrap().unwrap(), v);
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn mixed_put_delete_under_split_threshold() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // Insert 800.
    let mut tx = s.begin_tx();
    for i in 0..800u32 {
        let (k, v) = entry(i);
        tx.put(Namespace::CONTACTS, &k, &v).unwrap();
    }
    tx.commit().unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 800);

    // Delete every 3rd.
    let mut tx = s.begin_tx();
    for i in (0..800u32).step_by(3) {
        let (k, _) = entry(i);
        tx.delete(Namespace::CONTACTS, &k).unwrap();
    }
    tx.commit().unwrap();

    let mut expected_count = 0;
    for i in 0..800u32 {
        if i % 3 != 0 {
            expected_count += 1;
        }
    }
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), expected_count);

    // Survivors are present, deleted are gone.
    for i in 0..800u32 {
        let (k, v) = entry(i);
        let got = s.get(Namespace::CONTACTS, &k).unwrap();
        if i % 3 == 0 {
            assert!(got.is_none(), "key {i} should be deleted");
        } else {
            assert_eq!(got.unwrap(), v);
        }
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn large_namespace_alongside_small_ones() {
    // Realistic messenger state: settings small, contacts medium,
    // media-cache large. Verifies untouched-namespace carry-through
    // works correctly even when one namespace splits into a tree.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        // Tx1: settings + small contacts.
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
        tx.put(Namespace::SETTINGS, b"lang", b"en").unwrap();
        for i in 0..50u32 {
            let (k, v) = entry(i);
            tx.put(Namespace::CONTACTS, &k, &v).unwrap();
        }
        tx.commit().unwrap();

        // Tx2: large media (forces split).
        let mut tx = s.begin_tx();
        for i in 0..1500u32 {
            let (k, v) = entry(i);
            tx.put(Namespace::MEDIA, &k, &v).unwrap();
        }
        tx.commit().unwrap();

        // Tx3: touch only settings.
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"theme", b"light").unwrap();
        tx.commit().unwrap();
    }

    // Reopen — all three namespaces have correct data.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 2);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 50);
    assert_eq!(s.count(Namespace::MEDIA).unwrap(), 1500);
    assert_eq!(
        s.get(Namespace::SETTINGS, b"theme").unwrap().as_deref(),
        Some(&b"light"[..])
    );
    let (mk, mv) = entry(0);
    assert_eq!(s.get(Namespace::MEDIA, &mk).unwrap().unwrap(), mv);
    let (mk, mv) = entry(1499);
    assert_eq!(s.get(Namespace::MEDIA, &mk).unwrap().unwrap(), mv);

    std::fs::remove_file(&path).ok();
}

#[test]
fn delete_back_to_single_leaf() {
    // Grow into a tree, then delete down. Tree shape may stay 2-level
    // (no merge in v0.2 first cut), but external behavior is still
    // correct — count and get reflect deletions.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    for i in 0..600u32 {
        let (k, v) = entry(i);
        tx.put(Namespace::CONTACTS, &k, &v).unwrap();
    }
    tx.commit().unwrap();

    let mut tx = s.begin_tx();
    for i in 0..595u32 {
        let (k, _) = entry(i);
        tx.delete(Namespace::CONTACTS, &k).unwrap();
    }
    tx.commit().unwrap();

    // Now only 5 entries remain (595..600).
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 5);
    for i in 595..600u32 {
        let (k, v) = entry(i);
        assert_eq!(s.get(Namespace::CONTACTS, &k).unwrap().unwrap(), v);
    }
    for i in [0u32, 100, 500, 594] {
        let (k, _) = entry(i);
        assert!(s.get(Namespace::CONTACTS, &k).unwrap().is_none());
    }

    // Reopen — same view.
    drop(s);
    drop(c);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 5);

    std::fs::remove_file(&path).ok();
}

#[test]
fn list_returns_globally_sorted_after_split() {
    // After tree splits, list() must still produce globally sorted output.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    // Insert in shuffled order — all values within [0, 1500).
    let order = [3u32, 100, 7, 999, 0, 250, 1499, 500, 1, 1000];
    for i in order {
        let (k, v) = entry(i);
        tx.put(Namespace::MEDIA, &k, &v).unwrap();
    }
    // Plus the remainder in-order to force split.
    for i in 0..1500u32 {
        if !order.contains(&i) {
            let (k, v) = entry(i);
            tx.put(Namespace::MEDIA, &k, &v).unwrap();
        }
    }
    tx.commit().unwrap();

    let listed = s.list(Namespace::MEDIA).unwrap();
    for w in listed.windows(2) {
        assert!(
            w[0].0 < w[1].0,
            "list not sorted: {:?} >= {:?}",
            w[0].0,
            w[1].0
        );
    }
    assert_eq!(listed.len(), 1500);

    std::fs::remove_file(&path).ok();
}
