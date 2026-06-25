//! Multi-op transaction tests under the v0.2 KV API.

use hidden_volume::Container;
use hidden_volume::space::index::Namespace;

mod common;
use common::fast_params;

#[test]
fn multi_put_one_tx_atomic() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"alice", b"alice@example.com")
            .unwrap();
        tx.put(Namespace::CONTACTS, b"bob", b"bob@example.com")
            .unwrap();
        tx.put(Namespace::CONTACTS, b"carol", b"carol@example.com")
            .unwrap();
        tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
        tx.put(Namespace::SETTINGS, b"lang", b"en").unwrap();
        assert_eq!(tx.touched_namespaces(), 2);
        let new_seq = tx.commit().unwrap();
        assert_eq!(new_seq, 2);

        // Read back inside same session.
        assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 3);
        assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 2);
        assert_eq!(
            s.get(Namespace::CONTACTS, b"bob").unwrap().as_deref(),
            Some(&b"bob@example.com"[..])
        );
    }

    // Reopen.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 2);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 3);
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 2);

    std::fs::remove_file(&path).ok();
}

#[test]
fn dropped_tx_is_discarded() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"never").unwrap();
        // drop without commit
    }

    assert_eq!(s.commit_seq(), 1);
    assert!(s.get(Namespace::SETTINGS, b"k").unwrap().is_none());

    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"actual").unwrap();
    tx.commit().unwrap();

    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"actual"[..])
    );

    std::fs::remove_file(&path).ok();
}

/// Audit pass 7 (C1): committing an empty Tx is now a no-op —
/// `commit_tx` early-returns the current seq without writing a
/// Commit chunk, Superblock, or any fsyncs. This aligns the code
/// with `Tx::is_empty`'s documentation. Previously the seq advanced
/// by 1 on every empty commit (3 fsyncs each, multi-snapshot
/// writer-active leak).
#[test]
fn empty_tx_commit_is_a_no_op() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // Initial seq after create_space is 1 (the create-time SB).
    assert_eq!(s.commit_seq(), 1);

    let tx = s.begin_tx();
    assert!(tx.is_empty());
    let new_seq = tx.commit().unwrap();
    // No-op: seq unchanged.
    assert_eq!(new_seq, 1);
    assert_eq!(s.commit_seq(), 1);

    // Sanity: a non-empty commit still advances seq.
    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, b"alice", b"a@x").unwrap();
    assert_eq!(tx.commit().unwrap(), 2);

    std::fs::remove_file(&path).ok();
}

#[test]
fn delete_op_removes_key() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // First tx: put two keys.
    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, b"alice", b"a@x").unwrap();
    tx.put(Namespace::CONTACTS, b"bob", b"b@x").unwrap();
    tx.commit().unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 2);

    // Second tx: delete one.
    let mut tx = s.begin_tx();
    tx.delete(Namespace::CONTACTS, b"alice").unwrap();
    tx.commit().unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 1);
    assert!(s.get(Namespace::CONTACTS, b"alice").unwrap().is_none());
    assert_eq!(
        s.get(Namespace::CONTACTS, b"bob").unwrap().as_deref(),
        Some(&b"b@x"[..])
    );

    // Reopen — same view.
    drop(s);
    drop(c);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 1);

    std::fs::remove_file(&path).ok();
}

#[test]
fn replace_value_for_same_key() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"x", b"v1").unwrap();
    tx.commit().unwrap();

    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"x", b"v2").unwrap();
    tx.commit().unwrap();

    assert_eq!(
        s.get(Namespace::SETTINGS, b"x").unwrap().as_deref(),
        Some(&b"v2"[..])
    );
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 1);

    std::fs::remove_file(&path).ok();
}

#[test]
fn untouched_namespaces_carry_through_commits() {
    // Critical: a Tx that only touches namespace A must NOT lose data
    // in untouched namespaces B, C. The new Commit's roots vector
    // includes prior roots for B and C unchanged.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // Tx1: populate three namespaces.
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
    tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
    tx.put(Namespace::MEDIA, b"avatar.png", b"binary-blob")
        .unwrap();
    tx.commit().unwrap();

    // Tx2: only touch SETTINGS.
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"light").unwrap();
    tx.commit().unwrap();

    // CONTACTS and MEDIA must still have their data.
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 1);
    assert_eq!(
        s.get(Namespace::CONTACTS, b"alice").unwrap().as_deref(),
        Some(&b"a"[..])
    );
    assert_eq!(s.count(Namespace::MEDIA).unwrap(), 1);
    assert_eq!(
        s.get(Namespace::MEDIA, b"avatar.png").unwrap().as_deref(),
        Some(&b"binary-blob"[..])
    );
    // And SETTINGS reflects the update.
    assert_eq!(
        s.get(Namespace::SETTINGS, b"theme").unwrap().as_deref(),
        Some(&b"light"[..])
    );

    // Reopen — same view.
    drop(s);
    drop(c);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 1);
    assert_eq!(s.count(Namespace::MEDIA).unwrap(), 1);
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 1);

    std::fs::remove_file(&path).ok();
}

#[test]
fn two_spaces_independent_kv() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();

        let mut a = c.create_space(b"alice").unwrap();
        let mut tx = a.begin_tx();
        tx.put(Namespace::CONTACTS, b"k", b"alice-data").unwrap();
        tx.commit().unwrap();
        drop(a);

        let mut b = c.create_space(b"bob").unwrap();
        let mut tx = b.begin_tx();
        tx.put(Namespace::CONTACTS, b"k", b"bob-data").unwrap();
        tx.commit().unwrap();
    }

    let mut c = Container::open(&path).unwrap();

    let mut a = c.open_space(b"alice").unwrap();
    assert_eq!(
        a.get(Namespace::CONTACTS, b"k").unwrap().as_deref(),
        Some(&b"alice-data"[..])
    );
    drop(a);

    let mut b = c.open_space(b"bob").unwrap();
    assert_eq!(
        b.get(Namespace::CONTACTS, b"k").unwrap().as_deref(),
        Some(&b"bob-data"[..])
    );

    std::fs::remove_file(&path).ok();
}

/// Regression for the per-`seq` roots-payload cache in `load_prior_roots`: it
/// must be fully TRANSPARENT. Repeated reads within one commit era (cache hits)
/// agree, and a commit invalidates the cache so a subsequent read sees the new
/// era and NEVER the stale prior roots.
#[test]
fn roots_cache_transparent_across_reads_and_commits() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // Commit era 1: two namespaces (SETTINGS=1, CONTACTS=2).
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
    tx.put(Namespace::CONTACTS, b"alice", b"a1").unwrap();
    tx.commit().unwrap();

    // Repeated reads in the SAME era warm then hit the cache; all must agree.
    for _ in 0..5 {
        assert_eq!(
            s.get(Namespace::CONTACTS, b"alice").unwrap().as_deref(),
            Some(&b"a1"[..])
        );
        assert_eq!(
            s.list_namespaces().unwrap(),
            vec![Namespace::SETTINGS, Namespace::CONTACTS]
        );
    }

    // Commit era 2: overwrite alice + add MEDIA(=4). The cache MUST invalidate.
    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, b"alice", b"a2").unwrap();
    tx.put(Namespace::MEDIA, b"m", b"hi").unwrap();
    tx.commit().unwrap();

    assert_eq!(
        s.get(Namespace::CONTACTS, b"alice").unwrap().as_deref(),
        Some(&b"a2"[..]),
        "read after commit must see the new value, not the cached era"
    );
    assert_eq!(
        s.get(Namespace::MEDIA, b"m").unwrap().as_deref(),
        Some(&b"hi"[..]),
        "a namespace added in the new era must be visible (cache invalidated)"
    );
    assert_eq!(
        s.list_namespaces().unwrap(),
        vec![Namespace::SETTINGS, Namespace::CONTACTS, Namespace::MEDIA]
    );

    // Reopen → fresh (empty) cache → identical observable state.
    drop(s);
    drop(c);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace::CONTACTS, b"alice").unwrap().as_deref(),
        Some(&b"a2"[..])
    );

    std::fs::remove_file(&path).ok();
}
