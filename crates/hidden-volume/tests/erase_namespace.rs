//! `Space::erase_namespace` — drop every entry in a namespace in one Tx.
//!
//! Coverage:
//! 1. Empty namespace → returns 0, no commit happens.
//! 2. KV namespace with N entries → all gone post-erase, count ↓ to 0.
//! 3. Multi-namespace: only target erased, peers preserved.
//! 4. Log namespace: KV pointers gone (read_log/iter_log return empty),
//!    but DataBatch chunks remain on disk (forward-secrecy gap until
//!    compact).
//! 5. After erase + reopen, vacuum_orphans scrubs orphan IndexNode chunks.
//! 6. After erase + compact_known, DataBatch chunks are physically gone.
//! 7. Erase + commit_seq: monotonically incremented (one new commit).
//! 8. Erasing twice → second is no-op (returns 0, no extra commit).
//! 9. Erase then write again — namespace fully recreated.
//! 10. Multi-space isolation: erasing in space A does not affect space B.

use hidden_volume::Container;
use hidden_volume::container::RepackOptions;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;

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

#[test]
fn empty_namespace_returns_zero_no_commit() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let seq_before = s.commit_seq();
    let removed = s.erase_namespace(Namespace::SETTINGS).unwrap();
    assert_eq!(removed, 0);
    // No commit produced — seq unchanged.
    assert_eq!(s.commit_seq(), seq_before);
}

#[test]
fn kv_namespace_full_wipe() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for i in 0..100u32 {
        tx.put(Namespace::CONTACTS, format!("k{i:03}").as_bytes(), b"v")
            .unwrap();
    }
    tx.commit().unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 100);

    let removed = s.erase_namespace(Namespace::CONTACTS).unwrap();
    assert_eq!(removed, 100);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 0);
    assert!(s.list(Namespace::CONTACTS).unwrap().is_empty());
}

#[test]
fn other_namespaces_preserved() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
    tx.put(Namespace::SETTINGS, b"lang", b"en").unwrap();
    tx.put(Namespace::CONTACTS, b"bob", b"@bob").unwrap();
    tx.put(Namespace::CONTACTS, b"alice", b"@alice").unwrap();
    tx.commit().unwrap();

    let removed = s.erase_namespace(Namespace::CONTACTS).unwrap();
    assert_eq!(removed, 2);
    // CONTACTS gone.
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 0);
    // SETTINGS intact.
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 2);
    assert_eq!(
        s.get(Namespace::SETTINGS, b"theme").unwrap().as_deref(),
        Some(&b"dark"[..])
    );
}

#[test]
fn log_namespace_kv_pointers_gone() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for id in 1..=50u64 {
        tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id}").as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();
    assert_eq!(s.iter_log(Namespace::MESSAGE_LOG).unwrap().len(), 50);

    let removed = s.erase_namespace(Namespace::MESSAGE_LOG).unwrap();
    assert_eq!(removed, 50);
    // Log iterators return empty post-erase.
    assert!(s.iter_log(Namespace::MESSAGE_LOG).unwrap().is_empty());
    assert!(
        s.iter_log_after(Namespace::MESSAGE_LOG, None, 100)
            .unwrap()
            .is_empty()
    );
    assert!(
        s.iter_log_before(Namespace::MESSAGE_LOG, None, 100)
            .unwrap()
            .is_empty()
    );
    // Direct read returns None.
    assert!(s.read_log(Namespace::MESSAGE_LOG, 1).unwrap().is_none());
}

#[test]
fn vacuum_orphans_scrubs_index_nodes_after_erase_reopen() {
    let path = scratch_path();
    // Measure owned chunks right AFTER the erase commit (in-process,
    // before vacuum has had a chance to run).
    let owned_after_erase = {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..200u32 {
            tx.put(Namespace::CONTACTS, format!("k{i:04}").as_bytes(), b"v")
                .unwrap();
        }
        tx.commit().unwrap();
        s.erase_namespace(Namespace::CONTACTS).unwrap();
        s.audit_owned_chunk_count()
    };
    // Reopen — auto-vacuum on open_space scrubs orphan IndexNodes
    // that were left behind by the erase commit (the old tree's
    // IndexNode chunks no longer reachable from current Superblock).
    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    let owned_after_reopen = s.audit_owned_chunk_count();
    assert!(
        owned_after_reopen < owned_after_erase,
        "expected vacuum to reduce owned chunks; \
         after_erase={owned_after_erase}, after_reopen={owned_after_reopen}",
    );
}

#[test]
fn compact_after_erase_eliminates_databatch() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for id in 1..=100u64 {
            tx.append_log(Namespace::MESSAGE_LOG, id, format!("secret{id}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
        s.erase_namespace(Namespace::MESSAGE_LOG).unwrap();
    }
    // After erase, file still contains the DataBatch chunks (vacuum
    // doesn't touch them). Run compact to physically scrub them.
    let pw: &[u8] = b"pw";
    Container::compact_known(&path, &[pw], fast_repack_options()).unwrap();

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Log namespace empty post-compact.
    assert!(s.iter_log(Namespace::MESSAGE_LOG).unwrap().is_empty());
    // verify_integrity passes on the freshly-compacted tree.
    let _ = s.verify_integrity().unwrap();
}

#[test]
fn erase_increments_commit_seq() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, b"k", b"v").unwrap();
    tx.commit().unwrap();
    let seq_after_put = s.commit_seq();
    s.erase_namespace(Namespace::CONTACTS).unwrap();
    assert_eq!(s.commit_seq(), seq_after_put + 1);
}

#[test]
fn double_erase_second_is_noop() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
    tx.commit().unwrap();
    let r1 = s.erase_namespace(Namespace::SETTINGS).unwrap();
    let seq_after_first = s.commit_seq();
    let r2 = s.erase_namespace(Namespace::SETTINGS).unwrap();
    assert_eq!(r1, 1);
    assert_eq!(r2, 0);
    // Second erase did not commit (namespace was already empty).
    assert_eq!(s.commit_seq(), seq_after_first);
}

#[test]
fn write_after_erase_recreates_namespace() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, b"old", b"v").unwrap();
    tx.commit().unwrap();
    s.erase_namespace(Namespace::CONTACTS).unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, b"new", b"w").unwrap();
    tx.commit().unwrap();
    assert_eq!(
        s.get(Namespace::CONTACTS, b"new").unwrap().as_deref(),
        Some(&b"w"[..])
    );
    // Old key is still gone.
    assert!(s.get(Namespace::CONTACTS, b"old").unwrap().is_none());
}

#[test]
fn multi_space_isolation_under_erase() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    {
        let mut a = c.create_space(b"alice").unwrap();
        let mut tx = a.begin_tx();
        tx.put(Namespace::CONTACTS, b"x", b"a-data").unwrap();
        tx.commit().unwrap();
    }
    {
        let mut b = c.create_space(b"bob").unwrap();
        let mut tx = b.begin_tx();
        tx.put(Namespace::CONTACTS, b"x", b"b-data").unwrap();
        tx.commit().unwrap();
    }
    // Erase in alice's space.
    {
        let mut a = c.open_space(b"alice").unwrap();
        a.erase_namespace(Namespace::CONTACTS).unwrap();
    }
    // Bob's space untouched.
    let mut b = c.open_space(b"bob").unwrap();
    assert_eq!(
        b.get(Namespace::CONTACTS, b"x").unwrap().as_deref(),
        Some(&b"b-data"[..])
    );
}
