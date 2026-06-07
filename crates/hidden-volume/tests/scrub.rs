//! Forward-secrecy / scrub tests.
//!
//! Tx::delete + a subsequent Container::open_space must leave the
//! deleted entry's prior IndexNode chunks unrecoverable, even by an
//! adversary holding the space's password.
//!
//! Architecture (DESIGN §6 Inv-W1 revised, src/space/mod.rs):
//!   - commit_tx is append-only: new state on disk, old chunks remain
//!     readable as crash-recovery fallbacks.
//!   - Container::open_space calls Space::vacuum_orphans, which scrubs
//!     orphan IndexNode chunks (overwrites with uniform random).
//!   - DataBatch chunks are NOT scrubbed (a batch may still hold live
//!     entries); v0.3 compaction handles that.

use hidden_volume::Container;
use hidden_volume::space::index::Namespace;

mod common;
use common::fast_params;

#[test]
fn vacuum_drops_orphan_index_nodes_after_delete() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        // Tx1: put one entry.
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
        tx.commit().unwrap();
        let count_after_put = s.audit_owned_chunk_count();

        // Tx2: delete it.
        let mut tx = s.begin_tx();
        tx.delete(Namespace::CONTACTS, b"alice").unwrap();
        tx.commit().unwrap();
        // commit_tx is append-only — old IndexNode is still owned.
        assert!(s.audit_owned_chunk_count() > count_after_put);

        // Manual vacuum scrubs the orphan IndexNode from Tx1.
        let scrubbed = s.vacuum_orphans().unwrap();
        assert!(scrubbed >= 1, "expected at least one scrubbed orphan");
    }

    // Reopen — the deleted entry's IndexNode must now be unrecoverable.
    // open_space also auto-vacuums, so any orphans created since last
    // open are scrubbed.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert!(s.get(Namespace::CONTACTS, b"alice").unwrap().is_none());
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn auto_vacuum_on_open_scrubs_pending_orphans() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let initial_owned;

    let pre_vacuum_count;
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        // Force 1 replica for deterministic counts in this test.
        c.set_superblock_replicas(1).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"k", b"v").unwrap();
        tx.commit().unwrap();
        initial_owned = s.audit_owned_chunk_count();

        // Replace the value in many txs — each leaves an orphan IndexNode.
        for i in 0..10u8 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::CONTACTS, b"k", &[i]).unwrap();
            tx.commit().unwrap();
        }
        // 10 commits each made the previous IndexNode an orphan.
        // Without vacuum, owned chunk count grows by ~30 (10×{IndexNode,
        // Commit, SB}). With explicit vacuum dropped, only ~20.
        assert!(s.audit_owned_chunk_count() >= initial_owned + 20);
        pre_vacuum_count = s.audit_owned_chunk_count();
    }

    // Reopen — auto-vacuum scrubs the orphan IndexNodes.
    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    let after_vacuum = s.audit_owned_chunk_count();

    // After vacuum, only the LATEST IndexNode is reachable plus the
    // history of Superblocks/Commits (those aren't scrubbed).
    // Should be at least 9 chunks fewer (the 9 prior IndexNode orphans).
    assert!(
        after_vacuum + 9 <= pre_vacuum_count,
        "vacuum should drop ≥9 orphan IndexNodes: pre={pre_vacuum_count} post={after_vacuum}"
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn vacuum_is_idempotent() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
    tx.commit().unwrap();
    let mut tx = s.begin_tx();
    tx.delete(Namespace::CONTACTS, b"alice").unwrap();
    tx.commit().unwrap();

    let first = s.vacuum_orphans().unwrap();
    assert!(first >= 1);
    let second = s.vacuum_orphans().unwrap();
    assert_eq!(second, 0, "second vacuum should be a no-op");
    let third = s.vacuum_orphans().unwrap();
    assert_eq!(third, 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn vacuum_does_not_touch_other_spaces() {
    // Two spaces; vacuum on Alice's space must not scrub any chunks
    // belonging to Bob.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();

        let mut bob = c.create_space(b"bob").unwrap();
        let mut tx = bob.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"bob").unwrap();
        tx.commit().unwrap();
        // Replace it many times to generate orphans (will be scrubbed
        // when bob's space is reopened, not now).
        for i in 0..5u8 {
            let mut tx = bob.begin_tx();
            tx.put(Namespace::SETTINGS, b"name", &[b'b', i]).unwrap();
            tx.commit().unwrap();
        }
        drop(bob);

        let mut alice = c.create_space(b"alice").unwrap();
        let mut tx = alice.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"alice").unwrap();
        tx.commit().unwrap();
        let mut tx = alice.begin_tx();
        tx.delete(Namespace::SETTINGS, b"name").unwrap();
        tx.commit().unwrap();
        let scrubbed = alice.vacuum_orphans().unwrap();
        assert!(scrubbed >= 1);
    }

    // Reopen — Bob's data must be intact (bob's vacuum hasn't run yet
    // since we're opening fresh, but his last write should still be
    // reachable).
    let mut c = Container::open(&path).unwrap();
    let mut bob = c.open_space(b"bob").unwrap();
    // After vacuum, Bob has only his latest entry.
    let value = bob.get(Namespace::SETTINGS, b"name").unwrap();
    assert!(value.is_some(), "bob's namespace must still have data");
    drop(bob);

    let mut alice = c.open_space(b"alice").unwrap();
    assert!(alice.get(Namespace::SETTINGS, b"name").unwrap().is_none());

    std::fs::remove_file(&path).ok();
}

#[test]
fn vacuum_preserves_current_state() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for i in 0..50u32 {
        let k = format!("key{i:03}");
        let v = format!("value{i}");
        tx.put(Namespace::CONTACTS, k.as_bytes(), v.as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();

    let mut tx = s.begin_tx();
    for i in 0..50u32 {
        let k = format!("key{i:03}");
        let v = format!("UPDATED-value{i}");
        tx.put(Namespace::CONTACTS, k.as_bytes(), v.as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();

    s.vacuum_orphans().unwrap();

    // Current state must be preserved.
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 50);
    for i in 0..50u32 {
        let k = format!("key{i:03}");
        let want = format!("UPDATED-value{i}");
        assert_eq!(
            s.get(Namespace::CONTACTS, k.as_bytes()).unwrap().as_deref(),
            Some(want.as_bytes()),
        );
    }

    // Reopen — still consistent (auto-vacuum on open is idempotent).
    drop(s);
    drop(c);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 50);

    std::fs::remove_file(&path).ok();
}

#[test]
fn vacuum_does_not_break_databatch_messages() {
    // Important: vacuum scrubs IndexNode orphans only. DataBatch chunks
    // (where messages live) must NOT be scrubbed, since a single batch
    // may hold messages still referenced by other log_ids.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // Tx1: append 5 messages in one batch.
    let mut tx = s.begin_tx();
    for i in 1..=5u64 {
        tx.append_log(Namespace::MESSAGE_LOG, i, format!("msg{i}").as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();

    // Tx2: delete one message id (removes the KV pointer; batch chunk stays).
    let mut tx = s.begin_tx();
    tx.delete(
        Namespace::MESSAGE_LOG,
        &hidden_volume::space::log::log_id_key(3),
    )
    .unwrap();
    tx.commit().unwrap();

    s.vacuum_orphans().unwrap();

    // Other messages still readable.
    for i in [1u64, 2, 4, 5] {
        let want = format!("msg{i}");
        let got = s.read_log(Namespace::MESSAGE_LOG, i).unwrap();
        assert_eq!(got.as_deref(), Some(want.as_bytes()));
    }
    // Deleted id is gone.
    assert!(s.read_log(Namespace::MESSAGE_LOG, 3).unwrap().is_none());

    std::fs::remove_file(&path).ok();
}

#[test]
fn many_commits_then_vacuum_bounds_owned_count() {
    // Sanity check: without vacuum, owned chunks grow unboundedly with
    // commits. With vacuum, growth is bounded by the working set + the
    // commit history (which doesn't get scrubbed).
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for i in 0..50u32 {
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"single-key", &i.to_le_bytes())
            .unwrap();
        tx.commit().unwrap();
    }
    let pre_vacuum = s.audit_owned_chunk_count();
    s.vacuum_orphans().unwrap();
    let post_vacuum = s.audit_owned_chunk_count();
    // Should drop by at least the 49 orphan IndexNodes (each prior
    // commit's IndexNode is now orphan).
    assert!(
        pre_vacuum - post_vacuum >= 49,
        "vacuum should drop ≥49 chunks; pre={pre_vacuum} post={post_vacuum}"
    );

    std::fs::remove_file(&path).ok();
}
