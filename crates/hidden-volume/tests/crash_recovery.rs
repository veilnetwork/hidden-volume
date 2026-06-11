//! Crash recovery tests — validate the 3-fsync Tx commit protocol
//! under the v0.2 KV API.
//!
//! Tx commit protocol (DESIGN §6, src/tx/mod.rs):
//!   1. Append IndexNode chunks (one per touched namespace) + fsync.
//!   2. Append Commit chunk (namespace → IndexNode slot map)         + fsync.
//!   3. Append new Superblock pointing at Commit                     + fsync.
//!
//! Crash before final fsync → previous Superblock is still latest;
//! orphan IndexNode + Commit chunks read as garbage to anyone without
//! the space's key.
//!
//! We simulate a crash by truncating the file at a known chunk
//! boundary. This models "process died between fsync barriers" —
//! realistic on aligned 4 KiB writes to common filesystems.

use hidden_volume::space::index::Namespace;
use hidden_volume::{CHUNK_SIZE, Container};
use std::path::Path;

mod common;
use common::fast_params;

fn truncate_to_slots(path: &Path, slot_count: u64) {
    let new_size = (1 + slot_count) * CHUNK_SIZE as u64;
    let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_len(new_size).unwrap();
}

fn slots_on_disk(path: &Path) -> u64 {
    let len = std::fs::metadata(path).unwrap().len();
    assert_eq!(len % CHUNK_SIZE as u64, 0, "file size not chunk-aligned");
    (len / CHUNK_SIZE as u64) - 1
}

#[test]
fn crash_after_create_space_only_recovers_initial_state() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        c.set_superblock_replicas(1).unwrap();
        let _s = c.create_space(b"pw").unwrap();
    }
    assert_eq!(slots_on_disk(&path), 1);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 1);
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn crash_after_index_node_before_commit_rolls_back() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    let total;
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        c.set_superblock_replicas(1).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
        tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
        tx.commit().unwrap();
        total = slots_on_disk(&path);
    }
    // Layout: 0=initial SB; 1=IndexNode(CONTACTS); 2=IndexNode(SETTINGS);
    // 3=Commit; 4=new SB. Total = 5.
    assert_eq!(total, 5);

    // Truncate after IndexNodes but before Commit.
    truncate_to_slots(&path, 3);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Tx didn't commit; we see only the initial state.
    assert_eq!(s.commit_seq(), 1);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 0);
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn crash_after_commit_before_superblock_rolls_back() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        c.set_superblock_replicas(1).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
        tx.commit().unwrap();
    }
    let total = slots_on_disk(&path);
    // 0=initial SB; 1=IndexNode(CONTACTS); 2=Commit; 3=new SB. total=4.
    assert_eq!(total, 4);

    // Truncate to include Commit but exclude new Superblock.
    truncate_to_slots(&path, 3);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 1);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn crash_after_full_commit_visible() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        c.set_superblock_replicas(1).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"alice", b"a").unwrap();
        tx.commit().unwrap();
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 2);
    assert_eq!(
        s.get(Namespace::CONTACTS, b"alice").unwrap().as_deref(),
        Some(&b"a"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn chained_txs_partial_second_tx_keeps_first() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        c.set_superblock_replicas(1).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"first", b"v1").unwrap();
        tx.commit().unwrap();
        // 0=initial SB; 1=IndexNode; 2=Commit; 3=SB(seq=2). total=4.

        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"second", b"v2").unwrap();
        tx.commit().unwrap();
        // +1 IndexNode, +1 Commit, +1 SB = +3. total=7.
    }
    assert_eq!(slots_on_disk(&path), 7);

    // Truncate before tx2's new Superblock.
    truncate_to_slots(&path, 6);

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 2);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 1);
    assert_eq!(
        s.get(Namespace::CONTACTS, b"first").unwrap().as_deref(),
        Some(&b"v1"[..])
    );
    assert!(s.get(Namespace::CONTACTS, b"second").unwrap().is_none());

    std::fs::remove_file(&path).ok();
}

#[test]
fn crash_recovery_preserves_other_space_isolation() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        c.set_superblock_replicas(1).unwrap();

        let mut bob = c.create_space(b"bob").unwrap();
        let mut tx = bob.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"bob").unwrap();
        tx.commit().unwrap();
        drop(bob);

        let mut alice = c.create_space(b"alice").unwrap();
        let mut tx = alice.begin_tx();
        tx.put(Namespace::SETTINGS, b"name", b"alice").unwrap();
        tx.commit().unwrap();
    }
    let total = slots_on_disk(&path);

    // Drop alice's last write (her new Superblock). Bob's state must
    // be intact because he was committed in a separate, fully
    // completed Tx.
    truncate_to_slots(&path, total - 1);

    let mut c = Container::open(&path).unwrap();

    let mut bob = c.open_space(b"bob").unwrap();
    assert_eq!(
        bob.get(Namespace::SETTINGS, b"name").unwrap().as_deref(),
        Some(&b"bob"[..])
    );
    drop(bob);

    let mut alice = c.open_space(b"alice").unwrap();
    // Alice's Tx didn't fully land — back to her create_space state.
    assert_eq!(alice.commit_seq(), 1);
    assert_eq!(alice.count(Namespace::SETTINGS).unwrap(), 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn non_chunk_aligned_truncation_recovers_via_lenient_open() {
    // After v0.5 fault-injection audit (`tests/fault_injection.rs`),
    // `Container::open` is lenient about trailing partial chunks: a
    // crash that leaves the file size mid-chunk is recoverable as
    // long as enough complete chunks remain to find the latest
    // Superblock. This test exercises the common case: truncate the
    // last 100 bytes off (so the trailing SB chunk is partial) but
    // earlier replicas / older SBs remain intact.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        // Use 3 replicas so corrupting the last one still leaves
        // healthy ones for recovery.
        c.set_superblock_replicas(3).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"x", b"y").unwrap();
        tx.commit().unwrap();
    }

    let len = std::fs::metadata(&path).unwrap().len();
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(len - 100).unwrap();

    // Lenient open succeeds; the partial trailing bytes are ignored.
    let mut c = Container::open(&path).expect("open should be lenient on unaligned files");
    let mut s = c
        .open_space(b"pw")
        .expect("recovery via remaining SB replicas");
    assert_eq!(
        s.get(Namespace::SETTINGS, b"x").unwrap().as_deref(),
        Some(&b"y"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn many_chained_crashes_each_recovers_correctly() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);

    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        c.set_superblock_replicas(1).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..4u8 {
            let mut tx = s.begin_tx();
            tx.put(
                Namespace::CONTACTS,
                format!("k{i}").as_bytes(),
                format!("v{i}").as_bytes(),
            )
            .unwrap();
            tx.commit().unwrap();
        }
    }
    let full = std::fs::read(&path).unwrap();
    let total_slots = slots_on_disk(&path);

    for slot_cap in 1..=total_slots {
        std::fs::write(&path, &full).unwrap();
        truncate_to_slots(&path, slot_cap);

        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        let seq = s.commit_seq();
        assert!(
            (1..=5).contains(&seq),
            "commit_seq out of range at slot_cap={slot_cap}: {seq}"
        );
        // Recovery is always idempotent — list must succeed for
        // every namespace, returning a possibly-empty vec.
        let _ = s.list(Namespace::CONTACTS).unwrap();
    }

    std::fs::remove_file(&path).ok();
}
