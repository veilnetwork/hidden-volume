//! Multiple Superblock replicas — resilience to single-chunk corruption.
//!
//! Each commit writes `superblock_replicas` (default 3) SB chunks at
//! the same seq. Recovery scans all of them and picks any readable
//! replica at max seq. If one replica is bit-flipped or torn-written,
//! others provide the same state.
//!
//! Replicas don't help if the COMMIT chunk pointed at by the SB is
//! also corrupted — that's a separate concern (compaction + Merkle
//! integrity in v0.3+).

use hidden_volume::container::{ContainerOptions, DEFAULT_SUPERBLOCK_REPLICAS};
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::{CHUNK_SIZE, Container};
use std::io::{Seek, SeekFrom, Write};

mod common;
use common::{fast_params, scratch_path};

fn fast_options(replicas: u8) -> ContainerOptions {
    ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: replicas,
    }
}

fn slots_on_disk(path: &std::path::Path) -> u64 {
    let len = std::fs::metadata(path).unwrap().len();
    (len / CHUNK_SIZE as u64) - 1
}

/// Overwrite the chunk at `slot` with bit-flipped garbage (just XOR
/// the first byte), simulating a single-byte corruption that AEAD
/// will reject.
fn corrupt_slot(path: &std::path::Path, slot: u64) {
    let offset = (1 + slot) * CHUNK_SIZE as u64;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 1];
    use std::io::Read;
    f.read_exact(&mut buf).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(&[buf[0] ^ 0xFF]).unwrap();
    f.sync_all().unwrap();
}

#[test]
fn default_replicas_is_three() {
    let path = scratch_path();
    let c = Container::create(&path, fast_params()).unwrap();
    assert_eq!(c.superblock_replicas(), DEFAULT_SUPERBLOCK_REPLICAS);
    assert_eq!(DEFAULT_SUPERBLOCK_REPLICAS, 3);
    drop(c);
    std::fs::remove_file(&path).ok();
}

#[test]
fn create_space_writes_n_initial_replicas() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
        let _s = c.create_space(b"pw").unwrap();
    }
    // Initial state: 3 SB replicas. No other chunks.
    assert_eq!(slots_on_disk(&path), 3);

    std::fs::remove_file(&path).ok();
}

#[test]
fn commit_writes_n_replicas() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        // Initial: 3 SB replicas
        assert_eq!(slots_on_disk(&path), 3);

        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
        // Tx adds: 1 IndexNode + 1 Commit + 3 SB replicas = 5 chunks.
        // Total: 3 + 5 = 8.
        assert_eq!(slots_on_disk(&path), 8);
    }

    std::fs::remove_file(&path).ok();
}

#[test]
fn replicas_one_means_no_extras() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(1)).unwrap();
        let _s = c.create_space(b"pw").unwrap();
    }
    assert_eq!(slots_on_disk(&path), 1);
    std::fs::remove_file(&path).ok();
}

#[test]
fn corrupting_one_replica_does_not_break_recovery() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"alice", b"data").unwrap();
        tx.commit().unwrap();
    }
    // Layout: 0,1,2 = initial SB replicas; 3 = IndexNode; 4 = Commit;
    // 5,6,7 = new SB replicas.
    let total = slots_on_disk(&path);
    assert_eq!(total, 8);

    // Corrupt the LAST SB replica (slot 7).
    corrupt_slot(&path, 7);

    // Recovery should still find the data via slot 5 or 6.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace::CONTACTS, b"alice").unwrap().as_deref(),
        Some(&b"data"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn corrupting_two_of_three_replicas_still_works() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"key", b"value").unwrap();
        tx.commit().unwrap();
    }

    // Corrupt slots 5 and 6 (two of the three latest SB replicas).
    corrupt_slot(&path, 5);
    corrupt_slot(&path, 6);

    // Slot 7 is still intact — recovery uses it.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace::CONTACTS, b"key").unwrap().as_deref(),
        Some(&b"value"[..])
    );

    std::fs::remove_file(&path).ok();
}

#[test]
fn corrupting_all_three_replicas_falls_back_to_initial_sb() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::CONTACTS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }

    // Corrupt all three replicas at the latest seq (5, 6, 7).
    corrupt_slot(&path, 5);
    corrupt_slot(&path, 6);
    corrupt_slot(&path, 7);

    // Recovery falls back to the initial SB (seq=1) — the put is
    // lost (Tx2 rolled back), but the space is still openable.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 1);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 0);

    std::fs::remove_file(&path).ok();
}

#[test]
fn replicas_setter_takes_effect_for_next_commit() {
    let path = scratch_path();
    let mut c = Container::create_with_options(&path, fast_options(1)).unwrap();
    {
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    // First commit was N=1: initial SB + IndexNode + Commit + new SB = 4.
    assert_eq!(slots_on_disk(&path), 4);

    // Bump to 3 replicas mid-session.
    c.set_superblock_replicas(3).unwrap();
    {
        let mut s = c.open_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k2", b"v2").unwrap();
        tx.commit().unwrap();
    }
    // Second commit: +1 IndexNode (combined SETTINGS root) + 1 Commit
    // + 3 SB replicas = +5. (The vacuum_orphans on open_space scrubs
    // old IndexNode but doesn't change file size.) Total = 4 + 5 = 9.
    assert_eq!(slots_on_disk(&path), 9);

    std::fs::remove_file(&path).ok();
}

#[test]
fn zero_replicas_clamped_to_one() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(0)).unwrap();
        // Setter clamps to 1.
        assert_eq!(c.superblock_replicas(), 1);
        let _s = c.create_space(b"pw").unwrap();
    }
    assert_eq!(slots_on_disk(&path), 1);
    std::fs::remove_file(&path).ok();
}
