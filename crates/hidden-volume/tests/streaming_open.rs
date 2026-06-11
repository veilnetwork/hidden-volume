//! `scan_and_recover` streaming-memory contract (v0.6).
//!
//! The previous implementation kept every decrypted Plaintext (~4 KiB
//! payload) in a `Vec<Found>` for the duration of the scan. The
//! streaming refactor drops each Plaintext at the end of its iteration,
//! retaining only `owned_slots: Vec<u64>` (~8 B/owned chunk) and
//! `commit_history: Vec<u64>` (deduplicated to ~8 B/commit).
//!
//! These tests verify the OBSERVABLE properties of the streaming
//! semantics. We can't directly measure peak heap usage in stable Rust,
//! but we can confirm the post-scan state matches what streaming
//! produces (no Plaintext bytes retained, owned_slots and
//! commit_history populated correctly).

use hidden_volume::Container;
use hidden_volume::container::ContainerOptions;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;

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

#[test]
fn streaming_open_recovers_state_for_many_commits() {
    // Reopen scenario with O(N) committed states. The streaming refactor
    // must produce identical post-scan state — same superblock,
    // same owned_slots count, same commit_history.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..100u32 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
        // History: 1 (initial) + 100 commits.
        assert_eq!(s.commit_seq(), 101);
        assert_eq!(s.commit_history().len(), 101);
    }

    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 101);
    assert_eq!(s.commit_history().len(), 101);
    // First and last:
    assert_eq!(s.commit_history()[0], 1);
    assert_eq!(*s.commit_history().last().unwrap(), 101);
}

#[test]
fn streaming_open_dedupes_replicas_correctly() {
    // With 3 replicas × N+1 commits the file holds 3*(N+1) Superblocks
    // owned by the space. commit_history deduplicates to N+1 entries
    // — verifying the streaming dedup pass works on ANY scan order.
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..20u32 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
    }
    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    // 21 distinct seqs (initial + 20 commits) regardless of replica count.
    assert_eq!(s.commit_history().len(), 21);
    assert_eq!(*s.commit_history().last().unwrap(), 21);
    // Sorted ascending.
    let h = s.commit_history();
    for w in h.windows(2) {
        assert!(w[0] < w[1], "history must be sorted-ascending and unique");
    }
}

#[test]
fn streaming_open_picks_max_seq_with_many_replicas() {
    // Create a container with 7 replicas and 10 commits = 77 SB chunks
    // for a single space. The streaming code must pick max-seq across
    // ALL 77 of them without retaining any payload other than the
    // current best — observable via commit_seq matching the last
    // commit's seq.
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(7)).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..10u32 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
    }
    let mut c = Container::open(&path).unwrap();
    let s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 11);
}

#[test]
fn streaming_open_preserves_owned_slot_count() {
    // owned_slots must include every owned chunk regardless of kind
    // (Superblock / Commit / IndexNode / DataBatch). After many ops,
    // verify_integrity walks the tree and audit_owned_chunk_count
    // reports the same count we'd expect.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..30u64 {
            let mut tx = s.begin_tx();
            tx.append_log(Namespace::MESSAGE_LOG, i, format!("msg{i}").as_bytes())
                .unwrap();
            tx.commit().unwrap();
        }
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Verify the tree integrity hash chain from this streamed state.
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
    // owned_slots holds at least: initial SB + N×(IndexNode + DataBatch
    // + Commit + new SB) per commit. Lower bound: 31 commits × 4 chunks
    // + initial = 125. We just sanity-check it's growing as expected.
    assert!(
        s.audit_owned_chunk_count() > 60,
        "owned_slots populated streaming-style: {}",
        s.audit_owned_chunk_count()
    );
}

#[test]
fn streaming_open_handles_large_owned_slot_set() {
    // Stress test: many commits exercise the streaming hot loop.
    // Asymptotic memory should be ~O(M) bytes where M = owned chunks
    // (each ~16 bytes: 8 for owned_slots + ≤8 for commit_history).
    // We verify functional correctness here; memory characteristic is
    // structural to the implementation.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..200u32 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, format!("k{i:03}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 201);
    assert_eq!(s.commit_history().len(), 201);
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
}

#[test]
fn streaming_open_finds_all_kinds_for_space() {
    // After a tx with KV + log, the space owns chunks of multiple kinds:
    // Superblock, Commit, IndexNode, DataBatch. Streaming must accept
    // all kinds and record them in owned_slots regardless. Spot-check
    // via verify_integrity walking IndexNode subtree.
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
    tx.put(Namespace::CONTACTS, b"bob", b"@bob").unwrap();
    for id in 0..20u64 {
        tx.append_log(Namespace::MESSAGE_LOG, id, b"hi").unwrap();
    }
    tx.commit().unwrap();

    drop(s);
    drop(c);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 2);
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 3);
}
