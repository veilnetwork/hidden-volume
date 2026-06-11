//! Behavioral equivalence: `scan_and_recover_parallel` ↔ `scan_and_recover`.
//!
//! Verifies that the parallel-scan path (feature `parallel-scan`,
//! Unix-only) produces the same observable `SpaceState` as the
//! sequential streaming path. The only documented difference is the
//! *internal* parallelism; from a caller's POV the two are identical.
//!
//! These tests only build under `cfg(all(feature = "parallel-scan", unix))`.
//! On other platforms the file is empty (no tests).

#![cfg(all(feature = "parallel-scan", unix))]

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
fn parallel_open_recovers_same_state_as_sequential() {
    // Build a moderately-sized container exercising all chunk kinds:
    // KV across 3 namespaces, log batches, multiple commits.
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..50u32 {
            tx.put(Namespace::SETTINGS, format!("k{i:02}").as_bytes(), b"v")
                .unwrap();
        }
        tx.put(Namespace::CONTACTS, b"alice", b"@alice").unwrap();
        for id in 0..30u64 {
            tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
        // Second commit to layer history.
        let mut tx = s.begin_tx();
        for id in 30..50u64 {
            tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
    }

    // Open sequentially and capture observable state.
    let (seq_commit_seq, seq_history, seq_owned, seq_log) = {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        let log = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
        (
            s.commit_seq(),
            s.commit_history().to_vec(),
            s.audit_owned_chunk_count(),
            log,
        )
    };

    // Open with parallel scan and capture again.
    let (par_commit_seq, par_history, par_owned, par_log) = {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space_parallel(b"pw").unwrap();
        let log = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
        (
            s.commit_seq(),
            s.commit_history().to_vec(),
            s.audit_owned_chunk_count(),
            log,
        )
    };

    assert_eq!(seq_commit_seq, par_commit_seq);
    assert_eq!(seq_history, par_history);
    assert_eq!(seq_owned, par_owned);
    assert_eq!(seq_log, par_log);
}

#[test]
fn parallel_open_picks_max_seq_across_many_replicas() {
    // 7 replicas × ~10 commits = ~77 SB chunks owned by the space.
    // Parallel reduce must pick max-seq deterministically.
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
    let s = c.open_space_parallel(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 11);
    // History is dedup'd to 11 distinct seqs.
    assert_eq!(s.commit_history().len(), 11);
}

#[test]
fn parallel_open_preserves_owned_slots_sorted() {
    // par_iter doesn't preserve order; the parallel implementation must
    // sort owned_slots so downstream walks (verify_integrity, vacuum)
    // are deterministic.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..15u32 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space_parallel(b"pw").unwrap();
    // verify_integrity walks the tree — passes only if owned_slots is
    // self-consistent and chunks correctly hash-checked.
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
}

#[test]
fn parallel_open_wrong_password_returns_auth_failed() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"correct").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let result = c.open_space_parallel(b"wrong");
    assert!(matches!(result, Err(hidden_volume::Error::AuthFailed)));
}

#[test]
fn parallel_open_empty_file_authfails_too() {
    // No spaces written — any password fails.
    let path = scratch_path();
    {
        let _c = Container::create(&path, fast_params()).unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let result = c.open_space_parallel(b"any");
    assert!(matches!(result, Err(hidden_volume::Error::AuthFailed)));
}

#[test]
fn parallel_open_with_keys_skips_argon2() {
    // The pre-derived-keys path through the parallel scan must work
    // identically to its sequential counterpart.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let keys = c.derive_space_keys(b"pw").unwrap();
    let s = c.open_space_with_keys_parallel(keys).unwrap();
    assert_eq!(s.commit_seq(), 2);
}
