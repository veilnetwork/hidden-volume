//! Behavioral equivalence: parallel-scan CT companion ↔ sequential.
//!
//! `Container::open_space_parallel_constant_time` (v1.0) combines
//! the parallel-scan speedup with the per-chunk ChaCha20 timing
//! equalizer. The recovered `Space` MUST be observationally
//! identical to what the default sequential scan produces — only
//! the per-chunk timing shape differs. Mirrors
//! `tests/constant_time_scan.rs` for the parallel-scan path.

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
fn parallel_constant_time_recovers_same_state_as_sequential() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..30u32 {
            tx.put(Namespace::SETTINGS, format!("k{i:02}").as_bytes(), b"v")
                .unwrap();
        }
        tx.put(Namespace::CONTACTS, b"alice", b"@alice").unwrap();
        for id in 0..15u64 {
            tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
    }

    // Sequential reference.
    let (seq_seq, seq_owned, seq_count) = {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        (
            s.commit_seq(),
            s.audit_owned_chunk_count(),
            s.count(Namespace::SETTINGS).unwrap(),
        )
    };

    // Parallel-scan CT companion.
    let (ct_seq, ct_owned, ct_count) = {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space_parallel_constant_time(b"pw").unwrap();
        (
            s.commit_seq(),
            s.audit_owned_chunk_count(),
            s.count(Namespace::SETTINGS).unwrap(),
        )
    };

    assert_eq!(
        seq_seq, ct_seq,
        "commit_seq must match across parallel/sequential CT modes"
    );
    assert_eq!(
        seq_owned, ct_owned,
        "owned_chunk_count must match across parallel/sequential CT modes"
    );
    assert_eq!(
        seq_count, ct_count,
        "namespace entry count must match across parallel/sequential CT modes"
    );
}

#[test]
fn parallel_constant_time_wrong_password_returns_auth_failed() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
        let mut s = c.create_space(b"correct").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    // Wrong password on CT-parallel must fail the same way the
    // default parallel scan would (deniability: external
    // observation invariant across scan-mode opt-in).
    let mut c = Container::open(&path).unwrap();
    let err = c.open_space_parallel_constant_time(b"wrong").unwrap_err();
    assert!(matches!(err, hidden_volume::Error::AuthFailed));
}
