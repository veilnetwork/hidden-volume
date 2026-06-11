//! Behavioral equivalence: `scan_and_recover_mmap` ↔ sequential / parallel.
//!
//! The mmap-backed scan path (feature `mmap`, Unix-only) must
//! produce the same observable `SpaceState` as the streaming `pread`
//! path. The only documented difference is the read-syscall pattern;
//! callers see the same `Space`.
//!
//! These tests only build under `cfg(all(feature = "mmap", unix))`.

#![cfg(all(feature = "mmap", unix))]

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
fn mmap_open_recovers_same_state_as_sequential() {
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
        let mut tx = s.begin_tx();
        for id in 30..50u64 {
            tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
    }

    let (seq_seq, seq_history, seq_owned, seq_log) = {
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

    let (mmap_seq, mmap_history, mmap_owned, mmap_log) = {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space_mmap(b"pw").unwrap();
        let log = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
        (
            s.commit_seq(),
            s.commit_history().to_vec(),
            s.audit_owned_chunk_count(),
            log,
        )
    };

    assert_eq!(seq_seq, mmap_seq);
    assert_eq!(seq_history, mmap_history);
    assert_eq!(seq_owned, mmap_owned);
    assert_eq!(seq_log, mmap_log);
}

#[test]
fn mmap_open_picks_max_seq_across_many_replicas() {
    // 7 replicas × 10 commits = 77 SB chunks owned by the space.
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
    let s = c.open_space_mmap(b"pw").unwrap();
    assert_eq!(s.commit_seq(), 11);
    assert_eq!(s.commit_history().len(), 11);
}

#[test]
fn mmap_open_wrong_password_returns_auth_failed() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"correct").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let result = c.open_space_mmap(b"wrong");
    assert!(matches!(result, Err(hidden_volume::Error::AuthFailed)));
}

#[test]
fn mmap_open_empty_file_authfails_too() {
    let path = scratch_path();
    {
        let _c = Container::create(&path, fast_params()).unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let result = c.open_space_mmap(b"any");
    assert!(matches!(result, Err(hidden_volume::Error::AuthFailed)));
}

#[test]
fn mmap_open_with_keys_skips_argon2() {
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
    let s = c.open_space_with_keys_mmap(keys).unwrap();
    assert_eq!(s.commit_seq(), 2);
}

#[test]
fn mmap_open_then_verify_integrity_holds() {
    // Open via mmap, then walk Merkle chain — confirms the mmap path
    // populates owned_slots correctly so subsequent reads work.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for i in 0..200u32 {
            tx.put(Namespace::CONTACTS, format!("k{i:04}").as_bytes(), b"v")
                .unwrap();
        }
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space_mmap(b"pw").unwrap();
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
}

#[test]
fn mmap_three_paths_agree() {
    // Build a container, open via sequential / parallel / mmap and
    // confirm all three produce the same observable state.
    #[cfg(feature = "parallel-scan")]
    {
        let path = scratch_path();
        {
            let mut c = Container::create_with_options(&path, fast_options(3)).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            for i in 0..15u32 {
                let mut tx = s.begin_tx();
                tx.put(Namespace::CONTACTS, format!("k{i}").as_bytes(), b"v")
                    .unwrap();
                tx.commit().unwrap();
            }
        }
        let snap = |open: fn(&mut Container) -> hidden_volume::Result<()>| {
            let _ = open;
        };
        let _ = snap;

        let seq_state = {
            let mut c = Container::open(&path).unwrap();
            let mut s = c.open_space(b"pw").unwrap();
            (
                s.commit_seq(),
                s.commit_history().to_vec(),
                s.list(Namespace::CONTACTS).unwrap(),
            )
        };
        let par_state = {
            let mut c = Container::open(&path).unwrap();
            let mut s = c.open_space_parallel(b"pw").unwrap();
            (
                s.commit_seq(),
                s.commit_history().to_vec(),
                s.list(Namespace::CONTACTS).unwrap(),
            )
        };
        let mmap_state = {
            let mut c = Container::open(&path).unwrap();
            let mut s = c.open_space_mmap(b"pw").unwrap();
            (
                s.commit_seq(),
                s.commit_history().to_vec(),
                s.list(Namespace::CONTACTS).unwrap(),
            )
        };
        assert_eq!(seq_state, par_state);
        assert_eq!(seq_state, mmap_state);
    }
}
