//! `Space::verify_integrity` — Merkle-chain integrity walk (v0.3).
//!
//! Coverage:
//! 1. Empty space → trivially OK (0 chunks, 0 namespaces).
//! 2. Single-namespace single-leaf → OK; depth=1, namespaces=1, chunks≥2.
//! 3. Multi-namespace KV → namespaces count matches.
//! 4. B+ tree split (large namespace) → depth=2 reported.
//! 5. DataBatch log namespace → still verifies (KV-index covers it).
//! 6. Multi-space isolation → each space verifies independently.
//! 7. After compact_known → still verifies (fresh tree, same shape).
//! 8. AEAD corruption of the IndexNode root chunk → IntegrityFailure
//!    pointing at that slot.
//! 9. AEAD corruption of the Commit chunk → IntegrityFailure pointing
//!    at the commit slot.
//! 10. Read-only handle can call verify_integrity (no writes).

use hidden_volume::container::{ContainerOptions, RepackOptions};
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::{CHUNK_SIZE, Container, Error};
use std::io::{Read, Seek, SeekFrom, Write};

mod common;
use common::{fast_params, scratch_path};

fn fast_options() -> ContainerOptions {
    ContainerOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 3,
    }
}

fn fast_repack_options() -> RepackOptions {
    RepackOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 3,
    }
}

/// Bit-flip the first byte of the chunk at `slot` so that AEAD open
/// fails on it (matching the corruption pattern used by tests/sb_replicas.rs).
fn corrupt_slot(path: &std::path::Path, slot: u64) {
    let offset = (1 + slot) * CHUNK_SIZE as u64;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    let mut buf = [0u8; 1];
    f.read_exact(&mut buf).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(&[buf[0] ^ 0xFF]).unwrap();
    f.sync_all().unwrap();
}

#[test]
fn empty_space_verifies_trivially() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 0);
    assert_eq!(report.chunks_verified, 0);
    assert_eq!(report.max_depth, 0);
}

#[test]
fn single_namespace_single_leaf_verifies() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"username", b"alice").unwrap();
    tx.commit().unwrap();
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
    assert_eq!(report.max_depth, 1, "single-leaf depth should be 1");
    // Commit chunk + 1 leaf = 2 chunks verified.
    assert_eq!(report.chunks_verified, 2);
}

#[test]
fn multi_namespace_kv_verifies() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
    tx.put(Namespace::CONTACTS, b"bob", b"bob@example.com")
        .unwrap();
    tx.put(Namespace::MEDIA, b"avatar", b"\x00\x01\x02")
        .unwrap();
    tx.commit().unwrap();
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 3);
    // 1 commit + 3 leaves.
    assert_eq!(report.chunks_verified, 4);
    assert_eq!(report.max_depth, 1);
}

#[test]
fn b_plus_tree_split_reports_depth_two() {
    // Force a leaf split by stuffing one namespace beyond a single chunk.
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    // ~600 entries × ~8B keys + ~16B values; enough to overflow PAYLOAD_CAP.
    for i in 0..600u32 {
        let k = format!("k{i:08}");
        let v = format!("value-{i:08}");
        tx.put(Namespace::CONTACTS, k.as_bytes(), v.as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
    assert_eq!(report.max_depth, 2, "B+ tree split should produce depth=2");
    // chunks: 1 commit + 1 internal + N leaves; N≥2 by construction.
    assert!(
        report.chunks_verified >= 4,
        "expected commit + internal + ≥2 leaves; got {}",
        report.chunks_verified
    );
}

#[test]
fn databatch_log_namespace_verifies() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for id in 0..50u64 {
        tx.append_log(Namespace::MESSAGE_LOG, id, format!("msg{id}").as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();
    // M2 (2026-05-10): walker now extends past the KV index for log
    // namespaces, AEAD-decrypting + decode_batch'ing every referenced
    // DataBatch chunk. 50 records pack into ≥1 batches; assert at
    // least one was visited.
    let report = s.verify_integrity().unwrap();
    assert_eq!(report.namespaces_verified, 1);
    assert!(report.max_depth >= 1);
    assert!(
        report.data_batches_verified >= 1,
        "log namespace must report ≥1 verified DataBatch (got {})",
        report.data_batches_verified
    );
}

/// **M2 regression test (2026-05-10).** A DataBatch chunk pointed at by
/// a log-namespace leaf entry is corrupted on disk. Prior to M2,
/// `verify_integrity` walked only IndexNode chunks and reported OK
/// here, leaving the host-app to discover the corruption later at
/// `read_log` time. Post-M2, the walker AEAD-decrypts every DataBatch
/// reachable through log leaves and surfaces this as `IntegrityFailure`.
#[test]
fn corruption_of_databatch_chunk_surfaces_as_integrity_failure() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        // One log entry → one DataBatch chunk + one IndexNode (leaf) +
        // one Commit + 3 Superblock replicas. With initial_garbage=0 the
        // DataBatch lands at slot 2 (after slot 0 = first IndexNode for
        // empty roots, slot 1 = first commit; layout depends on
        // namespace ordering — so we accept any IntegrityFailure).
        tx.append_log(Namespace::MESSAGE_LOG, 1, b"sensitive-message")
            .unwrap();
        tx.commit().unwrap();
    }

    // Find the DataBatch chunk by trial: corrupt slots one-by-one until
    // verify_integrity flags one as the *DataBatch* failure (the test is
    // defensive against layout shifts; what matters is that DataBatch
    // corruption no longer silently passes).
    let mut found = false;
    for slot in 2u64..10 {
        let path_copy = scratch_path();
        std::fs::copy(&path, &path_copy).unwrap();
        corrupt_slot(&path_copy, slot);
        let mut c = match Container::open_readonly(&path_copy) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut s = match c.open_space(b"pw") {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Err(Error::IntegrityFailure {
            detail,
            slot: failed_slot,
        }) = s.verify_integrity()
            && detail.contains("DataBatch")
        {
            assert_eq!(failed_slot, slot);
            found = true;
            let _ = std::fs::remove_file(&path_copy);
            break;
        }
        let _ = std::fs::remove_file(&path_copy);
    }
    assert!(
        found,
        "corrupting some slot in [2, 10) should surface as a DataBatch IntegrityFailure"
    );
}

#[test]
fn multi_space_isolation_in_verify() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    {
        let mut a = c.create_space(b"alice").unwrap();
        let mut tx = a.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"alice-v").unwrap();
        tx.commit().unwrap();
        assert_eq!(a.verify_integrity().unwrap().namespaces_verified, 1);
    }
    {
        let mut b = c.create_space(b"bob").unwrap();
        let mut tx = b.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"bob-v").unwrap();
        tx.put(Namespace::CONTACTS, b"alice", b"hi").unwrap();
        tx.commit().unwrap();
        assert_eq!(b.verify_integrity().unwrap().namespaces_verified, 2);
    }
    // Re-open A — still 1 namespace, undisturbed by B.
    {
        let mut a = c.open_space(b"alice").unwrap();
        let r = a.verify_integrity().unwrap();
        assert_eq!(r.namespaces_verified, 1);
    }
}

#[test]
fn post_compact_verifies() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        for i in 0..10 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
        assert_eq!(s.verify_integrity().unwrap().namespaces_verified, 1);
    }
    let pw: &[u8] = b"pw";
    Container::compact_known(&path, &[pw], fast_repack_options()).unwrap();
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let r = s.verify_integrity().unwrap();
    assert_eq!(r.namespaces_verified, 1);
    assert_eq!(r.max_depth, 1);
}

#[test]
fn corruption_of_index_node_root_surfaces_as_integrity_failure() {
    // Create a fresh container with replicas=3. Slot layout after
    // create_space + one commit:
    //   slots 0..2: initial Superblock replicas (seq=1)
    //   slot 3:     IndexNode (single Leaf for the namespace we wrote)
    //   slot 4:     Commit chunk
    //   slots 5..7: new Superblock replicas (seq=2)
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
        assert!(s.verify_integrity().is_ok());
    }
    // Corrupt the IndexNode (Leaf) at slot 3.
    corrupt_slot(&path, 3);

    // Use `open_readonly` so we skip the auto-vacuum tree-walk (which
    // would itself fail on the corrupted chunk and surface as
    // `AuthFailed` from `open_space`). Read-only opens are exactly the
    // diagnostic-tool entry point for this scenario — host-app sees
    // `AuthFailed` from `open_space`, falls back to `open_readonly` +
    // `verify_integrity()` to localize the corruption.
    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    match s.verify_integrity() {
        Err(Error::IntegrityFailure { detail: _, slot }) => assert_eq!(slot, 3),
        other => panic!("expected IntegrityFailure at slot 3, got {other:?}"),
    }
}

#[test]
fn corruption_of_commit_chunk_surfaces_as_integrity_failure() {
    let path = scratch_path();
    {
        let mut c = Container::create_with_options(&path, fast_options()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    // Slot 4 = Commit chunk per the layout above.
    corrupt_slot(&path, 4);

    // Same diagnostic-tool entry pattern as the IndexNode-corruption test.
    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    match s.verify_integrity() {
        Err(Error::IntegrityFailure { detail: _, slot }) => assert_eq!(slot, 4),
        other => panic!("expected IntegrityFailure at slot 4, got {other:?}"),
    }
}

#[test]
fn verify_integrity_works_on_readonly_handle() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let r = s.verify_integrity().unwrap();
    assert_eq!(r.namespaces_verified, 1);
}

/// Audit pass 14: `open_space_verified` strict-mode opens cleanly
/// when the chain is intact.
#[test]
fn open_space_verified_succeeds_on_healthy_container() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.append_log(Namespace::MESSAGE_LOG, 1, b"msg").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space_verified(b"pw").unwrap();
    // Same handle as `open_space` would produce — both KV and log
    // entries readable.
    assert_eq!(
        s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
        Some(&b"v"[..])
    );
    assert_eq!(
        s.read_log(Namespace::MESSAGE_LOG, 1).unwrap().as_deref(),
        Some(&b"msg"[..])
    );
}

/// Audit pass 14: `open_space_verified` rejects at open time when
/// the latest Commit chunk is AEAD-corrupted; standard `open_space`
/// would have succeeded and surfaced the failure on first read.
#[test]
fn open_space_verified_rejects_corrupted_chain() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    // Corrupt the Commit chunk (slot 4 in the standard layout).
    corrupt_slot(&path, 4);

    let mut c = Container::open(&path).unwrap();
    // Strict mode catches the corruption at open time.
    let res = c.open_space_verified(b"pw");
    match res {
        Err(Error::IntegrityFailure { .. }) | Err(Error::AuthFailed) | Err(Error::Malformed(_)) => {
        },
        other => {
            panic!("expected IntegrityFailure / AuthFailed / Malformed at open, got {other:?}")
        },
    }
}
