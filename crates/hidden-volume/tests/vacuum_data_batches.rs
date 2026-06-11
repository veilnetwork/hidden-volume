//! `Space::vacuum_data_batches` — scrub owned DataBatch chunks that are
//! no longer referenced by any namespace's KV index.
//!
//! Coverage:
//! 1. No-op on empty space.
//! 2. No-op when every batch is currently referenced.
//! 3. After erase_namespace on a log namespace, vacuum_data_batches
//!    scrubs the now-orphan batches → owned chunk count drops.
//! 4. After repeated commits to the same log_ids (each new commit
//!    creates a fresh batch, prior becomes orphan), vacuum_data_batches
//!    reclaims the orphan batches.
//! 5. Multi-namespace: vacuum doesn't touch live batches in OTHER
//!    namespaces.
//! 6. Idempotent: running twice in a row → second call returns 0.
//! 7. Read-only handle: returns 0 without errors.
//! 8. Verify integrity after vacuum: hash chain still walks.

use hidden_volume::Container;
use hidden_volume::space::index::Namespace;

mod common;
use common::{fast_params, scratch_path};

#[test]
fn empty_space_vacuum_data_batches_is_noop() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    assert_eq!(s.vacuum_data_batches().unwrap(), 0);
}

#[test]
fn fresh_log_no_orphans_means_zero_scrubbed() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for id in 1..=20u64 {
        tx.append_log(Namespace::MESSAGE_LOG, id, format!("m{id}").as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();
    // Single commit → single live batch. No orphans yet.
    let scrubbed = s.vacuum_data_batches().unwrap();
    assert_eq!(scrubbed, 0);
    // Log still readable.
    assert_eq!(s.iter_log(Namespace::MESSAGE_LOG).unwrap().len(), 20);
}

#[test]
fn post_erase_log_orphans_get_scrubbed() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for id in 1..=30u64 {
        tx.append_log(Namespace::MESSAGE_LOG, id, format!("m{id}").as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();

    // Erase: KV pointers gone but DataBatch still owned.
    s.erase_namespace(Namespace::MESSAGE_LOG).unwrap();
    let owned_post_erase = s.audit_owned_chunk_count();
    let scrubbed = s.vacuum_data_batches().unwrap();
    assert!(scrubbed >= 1, "expected at least one DataBatch scrubbed");
    let owned_post_vacuum = s.audit_owned_chunk_count();
    assert!(
        owned_post_vacuum < owned_post_erase,
        "vacuum should reduce owned count; post_erase={owned_post_erase}, post_vacuum={owned_post_vacuum}",
    );
    // Log namespace still empty (vacuum didn't bring it back).
    assert!(s.iter_log(Namespace::MESSAGE_LOG).unwrap().is_empty());
}

#[test]
fn overwrite_creates_orphans_that_vacuum_reclaims() {
    // Sequence:
    //   tx1: append_log(1..10) → batch_X
    //   tx2: append_log(1..10) again → batch_Y, KV now points at Y, X orphaned
    //   tx3: ... etc.
    // After many such overwrites, vacuum_data_batches should scrub
    // every orphan batch (≥ N-1 of N batches owned).
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for round in 0..5u32 {
        let mut tx = s.begin_tx();
        for id in 1..=10u64 {
            tx.append_log(
                Namespace::MESSAGE_LOG,
                id,
                format!("round{round}-m{id}").as_bytes(),
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let owned_before = s.audit_owned_chunk_count();
    let scrubbed = s.vacuum_data_batches().unwrap();
    let owned_after = s.audit_owned_chunk_count();
    // Expect ≥ 4 orphans scrubbed (rounds 0..3 are all overwritten).
    assert!(
        scrubbed >= 4,
        "expected ≥4 orphan batches; got {scrubbed} (owned {owned_before} → {owned_after})",
    );
    // Final log payloads from round 4 are still readable.
    let log = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
    assert_eq!(log.len(), 10);
    for (id, payload) in &log {
        assert_eq!(payload, format!("round4-m{id}").as_bytes());
    }
}

#[test]
fn multi_namespace_other_log_preserved() {
    // Two log namespaces. Vacuum after editing one should leave the
    // other's batches alone.
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    // Namespace 7 = first log, namespace 8 = second log.
    let log_a = Namespace(7);
    let log_b = Namespace(8);
    {
        let mut tx = s.begin_tx();
        for id in 1..=5u64 {
            tx.append_log(log_a, id, b"a-orig").unwrap();
            tx.append_log(log_b, id, b"b-orig").unwrap();
        }
        tx.commit().unwrap();
    }
    // Overwrite log_a only — log_a's batch becomes orphan.
    {
        let mut tx = s.begin_tx();
        for id in 1..=5u64 {
            tx.append_log(log_a, id, b"a-NEW").unwrap();
        }
        tx.commit().unwrap();
    }
    let scrubbed = s.vacuum_data_batches().unwrap();
    assert!(scrubbed >= 1);
    // log_b's payloads unchanged.
    let log_b_entries = s.iter_log(log_b).unwrap();
    assert_eq!(log_b_entries.len(), 5);
    for (_id, payload) in &log_b_entries {
        assert_eq!(payload, b"b-orig");
    }
    // log_a has the new payloads.
    let log_a_entries = s.iter_log(log_a).unwrap();
    assert_eq!(log_a_entries.len(), 5);
    for (_id, payload) in &log_a_entries {
        assert_eq!(payload, b"a-NEW");
    }
}

#[test]
fn vacuum_is_idempotent() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    for round in 0..3u32 {
        let mut tx = s.begin_tx();
        for id in 1..=5u64 {
            tx.append_log(
                Namespace::MESSAGE_LOG,
                id,
                format!("r{round}-m{id}").as_bytes(),
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let first = s.vacuum_data_batches().unwrap();
    let second = s.vacuum_data_batches().unwrap();
    assert!(first >= 1);
    assert_eq!(
        second, 0,
        "second vacuum should scrub nothing (idempotent), got {second}",
    );
}

#[test]
fn readonly_handle_errors_on_explicit_vacuum() {
    // Audit pass 7 (L5): explicit `vacuum_data_batches` on a
    // read-only handle now errors with `Error::ReadOnly` — the
    // previous silent `Ok(0)` masked failed privacy expectations.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.append_log(Namespace::MESSAGE_LOG, 1, b"m").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    match s.vacuum_data_batches() {
        Err(hidden_volume::Error::ReadOnly) => {},
        other => panic!("expected Err(ReadOnly), got {other:?}"),
    }
}

#[test]
fn integrity_holds_after_vacuum() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    // Build up some history with overwrites to create orphan batches.
    for round in 0..3u32 {
        let mut tx = s.begin_tx();
        for id in 1..=8u64 {
            tx.append_log(
                Namespace::MESSAGE_LOG,
                id,
                format!("r{round}-m{id}").as_bytes(),
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    // Add a KV namespace too.
    {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
        tx.commit().unwrap();
    }
    // Vacuum.
    let _ = s.vacuum_data_batches().unwrap();
    // Merkle walk still passes.
    let report = s.verify_integrity().unwrap();
    assert!(report.namespaces_verified >= 1);
    // Live state unchanged.
    let log = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
    assert_eq!(log.len(), 8);
    assert_eq!(
        s.get(Namespace::SETTINGS, b"theme").unwrap().as_deref(),
        Some(&b"dark"[..])
    );
}
