//! R-NSKIND regression tests (audit pass 12 HIGH closed in pass 13).
//!
//! Format v2 added an explicit `NamespaceKind::{Kv, Log}` discriminant
//! to every `IndexRoot`. `Tx::put`/`delete` reject Kv ops on a Log
//! namespace and vice versa; `Container::repack` routes by the
//! persisted kind (no more shape-heuristic); `vacuum_data_batches`
//! collects batch-slot pointers only from Log-kind namespaces (no
//! more "8-byte KV value coincidentally suppresses scrub" false
//! negative).

use hidden_volume::space::index::Namespace;
use hidden_volume::tx::NamespaceKind;
use hidden_volume::{Container, Error};

mod common;
use common::{fast_params, scratch_path};

/// Intra-Tx: `put` then `append_log` on the same namespace must
/// reject with `WrongNamespaceKind` at the `append_log` call site,
/// before any chunk is written.
#[test]
fn intra_tx_kv_then_log_rejected() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace(5), b"k", b"v").unwrap();
    let res = tx.append_log(Namespace(5), 1, b"msg");
    match res {
        Err(Error::WrongNamespaceKind(_)) => {},
        other => panic!("expected WrongNamespaceKind, got {other:?}"),
    }
    drop(tx);
    drop(s);
    drop(c);
    std::fs::remove_file(&path).ok();
}

/// Intra-Tx: `append_log` then `put` on the same namespace must
/// reject with `WrongNamespaceKind`.
#[test]
fn intra_tx_log_then_kv_rejected() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.append_log(Namespace(7), 1, b"msg").unwrap();
    let res = tx.put(Namespace(7), b"k", b"v");
    match res {
        Err(Error::WrongNamespaceKind(_)) => {},
        other => panic!("expected WrongNamespaceKind, got {other:?}"),
    }
}

/// Cross-Tx: namespace established as Kv in Tx1 cannot be appended
/// to as Log in Tx2 — `commit_tx`'s prior-root check rejects.
#[test]
fn cross_tx_kv_namespace_locked() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace(5), b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    // Tx-side check passes (no pending KV on this ns yet).
    tx.append_log(Namespace(5), 1, b"msg").unwrap();
    // commit-side cross-Tx check fires.
    let res = tx.commit();
    match res {
        Err(Error::WrongNamespaceKind(_)) => {},
        other => panic!("expected commit-time WrongNamespaceKind, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

/// Cross-Tx: namespace established as Log cannot be `put`-ed in a
/// later Tx — symmetric to the test above.
#[test]
fn cross_tx_log_namespace_locked() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.append_log(Namespace(7), 1, b"msg").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace(7), b"k", b"v").unwrap();
    let res = tx.commit();
    match res {
        Err(Error::WrongNamespaceKind(_)) => {},
        other => panic!("expected commit-time WrongNamespaceKind, got {other:?}"),
    }
    std::fs::remove_file(&path).ok();
}

/// `Space::list_namespaces_with_kind` returns the persisted kind
/// for every namespace with at least one committed entry.
#[test]
fn list_namespaces_with_kind_reflects_actual_kind() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace(1), b"k1", b"v1").unwrap();
        tx.append_log(Namespace(3), 100, b"hi").unwrap();
        tx.put(Namespace(5), b"k5", b"v5").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let nks = s.list_namespaces_with_kind().unwrap();
    let by_ns: std::collections::BTreeMap<u8, NamespaceKind> =
        nks.into_iter().map(|(ns, k)| (ns.0, k)).collect();
    assert_eq!(by_ns.get(&1), Some(&NamespaceKind::Kv));
    assert_eq!(by_ns.get(&3), Some(&NamespaceKind::Log));
    assert_eq!(by_ns.get(&5), Some(&NamespaceKind::Kv));
    std::fs::remove_file(&path).ok();
}

/// Repack preserves kind across the rewrite. Without the persisted
/// kind, the v1 heuristic would have lost log payloads (audit pass
/// 12 HIGH).
#[test]
fn repack_preserves_kind_across_rewrite() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace(1), b"setting", b"value").unwrap();
        tx.append_log(Namespace(3), 1, b"msg-1").unwrap();
        tx.append_log(Namespace(3), 2, b"msg-2").unwrap();
        tx.commit().unwrap();
    }

    Container::compact_known(&path, &[b"pw"], Default::default()).unwrap();

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();

    // KV namespace 1 still readable as KV.
    assert_eq!(
        s.get(Namespace(1), b"setting").unwrap().as_deref(),
        Some(&b"value"[..])
    );
    // Log namespace 3 still readable as Log.
    let log = s.iter_log(Namespace(3)).unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].0, 1);
    assert_eq!(log[1].0, 2);
    assert_eq!(log[0].1, b"msg-1");
    assert_eq!(log[1].1, b"msg-2");

    // Kinds preserved on disk.
    let nks = s.list_namespaces_with_kind().unwrap();
    let by_ns: std::collections::BTreeMap<u8, NamespaceKind> =
        nks.into_iter().map(|(ns, k)| (ns.0, k)).collect();
    assert_eq!(by_ns.get(&1), Some(&NamespaceKind::Kv));
    assert_eq!(by_ns.get(&3), Some(&NamespaceKind::Log));

    std::fs::remove_file(&path).ok();
}

/// `vacuum_data_batches` only consults Log-kind namespaces, not
/// every namespace. A KV value that coincidentally matches a stale
/// batch slot must not suppress scrub.
#[test]
fn vacuum_ignores_kv_values_matching_batch_slot() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    // Tx 1: write a log entry to namespace 3.
    let mut tx = s.begin_tx();
    tx.append_log(Namespace(3), 1, b"oldest").unwrap();
    tx.commit().unwrap();

    // Tx 2: erase the log entry. The DataBatch chunk now has no
    // referencing log_id key in the index.
    s.erase_namespace(Namespace(3)).unwrap();

    // Tx 3: write a KV entry whose value is an arbitrary 8-byte
    // sequence. Even if it happened to encode a u64 matching an
    // owned slot, the new vacuum logic ignores Kv-kind namespaces
    // when collecting referenced batch_slot pointers.
    let arbitrary_8b: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let mut tx = s.begin_tx();
    tx.put(Namespace(1), b"key", &arbitrary_8b).unwrap();
    tx.commit().unwrap();

    // Now run vacuum_data_batches. The DataBatch chunk should be
    // scrubbed because no Log-kind namespace references it.
    let scrubbed = s.vacuum_data_batches().unwrap();
    assert!(
        scrubbed >= 1,
        "expected ≥ 1 scrubbed DataBatch, got {scrubbed} \
         (the v1 heuristic would have suppressed scrub)"
    );

    drop(s);
    drop(c);
    std::fs::remove_file(&path).ok();
}
