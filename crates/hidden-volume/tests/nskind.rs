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

/// Cross-Tx: a namespace established as Log cannot be `delete`-ed by
/// KEY in a later Tx (audit HV-04).
///
/// This got through both gates. The Tx-side check only asks whether
/// the OTHER kind is pending in the same transaction, which for a
/// lone `delete` it is not; the commit-side check then looked only for
/// a `Put` among the ops, because pure-`Delete` sets had been let
/// through deliberately so that `Space::erase_namespace` could clear a
/// Log namespace. That exemption was written for erase and applied to
/// everything shaped like erase, so an application that reached for
/// `delete` on its message log — the wrong call, but a plausible one —
/// silently unlinked a record's `DataBatch` pointer through an API
/// that is documented to reject exactly this.
#[test]
fn cross_tx_log_namespace_rejects_delete_by_key() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.append_log(Namespace(7), 1, b"msg").unwrap();
        tx.commit().unwrap();
    }
    {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        // The key a log record actually occupies, so this is the delete
        // that would have removed one had it been permitted.
        tx.delete(Namespace(7), &1u64.to_be_bytes()).unwrap();
        match tx.commit() {
            Err(Error::WrongNamespaceKind(_)) => {},
            other => panic!("expected commit-time WrongNamespaceKind, got {other:?}"),
        }
    }

    // And the record is still there — the rejection has to happen
    // before anything is written, not after.
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.read_log(Namespace(7), 1).unwrap().as_deref(),
        Some(&b"msg"[..]),
        "the rejected delete still unlinked the record"
    );
    std::fs::remove_file(&path).ok();
}

/// Cross-Tx: a namespace established as Kv cannot be `delete_log`-ed
/// in a later Tx (audit HV-04) — the mirror of the test above.
///
/// `delete_log` routes through the same internal helper
/// `erase_namespace` uses, which skips the kind check on purpose, and
/// the commit-side check never saw it because a log DELETE lands in
/// the KV op map rather than the log one. So the one op addressed by
/// log id was the one op that never met the recorded kind at all.
#[test]
fn cross_tx_kv_namespace_rejects_delete_by_log_id() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        // The key a `delete_log(ns, 1)` would address, so the delete
        // below names something that really is in this namespace.
        tx.put(Namespace(5), &1u64.to_be_bytes(), b"v").unwrap();
        tx.commit().unwrap();
    }
    {
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.delete_log(Namespace(5), 1).unwrap();
        match tx.commit() {
            Err(Error::WrongNamespaceKind(_)) => {},
            other => panic!("expected commit-time WrongNamespaceKind, got {other:?}"),
        }
    }

    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    assert_eq!(
        s.get(Namespace(5), &1u64.to_be_bytes()).unwrap().as_deref(),
        Some(&b"v"[..]),
        "the rejected delete_log still removed the entry"
    );
    std::fs::remove_file(&path).ok();
}

/// The exemption the two tests above close must stay open for the one
/// caller it was written for: `erase_namespace` clears a Log namespace
/// by issuing a `Delete` per key.
///
/// Without this, "reject deletes that do not match the recorded kind"
/// is trivially satisfiable by rejecting all of them, and the bulk
/// erase — the documented way to clear a chat history — would break.
#[test]
fn erase_namespace_still_clears_a_log_namespace() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for id in 0..5u64 {
        tx.append_log(Namespace(9), id, b"msg").unwrap();
    }
    tx.commit().unwrap();

    assert_eq!(s.erase_namespace(Namespace(9)).unwrap(), 5);
    assert_eq!(s.count(Namespace(9)).unwrap(), 0);
    std::fs::remove_file(&path).ok();
}

/// `delete_log` on a Log namespace is the legitimate use and must keep
/// working — the check has to read the RECORDED kind, not refuse every
/// delete that did not arrive through `put`/`delete`.
#[test]
fn delete_log_on_a_log_namespace_still_works() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.append_log(Namespace(11), 1, b"a").unwrap();
    tx.append_log(Namespace(11), 2, b"b").unwrap();
    tx.commit().unwrap();

    let mut tx = s.begin_tx();
    tx.delete_log(Namespace(11), 1).unwrap();
    tx.commit().unwrap();

    assert_eq!(s.read_log(Namespace(11), 1).unwrap(), None);
    assert_eq!(
        s.read_log(Namespace(11), 2).unwrap().as_deref(),
        Some(&b"b"[..])
    );
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
