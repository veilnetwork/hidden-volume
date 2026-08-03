//! The FFI's abandoned-call ledger (audit HV-02).
//!
//! `spawn_blocking` cannot interrupt a closure that has begun, so a foreign
//! caller who times out a `commit` and walks away cannot learn from the call
//! whether the transaction landed — and retrying a non-idempotent
//! `append_log` on a guess corrupts the log. `hidden-volume-async` has had
//! the answer since HV-11; this crate kept calling the plain `run_blocking`,
//! which builds a fresh ledger per call and destroys it on return, so every
//! verdict was filed into an object that immediately ceased to exist.
//!
//! What these tests pin is the half that is specific to this crate: the
//! ledger belongs to the *handle*, its records outlive the call that made
//! them, and the verdict it reports is true of the disk. The ledger's own
//! semantics — the admission permit, `NeverStarted` as a proof of no effect,
//! `Running` settling to `Succeeded` — are gated deterministically in
//! `hidden-volume-async/tests/abandoned_futures.rs` against the same
//! `OpLedger` this handle now holds.

use hidden_volume_ffi::{ArgonPreset, AsyncSpaceHandle, OperationOutcome, PaddingPreset, WriteOp};

fn scratch_path() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}

async fn handle(path: &std::path::Path) -> std::sync::Arc<AsyncSpaceHandle> {
    AsyncSpaceHandle::create(
        path.to_string_lossy().into_owned(),
        b"pw".to_vec(),
        ArgonPreset::Min,
        0,
        1,
    )
    .await
    .unwrap()
}

/// Poll `fut` exactly once, then drop it — the shape a foreign `withTimeout`
/// takes when the timeout is already expired.
///
/// One poll is enough and is not a race: the first poll takes the ledger's
/// admission permit and calls `spawn_blocking`, whose `JoinHandle` cannot be
/// ready yet, so the future is always still in flight when it is dropped and
/// the ledger always files a record. No sleeps, no scheduler hopes.
macro_rules! dispatch_then_abandon {
    ($fut:expr) => {{
        let mut fut = Box::pin($fut);
        tokio::select! {
            biased;
            _ = &mut fut => panic!("a spawn_blocking future cannot be ready on its first poll"),
            () = std::future::ready(()) => {},
        }
        drop(fut);
    }};
}

/// The verdict on an abandoned write is readable afterwards, and it agrees
/// with the disk. Before this pass the ledger holding it was destroyed with
/// the call, so there was nothing to ask.
///
/// The assertion is the agreement, not a fixed outcome. A one-poll abandon
/// reliably lands on `NeverStarted` — the ledger fires the cancel token as
/// the future drops, and the pool thread finds it already fired before
/// touching anything, which is the *strongest* verdict there is and the only
/// one under which a non-idempotent retry is safe. Pinning that string
/// specifically would be pinning a scheduling detail; what must hold on every
/// side of the race is that a no-effect verdict means nothing landed and a
/// success verdict means it did. (`Running` settling to `Succeeded` is gated
/// deterministically against this same ledger in
/// `hidden-volume-async/tests/abandoned_futures.rs`, using a closure the test
/// can park — something this crate's closed-form FFI surface has no way to
/// offer.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_commit_leaves_a_verdict_that_agrees_with_the_disk() {
    let path = scratch_path();
    let h = handle(&path).await;

    // Enough ops that the Tx-assembly loop — the one stretch of `commit`
    // where the cancel token can still be honoured rather than merely
    // reported — is genuinely running when the caller walks away.
    let ops: Vec<WriteOp> = (0..64)
        .map(|i| WriteOp::AppendLog {
            namespace: 3,
            log_id: i,
            payload: vec![b'x'; 512],
        })
        .collect();
    dispatch_then_abandon!(h.commit(ops));

    let filed = h.abandoned_operations();
    assert_eq!(
        filed.len(),
        1,
        "the abandoned call must be filed: {filed:?}"
    );

    let mut record = filed[0];
    for _ in 0..600 {
        record = h.abandoned_operations()[0];
        if record.settled {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(record.settled, "outcome never settled: {record:?}");

    let landed = h.read_log(3, 0).await.unwrap().is_some();
    match record.outcome {
        OperationOutcome::NeverStarted | OperationOutcome::Failed => assert!(
            !landed,
            "{:?} claims no durable effect, but the commit landed",
            record.outcome
        ),
        OperationOutcome::Succeeded => assert!(
            landed,
            "Succeeded must mean the commit landed, not that it was cancelled"
        ),
        other => panic!("unexpected settled outcome {other:?}"),
    }
    assert_eq!(
        record.may_have_mutated,
        record.outcome != OperationOutcome::NeverStarted,
        "only NeverStarted is backed by a proof of no effect"
    );

    let _ = std::fs::remove_file(&path);
}

/// The ledger is the handle's, not one per call.
///
/// This is the finding stated as an assertion: with a ledger built inside
/// `run_blocking` and dropped on return, both records below would be filed
/// into two different short-lived objects and this would read zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ledger_belongs_to_the_handle_not_to_the_call() {
    let path = scratch_path();
    let h = handle(&path).await;

    dispatch_then_abandon!(h.commit(vec![WriteOp::Put {
        namespace: 1,
        key: b"k1".to_vec(),
        value: b"v1".to_vec(),
    }]));
    dispatch_then_abandon!(h.set_padding_policy(PaddingPreset::None));

    let filed = h.abandoned_operations();
    assert_eq!(
        filed.len(),
        2,
        "both calls must be filed in the SAME ledger: {filed:?}"
    );
    assert_ne!(
        filed[0].id, filed[1].id,
        "operation ids must be distinct within a handle: {filed:?}"
    );

    // And a clone of the handle — which is what uniffi hands each foreign
    // caller — reads the same ledger, not an empty one of its own.
    let clone = std::sync::Arc::clone(&h);
    assert_eq!(clone.abandoned_operations().len(), 2);

    let _ = std::fs::remove_file(&path);
}

/// Reconciliation is not write-only: settled records can be retired, and
/// clearing them does not disturb the ones still in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clearing_settled_records_leaves_the_unsettled_ones() {
    let path = scratch_path();
    let h = handle(&path).await;

    dispatch_then_abandon!(h.commit(vec![WriteOp::Put {
        namespace: 1,
        key: b"k".to_vec(),
        value: b"v".to_vec(),
    }]));

    for _ in 0..600 {
        if h.abandoned_operations()[0].settled {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(h.abandoned_operations()[0].settled);

    h.clear_settled_operations();
    assert!(
        h.abandoned_operations().is_empty(),
        "a settled record must be retirable"
    );
    assert_eq!(
        h.forgotten_abandonments(),
        0,
        "nothing was evicted for lack of room"
    );

    let _ = std::fs::remove_file(&path);
}

/// Abandonment does not poison the handle: the next call works, and it is
/// filed nowhere because it was not abandoned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_completed_call_after_an_abandoned_one_files_nothing() {
    let path = scratch_path();
    let h = handle(&path).await;

    dispatch_then_abandon!(h.commit(vec![WriteOp::Put {
        namespace: 1,
        key: b"first".to_vec(),
        value: b"1".to_vec(),
    }]));

    // Awaited to completion — the guard disarms, so nothing is filed.
    h.commit(vec![WriteOp::Put {
        namespace: 1,
        key: b"second".to_vec(),
        value: b"2".to_vec(),
    }])
    .await
    .unwrap();

    assert_eq!(
        h.abandoned_operations().len(),
        1,
        "only the abandoned call is a record"
    );
    assert_eq!(
        h.get(1, b"second".to_vec()).await.unwrap().as_deref(),
        Some(&b"2"[..])
    );

    let _ = std::fs::remove_file(&path);
}
