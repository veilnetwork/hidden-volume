//! What happens to a blocking operation whose future is dropped
//! (audit HV-11).
//!
//! `tokio::task::spawn_blocking` cannot be interrupted, so the only
//! honest contract is a split one: before the closure starts,
//! abandonment is a real cancellation; after it starts, it is a report.
//! These tests pin down both halves — including the part that is *not*
//! a cancellation, so nobody later "fixes" it into a lie.
//!
//! Every ordering here is forced by an explicit gate (the ledger's
//! single admission permit, a channel handshake), never by hoping the
//! scheduler interleaves a certain way.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hidden_volume::Error;
use hidden_volume::cancel::CancelToken;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
use hidden_volume_async::{AsyncContainer, OpOutcome};

fn fast_params() -> Argon2Params {
    Argon2Params::MIN
}

fn scratch_path() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}

async fn container_with_space(path: &std::path::Path) -> AsyncContainer {
    let c = AsyncContainer::create(path, fast_params()).await.unwrap();
    c.run(|c| {
        let _ = c.create_space(b"pw")?;
        Ok(())
    })
    .await
    .unwrap();
    c
}

/// Park an operation inside the container so it holds the handle's one
/// admission permit. Returns the join handle plus the sender that lets
/// it finish.
///
/// The returned future has already entered its closure by the time this
/// function returns — every later step is therefore strictly ordered
/// after "the permit is taken".
async fn occupy_the_permit(
    c: &AsyncContainer,
) -> (
    tokio::task::JoinHandle<hidden_volume::Result<()>>,
    std::sync::mpsc::Sender<()>,
) {
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let handle = tokio::spawn({
        let c = c.clone();
        async move {
            c.run(move |_c| {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
            .await
        }
    });
    started_rx.await.unwrap();
    (handle, release_tx)
}

/// Dropping the future of an operation that has already begun does NOT
/// undo it — and the handle says so out loud instead of leaving the
/// caller to guess.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_write_that_already_started_is_reported_not_pretended() {
    let path = scratch_path();
    let c = container_with_space(&path).await;

    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

    {
        let c2 = c.clone();
        let fut = c2.run(move |c| {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            let mut s = c.open_space(b"pw")?;
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"late", b"landed")?;
            tx.commit()?;
            Ok(())
        });
        // `Box::pin`, not `tokio::pin!`: the latter shadows the binding
        // with a `Pin<&mut _>`, and dropping *that* drops nothing.
        let mut fut = Box::pin(fut);
        tokio::select! {
            _ = &mut fut => panic!("the closure is parked on a channel; it cannot have finished"),
            _ = started_rx => {},
        }
        // The caller walks away here, exactly like a `timeout` firing.
        drop(fut);
    }

    let filed = c.abandoned_operations();
    assert_eq!(filed.len(), 1, "the abandoned operation must be filed");
    assert_eq!(
        filed[0].outcome,
        OpOutcome::Running,
        "an already-started operation must be reported as still running, \
         not as cancelled"
    );
    assert!(
        filed[0].outcome.may_have_mutated(),
        "a running operation must never claim the container is untouched"
    );
    assert!(!filed[0].outcome.is_settled());

    // Let it finish and watch the record settle.
    release_tx.send(()).unwrap();
    let mut settled = OpOutcome::Running;
    for _ in 0..600 {
        settled = c.abandoned_operations()[0].outcome;
        if settled.is_settled() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        settled,
        OpOutcome::Succeeded,
        "the abandoned write ran to completion; the ledger must say so"
    );

    // ...and `Succeeded` is not decoration: the write really is on disk.
    let value = c
        .run(|c| {
            let mut s = c.open_space(b"pw")?;
            s.get(Namespace::SETTINGS, b"late")
        })
        .await
        .unwrap();
    assert_eq!(
        value.as_deref(),
        Some(&b"landed"[..]),
        "OpOutcome::Succeeded must mean the data landed"
    );

    let _ = std::fs::remove_file(&path);
}

/// The other half: abandoning an operation that has not been dispatched
/// yet really does cancel it. Nothing runs, and the record says so with
/// a proof rather than a hope.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_operation_abandoned_before_dispatch_provably_never_runs() {
    let path = scratch_path();
    let c = container_with_space(&path).await;

    let (parked, release) = occupy_the_permit(&c).await;

    let ran = Arc::new(AtomicBool::new(false));
    {
        let c2 = c.clone();
        let ran = Arc::clone(&ran);
        let mut fut = Box::pin(c2.run(move |c| {
            ran.store(true, Ordering::SeqCst);
            let mut s = c.open_space(b"pw")?;
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"ghost", b"x")?;
            tx.commit()?;
            Ok(())
        }));
        // One poll takes it as far as the admission permit, which the
        // parked operation holds. It cannot get further.
        assert!(futures_util::poll!(fut.as_mut()).is_pending());
        drop(fut);
    }

    // Release the parked operation: the permit is now free, so if the
    // abandoned operation were still going to run, this is when.
    release.send(()).unwrap();
    parked.await.unwrap().unwrap();

    assert!(
        !ran.load(Ordering::SeqCst),
        "an operation abandoned before dispatch must never execute"
    );

    let filed = c.abandoned_operations();
    assert_eq!(filed.len(), 1);
    assert_eq!(filed[0].outcome, OpOutcome::NeverStarted);
    assert!(
        !filed[0].outcome.may_have_mutated(),
        "NeverStarted is the one outcome allowed to claim no effect"
    );

    let missing = c
        .run(|c| {
            let mut s = c.open_space(b"pw")?;
            s.get(Namespace::SETTINGS, b"ghost")
        })
        .await
        .unwrap();
    assert!(missing.is_none(), "nothing may have been written");

    let _ = std::fs::remove_file(&path);
}

/// Cancelling a still-queued operation while awaiting it gives the
/// caller a typed `Cancelled` — not `Internal`, and not a silent
/// success — and the closure never touches the container.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_queued_operation_short_circuits_before_it_touches_anything() {
    let path = scratch_path();
    let c = container_with_space(&path).await;

    let (parked, release) = occupy_the_permit(&c).await;

    let token = CancelToken::new();
    let ran = Arc::new(AtomicBool::new(false));
    let pending = tokio::spawn({
        let c = c.clone();
        let token = token.clone();
        let ran = Arc::clone(&ran);
        async move {
            c.run_cancellable(token, move |_c, _t| {
                ran.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
        }
    });

    // The parked operation holds the only permit, so `pending` cannot
    // have been dispatched yet whatever the scheduler does.
    token.cancel();
    release.send(()).unwrap();
    parked.await.unwrap().unwrap();

    let outcome = pending.await.unwrap();
    assert!(
        matches!(outcome, Err(Error::Cancelled)),
        "a cancelled-before-start operation must surface as Cancelled, got {outcome:?}"
    );
    assert!(
        !ran.load(Ordering::SeqCst),
        "the closure must short-circuit before its body runs"
    );
    assert!(
        c.abandoned_operations().is_empty(),
        "the caller awaited its own result; there is nothing to file"
    );

    let _ = std::fs::remove_file(&path);
}

/// Dropping the future fires the caller's cancel token, so the sync
/// core's cooperative checkpoints get a chance to stop. This is the
/// weaker, honest half of "cancellation" — the closure has to look.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_the_future_fires_the_callers_cancel_token() {
    let path = scratch_path();
    let c = container_with_space(&path).await;

    let token = CancelToken::new();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
    let (observed_tx, observed_rx) = std::sync::mpsc::channel::<bool>();

    {
        let c2 = c.clone();
        let fut = c2.run_cancellable(token.clone(), move |_c, t| {
            let _ = started_tx.send(());
            // Stand-in for the sync core's periodic `token.check()?`.
            for _ in 0..2000 {
                if t.is_cancelled() {
                    let _ = observed_tx.send(true);
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            let _ = observed_tx.send(false);
            Ok(())
        });
        let mut fut = Box::pin(fut);
        tokio::select! {
            _ = &mut fut => panic!("the closure is spinning; it cannot have finished"),
            _ = started_rx => {},
        }
        drop(fut);
    }

    assert!(
        observed_rx.recv_timeout(Duration::from_secs(20)).unwrap(),
        "dropping the future must fire the token the caller passed in"
    );
    assert!(
        token.is_cancelled(),
        "the caller's own token handle must observe the cancel too"
    );

    let _ = std::fs::remove_file(&path);
}

/// The ledger is bounded: a host app that abandons in a loop and never
/// reconciles cannot grow it without limit, and the eviction is
/// reported rather than silent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_abandonment_ledger_is_bounded_and_says_what_it_forgot() {
    let path = scratch_path();
    let c = container_with_space(&path).await;

    let (parked, release) = occupy_the_permit(&c).await;

    for _ in 0..135 {
        let c2 = c.clone();
        let mut fut = Box::pin(c2.run(|_c| Ok(())));
        assert!(futures_util::poll!(fut.as_mut()).is_pending());
        drop(fut);
    }

    let filed = c.abandoned_operations();
    assert_eq!(filed.len(), 128, "the ledger must cap its records");
    assert_eq!(
        c.forgotten_abandonments(),
        7,
        "evictions must be counted, not swallowed"
    );
    // The survivors are the newest ones, in order — the oldest records
    // are what got dropped, not an arbitrary 128 of them.
    for pair in filed.windows(2) {
        assert_eq!(
            pair[1].id.0,
            pair[0].id.0 + 1,
            "records must stay contiguous and ordered"
        );
    }
    assert_eq!(filed[127].id.0 - filed[0].id.0, 127);

    c.clear_settled_operations();
    assert!(
        c.abandoned_operations().is_empty(),
        "all of these settled as NeverStarted, so all are clearable"
    );

    release.send(()).unwrap();
    parked.await.unwrap().unwrap();

    let _ = std::fs::remove_file(&path);
}
