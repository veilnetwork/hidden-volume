//! A nested `run` must fail fast, not hang.
//!
//! The async wrappers admit one operation at a time across a handle and every
//! clone of it, and the permit is taken BEFORE the closure starts. A closure
//! that drives another `run` on a clone therefore waits for a permit its own
//! caller is holding: a genuine hang that no timeout unwinds, reachable from
//! entirely safe code. The doc warned about it; nothing stopped it.
//!
//! ⚠️ HOW THESE FAIL. Reverting the guard does not make them go red — it makes
//! them HANG, and there is no way around that from inside the test: the
//! deadlock parks the runtime's workers, so a `tokio::time::timeout` around
//! the call never gets a thread to fire on. That was tried, at two workers and
//! at four, and it is decoration in the state that matters. A break-check here
//! reads "the run never finished", and that IS the finding.

use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume_async::AsyncContainer;

fn fast_options() -> ContainerOptions {
    ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

fn scratch_path() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nested_run_is_refused_rather_than_deadlocked() {
    let path = scratch_path();
    let c = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();
    let clone = c.clone();

    // Exactly the shape the doc calls out as fatal.
    let nested = c
        .run(move |_container| {
            tokio::runtime::Handle::current().block_on(async { clone.run(|_c| Ok(7u32)).await })
        })
        .await;

    // Without the guard this line is never reached: the outer future waits on
    // the inner call, which waits on the permit the outer one holds.
    match nested {
        Err(hidden_volume::Error::ReentrantRun) => {},
        other => panic!("expected ReentrantRun, got {other:?}"),
    }

    // And the handle is still usable — a refusal is not a poisoning.
    let after = c.run(|_c| Ok(11u32)).await.unwrap();
    assert_eq!(after, 11);

    let _ = std::fs::remove_file(&path);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_on_an_unrelated_container_is_not_refused() {
    // The guard keys on the permit, not on "am I inside a closure". Two
    // containers share nothing, so nesting across them cannot deadlock and
    // must not be turned into an error.
    let p1 = scratch_path();
    let p2 = scratch_path();
    let a = AsyncContainer::create_with_options(&p1, fast_options())
        .await
        .unwrap();
    let b = AsyncContainer::create_with_options(&p2, fast_options())
        .await
        .unwrap();

    let got = a
        .run(move |_ca| {
            tokio::runtime::Handle::current().block_on(async { b.run(|_cb| Ok(5u32)).await })
        })
        .await
        .unwrap();
    assert_eq!(got, 5, "an unrelated handle must still be reachable");

    let _ = std::fs::remove_file(&p1);
    let _ = std::fs::remove_file(&p2);
}

/// The guard was on `run` and nowhere else, so the two other ways in were
/// exactly as fatal and said nothing (report14 HV14-M2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nested_run_cancellable_is_refused_too() {
    let path = scratch_path();
    let c = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();
    let clone = c.clone();

    let nested = c
        .run(move |_container| {
            tokio::runtime::Handle::current().block_on(async {
                clone
                    .run_cancellable(hidden_volume::cancel::CancelToken::new(), |_c, _t| Ok(7u32))
                    .await
            })
        })
        .await;

    match nested {
        Err(hidden_volume::Error::ReentrantRun) => {},
        other => panic!("expected ReentrantRun, got {other:?}"),
    }

    // The other direction as well: the outer call is the cancellable one.
    let clone = c.clone();
    let nested = c
        .run_cancellable(hidden_volume::cancel::CancelToken::new(), move |_c, _t| {
            tokio::runtime::Handle::current().block_on(async { clone.run(|_c| Ok(9u32)).await })
        })
        .await;
    match nested {
        Err(hidden_volume::Error::ReentrantRun) => {},
        other => panic!("expected ReentrantRun from the cancellable side, got {other:?}"),
    }

    let after = c.run(|_c| Ok(11u32)).await.unwrap();
    assert_eq!(after, 11);
    let _ = std::fs::remove_file(&path);
}

/// A log stream takes the permit once per PAGE, so polling one from inside a
/// closure is the same deadlock wearing different clothes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_log_stream_polled_from_inside_a_run_is_refused() {
    use futures_util::StreamExt as _;

    let path = scratch_path();
    let space = hidden_volume_async::AsyncSpace::create(
        &path,
        b"pw".to_vec(),
        hidden_volume::crypto::kdf::Argon2Params::MIN,
    )
    .await
    .unwrap();
    let stream_owner = space.clone();

    let nested = space
        .run(move |_s| {
            tokio::runtime::Handle::current().block_on(async {
                let mut pages = Box::pin(stream_owner.stream_log_pages_after(0, None, 8));
                match pages.next().await {
                    Some(Err(e)) => Err(e),
                    // A page (or an empty stream) means the permit was taken
                    // from inside the closure holding it — which is the hang.
                    _ => Ok(0u32),
                }
            })
        })
        .await;

    match nested {
        Err(hidden_volume::Error::ReentrantRun) => {},
        other => panic!("expected ReentrantRun from the stream, got {other:?}"),
    }

    // …and the same stream, driven from outside, still works.
    let mut pages = Box::pin(space.stream_log_pages_after(0, None, 8));
    let first = pages.next().await;
    assert!(
        first.is_none() || first.unwrap().is_ok(),
        "the guard must not refuse an ordinary stream"
    );

    let _ = std::fs::remove_file(&path);
}

// ── report15 HV15-M1 — the cross-thread shape, and what actually escapes it ─
//
// The same-thread case above is refused outright. The cross-thread one cannot
// be: the mark is a thread-local, and a closure that hands its work to another
// OS thread and waits for it leaves no trace the child can see. It waits for a
// permit the parent is holding, and the parent waits for the child.
//
// What was ALSO believed is that nothing unwinds it — that a dropped future or
// a timeout cannot help, the way they cannot in the same-thread case above,
// where the deadlock parks the runtime's workers so the timer never gets a
// thread to fire on. That is not true here, and the difference is the whole
// severity: the child is parked on the PERMIT, which is an ordinary `.await`,
// and the parent's blocking thread is not a worker. The timer fires, the
// child's future is dropped while it is still queued, the ledger files it as
// never started, and the parent's join returns.
//
// So the hang is permanent only for a caller who never bounds it. That is
// worth knowing and worth keeping: it is the difference between "do not do
// this" and "if you must, put a deadline on the inner call".

/// A deadline on the INNER call unwinds the cross-thread re-entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deadline_on_the_inner_call_escapes_the_cross_thread_hang() {
    let path = scratch_path();
    let c = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();
    let clone = c.clone();
    let handle = tokio::runtime::Handle::current();

    let outer = c
        .run(move |_container| {
            // The shape the guard above cannot see: the work goes to another
            // OS thread, and this closure waits for it while holding the
            // permit that thread is about to queue for.
            let child = std::thread::spawn(move || {
                handle.block_on(async {
                    tokio::time::timeout(
                        std::time::Duration::from_millis(750),
                        clone.run(|_c| Ok(7u32)),
                    )
                    .await
                })
            });
            Ok(child.join().expect("child thread panicked"))
        })
        .await
        .expect("the outer run must return once the child does");

    assert!(
        outer.is_err(),
        "the inner call was not blocked at all — this fixture proves nothing \
         about the hang: {outer:?}"
    );
}

/// CONTROL: without the outer permit held, the very same cross-thread call
/// succeeds well inside that deadline.
///
/// Without this the test above is satisfied by any inner call that is merely
/// slow, or by one that fails for an unrelated reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_cross_thread_call_succeeds_when_no_permit_is_held() {
    let path = scratch_path();
    let c = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();
    let clone = c.clone();
    let handle = tokio::runtime::Handle::current();

    let child = std::thread::spawn(move || {
        handle.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_millis(750),
                clone.run(|_c| Ok(7u32)),
            )
            .await
        })
    });
    let answer = child.join().expect("child thread panicked");

    assert!(
        matches!(answer, Ok(Ok(7))),
        "the same call fails without a permit held, so the test above is not \
         measuring the permit: {answer:?}"
    );
    drop(c);
}

/// Asking without waiting turns the cross-thread deadlock into an answer.
///
/// The re-entrancy guard is a thread-local, so the child cannot be told it is
/// part of the parent's call. `try_run` does not need to be told: it refuses
/// the moment the permit is not free, which the parent is holding
/// (report16 HV16-M2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn try_run_refuses_across_threads_instead_of_queueing() {
    let path = scratch_path();
    let c = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();
    let clone = c.clone();
    let handle = tokio::runtime::Handle::current();

    let answer = c
        .run(move |_container| {
            let child = std::thread::spawn(move || {
                handle.block_on(async { clone.try_run(|_c| Ok(7u32)).await })
            });
            Ok(child.join().expect("child thread panicked"))
        })
        .await
        .expect("the outer run returns because the child does");

    assert!(
        matches!(answer, Err(hidden_volume::Error::WouldBlock)),
        "expected WouldBlock, got {answer:?}"
    );
}

/// CONTROL: with nobody holding the permit the same call runs.
///
/// Without this the test above is satisfied by a `try_run` that refuses
/// always, which is not an API.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn try_run_runs_when_the_permit_is_free() {
    let path = scratch_path();
    let c = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();

    let answer = c.try_run(|_c| Ok(7u32)).await;

    assert!(matches!(answer, Ok(7)), "got {answer:?}");
}

/// And a closure re-entering on its OWN thread still gets the error that
/// names what IT did, not the one about somebody else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn try_run_reentering_on_its_own_thread_is_still_reentrant() {
    let path = scratch_path();
    let c = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();
    let clone = c.clone();

    let answer = c
        .run(move |_container| {
            Ok(tokio::runtime::Handle::current()
                .block_on(async { clone.try_run(|_c| Ok(7u32)).await }))
        })
        .await
        .expect("the outer run returns");

    assert!(
        matches!(answer, Err(hidden_volume::Error::ReentrantRun)),
        "expected ReentrantRun, got {answer:?}"
    );
}

/// The SPACE handle needs the same escape as the container handle.
///
/// The re-entrancy guard is a thread-local, so a closure that hands its work
/// to another OS thread and waits for it leaves the child queueing for a
/// permit the parent will not release until the child returns. `AsyncContainer`
/// got `try_run` for exactly this in report16 HV16-M2; `AsyncSpace` did not,
/// so the same shape one level down still hung — and a space is where an
/// application does its work (report17 HV17-M2).
///
/// A HANG is what this test is about, and the deadline below does NOT rescue
/// it: the parent blocks a runtime worker on `join`, so the timer never gets
/// to fire. Measured — removing `AsyncSpace::try_run` makes this test hang
/// rather than fail, and the run has to be killed from outside. Anyone
/// break-checking this needs a hard deadline around `cargo test` itself; the
/// timeout here only covers a slow machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_try_run_refuses_across_threads_instead_of_queueing() {
    let path = scratch_path();
    let space = hidden_volume_async::AsyncSpace::create(
        &path,
        b"pw".to_vec(),
        hidden_volume::crypto::kdf::Argon2Params::MIN,
    )
    .await
    .unwrap();
    let clone = space.clone();
    let handle = tokio::runtime::Handle::current();

    let outer = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        space.run(move |_s| {
            let child = std::thread::spawn(move || {
                handle.block_on(async { clone.try_run(|_s| Ok(7u32)).await })
            });
            Ok(child.join().expect("child thread panicked"))
        }),
    )
    .await
    .expect(
        "the outer run never returned: the child is still queueing for a permit the parent holds",
    );

    let answer = outer.expect("the outer run returns because the child does");
    assert!(
        matches!(answer, Err(hidden_volume::Error::WouldBlock)),
        "expected WouldBlock, got {answer:?}"
    );
    let _ = std::fs::remove_file(&path);
}

/// CONTROL: with nobody holding the permit, the same call runs.
///
/// Without it the test above is satisfied by a `try_run` that refuses always,
/// which is not an API.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_try_run_runs_when_the_permit_is_free() {
    let path = scratch_path();
    let space = hidden_volume_async::AsyncSpace::create(
        &path,
        b"pw".to_vec(),
        hidden_volume::crypto::kdf::Argon2Params::MIN,
    )
    .await
    .unwrap();

    let answer = space.try_run(|_s| Ok(7u32)).await;

    assert!(matches!(answer, Ok(7)), "got {answer:?}");
    let _ = std::fs::remove_file(&path);
}

/// And a closure re-entering on its OWN thread still gets the error naming
/// what IT did, rather than the one about somebody else holding the permit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn space_try_run_reentering_on_its_own_thread_is_still_reentrant() {
    let path = scratch_path();
    let space = hidden_volume_async::AsyncSpace::create(
        &path,
        b"pw".to_vec(),
        hidden_volume::crypto::kdf::Argon2Params::MIN,
    )
    .await
    .unwrap();
    let clone = space.clone();

    let answer = space
        .run(move |_s| {
            tokio::runtime::Handle::current().block_on(async { clone.try_run(|_s| Ok(7u32)).await })
        })
        .await;

    match answer {
        Err(hidden_volume::Error::ReentrantRun) => {},
        other => panic!("expected ReentrantRun, got {other:?}"),
    }
    let _ = std::fs::remove_file(&path);
}
