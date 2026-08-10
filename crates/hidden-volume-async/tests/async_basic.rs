//! Async wrapper smoke tests.
//!
//! Run with: `cargo test -p hidden-volume-async`
//! Or include in full suite: `cargo test --workspace`

use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
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

#[tokio::test]
async fn create_then_run_a_commit() {
    let path = scratch_path();
    let container = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();

    container
        .run(|c| {
            let mut s = c.create_space(b"pw")?;
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"theme", b"dark")?;
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();

    drop(container);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn open_and_read_after_close() {
    let path = scratch_path();

    {
        let container = AsyncContainer::create_with_options(&path, fast_options())
            .await
            .unwrap();
        container
            .run(|c| {
                let mut s = c.create_space(b"pw")?;
                let mut tx = s.begin_tx();
                tx.put(Namespace::CONTACTS, b"alice", b"a@x")?;
                tx.commit()?;
                Ok(())
            })
            .await
            .unwrap();
    } // container dropped, lock released

    let container = AsyncContainer::open(&path).await.unwrap();
    let value = container
        .run(|c| {
            let mut s = c.open_space(b"pw")?;
            Ok(s.get(Namespace::CONTACTS, b"alice")?
                .map(|v| String::from_utf8_lossy(&v).into_owned()))
        })
        .await
        .unwrap();

    assert_eq!(value.as_deref(), Some("a@x"));
    drop(container);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn run_returns_typed_value() {
    let path = scratch_path();
    let container = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();

    let count: usize = container
        .run(|c| {
            let mut s = c.create_space(b"pw")?;
            let mut tx = s.begin_tx();
            for i in 0..10u8 {
                tx.put(Namespace::CONTACTS, &[i], b"value")?;
            }
            tx.commit()?;
            s.count(Namespace::CONTACTS)
        })
        .await
        .unwrap();

    assert_eq!(count, 10);
    drop(container);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn clones_share_underlying_container() {
    let path = scratch_path();
    let container = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();

    container
        .run(|c| {
            let _ = c.create_space(b"pw")?;
            Ok(())
        })
        .await
        .unwrap();

    // Clone the handle. Both reference the same Container under Arc<Mutex>.
    let c2 = container.clone();

    container
        .run(|c| {
            let mut s = c.open_space(b"pw")?;
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"x", b"1")?;
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();

    // c2 sees the same data.
    let v = c2
        .run(|c| {
            let mut s = c.open_space(b"pw")?;
            s.get(Namespace::SETTINGS, b"x")
        })
        .await
        .unwrap();
    assert_eq!(v.as_deref(), Some(&b"1"[..]));

    drop(container);
    drop(c2);
    std::fs::remove_file(&path).ok();
}

/// The container twin of `concurrent_space_runs_never_overlap`, and it carries
/// the same correction: this was called `concurrent_runs_serialize_via_mutex`
/// and the mutex is not what serializes it. `OpLedger::default()` admits one
/// operation at a time before `spawn_blocking` ever runs; the mutex is the
/// second layer behind that. The old body only counted that ten calls returned
/// and ten keys landed — both true of a fully parallel implementation — so the
/// peak reading below is the part that actually watches for overlap.
#[tokio::test]
async fn concurrent_container_runs_never_overlap() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let path = scratch_path();
    let container = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();
    container
        .run(|c| {
            let _ = c.create_space(b"pw")?;
            Ok(())
        })
        .await
        .unwrap();

    let counter = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    // Ten concurrent runs, each writing a unique key and each recording how
    // many closures were inside at the moment it entered.
    let mut handles = Vec::new();
    for i in 0..10u8 {
        let c = container.clone();
        let counter = counter.clone();
        let in_flight = in_flight.clone();
        let peak = peak.clone();
        handles.push(tokio::spawn(async move {
            c.run(move |c| {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                let outcome = (|| {
                    let mut s = c.open_space(b"pw")?;
                    let mut tx = s.begin_tx();
                    tx.put(Namespace::CONTACTS, &[i], b"v")?;
                    tx.commit()
                })();
                // Held wide enough that ten of these would meet if anything
                // let them; without it they finish one after another on a
                // fast machine and never overlap regardless.
                std::thread::sleep(std::time::Duration::from_millis(20));
                in_flight.fetch_sub(1, Ordering::SeqCst);
                outcome
            })
            .await
            .unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(counter.load(Ordering::SeqCst), 10);
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "two closures held `&mut Container` at once — the serialization \
         `AsyncContainer::run` promises is gone"
    );

    let final_count = container
        .run(|c| {
            let mut s = c.open_space(b"pw")?;
            s.count(Namespace::CONTACTS)
        })
        .await
        .unwrap();
    assert_eq!(final_count, 10);

    drop(container);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn set_padding_policy_via_async_api() {
    let path = scratch_path();
    let container = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();

    container
        .set_padding_policy(PaddingPolicy::BucketGrowth { bucket_chunks: 64 })
        .await
        .unwrap();

    container
        .run(|c| {
            assert_eq!(
                c.padding_policy(),
                PaddingPolicy::BucketGrowth { bucket_chunks: 64 }
            );
            Ok(())
        })
        .await
        .unwrap();

    drop(container);
    std::fs::remove_file(&path).ok();
}

#[tokio::test]
async fn error_from_inner_propagates() {
    let path = scratch_path();
    let container = AsyncContainer::create_with_options(&path, fast_options())
        .await
        .unwrap();

    container
        .run(|c| {
            let _ = c.create_space(b"pw")?;
            Ok(())
        })
        .await
        .unwrap();

    // Try to create the same space again — should error with SpaceAlreadyExists.
    let err = container
        .run(|c| {
            let _ = c.create_space(b"pw")?;
            Ok(())
        })
        .await
        .unwrap_err();

    assert!(
        matches!(err, hidden_volume::Error::SpaceAlreadyExists),
        "expected SpaceAlreadyExists, got {err:?}"
    );

    drop(container);
    std::fs::remove_file(&path).ok();
}

/// The AsyncSpace twin of the container test above — and the reason it exists
/// is the warning on `AsyncSpace::run`.
///
/// That warning tells a caller not to nest and steers them to "do the whole
/// job in one closure". If the non-nested path ever stopped serializing, the
/// steer would become the trap and nothing would notice.
///
/// WHAT IS ASSERTED is the observable property — no two closures are ever in
/// flight at once — and it is MEASURED, not inferred. An earlier version of
/// this test only counted that ten calls returned and ten keys landed, which
/// is true of a fully parallel implementation too: it stayed green against a
/// lock deliberately broken to fail fast instead of waiting. Counting outcomes
/// says nothing about order; a peak-concurrency reading does.
///
/// WHAT ENFORCES IT is two independent layers, and neither is the one the
/// warning named. `OpLedger::default()` is a ONE-permit semaphore acquired
/// before `spawn_blocking`, so dispatch admits a single operation at a time;
/// the mutex inside the closure is a second layer that in practice is never
/// contended. Breaking either alone leaves this test green — the survivor
/// still serializes — so treat a red here as "both went", and see the
/// positive control below for why a green is worth anything at all.
#[tokio::test]
async fn concurrent_space_runs_never_overlap() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let path = scratch_path();
    let space = hidden_volume_async::AsyncSpace::create(&path, b"pw".to_vec(), Argon2Params::MIN)
        .await
        .unwrap();

    let returned = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for i in 0..10u8 {
        let s = space.clone();
        let returned = returned.clone();
        let in_flight = in_flight.clone();
        let peak = peak.clone();
        handles.push(tokio::spawn(async move {
            s.run(move |space| {
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                let outcome = (|| {
                    let mut tx = space.begin_tx();
                    tx.put(Namespace::CONTACTS, &[i], b"v")?;
                    tx.commit()
                })();
                // Wide enough that ten of these would visibly overlap if
                // anything let them: without a hold the ten finished one
                // after another on a fast machine and never met.
                std::thread::sleep(std::time::Duration::from_millis(20));
                in_flight.fetch_sub(1, Ordering::SeqCst);
                outcome
            })
            .await
            .unwrap();
            returned.fetch_add(1, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(returned.load(Ordering::SeqCst), 10, "a run never returned");
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "two closures held `&mut Space` at the same time — the serialization \
         the `run` warning promises is gone, and its advice to do the whole \
         job in one closure now hands the caller a data race"
    );

    let landed = space
        .run(|space| space.count(Namespace::CONTACTS))
        .await
        .unwrap();
    assert_eq!(landed, 10, "ten tasks wrote ten keys and {landed} survived");

    drop(space);
    std::fs::remove_file(&path).ok();
}

/// The instrument, not the invariant: proof that the peak-concurrency reading
/// above can see an overlap when there is one.
///
/// A counter that never observes two-at-once because the machine, the pool or
/// the test shape never produced two-at-once reads exactly like a counter
/// proving serialization. This runs the same measurement over two raw blocking
/// tasks with no ledger and no mutex between them, and demands it report 2.
/// If this goes red the test above proves nothing and should be read as
/// unknown rather than green.
///
/// Bounded wait, not a barrier: a barrier would HANG a pool that cannot run
/// two at once, and a hang is a worse answer than a failure.
#[tokio::test]
async fn the_overlap_detector_sees_overlap_when_it_is_there() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let in_flight = in_flight.clone();
        let peak = peak.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            // On `peak`, not on `in_flight`: the second task to arrive sees
            // two and leaves at once, dropping `in_flight` back to one — a
            // waiter watching the live count would then sit here until the
            // deadline and cost every run two seconds for nothing.
            while peak.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            in_flight.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(
        peak.load(Ordering::SeqCst),
        2,
        "two unsynchronized blocking tasks never registered as concurrent, so \
         this measurement cannot distinguish serialized from parallel and the \
         serialization test it backs is inconclusive"
    );
}
