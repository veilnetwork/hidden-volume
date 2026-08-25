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
