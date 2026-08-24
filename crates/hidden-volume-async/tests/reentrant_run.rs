//! A nested `run` must fail fast, not hang.
//!
//! The async wrappers admit one operation at a time across a handle and every
//! clone of it, and the permit is taken BEFORE the closure starts. A closure
//! that drives another `run` on a clone therefore waits for a permit its own
//! caller is holding: a genuine hang that no timeout unwinds, reachable from
//! entirely safe code. The doc warned about it; nothing stopped it.

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
            tokio::runtime::Handle::current()
                .block_on(async { clone.run(|_c| Ok(7u32)).await })
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
