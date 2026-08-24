//! What an abandoned constructor leaves behind.
//!
//! `spawn_blocking` does not interrupt a running closure, so dropping the
//! future of `create` — a `timeout`, a `select!`, a cancelled task — cannot
//! stop it once it has started. `AsyncContainer`'s own doc points a caller at
//! `abandoned_operations` to find out what happened, and for a CONSTRUCTOR
//! that is a dead end: the ledger lives on the instance the abandoned call
//! never handed back.
//!
//! So the answer has to come from the file system, and these pin what it says.

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

/// Which side of the dispatch line an abandonment lands on is NOT testable.
///
/// `run_blocking` short-circuits a closure the pool has not started yet, so a
/// create abandoned early leaves nothing — and one abandoned a moment later
/// runs to completion and leaves a container. Whether a given timeout beats
/// the pool is a race the test cannot arrange: the same one-nanosecond timeout
/// produced both outcomes on this machine, minutes apart. An assertion about
/// either side would be a coin flip wearing a test's clothes.
///
/// So what is pinned below is the property that holds on BOTH sides.

/// And whichever side of that line an abandoned create falls on, the path is
/// usable afterwards.
///
/// This is what a caller retrying the same path needs: if the closure did run,
/// the container it produced is dropped with the task's result and its `flock`
/// goes with it — no `Busy` for the rest of the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abandoned_create_never_leaves_the_path_locked() {
    let path = scratch_path();

    // Long enough to be dispatched, short enough to be abandoned mid-Argon2.
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(2),
        AsyncContainer::create_with_options(&path, fast_options()),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Either it never started (no file — create one) or it finished (open it).
    // Both must succeed; a retained lock fails both.
    let usable = if path.exists() {
        AsyncContainer::open(&path).await.map(|_| ())
    } else {
        AsyncContainer::create_with_options(&path, fast_options())
            .await
            .map(|_| ())
    };
    assert!(
        usable.is_ok(),
        "the abandoned create left the path unusable: {:?}",
        usable.err(),
    );

    let _ = std::fs::remove_file(&path);
}
