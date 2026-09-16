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

// Which side of the dispatch line an abandonment lands on is NOT testable.
//
// `run_blocking` short-circuits a closure the pool has not started yet, so a
// create abandoned early leaves nothing — and one abandoned a moment later
// runs to completion and leaves a container. Whether a given timeout beats the
// pool is a race the test cannot arrange: the same one-nanosecond timeout
// produced both outcomes on this machine, minutes apart. An assertion about
// either side would be a coin flip wearing a test's clothes.
//
// So what is pinned below is the property that holds on BOTH sides.

/// Whichever side of that line an abandoned create falls on, the path is
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

/// A constructor that takes a password must guard it before the future exists.
///
/// The two that take one built their `Zeroizing` wrapper as the first
/// statement of an `async fn`, and an `async fn` body does not begin until the
/// first poll. A future built and dropped without ever being polled — the
/// `select!` that lost, the timeout that fired first, the task cancelled
/// between spawn and schedule, all of which this file exists to reason about —
/// therefore dropped the password as a plain `Vec` and left it in the
/// allocator's hands (report27 H03).
///
/// The shape is the fix: a plain `fn` returning `impl Future` runs its
/// prologue in the CALL, so the guard exists before there is a future to
/// abandon. Checked at the source, because the alternative is reading a buffer
/// after it has been freed, which is undefined behaviour — the same reason the
/// wipe helpers in the core are tested on live memory rather than after a drop.
#[test]
fn a_password_taking_constructor_guards_it_in_the_call_not_in_the_body() {
    let src = include_str!("../src/lib.rs");

    for name in ["fn create(", "fn open("] {
        // The AsyncSpace pair: `AsyncContainer` has same-named constructors
        // that take no password, and they are above this point.
        let from = src
            .find("impl AsyncSpace {")
            .expect("`impl AsyncSpace` moved — this guard watches nothing");
        let at = from
            + src[from..]
                .find(name)
                .unwrap_or_else(|| panic!("`AsyncSpace::{name}` moved"));
        let rest = &src[at..];
        // This constructor's own body, and not the next one's.
        let end = rest
            .find("\n    pub fn ")
            .into_iter()
            .chain(rest.find("\n    pub async fn "))
            .min()
            .unwrap_or(rest.len());
        let body = &rest[..end];

        let signature_end = body.find('{').expect("a body");
        assert!(
            !src[..at].ends_with("async ") && !body[..signature_end].contains("async"),
            "`AsyncSpace::{name}` is an `async fn` again — its password guard \
             is built on the first poll, and a future nobody polls frees the \
             password unwiped"
        );
        let guard_at = body
            .find("Zeroizing::new(password)")
            .unwrap_or_else(|| panic!("`AsyncSpace::{name}` no longer guards its password at all"));
        let block_at = body
            .find("async move {")
            .unwrap_or_else(|| panic!("`AsyncSpace::{name}` has no async block to be dropped"));
        assert!(
            guard_at < block_at,
            "`AsyncSpace::{name}` builds its password guard INSIDE the async \
             block, which is the same as building it in an `async fn` body: \
             nothing runs until the first poll"
        );
    }
}
