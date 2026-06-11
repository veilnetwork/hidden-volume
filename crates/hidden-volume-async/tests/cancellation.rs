//! Async cancellation smoke test — confirms `run_cancellable` threads
//! the [`CancelToken`] into the sync core's cancel path.
//!
//! Counterpart to `crates/hidden-volume/tests/cancellation.rs` (which
//! covers the sync surface in detail).

use hidden_volume::Error;
use hidden_volume::cancel::CancelToken;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
use hidden_volume_async::AsyncContainer;

fn fast_params() -> Argon2Params {
    Argon2Params::MIN
}

fn scratch_path() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}

#[tokio::test]
async fn async_run_cancellable_threads_token_through() {
    let path = scratch_path();
    let c = AsyncContainer::create(&path, fast_params()).await.unwrap();
    c.run(|c| {
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
        Ok(())
    })
    .await
    .unwrap();

    let token = CancelToken::new();
    token.cancel();
    let result = c
        .run_cancellable(token, |c, t| {
            // Should bail on the post-Argon2 check inside open_space_cancellable.
            c.open_space_cancellable(b"pw", t).map(|_| ())
        })
        .await;
    assert!(matches!(result, Err(Error::Cancelled)));
}
