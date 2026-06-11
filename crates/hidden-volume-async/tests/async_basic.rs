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

#[tokio::test]
async fn concurrent_runs_serialize_via_mutex() {
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

    // Launch 10 concurrent runs that each write a unique key. The mutex
    // serializes them, so all 10 commits land in sequence.
    let mut handles = Vec::new();
    for i in 0..10u8 {
        let c = container.clone();
        let counter = counter.clone();
        handles.push(tokio::spawn(async move {
            c.run(move |c| {
                let mut s = c.open_space(b"pw")?;
                let mut tx = s.begin_tx();
                tx.put(Namespace::CONTACTS, &[i], b"v")?;
                tx.commit()?;
                Ok(())
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
