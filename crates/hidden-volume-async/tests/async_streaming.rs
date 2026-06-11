//! `AsyncSpace` paginated streaming tests.
//!
//! Exercises the three `stream_log_pages_*` methods end-to-end:
//! constructor opens space → stream pages → consume via `StreamExt::next`
//! → verify ids, payloads, and page boundaries.

use futures_util::StreamExt;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::space::index::Namespace;
use hidden_volume_async::AsyncSpace;

const NS_LOG: u8 = Namespace::MESSAGE_LOG.0;

fn scratch_path() -> std::path::PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let p = tmp.path().to_owned();
    drop(tmp);
    p
}

/// Build a fresh container with `n` log entries committed in chunks of
/// `per_tx`, returning the path + the live `AsyncSpace` handle.
async fn build_log(n: u64, per_tx: u64) -> (std::path::PathBuf, AsyncSpace) {
    let path = scratch_path();
    let space = AsyncSpace::create(&path, b"pw".to_vec(), Argon2Params::MIN)
        .await
        .unwrap();
    let mut id = 1u64;
    while id <= n {
        let end = (id + per_tx - 1).min(n);
        let start = id;
        space
            .run(move |s| {
                let mut tx = s.begin_tx();
                for cur in start..=end {
                    tx.append_log(Namespace::MESSAGE_LOG, cur, format!("msg{cur}").as_bytes())?;
                }
                tx.commit().map(|_| ())
            })
            .await
            .unwrap();
        id = end + 1;
    }
    (path, space)
}

#[tokio::test]
async fn stream_after_yields_full_log_in_order() {
    let (path, space) = build_log(50, 10).await;

    let mut stream = Box::pin(space.stream_log_pages_after(NS_LOG, None, 7));
    let mut all: Vec<u64> = Vec::new();
    while let Some(page) = stream.next().await {
        let page = page.unwrap();
        assert!(!page.is_empty());
        assert!(page.len() <= 7, "page exceeds page_size: {}", page.len());
        // Strictly ascending within a page.
        for w in page.windows(2) {
            assert!(w[0].0 < w[1].0);
        }
        for (id, payload) in &page {
            let want = format!("msg{id}");
            assert_eq!(payload.as_slice(), want.as_bytes());
            all.push(*id);
        }
    }
    assert_eq!(all, (1..=50).collect::<Vec<_>>());

    drop(space);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn stream_before_yields_full_log_reversed() {
    let (path, space) = build_log(30, 5).await;

    let mut stream = Box::pin(space.stream_log_pages_before(NS_LOG, None, 4));
    let mut all: Vec<u64> = Vec::new();
    while let Some(page) = stream.next().await {
        let page = page.unwrap();
        assert!(!page.is_empty());
        // Strictly descending within a page.
        for w in page.windows(2) {
            assert!(w[0].0 > w[1].0);
        }
        for (id, _) in &page {
            all.push(*id);
        }
    }
    assert_eq!(all, (1..=30).rev().collect::<Vec<_>>());

    drop(space);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn stream_after_with_cursor_skips_prefix() {
    let (path, space) = build_log(20, 5).await;

    // Start from id > 12 → should yield 13..=20.
    let mut stream = Box::pin(space.stream_log_pages_after(NS_LOG, Some(12), 100));
    let mut all: Vec<u64> = Vec::new();
    while let Some(page) = stream.next().await {
        for (id, _) in page.unwrap() {
            all.push(id);
        }
    }
    assert_eq!(all, (13..=20).collect::<Vec<_>>());

    drop(space);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn stream_range_half_open() {
    let (path, space) = build_log(40, 5).await;

    // Range [10, 25) should yield 10, 11, …, 24.
    let mut stream = Box::pin(space.stream_log_pages_range(NS_LOG, Some(10), Some(25), 6));
    let mut all: Vec<u64> = Vec::new();
    while let Some(page) = stream.next().await {
        let page = page.unwrap();
        assert!(page.len() <= 6);
        for (id, _) in page {
            all.push(id);
        }
    }
    assert_eq!(all, (10..25).collect::<Vec<_>>());

    drop(space);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn stream_range_unbounded_above() {
    let (path, space) = build_log(15, 5).await;

    let mut stream = Box::pin(space.stream_log_pages_range(NS_LOG, Some(8), None, 3));
    let mut all: Vec<u64> = Vec::new();
    while let Some(page) = stream.next().await {
        for (id, _) in page.unwrap() {
            all.push(id);
        }
    }
    assert_eq!(all, (8..=15).collect::<Vec<_>>());

    drop(space);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn stream_range_unbounded_below() {
    let (path, space) = build_log(15, 5).await;

    let mut stream = Box::pin(space.stream_log_pages_range(NS_LOG, None, Some(5), 100));
    let mut all: Vec<u64> = Vec::new();
    while let Some(page) = stream.next().await {
        for (id, _) in page.unwrap() {
            all.push(id);
        }
    }
    assert_eq!(all, (1..5).collect::<Vec<_>>());

    drop(space);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn stream_range_degenerate_yields_empty() {
    let (path, space) = build_log(10, 5).await;

    // start >= end → no items.
    let mut stream = Box::pin(space.stream_log_pages_range(NS_LOG, Some(5), Some(5), 10));
    assert!(stream.next().await.is_none());

    let mut stream = Box::pin(space.stream_log_pages_range(NS_LOG, Some(8), Some(3), 10));
    assert!(stream.next().await.is_none());

    drop(space);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn stream_on_empty_namespace() {
    let path = scratch_path();
    let space = AsyncSpace::create(&path, b"pw".to_vec(), Argon2Params::MIN)
        .await
        .unwrap();

    let mut stream = Box::pin(space.stream_log_pages_after(NS_LOG, None, 10));
    assert!(stream.next().await.is_none());

    let mut stream = Box::pin(space.stream_log_pages_before(NS_LOG, None, 10));
    assert!(stream.next().await.is_none());

    let mut stream = Box::pin(space.stream_log_pages_range(NS_LOG, None, None, 10));
    assert!(stream.next().await.is_none());

    drop(space);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn stream_durable_across_reopen() {
    // Write data, drop space, reopen via AsyncSpace::open, stream all back.
    let path = scratch_path();
    {
        let space = AsyncSpace::create(&path, b"pw".to_vec(), Argon2Params::MIN)
            .await
            .unwrap();
        space
            .run(|s| {
                let mut tx = s.begin_tx();
                for i in 1..=12u64 {
                    tx.append_log(Namespace::MESSAGE_LOG, i, format!("m{i}").as_bytes())?;
                }
                tx.commit().map(|_| ())
            })
            .await
            .unwrap();
    }

    let space = AsyncSpace::open(&path, b"pw".to_vec()).await.unwrap();
    let mut stream = Box::pin(space.stream_log_pages_after(NS_LOG, None, 5));
    let mut all: Vec<u64> = Vec::new();
    while let Some(page) = stream.next().await {
        for (id, payload) in page.unwrap() {
            assert_eq!(payload, format!("m{id}").into_bytes());
            all.push(id);
        }
    }
    assert_eq!(all, (1..=12).collect::<Vec<_>>());

    drop(space);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn run_and_stream_share_same_underlying_state() {
    // Demonstrate the AsyncSpace::run + stream interplay: write via run,
    // immediately stream the new entries through the same handle.
    let path = scratch_path();
    let space = AsyncSpace::create(&path, b"pw".to_vec(), Argon2Params::MIN)
        .await
        .unwrap();

    space
        .run(|s| {
            let mut tx = s.begin_tx();
            for i in 1..=8u64 {
                tx.append_log(Namespace::MESSAGE_LOG, i, format!("v{i}").as_bytes())?;
            }
            tx.commit().map(|_| ())
        })
        .await
        .unwrap();

    let mut stream = Box::pin(space.stream_log_pages_after(NS_LOG, Some(3), 100));
    let page = stream.next().await.unwrap().unwrap();
    let ids: Vec<u64> = page.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, (4..=8).collect::<Vec<_>>());
    assert!(stream.next().await.is_none());

    drop(space);
    let _ = std::fs::remove_file(&path);
}
