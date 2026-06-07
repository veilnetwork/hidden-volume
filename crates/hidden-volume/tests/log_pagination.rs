//! Paginated log iteration (v0.7).
//!
//! Coverage:
//! 1. Empty namespace → both APIs return [].
//! 2. limit=0 → returns [] without touching the tree.
//! 3. iter_log_after(None, ∞) → equivalent to iter_log (full forward).
//! 4. iter_log_before(None, ∞) → full reverse.
//! 5. Cursor pagination forward: walk a 200-msg log in pages of 30.
//! 6. Cursor pagination reverse: walk a 200-msg log in reverse pages.
//! 7. Pagination across DataBatch boundaries — one page may span
//!    multiple batches; another page may sit inside a single batch.
//! 8. After-cursor past the last entry → [].
//! 9. Before-cursor at the first entry → [].
//! 10. Sparse log_ids (gaps) — pagination respects actual ids.
//! 11. limit > total entries → returns all (asc / desc accordingly).
//! 12. B+ tree split case (large enough namespace) — pagination correct.

use hidden_volume::Container;
use hidden_volume::space::index::Namespace;

mod common;
use common::{fast_params, scratch_path};

/// Build a log of `total` entries, committing in chunks of `per_tx`
/// entries each. Each commit produces its own DataBatch chunk.
fn build_log_chunked(total: u64, per_tx: u64) -> std::path::PathBuf {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut id = 1u64;
    while id <= total {
        let mut tx = s.begin_tx();
        let end = (id + per_tx - 1).min(total);
        for cur in id..=end {
            tx.append_log(Namespace::MESSAGE_LOG, cur, format!("msg{cur}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
        id = end + 1;
    }
    drop(s);
    drop(c);
    path
}

fn build_log(entries: u64) -> std::path::PathBuf {
    // Per-tx cap chosen to stay under PAYLOAD_CAP after zstd of the
    // synthetic "msgN" payloads. 200 is comfortably within the limit
    // even for the longest decimal expansion.
    build_log_chunked(entries, 200)
}

#[test]
fn empty_namespace_returns_empty() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let after = s.iter_log_after(Namespace::MESSAGE_LOG, None, 50).unwrap();
    let before = s.iter_log_before(Namespace::MESSAGE_LOG, None, 50).unwrap();
    assert!(after.is_empty());
    assert!(before.is_empty());
}

#[test]
fn limit_zero_returns_empty() {
    let path = build_log(10);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let after = s.iter_log_after(Namespace::MESSAGE_LOG, None, 0).unwrap();
    let before = s.iter_log_before(Namespace::MESSAGE_LOG, None, 0).unwrap();
    assert!(after.is_empty());
    assert!(before.is_empty());
}

#[test]
fn iter_log_after_full_forward_matches_iter_log() {
    let path = build_log(50);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let full = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
    let paged = s
        .iter_log_after(Namespace::MESSAGE_LOG, None, usize::MAX)
        .unwrap();
    assert_eq!(full, paged);
    assert_eq!(full.len(), 50);
    assert_eq!(full[0].0, 1);
    assert_eq!(full[49].0, 50);
}

#[test]
fn iter_log_before_full_reverse_matches_iter_log_reversed() {
    let path = build_log(50);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let full = s.iter_log(Namespace::MESSAGE_LOG).unwrap();
    let paged = s
        .iter_log_before(Namespace::MESSAGE_LOG, None, usize::MAX)
        .unwrap();
    let mut rev: Vec<_> = full.into_iter().collect();
    rev.reverse();
    assert_eq!(rev, paged);
    assert_eq!(paged[0].0, 50);
    assert_eq!(paged[49].0, 1);
}

#[test]
fn cursor_pagination_forward() {
    let path = build_log(200);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let page_size = 30;
    let mut cursor: Option<u64> = None;
    let mut all: Vec<u64> = Vec::new();
    loop {
        let page = s
            .iter_log_after(Namespace::MESSAGE_LOG, cursor, page_size)
            .unwrap();
        if page.is_empty() {
            break;
        }
        // Page must be ascending.
        for w in page.windows(2) {
            assert!(w[0].0 < w[1].0);
        }
        cursor = page.last().map(|(id, _)| *id);
        all.extend(page.iter().map(|(id, _)| *id));
    }
    assert_eq!(all, (1..=200).collect::<Vec<u64>>());
}

#[test]
fn cursor_pagination_reverse() {
    let path = build_log(200);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let page_size = 30;
    let mut cursor: Option<u64> = None;
    let mut all: Vec<u64> = Vec::new();
    loop {
        let page = s
            .iter_log_before(Namespace::MESSAGE_LOG, cursor, page_size)
            .unwrap();
        if page.is_empty() {
            break;
        }
        // Page must be descending.
        for w in page.windows(2) {
            assert!(w[0].0 > w[1].0);
        }
        cursor = page.last().map(|(id, _)| *id);
        all.extend(page.iter().map(|(id, _)| *id));
    }
    let expected: Vec<u64> = (1..=200).rev().collect();
    assert_eq!(all, expected);
}

#[test]
fn cursor_pagination_across_batches() {
    // 1024 entries × small payloads = at least 2 DataBatch chunks
    // (MAX_RECORDS_PER_BATCH=1024, but compression bound may force splits).
    // We don't care about the exact batch count — just that pagination
    // works regardless of batch boundaries.
    let path = build_log(1500);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Forward starting from id=500.
    let p1 = s
        .iter_log_after(Namespace::MESSAGE_LOG, Some(500), 100)
        .unwrap();
    assert_eq!(p1.len(), 100);
    assert_eq!(p1[0].0, 501);
    assert_eq!(p1[99].0, 600);
    // Reverse starting before id=1000.
    let p2 = s
        .iter_log_before(Namespace::MESSAGE_LOG, Some(1000), 100)
        .unwrap();
    assert_eq!(p2.len(), 100);
    assert_eq!(p2[0].0, 999);
    assert_eq!(p2[99].0, 900);
}

#[test]
fn after_cursor_past_end_returns_empty() {
    let path = build_log(10);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let page = s
        .iter_log_after(Namespace::MESSAGE_LOG, Some(10), 100)
        .unwrap();
    assert!(page.is_empty());
    let page = s
        .iter_log_after(Namespace::MESSAGE_LOG, Some(99999), 100)
        .unwrap();
    assert!(page.is_empty());
}

#[test]
fn before_cursor_at_start_returns_empty() {
    let path = build_log(10);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let page = s
        .iter_log_before(Namespace::MESSAGE_LOG, Some(1), 100)
        .unwrap();
    assert!(page.is_empty());
    let page = s
        .iter_log_before(Namespace::MESSAGE_LOG, Some(0), 100)
        .unwrap();
    assert!(page.is_empty());
}

#[test]
fn sparse_log_ids_paginate_correctly() {
    // log_ids picked sparsely: 100, 200, 350, 401, 999
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for id in [100u64, 200, 350, 401, 999] {
            tx.append_log(Namespace::MESSAGE_LOG, id, format!("m{id}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // After 250 → expect 350, 401, 999.
    let page = s
        .iter_log_after(Namespace::MESSAGE_LOG, Some(250), 10)
        .unwrap();
    let ids: Vec<u64> = page.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![350, 401, 999]);
    // Before 350 → expect 200, 100 (descending).
    let page = s
        .iter_log_before(Namespace::MESSAGE_LOG, Some(350), 10)
        .unwrap();
    let ids: Vec<u64> = page.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![200, 100]);
}

#[test]
fn limit_larger_than_total_returns_all() {
    let path = build_log(20);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let after = s
        .iter_log_after(Namespace::MESSAGE_LOG, None, 1000)
        .unwrap();
    assert_eq!(after.len(), 20);
    let before = s
        .iter_log_before(Namespace::MESSAGE_LOG, None, 1000)
        .unwrap();
    assert_eq!(before.len(), 20);
    assert_eq!(before[0].0, 20); // descending: latest first
    assert_eq!(before[19].0, 1);
}

#[test]
fn b_plus_tree_split_paginates_correctly() {
    // Force the KV index to split into multiple leaves with internal node.
    // ~1500 entries × {8B key + 8B value} ≈ 24 KiB → multiple leaves.
    // Commit in chunks of 200 so each DataBatch fits under PAYLOAD_CAP.
    let path = build_log(1500);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Pagination still works under split tree.
    let page1 = s.iter_log_after(Namespace::MESSAGE_LOG, None, 50).unwrap();
    assert_eq!(page1.len(), 50);
    assert_eq!(page1[0].0, 1);
    assert_eq!(page1[49].0, 50);
    // Reverse last 50.
    let last50 = s.iter_log_before(Namespace::MESSAGE_LOG, None, 50).unwrap();
    assert_eq!(last50.len(), 50);
    assert_eq!(last50[0].0, 1500);
    assert_eq!(last50[49].0, 1451);
}

#[test]
fn payload_content_preserved_across_pagination() {
    // Make sure the values aren't shuffled or wrong-batched.
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for id in 1..=100u64 {
            tx.append_log(
                Namespace::MESSAGE_LOG,
                id,
                format!("payload-id-{id}").as_bytes(),
            )
            .unwrap();
        }
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let page = s
        .iter_log_after(Namespace::MESSAGE_LOG, Some(40), 20)
        .unwrap();
    for (id, payload) in &page {
        assert_eq!(payload, format!("payload-id-{id}").as_bytes());
    }
    assert_eq!(page.first().unwrap().0, 41);
    assert_eq!(page.last().unwrap().0, 60);
}

// ---------- iter_log_range coverage ----------
//
// Coverage:
// R1.  Empty namespace → [].
// R2.  limit=0 → [].
// R3.  start >= end → [] (degenerate range).
// R4.  Both bounds None → equivalent to iter_log_after(None, limit).
// R5.  Lower bound only — log_id >= start.
// R6.  Upper bound only — log_id < end.
// R7.  Both bounds — log_id in [start, end).
// R8.  Off-by-one at start: start equals an existing id → that id IS included.
// R9.  Off-by-one at end:   end equals an existing id → that id is NOT included.
// R10. Limit caps result smaller than the natural range size.
// R11. Range past the last entry → [].
// R12. Range across DataBatch / B+ tree leaf boundaries.
// R13. Sparse ids (gaps) — only existing ids returned.

#[test]
fn r1_range_on_empty_namespace() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, None, None, 50)
        .unwrap();
    assert!(r.is_empty());
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(0), Some(100), 50)
        .unwrap();
    assert!(r.is_empty());
}

#[test]
fn r2_range_zero_limit_returns_empty() {
    let path = build_log_chunked(50, 10);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, None, None, 0)
        .unwrap();
    assert!(r.is_empty());
}

#[test]
fn r3_degenerate_range_empty() {
    let path = build_log_chunked(50, 10);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // start == end
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(20), Some(20), 100)
        .unwrap();
    assert!(r.is_empty());
    // start > end
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(30), Some(10), 100)
        .unwrap();
    assert!(r.is_empty());
}

#[test]
fn r4_no_bounds_matches_iter_log_after() {
    let path = build_log_chunked(80, 20);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let from_range = s
        .iter_log_range(Namespace::MESSAGE_LOG, None, None, 1000)
        .unwrap();
    let from_after = s
        .iter_log_after(Namespace::MESSAGE_LOG, None, 1000)
        .unwrap();
    assert_eq!(from_range, from_after);
    // build_log_chunked uses 1..=80 inclusive.
    assert_eq!(from_range.len(), 80);
    assert_eq!(from_range.first().unwrap().0, 1);
    assert_eq!(from_range.last().unwrap().0, 80);
}

#[test]
fn r5_lower_bound_only_inclusive() {
    let path = build_log_chunked(50, 10);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(40), None, 1000)
        .unwrap();
    let ids: Vec<u64> = r.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, (40..=50).collect::<Vec<_>>());
}

#[test]
fn r6_upper_bound_only_exclusive() {
    let path = build_log_chunked(50, 10);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, None, Some(10), 1000)
        .unwrap();
    let ids: Vec<u64> = r.iter().map(|(id, _)| *id).collect();
    // ids 1..=9 (10 is exclusive).
    assert_eq!(ids, (1..=9).collect::<Vec<_>>());
}

#[test]
fn r7_both_bounds_half_open() {
    let path = build_log_chunked(50, 10);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(15), Some(25), 1000)
        .unwrap();
    let ids: Vec<u64> = r.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, (15..25).collect::<Vec<_>>());
}

#[test]
fn r8_start_equal_to_existing_id_is_included() {
    let path = build_log_chunked(20, 5);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(7), Some(8), 10)
        .unwrap();
    let ids: Vec<u64> = r.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![7]);
}

#[test]
fn r9_end_equal_to_existing_id_is_excluded() {
    let path = build_log_chunked(20, 5);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // [10, 10) → empty (degenerate)
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(10), Some(10), 10)
        .unwrap();
    assert!(r.is_empty());
    // [9, 10) → [9]
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(9), Some(10), 10)
        .unwrap();
    let ids: Vec<u64> = r.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![9]);
}

#[test]
fn r10_limit_caps_below_natural_range() {
    let path = build_log_chunked(50, 10);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Range [10, 40) has 30 entries; ask for 5 of them.
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(10), Some(40), 5)
        .unwrap();
    let ids: Vec<u64> = r.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![10, 11, 12, 13, 14]);
}

#[test]
fn r11_range_past_last_entry_empty() {
    let path = build_log_chunked(20, 5);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(1000), Some(2000), 100)
        .unwrap();
    assert!(r.is_empty());
}

#[test]
fn r12_range_across_databatch_boundaries() {
    // 50 entries / 5 per tx = 10 DataBatch chunks. A range that spans
    // batches must follow KV pointers, not batch boundaries.
    let path = build_log_chunked(50, 5);
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // Range crosses batch boundaries (each batch holds 5 ids).
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(8), Some(23), 100)
        .unwrap();
    let ids: Vec<u64> = r.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, (8..23).collect::<Vec<_>>());
    // Payload content sanity-check (build_log_chunked uses "msgN").
    for (id, payload) in &r {
        let want = format!("msg{id}");
        assert_eq!(payload.as_slice(), want.as_bytes(), "id={id}");
    }
}

#[test]
fn r13_sparse_ids_only_existing_returned() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        for id in [10u64, 25, 30, 31, 32, 50, 100] {
            tx.append_log(Namespace::MESSAGE_LOG, id, format!("v{id}").as_bytes())
                .unwrap();
        }
        tx.commit().unwrap();
    }
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    // [25, 50) should hit 25, 30, 31, 32 — not 50, not 10.
    let r = s
        .iter_log_range(Namespace::MESSAGE_LOG, Some(25), Some(50), 100)
        .unwrap();
    let ids: Vec<u64> = r.iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, vec![25, 30, 31, 32]);
}
