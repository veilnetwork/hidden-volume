//! `Space::stats` — aggregate per-space statistics for UI surfaces.
//!
//! Coverage:
//! 1. Empty space (no commits beyond the initial Superblock) — zero
//!    namespaces, zero entries, owned_chunk_count > 0 (initial SB
//!    replicas).
//! 2. Single-namespace KV — entry count matches; total_entries sums.
//! 3. Multi-namespace KV+log — sorted by namespace.0 ascending, each
//!    count matches `count`/`iter_log` independently.
//! 4. Post-erase: the erased namespace disappears from
//!    `namespace_counts` (not just zeroed — the namespace is no
//!    longer in `list_namespaces`).
//! 5. Multiple commits → `commit_seq` and `commit_history_len`
//!    advance in lock-step.
//! 6. After repack the destination's stats reflect the live state
//!    only (no orphan chunks counted, owned_chunk_count drops).
//! 7. Read-only handle: `stats` works without writes.
//! 8. Total_entries helper sums per-namespace counts.

use hidden_volume::Container;
use hidden_volume::container::RepackOptions;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;

mod common;
use common::{fast_params, scratch_path};

fn fast_repack_options() -> RepackOptions {
    RepackOptions {
        argon2: fast_params(),
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 3,
    }
}

#[test]
fn empty_space_stats() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let stats = s.stats().unwrap();
    assert_eq!(stats.commit_seq, 1);
    assert_eq!(stats.commit_history_len, 1);
    // Initial SB replicas (default 3) are owned.
    assert!(stats.owned_chunk_count >= 1);
    assert!(stats.namespace_counts.is_empty());
    assert_eq!(stats.total_entries(), 0);
    // Audit pass 17: total_slot_count is populated and
    // utilization_ratio is sane on a fresh container.
    assert!(stats.total_slot_count >= stats.owned_chunk_count as u64);
    let r = stats.utilization_ratio();
    assert!((0.0..=1.0).contains(&r));
}

/// Audit pass 17: `utilization_ratio` correctly reflects the gap
/// between owned-chunk-count and total-slot-count after a heavy
/// initial garbage allocation. Confirms the API the host-app uses
/// to drive `compact_known` triggers.
#[test]
fn utilization_ratio_tracks_garbage_overhead() {
    use hidden_volume::container::ContainerOptions;
    use hidden_volume::padding::PaddingPolicy;

    let path = scratch_path();
    let opts = ContainerOptions {
        argon2: fast_params(),
        // Pre-allocate a large pool of garbage so live ratio drops
        // far below 1.0 — emulates the post-mass-delete state.
        initial_garbage_chunks: 200,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 3,
    };
    let mut c = hidden_volume::Container::create_with_options(&path, opts).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let stats = s.stats().unwrap();

    // 200 garbage + handful of SB replicas means owned ≪ total.
    assert!(
        stats.total_slot_count >= 200,
        "total_slot_count = {}",
        stats.total_slot_count,
    );
    assert!(
        stats.owned_chunk_count < 50,
        "owned_chunk_count = {}",
        stats.owned_chunk_count,
    );
    let r = stats.utilization_ratio();
    assert!(r < 0.5, "utilization_ratio = {r}");
    assert!(r > 0.0, "utilization_ratio = {r}");
}

#[test]
fn single_namespace_kv_stats() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    for i in 0..50u32 {
        tx.put(Namespace::CONTACTS, format!("k{i:02}").as_bytes(), b"v")
            .unwrap();
    }
    tx.commit().unwrap();

    let stats = s.stats().unwrap();
    assert_eq!(stats.commit_seq, 2);
    assert_eq!(stats.namespace_counts.len(), 1);
    assert_eq!(stats.namespace_counts[0].0, Namespace::CONTACTS);
    assert_eq!(stats.namespace_counts[0].1, 50);
    assert_eq!(stats.total_entries(), 50);
}

#[test]
fn multi_namespace_kv_and_log_stats() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"theme", b"dark").unwrap();
    tx.put(Namespace::SETTINGS, b"lang", b"en").unwrap();
    tx.put(Namespace::CONTACTS, b"alice", b"@a").unwrap();
    tx.put(Namespace::CONTACTS, b"bob", b"@b").unwrap();
    tx.put(Namespace::CONTACTS, b"carol", b"@c").unwrap();
    for id in 1..=20u64 {
        tx.append_log(Namespace::MESSAGE_LOG, id, format!("m{id}").as_bytes())
            .unwrap();
    }
    tx.commit().unwrap();

    let stats = s.stats().unwrap();
    assert_eq!(stats.namespace_counts.len(), 3);
    // Sorted ascending by namespace byte (SETTINGS=1, CONTACTS=2, MESSAGE_LOG=3).
    assert_eq!(stats.namespace_counts[0].0, Namespace::SETTINGS);
    assert_eq!(stats.namespace_counts[0].1, 2);
    assert_eq!(stats.namespace_counts[1].0, Namespace::CONTACTS);
    assert_eq!(stats.namespace_counts[1].1, 3);
    assert_eq!(stats.namespace_counts[2].0, Namespace::MESSAGE_LOG);
    assert_eq!(stats.namespace_counts[2].1, 20);
    assert_eq!(stats.total_entries(), 25);

    // Independent verification: each count matches the per-method API.
    assert_eq!(s.count(Namespace::SETTINGS).unwrap(), 2);
    assert_eq!(s.count(Namespace::CONTACTS).unwrap(), 3);
    assert_eq!(s.iter_log(Namespace::MESSAGE_LOG).unwrap().len(), 20);
}

#[test]
fn post_erase_namespace_disappears() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
    tx.put(Namespace::CONTACTS, b"a", b"a").unwrap();
    tx.commit().unwrap();
    assert_eq!(s.stats().unwrap().namespace_counts.len(), 2);

    s.erase_namespace(Namespace::CONTACTS).unwrap();
    let stats = s.stats().unwrap();
    // CONTACTS dropped from the namespace_counts list (not zeroed).
    assert_eq!(stats.namespace_counts.len(), 1);
    assert_eq!(stats.namespace_counts[0].0, Namespace::SETTINGS);
}

#[test]
fn commit_history_advances_with_commits() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let s0 = s.stats().unwrap();
    assert_eq!(s0.commit_seq, 1);
    assert_eq!(s0.commit_history_len, 1);

    for i in 0..5u32 {
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, format!("k{i}").as_bytes(), b"v")
            .unwrap();
        tx.commit().unwrap();
    }
    let s1 = s.stats().unwrap();
    assert_eq!(s1.commit_seq, 6);
    assert_eq!(s1.commit_history_len, 6); // initial + 5 commits
}

#[test]
fn post_repack_owned_count_drops() {
    let path = scratch_path();
    let owned_before;
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        // Several commits → many owned chunks (orphan IndexNodes etc.).
        for i in 0..10u32 {
            let mut tx = s.begin_tx();
            tx.put(Namespace::CONTACTS, format!("k{i}").as_bytes(), b"v")
                .unwrap();
            tx.commit().unwrap();
        }
        owned_before = s.stats().unwrap().owned_chunk_count;
    }
    let pw: &[u8] = b"pw";
    Container::compact_known(&path, &[pw], fast_repack_options()).unwrap();
    let mut c = Container::open(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let stats = s.stats().unwrap();
    assert!(
        stats.owned_chunk_count < owned_before,
        "compact should reduce owned chunks; before={owned_before}, after={}",
        stats.owned_chunk_count,
    );
    // Live state preserved.
    assert_eq!(stats.namespace_counts.len(), 1);
    assert_eq!(stats.namespace_counts[0].1, 10);
}

#[test]
fn readonly_handle_stats() {
    let path = scratch_path();
    {
        let mut c = Container::create(&path, fast_params()).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
    }
    let mut c = Container::open_readonly(&path).unwrap();
    let mut s = c.open_space(b"pw").unwrap();
    let stats = s.stats().unwrap();
    assert_eq!(stats.commit_seq, 2);
    assert_eq!(stats.namespace_counts.len(), 1);
    assert_eq!(stats.total_entries(), 1);
}

#[test]
fn total_entries_helper_sums_correctly() {
    let path = scratch_path();
    let mut c = Container::create(&path, fast_params()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();
    let mut tx = s.begin_tx();
    tx.put(Namespace(7), b"a", b"1").unwrap();
    tx.put(Namespace(7), b"b", b"2").unwrap();
    tx.put(Namespace(8), b"c", b"3").unwrap();
    tx.commit().unwrap();

    let stats = s.stats().unwrap();
    assert_eq!(stats.total_entries(), 3);
    let manual_sum: usize = stats.namespace_counts.iter().map(|(_, n)| n).sum();
    assert_eq!(manual_sum, stats.total_entries());
}
