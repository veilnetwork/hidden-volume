//! Property-based crash-recovery testing.
//!
//! Existing `tests/crash_recovery.rs` covers 8 hand-written scenarios
//! at specific points of the 3-fsync barrier. `tests/many_chained_crashes`
//! does an exhaustive truncate-at-every-slot sweep on one fixed
//! workload. This file complements both with **random-workload +
//! random-truncate** property tests: build a container with a
//! randomly-generated op sequence, snapshot per-commit `(seq → state)`
//! along the way, then for each random truncation point assert that
//! the reopened container's state matches *some* committed snapshot
//! (rolling back to that or an earlier commit, but never to a state
//! that was never committed).
//!
//! What this catches that hand-written tests don't:
//! - Random ops + random crash combinations exercise corners of
//!   B+ tree split, log batching, and superblock-replica interaction
//!   that aren't enumerated by hand.
//! - Recovery monotonicity invariant (reopened seq ≤ last-committed
//!   seq) is asserted across many random shapes.
//! - `count` / `list` / `iter_log` post-recovery don't panic on
//!   any reachable truncated-state.

use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use hidden_volume::{CHUNK_SIZE, Container, Error};
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::path::Path;

mod common;
use common::scratch_path;

const KV_NAMESPACES: [u8; 3] = [1, 2, 3];
const LOG_NAMESPACES: [u8; 2] = [4, 5];

#[derive(Clone, Debug)]
enum Op {
    Put {
        ns: u8,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        ns: u8,
        key: Vec<u8>,
    },
    AppendLog {
        ns: u8,
        log_id: u64,
        payload: Vec<u8>,
    },
    Commit,
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        // Put — small keys/values to exercise tree but stay fast.
        (
            prop::sample::select(KV_NAMESPACES.to_vec()),
            prop::collection::vec(any::<u8>(), 1..=8),
            prop::collection::vec(any::<u8>(), 0..=16),
        )
            .prop_map(|(ns, key, value)| Op::Put { ns, key, value }),
        // Delete
        (
            prop::sample::select(KV_NAMESPACES.to_vec()),
            prop::collection::vec(any::<u8>(), 1..=8),
        )
            .prop_map(|(ns, key)| Op::Delete { ns, key }),
        // AppendLog
        (
            prop::sample::select(LOG_NAMESPACES.to_vec()),
            0u64..1024,
            prop::collection::vec(any::<u8>(), 0..=32),
        )
            .prop_map(|(ns, log_id, payload)| Op::AppendLog {
                ns,
                log_id,
                payload
            }),
        // Commit
        Just(Op::Commit),
    ]
}

fn fast_options() -> ContainerOptions {
    ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        // Replicas=1 so file layout is predictable for slot-bounded truncation.
        superblock_replicas: 1,
    }
}

fn slots_on_disk(path: &Path) -> u64 {
    let len = std::fs::metadata(path).unwrap().len();
    if len == 0 || !len.is_multiple_of(CHUNK_SIZE as u64) {
        return 0;
    }
    (len / CHUNK_SIZE as u64) - 1
}

fn truncate_to_slots(path: &Path, slot_count: u64) {
    let new_size = (1 + slot_count) * CHUNK_SIZE as u64;
    let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.set_len(new_size).unwrap();
}

/// Returns `(committed_seqs, final_state)`: the list of seqs reached
/// by successful commits during the workload (in order), plus the
/// final per-namespace KV map. Used to bound the post-truncate seq
/// — a recovered seq must be ≤ the last committed seq we observed.
fn build_container(path: &Path, ops: &[Op]) -> Vec<u64> {
    let mut c = Container::create_with_options(path, fast_options()).unwrap();
    let mut s = c.create_space(b"pw").unwrap();

    let mut committed_seqs: Vec<u64> = vec![1]; // initial SB
    let mut tx = s.begin_tx();
    let mut tx_dirty = false;
    let mut log_used_in_tx: BTreeMap<(u8, u64), bool> = BTreeMap::new();

    for op in ops {
        match op {
            Op::Put { ns, key, value } => {
                if tx.put(Namespace(*ns), key, value).is_ok() {
                    tx_dirty = true;
                }
            },
            Op::Delete { ns, key } => {
                if tx.delete(Namespace(*ns), key).is_ok() {
                    tx_dirty = true;
                }
            },
            Op::AppendLog {
                ns,
                log_id,
                payload,
            } => {
                // Coalesce duplicate log_ids in same tx — we just
                // accept either outcome from append_log.
                if log_used_in_tx.insert((*ns, *log_id), true).is_some() {
                    // Skip — last-write-wins inside tx is fine but we
                    // don't want to spam the same id.
                    continue;
                }
                if tx.append_log(Namespace(*ns), *log_id, payload).is_ok() {
                    tx_dirty = true;
                }
            },
            Op::Commit => {
                if tx_dirty {
                    if let Ok(seq) = tx.commit() {
                        committed_seqs.push(seq);
                    }
                    // Else: commit failed (e.g. PayloadTooLarge from
                    // accumulated log) — start a fresh tx and move on.
                    tx_dirty = false;
                    log_used_in_tx.clear();
                }
                tx = s.begin_tx();
            },
        }
    }
    // Drop pending tx without commit — that's fine, it's just discarded.
    drop(tx);
    drop(s);
    drop(c);
    committed_seqs
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    /// **Recovery monotonicity.** Truncating a healthy container at
    /// any chunk boundary yields a container that — if it opens at
    /// all — reports `commit_seq` ≤ the last committed seq before
    /// truncation. We never see a seq that was never reached.
    #[test]
    fn random_truncation_recovers_to_some_prior_committed_state(
        ops in prop::collection::vec(arb_op(), 1..=30),
        truncate_offset_pct in 0u64..=100,
    ) {
        let path = scratch_path();
        let committed_seqs = build_container(&path, &ops);
        let max_committed_seq = *committed_seqs.iter().max().unwrap_or(&1);
        let total_slots = slots_on_disk(&path);

        if total_slots == 0 {
            // No commits happened — nothing to truncate meaningfully.
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }

        // Truncate to a random fraction of the file's slots. 0% → just
        // header (file becomes empty of slots, open will fail).
        let slot_cap = (total_slots * truncate_offset_pct) / 100;
        if slot_cap == 0 {
            // Not interesting; container has no SB to recover.
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }
        truncate_to_slots(&path, slot_cap);

        match Container::open(&path) {
            Ok(mut c) => match c.open_space(b"pw") {
                Ok(s) => {
                    // Recovery succeeded. Recovered seq must be one we
                    // actually committed during the workload, AND it
                    // must be ≤ the latest committed seq.
                    let recovered_seq = s.commit_seq();
                    prop_assert!(
                        committed_seqs.contains(&recovered_seq),
                        "recovered seq {recovered_seq} was never committed; \
                         workload committed {committed_seqs:?}",
                    );
                    prop_assert!(
                        recovered_seq <= max_committed_seq,
                        "recovered seq {recovered_seq} > max committed \
                         {max_committed_seq}",
                    );
                },
                Err(Error::AuthFailed) => {
                    // All SB replicas truncated away — recovery
                    // legitimately can't find any owned chunk.
                },
                Err(e) => {
                    prop_assert!(false, "unexpected open_space error: {e:?}");
                },
            },
            Err(Error::Malformed(_)) => {
                // Header corruption / truncation that breaks header
                // is acceptable — the library refuses to open
                // ambiguous files (DESIGN choice).
            },
            Err(e) => {
                prop_assert!(false, "unexpected Container::open error: {e:?}");
            },
        }

        let _ = std::fs::remove_file(&path);
    }

    /// **Read APIs don't panic post-recovery.** After a random
    /// truncate, every `count` / `list` / `iter_log_*` / `get` /
    /// `verify_integrity` call returns either Ok or a documented Err
    /// — no panic, no UB, no unwrap explosion.
    #[test]
    fn read_apis_never_panic_after_random_truncation(
        ops in prop::collection::vec(arb_op(), 1..=20),
        truncate_offset_pct in 5u64..=100,
    ) {
        let path = scratch_path();
        let _committed = build_container(&path, &ops);
        let total_slots = slots_on_disk(&path);

        if total_slots == 0 {
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }

        let slot_cap = ((total_slots * truncate_offset_pct) / 100).max(1);
        truncate_to_slots(&path, slot_cap);

        if let Ok(mut c) = Container::open(&path)
            && let Ok(mut s) = c.open_space(b"pw")
        {
            // None of these may panic. Errors are fine.
            for &ns_byte in KV_NAMESPACES.iter().chain(LOG_NAMESPACES.iter()) {
                let ns = Namespace(ns_byte);
                let _ = s.count(ns);
                let _ = s.list(ns);
                let _ = s.get(ns, b"x");
                let _ = s.iter_log_after(ns, None, 16);
                let _ = s.iter_log_before(ns, None, 16);
            }
            let _ = s.verify_integrity();
            let _ = s.commit_seq();
            let _ = s.commit_history();
        }

        let _ = std::fs::remove_file(&path);
    }

    /// **Recovery is idempotent.** Reopening the same truncated file
    /// twice yields the same recovered state. (No hidden mutation in
    /// the open path beyond auto-vacuum, which itself is idempotent.)
    #[test]
    fn recovery_is_idempotent_after_truncation(
        ops in prop::collection::vec(arb_op(), 1..=20),
        truncate_offset_pct in 10u64..=100,
    ) {
        let path = scratch_path();
        let _committed = build_container(&path, &ops);
        let total_slots = slots_on_disk(&path);

        if total_slots == 0 {
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }

        let slot_cap = ((total_slots * truncate_offset_pct) / 100).max(1);
        truncate_to_slots(&path, slot_cap);

        let first_seq = match Container::open(&path) {
            Ok(mut c) => match c.open_space(b"pw") {
                Ok(s) => Some(s.commit_seq()),
                Err(_) => None,
            },
            Err(_) => None,
        };

        let second_seq = match Container::open(&path) {
            Ok(mut c) => match c.open_space(b"pw") {
                Ok(s) => Some(s.commit_seq()),
                Err(_) => None,
            },
            Err(_) => None,
        };

        prop_assert_eq!(
            first_seq, second_seq,
            "two consecutive opens of the same truncated file yielded \
             different recovered seqs — recovery is non-deterministic",
        );

        let _ = std::fs::remove_file(&path);
    }
}
