//! Comprehensive property test: random sequence of (put / delete /
//! append_log / commit / reopen) operations against the public API,
//! validated against an in-memory reference model (BTreeMap).
//!
//! This catches edge cases that hand-written tests miss:
//! - Tx coalesce semantics (last write wins for repeated keys)
//! - put/delete interleaving in same Tx
//! - Reopen + auto-vacuum invariants
//! - B+ tree split correctness under mixed ops
//! - Log entry replacement across batches
//! - Multi-namespace independence under random ordering
//!
//! Namespace partitioning: 1..=5 are KV namespaces, 6..=10 are log
//! namespaces. The test never mixes them on the same namespace
//! (mixing is undefined behavior at the API level).

use hidden_volume::Container;
use hidden_volume::container::ContainerOptions;
use hidden_volume::crypto::kdf::Argon2Params;
use hidden_volume::padding::PaddingPolicy;
use hidden_volume::space::index::Namespace;
use proptest::prelude::*;
use std::collections::BTreeMap;

const KV_NAMESPACES: [u8; 5] = [1, 2, 3, 4, 5];
const LOG_NAMESPACES: [u8; 5] = [6, 7, 8, 9, 10];

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
    Reopen,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let kv_ns = prop_oneof![Just(1u8), Just(2), Just(3), Just(4), Just(5)];
    let log_ns = prop_oneof![Just(6u8), Just(7), Just(8), Just(9), Just(10)];
    let key = prop::collection::vec(any::<u8>(), 1..=16);
    let value = prop::collection::vec(any::<u8>(), 0..=64);
    let log_id = 0u64..200;

    prop_oneof![
        // 4 weight: put dominates
        4 => (kv_ns.clone(), key.clone(), value.clone())
            .prop_map(|(ns, k, v)| Op::Put { ns, key: k, value: v }),
        2 => (kv_ns, key)
            .prop_map(|(ns, k)| Op::Delete { ns, key: k }),
        2 => (log_ns, log_id, value)
            .prop_map(|(ns, id, p)| Op::AppendLog { ns, log_id: id, payload: p }),
        3 => Just(Op::Commit),
        1 => Just(Op::Reopen),
    ]
}

fn fast_options() -> ContainerOptions {
    ContainerOptions {
        argon2: Argon2Params::MIN,
        initial_garbage_chunks: 0,
        padding_policy: PaddingPolicy::None,
        superblock_replicas: 1,
    }
}

#[derive(Default)]
struct RefModel {
    /// Committed KV state: (ns, key) -> value.
    kv: BTreeMap<(u8, Vec<u8>), Vec<u8>>,
    /// Committed log state: (ns, log_id) -> payload.
    log: BTreeMap<(u8, u64), Vec<u8>>,
    /// Pending KV ops in current Tx, applied in order. Used to track
    /// what would be committed.
    pending_kv: Vec<(u8, Vec<u8>, Option<Vec<u8>>)>,
    /// Pending log ops in current Tx. Last-write-wins coalesce by (ns, log_id).
    pending_log: BTreeMap<(u8, u64), Vec<u8>>,
}

impl RefModel {
    fn apply_pending_to_committed(&mut self) {
        for (ns, key, val) in self.pending_kv.drain(..) {
            match val {
                Some(v) => {
                    self.kv.insert((ns, key), v);
                },
                None => {
                    self.kv.remove(&(ns, key));
                },
            }
        }
        for (k, v) in std::mem::take(&mut self.pending_log) {
            self.log.insert(k, v);
        }
    }

    fn discard_pending(&mut self) {
        self.pending_kv.clear();
        self.pending_log.clear();
    }
}

type KvMap = BTreeMap<(u8, Vec<u8>), Vec<u8>>;
type LogMap = BTreeMap<(u8, u64), Vec<u8>>;

fn collect_actual_kv(space: &mut hidden_volume::Space<'_>) -> hidden_volume::Result<KvMap> {
    let mut out = BTreeMap::new();
    for &ns_byte in &KV_NAMESPACES {
        let ns = Namespace(ns_byte);
        for (k, v) in space.list(ns)? {
            out.insert((ns_byte, k), v);
        }
    }
    Ok(out)
}

fn collect_actual_log(space: &mut hidden_volume::Space<'_>) -> hidden_volume::Result<LogMap> {
    let mut out = BTreeMap::new();
    for &ns_byte in &LOG_NAMESPACES {
        let ns = Namespace(ns_byte);
        for (id, payload) in space.iter_log(ns)? {
            out.insert((ns_byte, id), payload);
        }
    }
    Ok(out)
}

fn run_ops(ops: Vec<Op>) -> Result<(), TestCaseError> {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_owned();
    drop(tmp);
    let password = b"property-test-pwd";

    let mut model = RefModel::default();

    // We can't keep tx/space/container all in scope simultaneously
    // across iterations because of borrow propagation through Reopen.
    // Strategy: reopen state on every op as needed via a helper.
    // For efficiency: keep container open, reopen tx on every Commit.

    let mut container = Container::create_with_options(&path, fast_options())
        .map_err(|e| TestCaseError::fail(format!("create: {e:?}")))?;
    {
        let _space = container
            .create_space(password)
            .map_err(|e| TestCaseError::fail(format!("create_space: {e:?}")))?;
    }

    // Outer loop: open space for each "session" (between Reopen ops).
    let mut idx = 0;
    while idx < ops.len() {
        let mut space = container
            .open_space(password)
            .map_err(|e| TestCaseError::fail(format!("open_space: {e:?}")))?;
        let mut tx = space.begin_tx();

        while idx < ops.len() {
            match ops[idx].clone() {
                Op::Put { ns, key, value } => {
                    tx.put(Namespace(ns), &key, &value)
                        .map_err(|e| TestCaseError::fail(format!("put: {e:?}")))?;
                    model.pending_kv.push((ns, key, Some(value)));
                },
                Op::Delete { ns, key } => {
                    tx.delete(Namespace(ns), &key)
                        .map_err(|e| TestCaseError::fail(format!("delete: {e:?}")))?;
                    model.pending_kv.push((ns, key, None));
                },
                Op::AppendLog {
                    ns,
                    log_id,
                    payload,
                } => {
                    tx.append_log(Namespace(ns), log_id, &payload)
                        .map_err(|e| TestCaseError::fail(format!("append_log: {e:?}")))?;
                    model.pending_log.insert((ns, log_id), payload);
                },
                Op::Commit => {
                    tx.commit()
                        .map_err(|e| TestCaseError::fail(format!("commit: {e:?}")))?;
                    model.apply_pending_to_committed();
                    tx = space.begin_tx();
                },
                Op::Reopen => {
                    // Pending Tx is dropped — its ops are not committed.
                    model.discard_pending();
                    idx += 1;
                    break;
                },
            }
            idx += 1;
        }

        // End of inner loop — either ops exhausted or Reopen.
        // If Reopen: drop tx + space, then re-iterate.
        drop(tx);
        drop(space);
    }

    // Final verification: open space, compare to committed reference.
    // (Pending Tx was dropped; only committed state should match.)
    let mut space = container
        .open_space(password)
        .map_err(|e| TestCaseError::fail(format!("final open_space: {e:?}")))?;

    let actual_kv = collect_actual_kv(&mut space)
        .map_err(|e| TestCaseError::fail(format!("collect_kv: {e:?}")))?;
    let actual_log = collect_actual_log(&mut space)
        .map_err(|e| TestCaseError::fail(format!("collect_log: {e:?}")))?;

    prop_assert_eq!(&actual_kv, &model.kv, "KV state mismatch");
    prop_assert_eq!(&actual_log, &model.log, "log state mismatch");

    drop(space);
    drop(container);
    let _ = std::fs::remove_file(&path);

    Ok(())
}

proptest! {
    // Each case spawns its own Argon2id derivation, file creation,
    // many ops. Keep cases small to fit Argon2 cost.
    #![proptest_config(ProptestConfig {
        cases: 16,
        .. ProptestConfig::default()
    })]

    /// Random sequence of operations matches the reference model.
    #[test]
    fn random_ops_match_reference(ops in prop::collection::vec(op_strategy(), 1..=40)) {
        run_ops(ops)?;
    }
}

// --- Targeted regression tests (deterministic) ---

#[test]
fn regression_put_delete_put_same_key_in_one_tx() {
    let ops = vec![
        Op::Put {
            ns: 1,
            key: b"k".to_vec(),
            value: b"v1".to_vec(),
        },
        Op::Delete {
            ns: 1,
            key: b"k".to_vec(),
        },
        Op::Put {
            ns: 1,
            key: b"k".to_vec(),
            value: b"v2".to_vec(),
        },
        Op::Commit,
    ];
    run_ops(ops).unwrap();
}

#[test]
fn regression_log_replace_across_txs() {
    let ops = vec![
        Op::AppendLog {
            ns: 6,
            log_id: 1,
            payload: b"old".to_vec(),
        },
        Op::Commit,
        Op::AppendLog {
            ns: 6,
            log_id: 1,
            payload: b"new".to_vec(),
        },
        Op::Commit,
    ];
    run_ops(ops).unwrap();
}

#[test]
fn regression_reopen_drops_uncommitted_pending() {
    let ops = vec![
        Op::Put {
            ns: 1,
            key: b"k".to_vec(),
            value: b"v1".to_vec(),
        },
        Op::Commit,
        Op::Put {
            ns: 1,
            key: b"k".to_vec(),
            value: b"v2".to_vec(),
        }, // pending
        Op::Reopen, // pending discarded
    ];
    run_ops(ops).unwrap();
    // Final state should have v1, not v2.
}

#[test]
fn regression_many_puts_then_many_deletes() {
    let mut ops = Vec::new();
    for i in 0..30u8 {
        ops.push(Op::Put {
            ns: 1,
            key: vec![i],
            value: vec![i, i, i],
        });
    }
    ops.push(Op::Commit);
    for i in 0..30u8 {
        ops.push(Op::Delete {
            ns: 1,
            key: vec![i],
        });
    }
    ops.push(Op::Commit);
    run_ops(ops).unwrap();
}

#[test]
fn regression_mixed_kv_and_log_one_tx() {
    let ops = vec![
        Op::Put {
            ns: 1,
            key: b"a".to_vec(),
            value: b"x".to_vec(),
        },
        Op::Put {
            ns: 2,
            key: b"b".to_vec(),
            value: b"y".to_vec(),
        },
        Op::AppendLog {
            ns: 6,
            log_id: 100,
            payload: b"msg1".to_vec(),
        },
        Op::AppendLog {
            ns: 7,
            log_id: 200,
            payload: b"msg2".to_vec(),
        },
        Op::Commit,
    ];
    run_ops(ops).unwrap();
}

#[test]
fn regression_alternating_commit_reopen() {
    let ops = vec![
        Op::Put {
            ns: 1,
            key: b"a".to_vec(),
            value: b"1".to_vec(),
        },
        Op::Commit,
        Op::Reopen,
        Op::Put {
            ns: 1,
            key: b"b".to_vec(),
            value: b"2".to_vec(),
        },
        Op::Commit,
        Op::Reopen,
        Op::Delete {
            ns: 1,
            key: b"a".to_vec(),
        },
        Op::Commit,
        Op::Reopen,
    ];
    run_ops(ops).unwrap();
}
