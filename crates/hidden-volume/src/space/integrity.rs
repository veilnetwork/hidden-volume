//! Merkle integrity walk for a `Space`. Audit pass 8 (E7) split
//! out of `space/mod.rs` so the integrity-check logic is reviewable
//! as a self-contained ~150-LOC chunk independent of commit / vacuum
//! / log-iteration paths.

use crate::chunk::ChunkKind;
use crate::chunk::format::Plaintext;
use crate::tx::commit::{CommitPayload, NamespaceKind, blake3_of};
use crate::{Error, Result};

use super::IntegrityReport;
use super::Space;
use super::index::{IndexNode, Namespace};
use super::log::{decode_batch, parse_batch_slot_value, parse_log_id_key};
use super::superblock::NO_RECORD;
use super::walk::TreeWalk;

/// Walk-wide mutable state, threaded through the recursion as one
/// parameter so the per-node arguments stay reviewable.
struct VerifyCtx {
    /// Visited set + traversal budget shared by every namespace root
    /// AND by the DataBatch pass — see [`super::walk`]. One guard for
    /// the whole `verify_integrity` call means a chunk claimed by two
    /// namespaces, or by both an index and a log pointer, is a failure
    /// rather than extra work.
    walk: TreeWalk,
    /// `(batch_slot, log_id)` pairs harvested from the leaves of every
    /// Log-kind namespace, verified in one pass after the tree walk.
    log_pairs: Vec<(u64, u64)>,
    report: IntegrityReport,
}

/// Everything the parent link promises about the node at `slot`.
struct Subtree<'k> {
    slot: u64,
    /// BLAKE3 the parent recorded for this chunk's plaintext payload.
    expected_hash: [u8; 32],
    /// Namespace byte declared by the `IndexRoot` this descent started
    /// from; every node in the subtree must carry it.
    namespace: Namespace,
    /// Whether the namespace is a Log, i.e. whether leaf values are
    /// `DataBatch` slot pointers to be collected and verified.
    is_log: bool,
    /// Inclusive lower bound every key in this subtree must meet.
    /// `None` at the root = unbounded below.
    lower: Option<&'k [u8]>,
    /// Exclusive upper bound every key in this subtree must stay under.
    /// `None` at the root = unbounded above.
    upper: Option<&'k [u8]>,
    /// Descents taken to reach this node, root = 0 — the same counter
    /// every other walker keeps, and what `TreeWalk` bounds. The
    /// report's `max_depth` counts levels, so it is this plus one.
    depth: u8,
}

impl<'f> Space<'f> {
    /// Walk the entire Merkle hash chain rooted at the current
    /// Superblock and confirm that every link matches its parent's
    /// recorded hash.
    ///
    /// What is verified, link by link:
    /// 1. `Superblock.root_hash` equals
    ///    `BLAKE3(concat(roots[i].payload_hash))`, recomputed from the
    ///    Commit chunk at `Superblock.root_slot`.
    /// 2. `CommitPayload.tx_root_hash` field is internally consistent
    ///    with the `roots` list it carries.
    /// 3. For every `IndexRoot { index_slot, payload_hash, .. }`,
    ///    `BLAKE3(IndexNode chunk plaintext at index_slot)` equals
    ///    `payload_hash`.
    /// 4. For every Internal IndexNode, `BLAKE3(child IndexNode chunk
    ///    plaintext at child.child_slot)` equals `child.child_hash`,
    ///    recursively.
    ///
    /// Beyond the hash chain, the walk enforces the structural
    /// invariants a reader depends on but a Merkle hash cannot express
    /// — the hash binds the bytes of each node, not the relationship
    /// between nodes:
    ///
    /// 5. **Key ranges.** Every key in the subtree under
    ///    `children[i]` falls in `[children[i].first_key,
    ///    children[i+1].first_key)` (the last child inherits the
    ///    parent's upper bound). `LeafNode::decode` only enforces
    ///    order *within* one leaf; without this, sibling leaves may
    ///    overlap or sit out of order while every hash still matches.
    ///    The result is a namespace whose entries `Space::get` cannot
    ///    reach — `get` binary-searches `first_key` on the way down —
    ///    and whose next commit would be rejected by `flatten_tree`'s
    ///    global-sortedness gate. That is exactly the
    ///    "verified-but-unreadable" state this method exists to rule
    ///    out.
    /// 6. **One path per chunk.** No slot is read twice in a walk, so
    ///    an index that is a DAG rather than a tree (children sharing
    ///    a `child_slot`, or two namespaces naming the same chunk) is
    ///    reported instead of silently costing `fanout^depth` reads.
    /// 7. **Traversal budget.** The walk may read no more chunks than
    ///    the space owns, so an unforeseen shape still terminates.
    ///
    /// AEAD already protects each chunk's bytes individually (any
    /// single-byte flip surfaces as `AuthFailed` from the underlying
    /// read). This API surfaces such AEAD failures as
    /// [`Error::IntegrityFailure`] so the caller can distinguish
    /// "corrupted owned chunk during integrity walk" from "wrong
    /// password / not our chunk during open scan".
    ///
    /// **Cost.** O(N) where N is the number of chunks reachable from
    /// the current Superblock — each is read once and BLAKE3-hashed.
    /// On a 10K-entry namespace with B+ tree split this is a few
    /// hundred chunk reads, milliseconds total. Log namespaces are
    /// walked once, not twice: the same descent that checks hashes
    /// collects the `DataBatch` pointers.
    ///
    /// **Read-only safe.** No writes occur; this method works on a
    /// handle returned by [`crate::Container::open_readonly`].
    ///
    /// **Returns** an [`IntegrityReport`] on success; the first
    /// detected mismatch raises [`Error::IntegrityFailure`].
    pub fn verify_integrity(&mut self) -> Result<IntegrityReport> {
        let mut ctx = VerifyCtx {
            walk: self.new_tree_walk(),
            log_pairs: Vec::new(),
            report: IntegrityReport {
                namespaces_verified: 0,
                chunks_verified: 0,
                max_depth: 0,
                data_batches_verified: 0,
            },
        };

        // Empty space — superblock points at NO_RECORD; nothing to verify.
        if self.state.superblock.root_slot == NO_RECORD {
            return Ok(ctx.report);
        }

        // 1. Read CommitPayload from Superblock.root_slot.
        let commit_slot = self.state.superblock.root_slot;
        // The Commit chunk is not part of any tree — depth 0, the
        // walk's guard is here for the visited set and the budget.
        ctx.walk.admit_for_verify(commit_slot, 0)?;
        let pt = self.read_chunk_for_verify(commit_slot, "owned-chunk AEAD failure on Commit")?;
        if pt.kind != ChunkKind::Commit {
            return Err(Error::IntegrityFailure {
                detail: "Superblock root_slot points at non-Commit chunk",
                slot: commit_slot,
            });
        }
        ctx.report.chunks_verified += 1;
        let cp = CommitPayload::decode(&pt.payload).map_err(|_| Error::IntegrityFailure {
            detail: "CommitPayload decode failed",
            slot: commit_slot,
        })?;

        // 2. SB.root_hash == BLAKE3(concat(roots[i].payload_hash))
        let recomputed = CommitPayload::compute_tx_root_hash(&cp.roots);
        if recomputed != self.state.superblock.root_hash {
            return Err(Error::IntegrityFailure {
                detail: "Superblock.root_hash != BLAKE3(roots)",
                slot: commit_slot,
            });
        }

        // 3. CommitPayload's stored tx_root_hash must equal the recompute.
        if cp.tx_root_hash != recomputed {
            return Err(Error::IntegrityFailure {
                detail: "CommitPayload.tx_root_hash internally inconsistent",
                slot: commit_slot,
            });
        }

        // 4. For each IndexRoot, recursively verify the subtree.
        //    For Log roots the same descent also collects every leaf
        //    entry's referenced `DataBatch` pointer (audit M2,
        //    2026-05-10), verified below.
        for root in &cp.roots {
            // Audit pass 19 round 6 finding (M2 user-report 2026-05-28):
            // pass the IndexRoot.namespace into the walk so every
            // IndexNode chunk is checked against it. Before this, a
            // key-holder / buggy writer could craft an IndexNode with
            // a different `namespace` byte than the IndexRoot meant
            // — Merkle hash still passed because payload_hash binds
            // the encoded bytes (which include the namespace byte) but
            // a *relabel* attack on the IndexRoot side (different
            // namespace declared in `cp.roots[i].namespace` vs what
            // the IndexNode actually carries) was undetected. The
            // expected-namespace gate closes that surface without a
            // format bump.
            let depth = self.verify_subtree(
                Subtree {
                    slot: root.index_slot,
                    expected_hash: root.payload_hash,
                    namespace: root.namespace,
                    is_log: matches!(root.kind, NamespaceKind::Log),
                    // A namespace root is unbounded on both sides; the
                    // bounds tighten on every descent.
                    lower: None,
                    upper: None,
                    depth: 0,
                },
                &mut ctx,
            )?;
            // `depth` counts descents (0 = the root is a leaf); the
            // report counts levels, so a single-leaf namespace is 1.
            let levels = depth.saturating_add(1);
            if levels > ctx.report.max_depth {
                ctx.report.max_depth = levels;
            }
            ctx.report.namespaces_verified += 1;
        }

        self.verify_log_data_batches(&mut ctx)?;

        Ok(ctx.report)
    }

    /// AEAD-decrypt + decode every `DataBatch` chunk the log namespaces
    /// pointed at, and confirm each pointer's record is really in the
    /// batch it names. This closes the M2 audit gap: prior to
    /// 2026-05-10 the Merkle walk stopped at Leaf nodes, so a corrupted
    /// DataBatch chunk passed `verify_integrity` and only failed later
    /// at `read_log` time.
    ///
    /// Algorithm:
    ///   1. Sort the `(batch_slot, log_id)` pairs the tree walk
    ///      collected, so every record claiming to live in one chunk
    ///      groups together, and drop exact duplicates.
    ///   2. For each unique slot: admit it to the traversal guard
    ///      (so a batch chunk shared with the index tree, or claimed by
    ///      two namespaces, is a failure), AEAD-decrypt, kind-check,
    ///      decode, and check every claimed `log_id` is present.
    ///
    /// Pairs from every namespace are pooled, so a batch slot is read
    /// once per walk even if several log namespaces name it.
    ///
    /// Cost: O(unique_batch_slots), bounded by the space's owned
    /// chunk count. Same per-chunk cost as the IndexNode walk above.
    fn verify_log_data_batches(&mut self, ctx: &mut VerifyCtx) -> Result<()> {
        // Taken out of `ctx` so the loop below can hold a slice of the
        // pairs while still mutating the guard and the report.
        let mut pairs = std::mem::take(&mut ctx.log_pairs);
        pairs.sort_unstable();
        pairs.dedup();

        let mut idx = 0;
        while idx < pairs.len() {
            let slot = pairs[idx].0;
            let end = idx + pairs[idx..].partition_point(|(s, _)| *s == slot);

            // A DataBatch hangs off a leaf entry rather than off a
            // descent; this loop is iterative, so depth 0 (the visited
            // set and the budget still apply).
            ctx.walk.admit_for_verify(slot, 0)?;
            let pt = self.read_chunk_for_verify(slot, "owned-chunk AEAD failure on DataBatch")?;
            if pt.kind != ChunkKind::DataBatch {
                return Err(Error::IntegrityFailure {
                    detail: "Log leaf entry references chunk that is not DataBatch",
                    slot,
                });
            }
            let records = decode_batch(&pt.payload).map_err(|_| Error::IntegrityFailure {
                detail: "DataBatch decode failed during integrity walk",
                slot,
            })?;

            // Verifying that the chunk decodes says nothing about whether the
            // record the index pointed at is in it. A state where a leaf maps
            // log_id -> slot and that slot's batch never contained log_id is
            // AEAD-valid, decodes cleanly, passes the old walk, and then fails
            // at read_log — the integrity check reported healthy about the one
            // thing the reader cannot do.
            let present: std::collections::HashSet<u64> =
                records.iter().map(|(id, _)| *id).collect();
            for (_, log_id) in &pairs[idx..end] {
                if !present.contains(log_id) {
                    return Err(Error::IntegrityFailure {
                        detail: "log index points at a DataBatch that does not hold its record",
                        slot,
                    });
                }
            }

            ctx.report.data_batches_verified += 1;
            idx = end;
        }
        Ok(())
    }

    /// Read a chunk at `slot` that we expect to own; map AEAD failure
    /// onto [`Error::IntegrityFailure`] (the integrity walk's contract
    /// is "AEAD-fail on a chunk we expected to own = corruption").
    ///
    /// Callers admit `slot` to the walk's guard first — the guard is
    /// what bounds how many times this can be reached.
    fn read_chunk_for_verify(
        &mut self,
        slot: u64,
        aead_fail_detail: &'static str,
    ) -> Result<Plaintext> {
        match self.read_owned_chunk(slot) {
            Ok(pt) => Ok(pt),
            Err(Error::AuthFailed) => Err(Error::IntegrityFailure {
                detail: aead_fail_detail,
                slot,
            }),
            Err(other) => Err(other),
        }
    }

    /// Recursively verify the IndexNode described by `exp` and its
    /// children, returning the greatest descent count observed below
    /// it (0 = this node is a leaf). The caller turns that into the
    /// report's level count.
    ///
    /// Depth-, width- and shape-capped via `ctx.walk`. The Merkle hash
    /// chain makes adversarial *cycles* cryptographically infeasible (a
    /// cycle needs a node to contain its own hash), but a **DAG** costs
    /// the attacker nothing: the same child hash under many parents is
    /// consistent, so without the visited set a 4-level fan-out of ~90
    /// re-reads four distinct chunks 90³ times.
    ///
    /// `exp.namespace` is the namespace byte declared by the
    /// `IndexRoot` we descended from. Every `IndexNode` chunk in the
    /// subtree MUST carry the same namespace; a mismatch is an
    /// integrity failure (a key-holder / buggy writer could otherwise
    /// "relabel" an IndexRoot to point at an IndexNode tree that
    /// physically belongs to another namespace — Merkle hash still
    /// passed before this gate because `payload_hash` covers the
    /// encoded bytes including the namespace byte, but a relabel on
    /// the IndexRoot side is undetected without this cross-check).
    ///
    /// `exp.lower` / `exp.upper` are the half-open key range this
    /// subtree was promised to hold, derived from the parent's
    /// `first_key` list. The writer sets each child's `first_key` to
    /// the first key of that child (`write_tree_for_namespace`), so a
    /// well-formed tree satisfies the bounds exactly.
    fn verify_subtree(&mut self, exp: Subtree<'_>, ctx: &mut VerifyCtx) -> Result<u8> {
        ctx.walk.admit_for_verify(exp.slot, exp.depth)?;
        let pt = self.read_chunk_for_verify(exp.slot, "owned-chunk AEAD failure on IndexNode")?;
        if pt.kind != ChunkKind::IndexNode {
            return Err(Error::IntegrityFailure {
                detail: "expected IndexNode chunk; found different kind",
                slot: exp.slot,
            });
        }
        let actual = blake3_of(&pt.payload);
        if actual != exp.expected_hash {
            return Err(Error::IntegrityFailure {
                detail: "IndexNode chunk hash != parent's recorded hash",
                slot: exp.slot,
            });
        }
        ctx.report.chunks_verified += 1;

        let node = IndexNode::decode(&pt.payload).map_err(|_| Error::IntegrityFailure {
            detail: "IndexNode decode failed during integrity walk",
            slot: exp.slot,
        })?;

        // Cross-check the namespace byte: the IndexNode must claim
        // the same namespace the IndexRoot pointed at. Closes the
        // root-relabel attack (audit pass 19 round 6 user-report
        // 2026-05-28).
        let node_ns = match &node {
            IndexNode::Leaf(l) => l.namespace,
            IndexNode::Internal(i) => i.namespace,
        };
        if node_ns != exp.namespace {
            return Err(Error::IntegrityFailure {
                detail: "IndexNode.namespace != IndexRoot.namespace",
                slot: exp.slot,
            });
        }

        match node {
            IndexNode::Leaf(leaf) => {
                for (key, value) in leaf.entries.iter() {
                    // `LeafNode::decode` guarantees these are sorted and
                    // distinct within this leaf; the bounds are what tie
                    // the leaf to its place in the tree.
                    if let Some(lo) = exp.lower
                        && key.as_slice() < lo
                    {
                        return Err(Error::IntegrityFailure {
                            detail: "leaf key below the range its parent promised",
                            slot: exp.slot,
                        });
                    }
                    if let Some(hi) = exp.upper
                        && key.as_slice() >= hi
                    {
                        return Err(Error::IntegrityFailure {
                            detail: "leaf key at or above the range its parent promised",
                            slot: exp.slot,
                        });
                    }
                    if exp.is_log {
                        // The key IS the log_id; discarding it here was
                        // why nothing downstream could check that the
                        // batch holds the record the index promised.
                        let log_id =
                            parse_log_id_key(key).map_err(|_| Error::IntegrityFailure {
                                detail: "log leaf entry key not 8 bytes (log_id)",
                                slot: exp.slot,
                            })?;
                        let batch_slot =
                            parse_batch_slot_value(value).map_err(|_| Error::IntegrityFailure {
                                detail: "log leaf entry value not 8 bytes (batch_slot)",
                                slot: exp.slot,
                            })?;
                        ctx.log_pairs.push((batch_slot, log_id));
                    }
                }
                Ok(exp.depth)
            },
            IndexNode::Internal(inner) => {
                // `InternalNode::decode` rejects zero children and
                // unsorted `first_key`s, so checking the first and last
                // against the inherited bounds covers all of them.
                let first = inner.children.first().ok_or(Error::IntegrityFailure {
                    detail: "internal node with zero children reached the integrity walk",
                    slot: exp.slot,
                })?;
                if let Some(lo) = exp.lower
                    && first.first_key.as_slice() < lo
                {
                    return Err(Error::IntegrityFailure {
                        detail: "internal child first_key below the range its parent promised",
                        slot: exp.slot,
                    });
                }
                if let Some(hi) = exp.upper
                    && let Some(last) = inner.children.last()
                    && last.first_key.as_slice() >= hi
                {
                    return Err(Error::IntegrityFailure {
                        detail: "internal child first_key at or above the range its parent promised",
                        slot: exp.slot,
                    });
                }

                let mut max_child_depth = exp.depth;
                for (i, child) in inner.children.iter().enumerate() {
                    // Child i owns `[first_key_i, first_key_{i+1})`;
                    // the last child runs to this node's own upper
                    // bound. Sibling ranges therefore tile the parent's
                    // range without gaps or overlap.
                    let child_upper = match inner.children.get(i + 1) {
                        Some(next) => Some(next.first_key.as_slice()),
                        None => exp.upper,
                    };
                    let child_depth = self.verify_subtree(
                        Subtree {
                            slot: child.child_slot,
                            expected_hash: child.child_hash,
                            namespace: exp.namespace,
                            is_log: exp.is_log,
                            lower: Some(child.first_key.as_slice()),
                            upper: child_upper,
                            depth: exp.depth + 1,
                        },
                        ctx,
                    )?;
                    if child_depth > max_child_depth {
                        max_child_depth = child_depth;
                    }
                }
                Ok(max_child_depth)
            },
        }
    }
}

/// Forged-container tests for the structural gates the Merkle hash
/// chain cannot express.
///
/// These live in-crate rather than under `tests/` on purpose. Tampering
/// with a container's bytes from outside (the `namespace_relabel.rs`
/// approach) breaks the hash of whatever node was edited, so the walk
/// stops at "hash != parent's record" long before the structural check
/// under test — and would leave a green test proving nothing. Building
/// the forgery with the writer's own primitives (`append_chunk`,
/// `compute_tx_root_hash`, `append_superblock`) produces a container
/// that is Merkle-consistent end to end, so the *only* thing that can
/// reject it is the gate being tested.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Container;
    use crate::crypto::kdf::Argon2Params;
    use crate::redact::Redacted;
    use crate::space::index::{ChildPointer, InternalNode, LeafNode};
    use crate::tx::commit::IndexRoot;

    use super::super::superblock::Superblock;

    fn scratch_path() -> std::path::PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
    }

    /// Seal `node` into a fresh IndexNode chunk, returning the
    /// `(slot, payload_hash)` a parent link must carry to be
    /// Merkle-consistent with it.
    fn seal_node(s: &mut Space<'_>, node: &IndexNode, seq: u64) -> (u64, [u8; 32]) {
        let bytes = node.encode().unwrap();
        let slot = s.append_chunk(ChunkKind::IndexNode, seq, &bytes).unwrap();
        (slot, blake3_of(&bytes))
    }

    fn leaf(ns: Namespace, entries: &[(&[u8], &[u8])]) -> IndexNode {
        IndexNode::Leaf(LeafNode {
            namespace: ns,
            entries: Redacted::new(
                entries
                    .iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect(),
            ),
        })
    }

    /// Publish `roots` as the current commit: Commit chunk with a
    /// correctly recomputed `tx_root_hash`, then a Superblock whose
    /// `root_hash` matches it. Steps 1-3 of `verify_integrity` pass by
    /// construction.
    fn publish(s: &mut Space<'_>, roots: Vec<IndexRoot>, seq: u64) {
        let tx_root_hash = CommitPayload::compute_tx_root_hash(&roots);
        let cp = CommitPayload {
            roots,
            tx_root_hash,
        };
        let cp_bytes = cp.encode().unwrap();
        let commit_slot = s.append_chunk(ChunkKind::Commit, seq, &cp_bytes).unwrap();
        let sb = Superblock {
            seq,
            root_slot: commit_slot,
            root_hash: tx_root_hash,
            checkpoint_slot: s.state.superblock.checkpoint_slot,
        };
        s.append_superblock(&sb).unwrap();
        s.state.superblock = sb;
        s.state.roots_payload_cache = None;
    }

    fn kv_root(ns: Namespace, slot: u64, hash: [u8; 32]) -> IndexRoot {
        IndexRoot {
            namespace: ns,
            kind: NamespaceKind::Kv,
            index_slot: slot,
            payload_hash: hash,
        }
    }

    fn integrity_detail(e: Error) -> &'static str {
        match e {
            Error::IntegrityFailure { detail, .. } => detail,
            other => panic!("expected IntegrityFailure, got {other:?}"),
        }
    }

    /// Positive control. The same forge machinery, used to build a
    /// *well-formed* two-leaf tree, must pass — otherwise the negative
    /// tests below would be green for the wrong reason (any forgery
    /// failing, rather than the specific gate firing).
    #[test]
    fn a_hand_built_well_formed_tree_verifies() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let ns = Namespace::SETTINGS;
        let (s0, h0) = seal_node(&mut s, &leaf(ns, &[(b"a", b"1"), (b"b", b"2")]), 1);
        let (s1, h1) = seal_node(&mut s, &leaf(ns, &[(b"m", b"3"), (b"z", b"4")]), 1);
        let internal = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![
                ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: s0,
                    child_hash: h0,
                },
                ChildPointer {
                    first_key: Redacted::new(b"m".to_vec()),
                    child_slot: s1,
                    child_hash: h1,
                },
            ],
        });
        let (root_slot, root_hash) = seal_node(&mut s, &internal, 1);
        publish(&mut s, vec![kv_root(ns, root_slot, root_hash)], 1);

        let report = s.verify_integrity().unwrap();
        assert_eq!(report.namespaces_verified, 1);
        // Commit + internal + two leaves.
        assert_eq!(report.chunks_verified, 4);
        assert_eq!(report.max_depth, 2);

        let _ = std::fs::remove_file(&path);
    }

    /// Two children naming the same `child_slot`: every hash matches,
    /// every node decodes, and the walk would re-read the same subtree
    /// once per pointer. At `MAX_TREE_DEPTH` with a full-width internal
    /// node that is `fanout^depth` reads out of a handful of chunks.
    #[test]
    fn two_children_naming_one_chunk_are_rejected() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let ns = Namespace::SETTINGS;
        let (s0, h0) = seal_node(&mut s, &leaf(ns, &[(b"a", b"1")]), 1);
        let internal = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![
                ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: s0,
                    child_hash: h0,
                },
                // Distinct first_key (decode rejects unsorted/equal),
                // same target chunk.
                ChildPointer {
                    first_key: Redacted::new(b"b".to_vec()),
                    child_slot: s0,
                    child_hash: h0,
                },
            ],
        });
        let (root_slot, root_hash) = seal_node(&mut s, &internal, 1);
        publish(&mut s, vec![kv_root(ns, root_slot, root_hash)], 1);

        let detail = integrity_detail(s.verify_integrity().unwrap_err());
        assert_eq!(detail, "chunk reachable more than once in one tree walk");

        let _ = std::fs::remove_file(&path);
    }

    /// Stack a chain of single-child Internal nodes `descents` deep over
    /// one leaf and publish it as `ns`'s root. Every link is
    /// Merkle-consistent, every node decodes, the key ranges tile
    /// correctly, and no slot repeats — the shape is a legal tree in
    /// every respect except how tall it is.
    fn publish_chain(s: &mut Space<'_>, ns: Namespace, descents: u8, seq: u64) {
        let (mut slot, mut hash) = seal_node(s, &leaf(ns, &[(b"a", b"1")]), seq);
        for _ in 0..descents {
            let node = IndexNode::Internal(InternalNode {
                namespace: ns,
                children: vec![ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: slot,
                    child_hash: hash,
                }],
            });
            (slot, hash) = seal_node(s, &node, seq);
        }
        publish(s, vec![kv_root(ns, slot, hash)], seq);
    }

    /// A tree deeper than the container could possibly hold. Every
    /// walker must name it and stop — not recurse until the stack
    /// overflows, and not read its way down a chain that could be as
    /// long as the file has chunks (audit HV-15).
    ///
    /// The bound is not a constant but what this space's chunk count
    /// could be arranged into, so this walks the boundary from both
    /// sides: at every depth, accepted if and only if the chunks are
    /// there for it. A dozen owned chunks cannot hold a three-descent
    /// tree; the identical forgery is accepted in
    /// [`the_same_chain_verifies_in_a_container_big_enough_for_it`],
    /// where the only difference is the container's size.
    #[test]
    fn a_chain_deeper_than_the_container_could_hold_is_rejected() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let ns = Namespace::SETTINGS;

        let mut saw_reject = false;
        for descents in 1..=5u8 {
            publish_chain(&mut s, ns, descents, u64::from(descents));
            let owned = s.audit_owned_chunk_count();
            let bound = super::super::walk::max_depth_for_budget(owned);

            if descents <= bound {
                s.verify_integrity().unwrap_or_else(|e| {
                    panic!("{descents} descents fit in {owned} chunks (bound {bound}): {e:?}")
                });
                assert_eq!(s.get(ns, b"a").unwrap().as_deref(), Some(&b"1"[..]));
                continue;
            }

            saw_reject = true;
            // One descent past the bound must already be refused —
            // this is the "near miss", not a chain of thousands.
            assert_eq!(
                descents,
                bound + 1,
                "walking the boundary one step at a time"
            );
            let detail = integrity_detail(s.verify_integrity().unwrap_err());
            assert_eq!(detail, "tree deeper than this space's chunk count can hold");
            // Every read path, not just the integrity walk: `get`
            // follows one path and would otherwise loop; `count` /
            // `list` recurse.
            for err in [
                s.get(ns, b"a").unwrap_err(),
                s.count(ns).unwrap_err(),
                s.list(ns).unwrap_err(),
                // The vacuum walk decides what to scrub; a chain it
                // cannot walk must abort the pass rather than declare
                // live chunks unreachable.
                s.vacuum_orphans().unwrap_err(),
            ] {
                assert!(
                    matches!(err, Error::Malformed(d) if d.contains("deeper than")),
                    "every walker must refuse the same shape, got {err:?}"
                );
            }
            break;
        }
        assert!(saw_reject, "a near-empty container must run out of depth");

        let _ = std::fs::remove_file(&path);
    }

    /// The control for the test above: the *same* forged chain, in a
    /// space that owns enough chunks for a tree that tall, verifies.
    ///
    /// This is what makes the bound a budget and not a magic number —
    /// what changed between the two tests is the container's size, and
    /// nothing else.
    #[test]
    fn the_same_chain_verifies_in_a_container_big_enough_for_it() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        // Real data, purely to make the space own enough chunks: a
        // three-descent tree needs at least 161 of them.
        let mut tx = s.begin_tx();
        for i in 0..8000u32 {
            tx.put(Namespace::MEDIA, format!("k{i:08}").as_bytes(), &[b'v'; 64])
                .unwrap();
        }
        tx.commit().unwrap();

        let ns = Namespace::SETTINGS;
        let descents = 3u8;
        let seq = s.state.superblock.seq + 1;
        publish_chain(&mut s, ns, descents, seq);

        let owned = s.audit_owned_chunk_count();
        let bound = super::super::walk::max_depth_for_budget(owned);
        assert!(
            descents <= bound,
            "{owned} owned chunks should permit {descents} descents, got {bound}"
        );

        let report = s.verify_integrity().unwrap();
        assert_eq!(report.max_depth, descents + 1, "levels = descents + 1");
        assert_eq!(s.get(ns, b"a").unwrap().as_deref(), Some(&b"1"[..]));
        assert_eq!(s.count(ns).unwrap(), 1);

        let _ = std::fs::remove_file(&path);
    }

    /// Two `IndexRoot`s of different namespaces pointing at one chunk.
    /// The namespace cross-check would catch the second descent, but
    /// only after paying for it; the guard rejects the aliasing itself.
    #[test]
    fn two_namespaces_naming_one_chunk_are_rejected() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let ns = Namespace::SETTINGS;
        let (s0, h0) = seal_node(&mut s, &leaf(ns, &[(b"a", b"1")]), 1);
        publish(
            &mut s,
            vec![kv_root(ns, s0, h0), kv_root(Namespace::CONTACTS, s0, h0)],
            1,
        );

        let detail = integrity_detail(s.verify_integrity().unwrap_err());
        assert_eq!(detail, "chunk reachable more than once in one tree walk");

        let _ = std::fs::remove_file(&path);
    }

    /// Sibling leaves whose key ranges overlap. Leaf 0 spans `a..m`
    /// while its parent promised `[a, c)`; `Space::get(b"m")` descends
    /// into child 1 (whose `first_key` is `c`) and finds nothing, so
    /// the entry is stored but unreachable — and the next commit's
    /// `flatten_tree` gate would reject the namespace outright. Every
    /// hash in this container matches.
    #[test]
    fn overlapping_sibling_key_ranges_are_rejected() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let ns = Namespace::SETTINGS;
        let (s0, h0) = seal_node(&mut s, &leaf(ns, &[(b"a", b"1"), (b"m", b"2")]), 1);
        let (s1, h1) = seal_node(&mut s, &leaf(ns, &[(b"c", b"3"), (b"z", b"4")]), 1);
        let internal = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![
                ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: s0,
                    child_hash: h0,
                },
                ChildPointer {
                    first_key: Redacted::new(b"c".to_vec()),
                    child_slot: s1,
                    child_hash: h1,
                },
            ],
        });
        let (root_slot, root_hash) = seal_node(&mut s, &internal, 1);
        publish(&mut s, vec![kv_root(ns, root_slot, root_hash)], 1);

        // Pre-gate, this container verified clean. Show the damage is
        // real while we are here: the stored entry is unreachable.
        assert_eq!(s.get(ns, b"m").unwrap(), None);

        let detail = integrity_detail(s.verify_integrity().unwrap_err());
        assert_eq!(detail, "leaf key at or above the range its parent promised");

        let _ = std::fs::remove_file(&path);
    }

    /// The boundary case of the same check: a leaf whose last key is
    /// exactly its sibling's `first_key`. The upper bound is exclusive
    /// — the key belongs to the sibling — so this is one duplicated key
    /// across two leaves, precisely what `flatten_tree`'s
    /// global-sortedness gate rejects at the next commit. A check
    /// written with `>` instead of `>=` would wave it through.
    #[test]
    fn a_leaf_key_exactly_on_the_sibling_boundary_is_rejected() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let ns = Namespace::SETTINGS;
        let (s0, h0) = seal_node(&mut s, &leaf(ns, &[(b"a", b"1"), (b"c", b"2")]), 1);
        let (s1, h1) = seal_node(&mut s, &leaf(ns, &[(b"c", b"3"), (b"z", b"4")]), 1);
        let internal = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![
                ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: s0,
                    child_hash: h0,
                },
                ChildPointer {
                    first_key: Redacted::new(b"c".to_vec()),
                    child_slot: s1,
                    child_hash: h1,
                },
            ],
        });
        let (root_slot, root_hash) = seal_node(&mut s, &internal, 1);
        publish(&mut s, vec![kv_root(ns, root_slot, root_hash)], 1);

        let detail = integrity_detail(s.verify_integrity().unwrap_err());
        assert_eq!(detail, "leaf key at or above the range its parent promised");

        let _ = std::fs::remove_file(&path);
    }

    /// A leaf holding keys below the `first_key` its parent advertised
    /// for it — the other half of the range check, and equally
    /// unreachable through `get`.
    #[test]
    fn a_leaf_under_its_promised_lower_bound_is_rejected() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let ns = Namespace::SETTINGS;
        let (s0, h0) = seal_node(&mut s, &leaf(ns, &[(b"a", b"1")]), 1);
        let (s1, h1) = seal_node(&mut s, &leaf(ns, &[(b"b", b"2")]), 1);
        let internal = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![
                ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: s0,
                    child_hash: h0,
                },
                // Claims to start at "m"; actually holds "b".
                ChildPointer {
                    first_key: Redacted::new(b"m".to_vec()),
                    child_slot: s1,
                    child_hash: h1,
                },
            ],
        });
        let (root_slot, root_hash) = seal_node(&mut s, &internal, 1);
        publish(&mut s, vec![kv_root(ns, root_slot, root_hash)], 1);

        assert_eq!(s.get(ns, b"b").unwrap(), None);

        let detail = integrity_detail(s.verify_integrity().unwrap_err());
        assert_eq!(detail, "leaf key below the range its parent promised");

        let _ = std::fs::remove_file(&path);
    }

    /// Ranges are checked at internal nodes too, not only at leaves: a
    /// grandchild pointer that escapes the span its grandparent
    /// promised is caught at the node that declares it.
    #[test]
    fn an_internal_child_outside_its_promised_range_is_rejected() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let ns = Namespace::SETTINGS;
        let (l0, lh0) = seal_node(&mut s, &leaf(ns, &[(b"a", b"1")]), 1);
        let (l1, lh1) = seal_node(&mut s, &leaf(ns, &[(b"q", b"2")]), 1);
        let (l2, lh2) = seal_node(&mut s, &leaf(ns, &[(b"m", b"3")]), 1);

        // Mid level: the root gives it [a, m), but its second child
        // advertises first_key "m" — landing exactly on the boundary,
        // i.e. inside its sibling's range. The bound is exclusive, so
        // this is the tightest violation the check must still catch.
        let mid = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![
                ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: l0,
                    child_hash: lh0,
                },
                ChildPointer {
                    first_key: Redacted::new(b"m".to_vec()),
                    child_slot: l2,
                    child_hash: lh2,
                },
            ],
        });
        let (mid_slot, mid_hash) = seal_node(&mut s, &mid, 1);

        let root = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![
                ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: mid_slot,
                    child_hash: mid_hash,
                },
                ChildPointer {
                    first_key: Redacted::new(b"m".to_vec()),
                    child_slot: l1,
                    child_hash: lh1,
                },
            ],
        });
        let (root_slot, root_hash) = seal_node(&mut s, &root, 1);
        publish(&mut s, vec![kv_root(ns, root_slot, root_hash)], 1);

        let detail = integrity_detail(s.verify_integrity().unwrap_err());
        assert_eq!(
            detail,
            "internal child first_key at or above the range its parent promised"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The internal node's *lower*-bound check, which no leaf check can
    /// stand in for: a child's promised lower bound is its own
    /// `first_key`, so a mid-level node that starts below the span its
    /// parent gave it hands every leaf underneath a bound those leaves
    /// satisfy. Only comparing the node's own first `first_key` against
    /// the inherited bound catches it — and the entry really is
    /// unreachable, as the `get` below shows.
    #[test]
    fn an_internal_node_starting_below_its_promised_range_is_rejected() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let ns = Namespace::SETTINGS;
        let (l0, lh0) = seal_node(&mut s, &leaf(ns, &[(b"a", b"1")]), 1);
        let (l1, lh1) = seal_node(&mut s, &leaf(ns, &[(b"b", b"2")]), 1);

        // Mid node claims to start at "b"; the root placed it at "m".
        let mid = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![ChildPointer {
                first_key: Redacted::new(b"b".to_vec()),
                child_slot: l1,
                child_hash: lh1,
            }],
        });
        let (mid_slot, mid_hash) = seal_node(&mut s, &mid, 1);

        let root = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![
                ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: l0,
                    child_hash: lh0,
                },
                ChildPointer {
                    first_key: Redacted::new(b"m".to_vec()),
                    child_slot: mid_slot,
                    child_hash: mid_hash,
                },
            ],
        });
        let (root_slot, root_hash) = seal_node(&mut s, &root, 1);
        publish(&mut s, vec![kv_root(ns, root_slot, root_hash)], 1);

        assert_eq!(s.get(ns, b"b").unwrap(), None);

        let detail = integrity_detail(s.verify_integrity().unwrap_err());
        assert_eq!(
            detail,
            "internal child first_key below the range its parent promised"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// The guard is not the integrity walk's alone. `list` / `count` /
    /// the `iter_log_*` family / `vacuum_orphans` follow the very same
    /// pointers with no Merkle check at all, so on a DAG they paid the
    /// same amplification — and `iter_log_*`'s `limit` does not help,
    /// since it bounds the output rather than the chunk reads. All of
    /// them must refuse the shape.
    #[test]
    fn every_walker_refuses_a_dag_not_just_the_integrity_walk() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        // Log namespace, so the `iter_log_*` walkers are exercised on
        // the same forged tree as `list` / `count`.
        let ns = Namespace::MESSAGE_LOG;
        let entry = (
            super::super::log::log_id_key(1).to_vec(),
            super::super::log::encode_batch_slot_value(0).to_vec(),
        );
        let (l0, lh0) = seal_node(
            &mut s,
            &IndexNode::Leaf(LeafNode {
                namespace: ns,
                entries: Redacted::new(vec![entry]),
            }),
            1,
        );
        let internal = IndexNode::Internal(InternalNode {
            namespace: ns,
            children: vec![
                ChildPointer {
                    first_key: Redacted::new(b"a".to_vec()),
                    child_slot: l0,
                    child_hash: lh0,
                },
                ChildPointer {
                    first_key: Redacted::new(b"b".to_vec()),
                    child_slot: l0,
                    child_hash: lh0,
                },
            ],
        });
        let (root_slot, root_hash) = seal_node(&mut s, &internal, 1);
        publish(
            &mut s,
            vec![IndexRoot {
                namespace: ns,
                kind: NamespaceKind::Log,
                index_slot: root_slot,
                payload_hash: root_hash,
            }],
            1,
        );

        let aliased = |e: Error| match e {
            Error::Malformed(m) => assert_eq!(m, "chunk reachable more than once in one tree walk"),
            other => panic!("expected Malformed, got {other:?}"),
        };
        aliased(s.list(ns).unwrap_err());
        aliased(s.count(ns).unwrap_err());
        // A limit above what the tree can yield, so the walkers do not
        // stop at the first child and miss the second pointer — the
        // very reason `limit` is not a bound on chunk reads.
        aliased(s.iter_log_after(ns, None, 10).unwrap_err());
        aliased(s.iter_log_before(ns, None, 10).unwrap_err());
        aliased(s.iter_log_range(ns, None, None, 10).unwrap_err());
        aliased(s.vacuum_orphans().unwrap_err());

        let _ = std::fs::remove_file(&path);
    }

    /// A log namespace whose leaf pointer names an IndexNode chunk of
    /// the tree that was just walked. The batch pass shares the tree
    /// walk's guard, so the reuse is reported as aliasing rather than
    /// being read a second time.
    #[test]
    fn a_log_pointer_aliasing_an_index_chunk_is_rejected() {
        let path = scratch_path();
        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();

        let ns = Namespace::MESSAGE_LOG;
        // Slot the leaf will land on, so it can point at itself.
        let self_slot = s.file.slot_count();
        let node = IndexNode::Leaf(LeafNode {
            namespace: ns,
            entries: Redacted::new(vec![(
                super::super::log::log_id_key(7).to_vec(),
                super::super::log::encode_batch_slot_value(self_slot).to_vec(),
            )]),
        });
        let (slot, hash) = seal_node(&mut s, &node, 1);
        assert_eq!(slot, self_slot, "leaf must land on the slot it names");
        publish(
            &mut s,
            vec![IndexRoot {
                namespace: ns,
                kind: NamespaceKind::Log,
                index_slot: slot,
                payload_hash: hash,
            }],
            1,
        );

        let detail = integrity_detail(s.verify_integrity().unwrap_err());
        assert_eq!(detail, "chunk reachable more than once in one tree walk");

        let _ = std::fs::remove_file(&path);
    }
}
