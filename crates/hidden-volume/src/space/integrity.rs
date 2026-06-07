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
use super::log::{decode_batch, parse_batch_slot_value};
use super::superblock::NO_RECORD;

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
    /// hundred chunk reads, milliseconds total.
    ///
    /// **Read-only safe.** No writes occur; this method works on a
    /// handle returned by [`crate::Container::open_readonly`].
    ///
    /// **Returns** an [`IntegrityReport`] on success; the first
    /// detected mismatch raises [`Error::IntegrityFailure`].
    pub fn verify_integrity(&mut self) -> Result<IntegrityReport> {
        let mut report = IntegrityReport {
            namespaces_verified: 0,
            chunks_verified: 0,
            max_depth: 0,
            data_batches_verified: 0,
        };

        // Empty space — superblock points at NO_RECORD; nothing to verify.
        if self.state.superblock.root_slot == NO_RECORD {
            return Ok(report);
        }

        // 1. Read CommitPayload from Superblock.root_slot.
        let commit_slot = self.state.superblock.root_slot;
        let pt = self.read_chunk_for_verify(commit_slot, "owned-chunk AEAD failure on Commit")?;
        if pt.kind != ChunkKind::Commit {
            return Err(Error::IntegrityFailure {
                detail: "Superblock root_slot points at non-Commit chunk",
                slot: commit_slot,
            });
        }
        report.chunks_verified += 1;
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
        //    For Log roots, additionally walk every leaf entry's
        //    referenced `DataBatch` chunk (audit M2, 2026-05-10).
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
                root.index_slot,
                root.payload_hash,
                root.namespace,
                1,
                &mut report,
            )?;
            if depth > report.max_depth {
                report.max_depth = depth;
            }
            if matches!(root.kind, NamespaceKind::Log) {
                self.verify_log_data_batches(root.index_slot, &mut report)?;
            }
            report.namespaces_verified += 1;
        }

        Ok(report)
    }

    /// For a Log namespace rooted at `root_slot`, walk every leaf entry
    /// and AEAD-decrypt + decode the referenced `DataBatch` chunk. This
    /// closes the M2 audit gap: prior to 2026-05-10 the Merkle walk
    /// stopped at Leaf nodes, so a corrupted DataBatch chunk passed
    /// `verify_integrity` and only failed later at `read_log` time.
    ///
    /// Algorithm:
    ///   1. Collect every leaf-entry's value (8-byte LE batch_slot).
    ///   2. Deduplicate slots — multiple log entries can point at the
    ///      same DataBatch (one batch packs many records).
    ///   3. For each unique slot: AEAD-decrypt, kind-check, decode.
    ///
    /// Cost: O(unique_batch_slots), bounded by the namespace's owned
    /// chunk count. Same per-chunk cost as the IndexNode walk above.
    fn verify_log_data_batches(
        &mut self,
        root_slot: u64,
        report: &mut IntegrityReport,
    ) -> Result<()> {
        let mut batch_slots = Vec::new();
        self.collect_log_batch_slots(root_slot, &mut batch_slots)?;
        // Dedup: many log entries can fit in one DataBatch chunk; verify
        // each unique slot once.
        batch_slots.sort_unstable();
        batch_slots.dedup();

        for slot in batch_slots {
            let pt = self.read_chunk_for_verify(slot, "owned-chunk AEAD failure on DataBatch")?;
            if pt.kind != ChunkKind::DataBatch {
                return Err(Error::IntegrityFailure {
                    detail: "Log leaf entry references chunk that is not DataBatch",
                    slot,
                });
            }
            decode_batch(&pt.payload).map_err(|_| Error::IntegrityFailure {
                detail: "DataBatch decode failed during integrity walk",
                slot,
            })?;
            report.data_batches_verified += 1;
        }
        Ok(())
    }

    /// Walk subtree rooted at `slot`, accumulating every leaf-entry's
    /// 8-byte LE-encoded batch_slot pointer. Caller dedups.
    /// Depth-capped via [`super::index::MAX_TREE_DEPTH`].
    fn collect_log_batch_slots(&mut self, slot: u64, out: &mut Vec<u64>) -> Result<()> {
        self.collect_log_batch_slots_at(slot, 0, out)
    }

    fn collect_log_batch_slots_at(
        &mut self,
        slot: u64,
        depth: u8,
        out: &mut Vec<u64>,
    ) -> Result<()> {
        if depth > super::index::MAX_TREE_DEPTH {
            return Err(Error::IntegrityFailure {
                detail: "tree depth exceeded MAX_TREE_DEPTH",
                slot,
            });
        }
        let pt = self.read_chunk_for_verify(slot, "owned-chunk AEAD failure on IndexNode")?;
        if pt.kind != ChunkKind::IndexNode {
            return Err(Error::IntegrityFailure {
                detail: "expected IndexNode chunk during log batch-slot walk",
                slot,
            });
        }
        let node = IndexNode::decode(&pt.payload).map_err(|_| Error::IntegrityFailure {
            detail: "IndexNode decode failed during log batch-slot walk",
            slot,
        })?;
        match node {
            IndexNode::Leaf(leaf) => {
                for (_key, value) in leaf.entries {
                    let batch_slot =
                        parse_batch_slot_value(&value).map_err(|_| Error::IntegrityFailure {
                            detail: "log leaf entry value not 8 bytes (batch_slot)",
                            slot,
                        })?;
                    out.push(batch_slot);
                }
            },
            IndexNode::Internal(internal) => {
                for child in internal.children {
                    self.collect_log_batch_slots_at(child.child_slot, depth + 1, out)?;
                }
            },
        }
        Ok(())
    }

    /// Read a chunk at `slot` that we expect to own; map AEAD failure
    /// onto [`Error::IntegrityFailure`] (the integrity walk's contract
    /// is "AEAD-fail on a chunk we expected to own = corruption").
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

    /// Recursively verify the IndexNode at `slot` and its children,
    /// returning the maximum depth observed (1 = leaf, 2 = internal+leaves).
    /// Depth-capped via [`super::index::MAX_TREE_DEPTH`] — although the
    /// Merkle hash chain makes adversarial cycles cryptographically
    /// infeasible here, the cap matches the non-verify walkers for
    /// defense-in-depth consistency.
    ///
    /// `expected_namespace` is the namespace byte declared by the
    /// `IndexRoot` we descended from. Every `IndexNode` chunk in the
    /// subtree MUST carry the same namespace; a mismatch is an
    /// integrity failure (a key-holder / buggy writer could otherwise
    /// "relabel" an IndexRoot to point at an IndexNode tree that
    /// physically belongs to another namespace — Merkle hash still
    /// passed before this gate because `payload_hash` covers the
    /// encoded bytes including the namespace byte, but a relabel on
    /// the IndexRoot side is undetected without this cross-check).
    fn verify_subtree(
        &mut self,
        slot: u64,
        expected_hash: [u8; 32],
        expected_namespace: Namespace,
        depth_so_far: u8,
        report: &mut IntegrityReport,
    ) -> Result<u8> {
        if depth_so_far > super::index::MAX_TREE_DEPTH {
            return Err(Error::IntegrityFailure {
                detail: "tree depth exceeded MAX_TREE_DEPTH",
                slot,
            });
        }
        let pt = self.read_chunk_for_verify(slot, "owned-chunk AEAD failure on IndexNode")?;
        if pt.kind != ChunkKind::IndexNode {
            return Err(Error::IntegrityFailure {
                detail: "expected IndexNode chunk; found different kind",
                slot,
            });
        }
        let actual = blake3_of(&pt.payload);
        if actual != expected_hash {
            return Err(Error::IntegrityFailure {
                detail: "IndexNode chunk hash != parent's recorded hash",
                slot,
            });
        }
        report.chunks_verified += 1;

        let node = IndexNode::decode(&pt.payload).map_err(|_| Error::IntegrityFailure {
            detail: "IndexNode decode failed during integrity walk",
            slot,
        })?;

        // Cross-check the namespace byte: the IndexNode must claim
        // the same namespace the IndexRoot pointed at. Closes the
        // root-relabel attack (audit pass 19 round 6 user-report
        // 2026-05-28).
        let node_ns = match &node {
            IndexNode::Leaf(l) => l.namespace,
            IndexNode::Internal(i) => i.namespace,
        };
        if node_ns != expected_namespace {
            return Err(Error::IntegrityFailure {
                detail: "IndexNode.namespace != IndexRoot.namespace",
                slot,
            });
        }

        match node {
            IndexNode::Leaf(_) => Ok(depth_so_far),
            IndexNode::Internal(inner) => {
                let mut max_child_depth = depth_so_far;
                for child in inner.children {
                    let child_depth = self.verify_subtree(
                        child.child_slot,
                        child.child_hash,
                        expected_namespace,
                        depth_so_far + 1,
                        report,
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
