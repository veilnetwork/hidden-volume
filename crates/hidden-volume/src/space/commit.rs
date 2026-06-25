//! Tx commit logic: the 3-fsync protocol that promotes a Tx's
//! pending operations into a new on-disk commit. Audit pass 8 (E7)
//! split out of `space/mod.rs` so the commit path (the most
//! security-sensitive write code in the crate) is reviewable as a
//! self-contained ~280-LOC chunk.

use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::chunk::ChunkKind;
use crate::tx::KvOp;
use crate::tx::commit::{CommitPayload, IndexRoot, blake3_of};
use crate::{Error, Result};

use super::Space;
use super::index::{ChildPointer, InternalNode, LeafNode, Namespace};
use super::log;
use super::superblock::Superblock;

impl<'f> Space<'f> {
    /// Apply a Tx's pending KV + log operations and run the 3-fsync
    /// commit protocol. See [`crate::tx`] for the protocol details.
    ///
    /// commit_tx is append-only — it never scrubs. Within a single
    /// open session, old IndexNode chunks from previous commits
    /// remain on disk as in-flight-commit recovery fallbacks. They
    /// are scrubbed automatically by the next call to
    /// [`Container::open_space`] via [`Space::vacuum_orphans`], so
    /// **across application restarts those fallbacks are gone** —
    /// cross-launch rollback / fork detection works through the
    /// multi-Superblock-replicas path
    /// ([`Space::commit_history`]), not through orphan IndexNode
    /// preservation. (Audit pass 7 C3 — clarification.)
    ///
    /// **Post-failure state (audit pass 7 C4).** If `commit_tx`
    /// returns `Err`, some chunks may have been appended to the
    /// file and `state.owned_slots` extended before the failing
    /// step. `state.superblock` is **unchanged** (we only swap it
    /// after the final fsync). The next [`Space::vacuum_orphans`]
    /// reclaims orphan IndexNode chunks. **Orphan DataBatch chunks
    /// from a failed Phase 0 are NOT cleaned by `vacuum_orphans`**;
    /// run [`Space::vacuum_data_batches`] explicitly after a
    /// commit-fail to close the forward-secrecy gap (audit pass 7
    /// D1).
    ///
    /// **Padding-step failure (audit M1, 2026-05-10).** Once the
    /// superblock fsync (the durable-publish moment) succeeds, this
    /// function returns `Ok(seq)` regardless of whether the
    /// post-commit padding step succeeds or fails. A padding failure
    /// is recorded on [`SpaceState::last_padding_error`] for caller
    /// introspection but does not downgrade the durable commit into
    /// an apparent failure — that would lie about visibility of the
    /// commit to other processes (other processes already see the
    /// new superblock). Padding is a privacy hardening, not a
    /// correctness invariant; a single skipped padding round only
    /// makes that commit's size observable to a multi-snapshot
    /// adversary.
    pub(crate) fn commit_tx(
        &mut self,
        mut pending: BTreeMap<u8, Vec<KvOp>>,
        pending_log: BTreeMap<u8, Vec<(u64, Vec<u8>)>>,
    ) -> Result<u64> {
        // Audit pass 7 (C1): if both pending maps are empty, the
        // commit is a no-op. Previously commit_tx unconditionally
        // bumped seq, wrote a Commit chunk + Superblock replicas,
        // and ran 3 fsyncs — contradicting `Tx::is_empty`'s doc and
        // wasting disk + adding a multi-snapshot writer-active
        // signal. Early-return the current seq instead.
        if pending.values().all(|ops| ops.is_empty())
            && pending_log.values().all(|recs| recs.is_empty())
        {
            return Ok(self.state.superblock.seq);
        }

        // Audit pass 11 (L3): defensive `checked_add`. Practically
        // unreachable through honest use (would require `u64::MAX`
        // commits), but a malformed AEAD-valid Superblock could push
        // `seq` to `u64::MAX` and crash a subsequent commit on
        // overflow. Convert to an explicit `Error::Internal` instead.
        let new_seq = self
            .state
            .superblock
            .seq
            .checked_add(1)
            .ok_or(Error::Internal("commit seq overflow"))?;

        // R-NSKIND: validate kind consistency upfront. A namespace
        // that already has a prior IndexRoot must keep its kind;
        // touching it with the wrong kind in this Tx is a
        // `WrongNamespaceKind` error before we write a single chunk.
        // A namespace that's both in `pending` (KV ops) AND
        // `pending_log` is also rejected — `Tx` already enforces
        // single-kind-per-Tx, this is a defense-in-depth safety net.
        let prior_roots_by_ns: std::collections::BTreeMap<u8, IndexRoot> = self
            .load_prior_roots()?
            .into_iter()
            .map(|r| (r.namespace.0, r))
            .collect();

        for (ns, ops) in &pending {
            if pending_log.contains_key(ns) {
                return Err(Error::WrongNamespaceKind(
                    "namespace touched as both Kv and Log in one Tx",
                ));
            }
            // Pure-Delete op sets are allowed against a Log namespace
            // because they cannot introduce mixed-kind state (no new
            // entries, only removal). This is the path
            // `Space::erase_namespace` uses to clear a Log namespace
            // via `delete_internal`. Anything else (any `Put`) is
            // a true Kv-on-Log violation.
            if let Some(prior) = prior_roots_by_ns.get(ns)
                && prior.kind != crate::tx::NamespaceKind::Kv
                && ops.iter().any(|op| matches!(op, KvOp::Put { .. }))
            {
                return Err(Error::WrongNamespaceKind(
                    "Kv Put op against existing Log namespace",
                ));
            }
        }
        for ns in pending_log.keys() {
            if let Some(prior) = prior_roots_by_ns.get(ns)
                && prior.kind != crate::tx::NamespaceKind::Log
            {
                return Err(Error::WrongNamespaceKind(
                    "Log op against existing Kv namespace",
                ));
            }
        }

        // Audit pass 11 (L2): the resulting active root set is
        // `prior_roots ∪ pending` (not just `pending`) — `Tx`
        // already rejects `pending.len() > MAX_NAMESPACES_PER_TX`
        // via `check_namespace_capacity`, but a near-capacity space
        // could still cross the limit when prior untouched roots
        // are carried forward. Compute the union upfront and reject
        // BEFORE writing any chunk; previously the failure surfaced
        // late inside `CommitPayload::encode` as `Error::Internal`
        // with orphan chunks already on disk.
        //
        // The union is an **upper bound** on the resulting active
        // root count, not the exact value. A pending namespace that
        // ends up empty after applying ops (e.g. all-deletes) is
        // dropped from `new_roots` later (search for `entries.is_empty()`).
        // Rejecting on the upper bound is conservative: it can fail
        // a Tx that would have squeezed in just under the limit. The
        // host-app remedy is to split the Tx; the trade-off is that
        // every chunk write is preceded by a guaranteed-safe check.
        {
            let mut union: std::collections::BTreeSet<u8> =
                prior_roots_by_ns.keys().copied().collect();
            for ns in pending.keys() {
                union.insert(*ns);
            }
            for ns in pending_log.keys() {
                union.insert(*ns);
            }
            if union.len() > crate::tx::MAX_NAMESPACES_PER_TX {
                return Err(Error::TooManyNamespaces {
                    limit: crate::tx::MAX_NAMESPACES_PER_TX,
                });
            }
        }

        // Build the kind register for this Tx: Log for namespaces
        // touched by `pending_log`, otherwise inherit from prior root,
        // otherwise default Kv. This drives the `kind` field of every
        // new IndexRoot emitted below.
        let log_namespaces: std::collections::BTreeSet<u8> = pending_log.keys().copied().collect();
        let kind_for_namespace = |ns: u8| -> crate::tx::NamespaceKind {
            if log_namespaces.contains(&ns) {
                return crate::tx::NamespaceKind::Log;
            }
            if let Some(prior) = prior_roots_by_ns.get(&ns) {
                return prior.kind;
            }
            crate::tx::NamespaceKind::Kv
        };

        let slots_before = self.file.slot_count();

        // Phase 0: Flush each non-empty log buffer to a DataBatch chunk,
        // then route resulting batch_slot pointers as KV puts. After
        // this, the rest of commit_tx is the same KV-only flow.
        for (ns_byte, log_records) in pending_log {
            if log_records.is_empty() {
                continue;
            }
            // Coalesce duplicate log_ids — last append wins (matches
            // KV semantics for repeated puts in one tx). Use a BTreeMap
            // keyed by log_id; later inserts overwrite earlier ones.
            let mut by_id: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            for (id, payload) in log_records {
                by_id.insert(id, payload);
            }
            let log_records: Vec<(u64, Vec<u8>)> = by_id.into_iter().collect();

            // Auto-split into 1+ DataBatch chunks if the compressed
            // payload of the full record set would exceed PAYLOAD_CAP.
            // Common case (records compress well, ≤ ~150 messages):
            // exactly one batch, one zstd call.
            let batches = log::encode_batches_split(&log_records)?;

            let kv_ops = pending.entry(ns_byte).or_default();
            for (log_ids, batch_bytes) in batches {
                let batch_slot = self.append_chunk(ChunkKind::DataBatch, new_seq, &batch_bytes)?;
                for log_id in log_ids {
                    kv_ops.push(KvOp::Put {
                        key: log::log_id_key(log_id).to_vec(),
                        value: log::encode_batch_slot_value(batch_slot).to_vec(),
                    });
                }
            }
        }

        // 1. For each touched namespace, build the new tree and emit
        //    chunks (potentially multiple if leaf splits).
        let mut new_roots: Vec<IndexRoot> = Vec::new();

        // Carry forward untouched prior roots (kind preserved verbatim).
        for prior in prior_roots_by_ns.values() {
            if !pending.contains_key(&prior.namespace.0) {
                new_roots.push(*prior);
            }
        }

        for (ns_byte, ops) in &pending {
            let ns = Namespace(*ns_byte);
            // Load the entire tree's current entries into a flat sorted vec,
            // apply ops, then rebuild the tree from scratch. This is
            // simpler than path-tracking incremental updates and is
            // fine at the namespace sizes we target (≤ ~10K entries).
            let mut entries = match prior_roots_by_ns.get(ns_byte) {
                Some(r) => self.flatten_tree(r.index_slot, ns)?,
                None => Vec::new(),
            };

            for op in ops {
                apply_op_to_sorted(&mut entries, op);
            }

            if entries.is_empty() {
                // Empty namespace → omit from new Commit.
                continue;
            }

            let (root_slot, root_hash) = self.write_tree_for_namespace(ns, &entries, new_seq)?;
            new_roots.push(IndexRoot {
                namespace: ns,
                kind: kind_for_namespace(*ns_byte),
                index_slot: root_slot,
                payload_hash: root_hash,
            });
        }

        new_roots.sort_by_key(|r| r.namespace.0);

        self.file.fsync()?;

        // 2. Commit chunk.
        let tx_root_hash = CommitPayload::compute_tx_root_hash(&new_roots);
        let cp = CommitPayload {
            roots: new_roots,
            tx_root_hash,
        };
        let cp_bytes = cp.encode()?;
        let commit_slot = self.append_chunk(ChunkKind::Commit, new_seq, &cp_bytes)?;
        self.file.fsync()?;

        // 3. New Superblock — at this point the new commit is visible
        // and a crash here-or-later leaves the user with the new state.
        // Multiple replicas for resilience to torn writes / single-chunk
        // corruption (DESIGN §7). Recovery picks any readable replica
        // at max seq.
        let new_sb = Superblock {
            seq: new_seq,
            root_slot: commit_slot,
            root_hash: tx_root_hash,
            // Carry the checkpoint pointer forward verbatim. The commit
            // path never mints or moves a checkpoint (that is the
            // open-scan self-heal writer's job); copying the existing
            // pointer into the superblock we are already writing keeps
            // the latest superblock pointing at the live checkpoint at
            // zero extra disk cost. Defaults to NO_RECORD until the
            // first self-heal writes a checkpoint.
            checkpoint_slot: self.state.superblock.checkpoint_slot,
        };
        let replicas = self.file.superblock_replicas.max(1);
        for _ in 0..replicas {
            self.append_superblock(&new_sb)?;
        }
        self.file.fsync()?;

        self.state.superblock = new_sb;
        // The prior commit era's cached roots payload is now stale — drop it so
        // its decrypted bytes are zeroized promptly (rather than lingering until
        // the next `load_prior_roots` replaces it), and so the next read decodes
        // the fresh era. The `seq` gate in `load_prior_roots` is the correctness
        // backstop; this clear is the memory-hygiene half.
        self.state.roots_payload_cache = None;
        // new_seq is strictly greater than every prior entry (commit_tx
        // monotonically increments seq), so push preserves sort order
        // and uniqueness of `commit_history` without re-sorting.
        self.state.commit_history.push(new_seq);

        // Post-commit padding (DESIGN §8): mask per-commit file size
        // growth from a multi-snapshot adversary. Garbage chunks are
        // uniform random — visually identical to AEAD-encrypted chunks.
        //
        // **M1 hardening (audit 2026-05-10).** The superblock fsync
        // above makes the commit durable and visible to
        // other processes; from that moment on, `new_seq` is the
        // canonical commit_seq for the space. Any failure in this
        // padding block must NOT downgrade that visible success into
        // an `Err` return — that would lie to the caller about
        // durability (host-app would retry the commit, double-write,
        // or corrupt its sync state). We therefore catch padding
        // failures, stash them on `state.last_padding_error` for
        // introspection, and still return `Ok(new_seq)`. Padding is
        // a privacy hardening (mask file-size growth from a
        // multi-snapshot adversary), not a correctness invariant —
        // a single missed padding round just means this one commit's
        // size is observable, not that data is lost.
        let real_added = self.file.slot_count() - slots_before;
        let padding_outcome = self
            .file
            .padding_policy
            .garbage_after_commit(self.file.slot_count(), real_added)
            .and_then(|pad_count| {
                if pad_count > 0 {
                    self.file.append_garbage_chunks(pad_count)?;
                    self.file.fsync()?;
                }
                Ok(())
            });
        // Replace (don't merge) — `last_padding_error` reflects only
        // the most recent commit's padding outcome. A successful
        // padding round clears any previously-stuck error.
        self.state.last_padding_error = padding_outcome.err();

        Ok(new_seq)
    }

    /// Read all entries of a namespace's tree into a flat sorted Vec.
    /// Used during commit_tx to load the prior state before applying ops.
    fn flatten_tree(
        &mut self,
        root_slot: u64,
        namespace: Namespace,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        self.collect_leaves(root_slot, namespace, &mut out)?;
        // Per-node decode only checks intra-leaf order; the *global*
        // (cross-leaf) order is an assumption the rest of the commit
        // path relies on (`apply_op_to_sorted` binary-searches the
        // flattened vec, and `LeafNode::encode` only `debug_assert`s
        // sortedness in release). A key-holder / buggy writer can
        // craft a tree whose child `first_key`s are sorted but whose
        // leaf ranges overlap — that would silently produce an
        // unsorted commit, bricking the namespace on the next read.
        // Reject it here (audit pass 20).
        if out.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(Error::Malformed(
                "tree leaves are not globally sorted / contain duplicate keys",
            ));
        }
        Ok(out)
    }

    /// Build a tree from a sorted entries vec and write all its chunks.
    /// Returns the root slot + hash.
    ///
    /// Strategy:
    /// 1. Try to fit everything in a single Leaf — emits one chunk.
    /// 2. If overflow, split into multiple Leaves and emit one Internal
    ///    node above them.
    /// 3. If the Internal node would overflow → Error::IndexFull.
    fn write_tree_for_namespace(
        &mut self,
        ns: Namespace,
        entries: &[(Vec<u8>, Vec<u8>)],
        new_seq: u64,
    ) -> Result<(u64, [u8; 32])> {
        // Try single-leaf first.
        let single = LeafNode {
            namespace: ns,
            entries: entries.to_vec(),
        };
        if let Ok(bytes) = single.encode() {
            // Encoded leaf carries user KV bytes; scrub on drop.
            let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(bytes);
            let slot = self.append_chunk(ChunkKind::IndexNode, new_seq, &bytes)?;
            return Ok((slot, blake3_of(&bytes)));
        }

        // Need to split. Pack greedily into leaves that each fit.
        let leaves = pack_into_leaves(ns, entries)?;
        if leaves.is_empty() {
            return Err(Error::Internal("pack_into_leaves returned empty"));
        }

        // Emit each leaf as a chunk and collect ChildPointers for the
        // Internal root.
        let mut children = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            let first_key = leaf.entries[0].0.clone();
            // Encoded leaf carries user KV bytes; scrub on drop.
            let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(leaf.encode()?);
            let slot = self.append_chunk(ChunkKind::IndexNode, new_seq, &bytes)?;
            children.push(ChildPointer {
                first_key,
                child_slot: slot,
                child_hash: blake3_of(&bytes),
            });
        }

        let internal = InternalNode {
            namespace: ns,
            children,
        };
        // Encoded internal node carries user `first_key` bytes; scrub.
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(internal.encode()?);
        let slot = self.append_chunk(ChunkKind::IndexNode, new_seq, &bytes)?;
        Ok((slot, blake3_of(&bytes)))
    }
}

// --- free helpers ---

/// Apply one KvOp to a sorted Vec of entries, preserving sort order.
fn apply_op_to_sorted(entries: &mut Vec<(Vec<u8>, Vec<u8>)>, op: &KvOp) {
    match op {
        KvOp::Put { key, value } => {
            match entries.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
                Ok(idx) => entries[idx].1 = value.clone(),
                Err(idx) => entries.insert(idx, (key.clone(), value.clone())),
            }
        },
        KvOp::Delete { key } => {
            if let Ok(idx) = entries.binary_search_by(|(k, _)| k.as_slice().cmp(key)) {
                entries.remove(idx);
            }
        },
    }
}

/// Split a sorted entries vec into LeafNodes that each fit under
/// PAYLOAD_CAP. Greedy first-fit: pack into the current leaf until the
/// next entry would overflow, then start a new leaf.
///
/// Errors with [`Error::Malformed`] only if a single entry is too big
/// to fit in any leaf at all (which should be caught earlier by
/// MAX_KEY_LEN / MAX_VALUE_LEN bounds in `Tx::put`).
fn pack_into_leaves(ns: Namespace, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<LeafNode>> {
    let mut leaves: Vec<LeafNode> = Vec::new();
    let mut current = LeafNode::new(ns);

    for (k, v) in entries {
        // Cost of adding this entry to the current leaf:
        let entry_cost = 2 + k.len() + 4 + v.len();

        // If empty leaf can't even hold this single entry, we can't
        // proceed (single entry too large for any leaf).
        if current.entries.is_empty()
            && (1 + 1 + 2 + entry_cost) > crate::chunk::format::PAYLOAD_CAP
        {
            return Err(Error::Malformed("single entry too large for any leaf"));
        }

        if current.encoded_len() + entry_cost > crate::chunk::format::PAYLOAD_CAP {
            // Seal current leaf, start a new one.
            leaves.push(std::mem::replace(&mut current, LeafNode::new(ns)));
        }

        current.entries.push((k.clone(), v.clone()));
    }

    if !current.entries.is_empty() {
        leaves.push(current);
    }

    Ok(leaves)
}
