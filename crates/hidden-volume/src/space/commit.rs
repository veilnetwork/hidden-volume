//! Tx commit logic: the 3-fsync protocol that promotes a Tx's
//! pending operations into a new on-disk commit. Audit pass 8 (E7)
//! split out of `space/mod.rs` so the commit path (the most
//! security-sensitive write code in the crate) is reviewable as a
//! self-contained ~280-LOC chunk.

use std::collections::{BTreeMap, HashMap, HashSet};

use zeroize::Zeroizing;

use crate::chunk::ChunkKind;
use crate::tx::KvOp;
use crate::tx::commit::{CommitPayload, IndexRoot, blake3_of};
use crate::{Error, Result};

use super::Space;
use super::index::{ChildPointer, InternalNode, LeafNode, Namespace};
use super::log;
use super::superblock::Superblock;

/// Index chunks of a namespace's **current** tree, keyed by the BLAKE3
/// of their plaintext payload — the same hash the parent already stores
/// as its Merkle link, so building this costs no extra chunk read and
/// no hashing: it falls out of the flatten walk the commit performs
/// anyway ([`Space::flatten_tree`]).
///
/// A rebuild that produces a node whose payload hashes to a key in here
/// has produced a node that is already on disk, byte for byte, in a
/// chunk this space owns and currently reaches. Pointing at that chunk
/// is not an optimisation of the encoding — it *is* the same node.
///
/// The hash covers the node-type byte and the namespace byte (they sit
/// in the encoded header), so a match cannot silently swap a leaf for
/// an internal node or graft a chunk from a neighbouring namespace.
type ReusableNodes = HashMap<[u8; 32], u64>;

/// A namespace's entries, flattened and sorted, plus the nodes of the
/// tree they came out of that a rebuild may point at again.
type FlattenedNamespace = (Vec<(Vec<u8>, Vec<u8>)>, ReusableNodes);

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

        // Committing on top of a stale root FORKS the space: the newer writer's
        // era and ours both claim descent from different states, and the open
        // scan resolves that by seq alone. Reading such a container is fine —
        // writing to it is not. See `SpaceState::unreadable_newer_superblock`.
        if self.state.unreadable_newer_superblock.is_some() {
            return Err(Error::UnreadableNewerState);
        }

        // Audit pass 11 (L3): defensive `checked_add`. Practically
        // unreachable through honest use (would require `u64::MAX`
        // commits), but a malformed AEAD-valid Superblock could push
        // `seq` to `u64::MAX` and crash a subsequent commit on
        // overflow. Convert to an explicit `Error::Internal` instead.
        // Derived from `attempted_seq`, not `superblock.seq`: a previous
        // publish may have put a replica of a higher seq on disk and then
        // failed, and re-using that number for a different payload loses one
        // of the two commits silently. See [`SpaceState::attempted_seq`].
        let new_seq = self
            .state
            .attempted_seq
            .max(self.state.superblock.seq)
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
            // simpler than path-tracking incremental updates, and the
            // commit is fsync-bound at every size measured (HV-14).
            //
            // The rebuild is only a rebuild *in memory*. Every node it
            // produces that already exists on disk is pointed at rather
            // than written again — see `ReusableNodes` and audit HV-14.
            let (mut entries, reusable) = match prior_roots_by_ns.get(ns_byte) {
                Some(r) => self.flatten_tree(r)?,
                None => (Vec::new(), ReusableNodes::new()),
            };

            for op in ops {
                apply_op_to_sorted(&mut entries, op);
            }

            if entries.is_empty() {
                // Empty namespace → omit from new Commit.
                continue;
            }

            let (root_slot, root_hash) =
                self.write_tree_for_namespace(ns, &entries, new_seq, &reusable)?;
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
        // Burn the number BEFORE the first replica can reach the disk: if one
        // lands and a later replica (or the fsync) fails, this seq must never
        // be handed out again.
        self.state.attempted_seq = new_seq;
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

    /// Read all entries of a namespace's tree into a flat sorted Vec,
    /// and collect the nodes a rebuild may point at instead of writing
    /// again (audit HV-14). Used during commit_tx to load the prior
    /// state before applying ops.
    ///
    /// The reuse map is a by-product of the walk, not a second pass:
    /// flattening reads every node of the tree already, and every one
    /// of them is reached through a parent that stores its BLAKE3. So
    /// the map costs no extra read and no hashing, and — unlike the
    /// root-only map this replaces — it covers every level, which is
    /// what keeps a one-key edit at one write per level once trees grow
    /// past two levels (audit HV-15).
    ///
    /// The root's own hash is included because a Tx whose ops all turn
    /// out to be no-ops (`put` of the value already stored) rebuilds a
    /// tree identical to the one on disk, and there is no reason for
    /// that to cost a single write.
    fn flatten_tree(&mut self, root: &IndexRoot) -> Result<FlattenedNamespace> {
        let mut out = Vec::new();
        let mut reusable = ReusableNodes::new();
        reusable.insert(root.payload_hash, root.index_slot);
        self.collect_leaves_and_links(
            root.index_slot,
            root.namespace,
            &mut out,
            &mut Some(&mut reusable),
        )?;
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
        Ok((out, reusable))
    }

    /// Put an index node on disk — or discover it is already there.
    ///
    /// A hash hit means the chunk at that slot decrypts to exactly these
    /// bytes: same node type, same namespace, same entries. The chunk is
    /// owned by this space and reachable from the committed tree, so it
    /// is neither foreign, nor scrubbed, nor about to be: it stays
    /// reachable from the tree being built, which is what
    /// `vacuum_orphans` computes reachability against.
    ///
    /// `emitted` is a belt-and-braces guard, not a load-bearing check.
    /// Two leaves of one tree hold disjoint key ranges and so cannot
    /// encode to the same bytes; but a chunk reachable twice in one walk
    /// is a structural failure the readers reject outright
    /// (`space::walk`), and a hostile prior tree is the input here. If a
    /// slot would be used twice, write a fresh chunk instead.
    fn emit_index_node(
        &mut self,
        bytes: &[u8],
        new_seq: u64,
        reuse: &ReusableNodes,
        emitted: &mut HashSet<u64>,
    ) -> Result<(u64, [u8; 32])> {
        let hash = blake3_of(bytes);
        if let Some(&slot) = reuse.get(&hash)
            && emitted.insert(slot)
        {
            return Ok((slot, hash));
        }
        let slot = self.append_chunk(ChunkKind::IndexNode, new_seq, bytes)?;
        emitted.insert(slot);
        Ok((slot, hash))
    }

    /// Build a tree from a sorted entries vec and write the chunks that
    /// are not already on disk. Returns the root slot + hash.
    ///
    /// Strategy:
    /// 1. Try to fit everything in a single Leaf — emits one chunk.
    /// 2. If overflow, pack the entries into a row of Leaves.
    /// 3. While the row does not fit under a single Internal node, pack
    ///    it into a row of Internal nodes and go up one level.
    /// 4. The level that ends up one node wide is the root.
    ///
    /// ## Why there is no depth limit (audit HV-15)
    ///
    /// Step 3 used to be "emit one Internal node over the leaves, or
    /// `Error::IndexFull` if they do not fit under it". That made the
    /// namespace's capacity a property of the *shape of one chunk*: an
    /// internal node holds `(PAYLOAD_CAP - 4) / (2 + key_len + 8 + 32)`
    /// children — 79 with 9-byte keys — so a namespace stopped at 79
    /// leaves. Measured, that was 4 029 entries with 64-byte values,
    /// 553 with 512-byte values and **79 with 2 048-byte values**, and
    /// nothing above it could be stored at all.
    ///
    /// Adding one more fixed level would only move the wall (79 → 6 241
    /// leaves). Growing levels until one node covers them removes it:
    /// what a namespace can hold is now what the container can hold,
    /// and the container's own budget — `MAX_OPEN_SCAN_CHUNKS`, checked
    /// on every append — is what refuses, with `ContainerTooLarge`.
    /// Depth stays small on its own because each level is at least
    /// [`super::index::MIN_FULL_INTERNAL_FANOUT`] times narrower than
    /// the one below: 3 levels index ~17 M entries. The readers derive
    /// their bound from the same arithmetic, so nothing needs to agree
    /// on a constant — see [`super::walk`].
    ///
    /// `Error::IndexFull` survives as the guard on step 3 making no
    /// progress, which needs a child pointer so large that two do not
    /// fit in a chunk. Not reachable through `MAX_KEY_LEN`: the largest
    /// possible pointer is 298 bytes against a 4 040-byte payload.
    ///
    /// ## Why the whole tree is still built (audit HV-14)
    ///
    /// Changing one key used to append the *entire* namespace again:
    /// 82 chunks (336 KiB) for a one-key edit in a 4 000-entry
    /// namespace, 48 chunks (196 KiB) to append one 200-byte message to
    /// an 8 000-message log. The chunks are immutable and content-
    /// addressed, so the fix is to notice that almost all of them
    /// already exist: the packing is deterministic, an edit that does
    /// not move a leaf boundary leaves every other leaf encoding to
    /// identical bytes, and appending at the high end of a log moves no
    /// boundary at all. Only the nodes that genuinely differ, plus the
    /// path of parents above them, are written — path copying, arrived
    /// at by comparison rather than by descent. That holds at any
    /// depth: the reuse map covers every level of the previous tree
    /// (`collect_leaves_and_links`), so a one-key edit costs one node
    /// per level, not one node per level *below the root*.
    ///
    /// This cannot do worse than the old behaviour: a rebuild where
    /// every node differs writes every node, exactly as before.
    ///
    /// The in-memory flatten-and-repack stays. Measurement is why: the
    /// commit is fsync-bound (~11-22 ms flat from 10 to 8 000 entries
    /// on an SSD), so the O(N) CPU the audit flagged does not surface;
    /// and the repack's greedy self-compaction is what keeps repeated
    /// delete/insert cycles from fragmenting a namespace into ever more
    /// half-empty chunks. See `docs/en/contributing/benchmarks.md`.
    fn write_tree_for_namespace(
        &mut self,
        ns: Namespace,
        entries: &[(Vec<u8>, Vec<u8>)],
        new_seq: u64,
        reuse: &ReusableNodes,
    ) -> Result<(u64, [u8; 32])> {
        let mut emitted: HashSet<u64> = HashSet::new();

        // Try single-leaf first. Measure before cloning: `entries` is
        // the whole namespace, and now that a namespace can be
        // arbitrarily large, cloning it only to watch `encode` refuse
        // it is a copy of everything the user has stored (audit HV-15).
        if leaf_encoded_len(entries) <= crate::chunk::format::PAYLOAD_CAP {
            let single = LeafNode {
                namespace: ns,
                entries: entries.to_vec(),
            };
            // Encoded leaf carries user KV bytes; scrub on drop.
            let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(single.encode()?);
            return self.emit_index_node(&bytes, new_seq, reuse, &mut emitted);
        }

        // Need to split. Pack greedily into leaves that each fit.
        let leaves = pack_into_leaves(ns, entries)?;
        if leaves.is_empty() {
            return Err(Error::Internal("pack_into_leaves returned empty"));
        }

        // Emit each leaf as a chunk and collect the ChildPointers that
        // the level above will index.
        let mut level = Vec::with_capacity(leaves.len());
        for leaf in leaves {
            let first_key = leaf.entries[0].0.clone();
            // Encoded leaf carries user KV bytes; scrub on drop.
            let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(leaf.encode()?);
            let (slot, hash) = self.emit_index_node(&bytes, new_seq, reuse, &mut emitted)?;
            level.push(ChildPointer {
                first_key,
                child_slot: slot,
                child_hash: hash,
            });
        }

        // Grow levels until one node covers the whole row.
        let mut nodes = level.len();
        let mut descents: u8 = 0;
        while level.len() > 1 {
            let parents = pack_into_internals(ns, &level)?;
            // Every level is strictly narrower than the one below it —
            // `pack_into_internals` seals a node only when the next
            // pointer does not fit, so a node holds ≥ 2 pointers unless
            // one alone fills a chunk. Without progress this would spin
            // forever appending chunks; refuse instead.
            if parents.len() >= level.len() {
                return Err(Error::IndexFull);
            }
            let mut next = Vec::with_capacity(parents.len());
            for node in parents {
                let first_key = match node.children.first() {
                    Some(c) => c.first_key.clone(),
                    None => return Err(Error::Internal("internal node packed with no children")),
                };
                // Encoded internal node carries user `first_key` bytes; scrub.
                let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(node.encode()?);
                let (slot, hash) = self.emit_index_node(&bytes, new_seq, reuse, &mut emitted)?;
                next.push(ChildPointer {
                    first_key,
                    child_slot: slot,
                    child_hash: hash,
                });
            }
            nodes += next.len();
            descents = descents.saturating_add(1);
            level = next;
        }

        // Never publish a tree this crate's own readers would refuse.
        //
        // Their depth bound is derived from the chunks a space owns
        // ([`super::walk::max_depth_for_budget`]), which is always at
        // least this tree's own node count — so checking against that
        // count is the strictest form of the same question. A greedy
        // pack cannot fail it: the bound is the inverse of exactly the
        // "every node but the last of a level is full" property
        // `pack_into_internals` provides. What this catches is a future
        // change that quietly weakens that packing, which would
        // otherwise commit successfully and leave the namespace
        // unreadable — the worst failure this crate has.
        if descents > super::walk::max_depth_for_budget(nodes) {
            return Err(Error::IndexFull);
        }

        match level.pop() {
            Some(root) => Ok((root.child_slot, root.child_hash)),
            // `pack_into_leaves` returned a non-empty row and every
            // packing step preserves that, so this is unreachable.
            None => Err(Error::Internal("tree build produced no root")),
        }
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

/// What [`LeafNode::encoded_len`] would report for a leaf holding
/// `entries` — without building one. The header size is taken from an
/// empty `LeafNode` so this cannot drift from the encoder.
fn leaf_encoded_len(entries: &[(Vec<u8>, Vec<u8>)]) -> usize {
    let header = LeafNode::new(Namespace::RESERVED).encoded_len();
    entries.iter().fold(header, |n, (k, v)| {
        n.saturating_add(2 + k.len() + 4 + v.len())
    })
}

/// Split a row of child pointers into InternalNodes that each fit under
/// PAYLOAD_CAP. Greedy first-fit, exactly like [`pack_into_leaves`]:
/// pack into the current node until the next pointer would overflow,
/// then start a new one. Every node but the last of the row is
/// therefore *full*, which is what bounds tree depth — see
/// [`super::index::MIN_FULL_INTERNAL_FANOUT`].
///
/// Determinism matters as much as the packing: an unchanged stretch of
/// a level must re-pack to byte-identical nodes, or the HV-14 reuse
/// map never hits and every commit rewrites the whole tree.
fn pack_into_internals(ns: Namespace, children: &[ChildPointer]) -> Result<Vec<InternalNode>> {
    let mut out: Vec<InternalNode> = Vec::new();
    let mut current = InternalNode::new(ns);

    for c in children {
        let entry_cost = 2 + c.first_key.len() + 8 + 32;
        if current.children.is_empty()
            && current.encoded_len() + entry_cost > crate::chunk::format::PAYLOAD_CAP
        {
            // Unreachable via MAX_KEY_LEN (298 bytes at most against a
            // 4 040-byte payload), but a first_key is copied from user
            // data and this is the write path.
            return Err(Error::Malformed(
                "single child pointer too large for any internal node",
            ));
        }
        if current.encoded_len() + entry_cost > crate::chunk::format::PAYLOAD_CAP {
            out.push(std::mem::replace(&mut current, InternalNode::new(ns)));
        }
        current.children.push(c.clone());
    }

    if !current.children.is_empty() {
        out.push(current);
    }

    Ok(out)
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

#[cfg(test)]
mod seq_allocation_tests {
    use crate::container::Container;
    use crate::crypto::kdf::Argon2Params;
    use crate::space::index::Namespace;

    fn scratch() -> std::path::PathBuf {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let p = tmp.path().to_owned();
        drop(tmp);
        p
    }

    /// A seq whose replica may already be on disk must never be handed out
    /// again.
    ///
    /// Both publishers append N Superblock replicas and adopt the new
    /// superblock only after the final fsync. If a replica lands and the next
    /// one (or the fsync) fails — ENOSPC on a nearly-full disk is the mobile
    /// case — the disk holds seq N+1 while `superblock.seq` still says N.
    /// Deriving the next seq from `superblock.seq` alone published a DIFFERENT
    /// payload under that same N+1, and the open scan resolves a same-seq
    /// collision by slot order, so one of the two commits disappeared. Nothing
    /// detected it: the winner is self-consistent so `verify_integrity`
    /// passes, and N+1 is present in `commit_history` so the multi-device
    /// triage sees no fork.
    ///
    /// The partial publish itself needs an I/O fault to induce, so this drives
    /// the state it leaves behind: `attempted_seq` set without `superblock`
    /// advancing, exactly as `commit_tx` does before its first append.
    #[test]
    fn a_burnt_seq_is_never_reused() {
        let path = scratch();
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v1").unwrap();
            tx.commit().unwrap();
            let durable = s.commit_seq();

            // A publish of `durable + 1` got a replica onto the disk and then
            // failed; `superblock` was never adopted.
            s.state.attempted_seq = durable + 1;

            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v2").unwrap();
            tx.commit().unwrap();
            assert_eq!(
                s.commit_seq(),
                durable + 2,
                "the next commit must skip the seq a failed publish may have \
                 already written"
            );
        }
        // ...and the container still opens on the era that was actually
        // published.
        let mut c = Container::open(&path).unwrap();
        let mut s = c.open_space(b"pw").unwrap();
        assert_eq!(
            s.get(Namespace::SETTINGS, b"k").unwrap().as_deref(),
            Some(&b"v2"[..])
        );
        drop(s);
        let _ = std::fs::remove_file(&path);
    }

    /// Reopening seeds the burn mark from the whole scan, not from the winning
    /// superblock — otherwise a seq burnt by a crash comes back on restart.
    #[test]
    fn the_burn_mark_survives_a_reopen() {
        let path = scratch();
        {
            let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
            let mut s = c.create_space(b"pw").unwrap();
            let mut tx = s.begin_tx();
            tx.put(Namespace::SETTINGS, b"k", b"v1").unwrap();
            tx.commit().unwrap();
        }
        let mut c = Container::open(&path).unwrap();
        let s = c.open_space(b"pw").unwrap();
        assert!(
            s.state.attempted_seq >= s.commit_seq(),
            "attempted_seq {} must cover the published era {}",
            s.state.attempted_seq,
            s.commit_seq()
        );
        drop(s);
        let _ = std::fs::remove_file(&path);
    }
}
