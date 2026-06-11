//! Forward-secrecy scrub paths: `vacuum_orphans` (auto-runs on
//! `Container::open_space`) and `vacuum_data_batches`
//! (host-app-driven). Audit pass 8 (E7) split out of `space/mod.rs`
//! so vacuum / scrub logic is reviewable as a self-contained
//! ~250-LOC chunk.

use crate::chunk::ChunkKind;
use crate::{Error, Result};

use super::Space;
use super::index::IndexNode;
use super::superblock::NO_RECORD;

impl<'f> Space<'f> {
    /// Scrub orphan IndexNode chunks — owned chunks (decrypt under our
    /// key) of kind `IndexNode` that are NOT reachable from the current
    /// Superblock's tree. Overwrites them with uniform random; they
    /// become indistinguishable from garbage and a forensic adversary
    /// with our password can no longer recover prior versions of
    /// "deleted" KV entries from them.
    ///
    /// Idempotent: subsequent calls without intervening commits are no-ops.
    /// Safe to invoke at any time; called automatically at the end of
    /// [`crate::Container::open_space`] so app-launch yields clean state.
    ///
    /// Does NOT scrub:
    /// - DataBatch chunks (a single batch may still contain live entries
    ///   referenced by other log_ids; [`Space::vacuum_data_batches`] and
    ///   `Container::repack` handle batch repacking with proper scrub).
    /// - Superblock or Commit chunks of prior commits (kept as
    ///   crash-recovery fallbacks).
    ///
    /// Returns the number of chunks scrubbed.
    ///
    /// **Read-only handles** (`open_readonly` → `LOCK_SH`) cannot
    /// scrub: returns [`Error::ReadOnly`]. Audit pass 7 (L5)
    /// changed this from a silent `Ok(0)` so that an explicit
    /// host-app call now surfaces the privacy expectation it
    /// failed. The auto-call from `Container::open_space*` is
    /// suppressed on read-only handles before reaching this method
    /// (forward-secrecy is, intentionally, a writer-only property).
    pub fn vacuum_orphans(&mut self) -> Result<usize> {
        if self.file.lock_mode == crate::container::file::LockMode::Shared {
            return Err(Error::ReadOnly);
        }
        if self.state.superblock.root_slot == NO_RECORD {
            return Ok(0);
        }

        // Reachable from current tree. HashSet (not BTreeSet): we
        // only need O(1) `contains` for the membership check below;
        // we don't need ordered iteration.
        let mut reachable: std::collections::HashSet<u64> = std::collections::HashSet::new();
        reachable.insert(self.state.superblock.root_slot);
        let prior_roots = self.load_prior_roots()?;
        for r in prior_roots {
            self.collect_tree_chunks_into_set(r.index_slot, &mut reachable)?;
        }

        // Owned but not reachable.
        let owned_snapshot: Vec<u64> = self.state.owned_slots.clone();
        let mut scrubbed = 0;
        // HashSet, not Vec, so the `retain(|s| !to_drop.contains(s))`
        // call below is O(N) instead of O(N²). Audit F1 (2026-05-03):
        // matters for heavy-history containers (100K owned + 1K
        // to-scrub = 100M comparisons with Vec::contains).
        let mut to_drop: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for slot in owned_snapshot {
            if reachable.contains(&slot) {
                continue;
            }
            // Inspect kind — only scrub IndexNode orphans. Old
            // Superblocks / Commits / DataBatch chunks are left alone
            // (fallbacks / shared batches respectively).
            let pt = match self.read_owned_chunk(slot) {
                Ok(p) => p,
                Err(Error::AuthFailed) => {
                    // Already scrubbed (or otherwise non-decryptable).
                    to_drop.insert(slot);
                    continue;
                },
                Err(other) => return Err(other),
            };
            if pt.kind != ChunkKind::IndexNode {
                continue;
            }
            self.file.scrub_slot(slot)?;
            to_drop.insert(slot);
            scrubbed += 1;
        }
        if scrubbed > 0 {
            self.file.fsync()?;
            self.state.owned_slots.retain(|s| !to_drop.contains(s));
        }
        Ok(scrubbed)
    }

    /// Scrub `DataBatch` chunks owned by this space that are no longer
    /// referenced by any current namespace's KV index. Returns the
    /// number of chunks scrubbed.
    ///
    /// ## Why this exists
    ///
    /// [`Self::vacuum_orphans`] (auto-runs on `open_space`) only
    /// scrubs orphan IndexNode chunks. DataBatch chunks are left
    /// alone because a single batch can hold live entries from many
    /// log_ids — vacuum can't decide kind-by-kind whether a batch is
    /// still needed.
    ///
    /// In a typical messenger workload, however, batches DO get
    /// orphaned over time: editing a message creates a fresh batch
    /// with the new payload and the original batch becomes
    /// unreachable. Without this method (or full
    /// [`crate::Container::compact_known`]) the orphan batches stay
    /// on disk, AEAD-decryptable, leaking the original payloads to
    /// anyone who later obtains the password.
    ///
    /// `vacuum_data_batches` walks the live KV index of every
    /// namespace, builds the set of currently-referenced batch slots
    /// (any 8-byte KV value is treated as a candidate batch_slot
    /// pointer — a heuristic, but values that *aren't* batch slots
    /// just won't match owned DataBatch slots and so the heuristic
    /// only causes false negatives, never wrongful scrub), then
    /// scrubs every owned DataBatch chunk that isn't referenced.
    ///
    /// ## Cost
    ///
    /// One full walk of every namespace's tree (≤ Σ count(ns)) plus
    /// O(M) chunk reads where M is the number of owned chunks. On a
    /// 100 K-message log this is a few ms.
    ///
    /// ## Read-only handles
    ///
    /// Returns [`Error::ReadOnly`]. Audit pass 7 (L5): this surfaces
    /// the failed privacy expectation when a host-app calls vacuum
    /// on a `LOCK_SH` handle — previously silent `Ok(0)` masked the
    /// fact that forward-secrecy scrubbing did not happen.
    ///
    /// ## When to call
    ///
    /// - After [`Self::erase_namespace`] on a log namespace.
    /// - Periodically (e.g. once per app launch) for "always-on"
    ///   forward-secrecy of edited messages.
    /// - **After any [`crate::tx::Tx::commit`] that returned an
    ///   error**: a mid-Phase-0 failure can leave orphan DataBatch
    ///   chunks (see audit pass 7 D1). The next auto-vacuum on
    ///   `Container::open_space` only handles IndexNode orphans;
    ///   DataBatch orphans persist until this call runs.
    /// - Cheaper than [`crate::Container::compact_known`] for
    ///   forward-secrecy alone — compaction additionally rewrites the
    ///   whole container with a fresh `container_id` and resets
    ///   `commit_history`, both of which `vacuum_data_batches`
    ///   leaves alone.
    pub fn vacuum_data_batches(&mut self) -> Result<usize> {
        if self.file.lock_mode == crate::container::file::LockMode::Shared {
            return Err(Error::ReadOnly);
        }
        if self.state.superblock.root_slot == NO_RECORD {
            return Ok(0);
        }

        // 1. Build the set of currently-referenced batch_slot
        //    pointers. R-NSKIND (format v2): each `IndexRoot` carries
        //    an explicit `kind` byte; we only consult Log-kind
        //    namespaces for batch_slot pointers. The v1 implementation
        //    iterated EVERY namespace and treated every 8-byte value
        //    as a candidate, which made "any KV value coincidentally
        //    matching a stale batch slot" suppress scrub — false
        //    negative window. With kind-bound iteration that window
        //    is structurally closed.
        let prior_roots = self.load_prior_roots()?;
        // HashSet: we only need O(1) `contains`, no ordered iteration.
        let mut referenced: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for root in &prior_roots {
            if root.kind != crate::tx::NamespaceKind::Log {
                continue;
            }
            let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
            self.collect_leaves(root.index_slot, root.namespace, &mut entries)?;
            for (_key, value) in entries {
                if value.len() == 8 {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&value);
                    referenced.insert(u64::from_le_bytes(buf));
                }
            }
        }

        // 2. Walk owned slots; scrub each DataBatch not in `referenced`.
        let owned_snapshot: Vec<u64> = self.state.owned_slots.clone();
        let mut scrubbed = 0;
        // HashSet, not Vec, so the `retain(|s| !to_drop.contains(s))`
        // call below is O(N) instead of O(N²). Audit F1 (2026-05-03):
        // matters for heavy-history containers (100K owned + 1K
        // to-scrub = 100M comparisons with Vec::contains).
        let mut to_drop: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for slot in owned_snapshot {
            if referenced.contains(&slot) {
                continue;
            }
            let pt = match self.read_owned_chunk(slot) {
                Ok(p) => p,
                Err(Error::AuthFailed) => {
                    // Already scrubbed (or otherwise non-decryptable).
                    to_drop.insert(slot);
                    continue;
                },
                Err(other) => return Err(other),
            };
            if pt.kind != ChunkKind::DataBatch {
                continue;
            }
            self.file.scrub_slot(slot)?;
            to_drop.insert(slot);
            scrubbed += 1;
        }
        if scrubbed > 0 {
            self.file.fsync()?;
            self.state.owned_slots.retain(|s| !to_drop.contains(s));
        }
        Ok(scrubbed)
    }

    /// Walk the tree rooted at `slot` and append every IndexNode chunk
    /// slot (Leaves and Internal nodes) into `out`. Used at vacuum time.
    /// Depth-capped via [`super::index::MAX_TREE_DEPTH`] to defend
    /// against cyclic IndexNode chains (writer-bug regression or
    /// adversarial key-holder).
    fn collect_tree_chunks_into_set(
        &mut self,
        slot: u64,
        out: &mut std::collections::HashSet<u64>,
    ) -> Result<()> {
        self.collect_tree_chunks_into_set_at(slot, 0, out)
    }

    fn collect_tree_chunks_into_set_at(
        &mut self,
        slot: u64,
        depth: u8,
        out: &mut std::collections::HashSet<u64>,
    ) -> Result<()> {
        if depth > super::index::MAX_TREE_DEPTH {
            return Err(Error::Malformed("tree depth exceeded MAX_TREE_DEPTH"));
        }
        out.insert(slot);
        let node = self.read_index_node_at(slot)?;
        if let IndexNode::Internal(i) = node {
            for c in i.children {
                self.collect_tree_chunks_into_set_at(c.child_slot, depth + 1, out)?;
            }
        }
        Ok(())
    }
}
