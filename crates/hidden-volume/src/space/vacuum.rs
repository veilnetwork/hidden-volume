//! Forward-secrecy scrub paths: `vacuum_orphans` (auto-runs on
//! `Container::open_space`) and `vacuum_data_batches`
//! (host-app-driven). Audit pass 8 (E7) split out of `space/mod.rs`
//! so vacuum / scrub logic is reviewable as a self-contained
//! ~250-LOC chunk.

use crate::chunk::ChunkKind;
use crate::{Error, Result};

use super::Space;
use super::index::IndexNode;
use super::slots::DenseSlotSet;
use super::superblock::{NO_RECORD, Superblock};
use super::walk::TreeWalk;

/// How many `(log_id_key, batch_slot)` entries
/// [`Space::vacuum_data_batches`] pulls out of a namespace at a time
/// (audit HV-03).
///
/// Both halves of such an entry are 8 bytes, but what the page actually
/// costs is dominated by the `Vec<(Vec<u8>, Vec<u8>)>` that carries it
/// — 48 bytes of spine and two allocations per entry, so ~64 bytes
/// against 16 of payload. 512 keeps a page around 32 KiB; every page
/// re-descends the tree from the cursor, and at this width that is a
/// handful of descents per namespace.
const BATCH_POINTER_PAGE: usize = 512;

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
        // A superblock NEWER than the one we settled on decrypted under our key
        // and could not be parsed — something we do not understand published
        // state after us. Vacuum deletes every chunk unreachable from OUR root,
        // which is exactly that writer's data. Refuse.
        //
        // This is the invariant whose absence made a format extension into
        // silent data loss: a 1.1.0 reader dropped the 56-byte superblock it
        // could not decode, fell back to an older era, and scrubbed the newer
        // one away on the next writable open.
        if let Some(seq) = self.state.unreadable_newer_superblock {
            let _ = seq;
            return Err(Error::UnreadableNewerState);
        }
        if !self.file.lock_mode.allows_writes() {
            return Err(Error::ReadOnly);
        }
        // A publish that got a replica onto the disk and then failed leaves
        // this handle a full era behind what a reopen would select. Walking
        // THIS tree and erasing the rest would erase that era's chunks, and
        // the reopen then lands on a Superblock pointing at nothing
        // (audit HV-01). Reopen first; the open scan settles which era landed.
        if self.state.attempted_seq > self.state.superblock.seq {
            return Err(Error::PublishUncertain("vacuuming"));
        }
        if self.state.superblock.root_slot == NO_RECORD {
            return Ok(0);
        }

        // Which chunks the current tree reaches. There is no separate
        // set for this: `walk` already records exactly it.
        //
        // `walk_tree_chunks` admits every node it descends into and
        // descends into nothing it has not admitted, in one function,
        // unconditionally — so the guard's visited set and the reachable
        // set are the same set by construction, and building a second
        // one alongside it cost another hashed `u64` per live chunk for
        // no information (audit HV-03). The Commit chunk at
        // `superblock.root_slot` is not part of any tree, so it is
        // admitted here rather than by a descent; the guard's
        // seen-twice rule then also covers the case of a tree claiming
        // the Commit chunk as one of its nodes.
        let prior_roots = self.load_prior_roots()?;
        let mut walk = self.new_tree_walk();
        walk.admit(self.state.superblock.root_slot, 0)?;
        for r in prior_roots {
            self.walk_tree_chunks(r.index_slot, &mut walk)?;
        }

        // Owned but not reachable. Indexed rather than cloned: the loop
        // body reads chunks and scrubs bytes but never touches
        // `owned_slots`, which is only rewritten after it (audit HV-03
        // — the clone was a second copy of the whole slot list, live
        // for the duration of the pass).
        let mut scrubbed = 0;
        // A second `DenseSlotSet`, so the `retain` below stays O(N) rather
        // than the O(N²) a `Vec::contains` would make it. Audit F1
        // (2026-05-03): matters for heavy-history containers (100K
        // owned + 1K to-scrub = 100M comparisons with Vec::contains).
        let mut to_drop = DenseSlotSet::with_capacity(self.file.slot_count());
        // Eras older than the anchor horizon are retired here, superblock and
        // Commit chunk together. See [`crate::ANCHOR_HORIZON`] for why the two
        // travel as a pair and what the horizon costs.
        //
        // Both sets are bitmaps over the file, so the bookkeeping is a bit per
        // slot rather than a list of eras — a container that has never been
        // vacuumed can hold a very large number of them.
        let threshold = self
            .state
            .superblock
            .seq
            .saturating_sub(crate::ANCHOR_HORIZON);
        let mut kept_roots = DenseSlotSet::with_capacity(self.file.slot_count());
        let mut doomed_roots = DenseSlotSet::with_capacity(self.file.slot_count());
        // Explicit, though the loop would also reach it: the current era's
        // Commit chunk is the one thing that must survive whatever else does.
        kept_roots.insert(self.state.superblock.root_slot);
        // Walked one bitmap word at a time, because the body holds `&mut
        // self` to read and scrub. A borrowed iterator cannot survive that,
        // and materializing the slot list is the whole-list copy audit HV-03
        // removed — one `u64` of stack covers 64 slots instead.
        for w in 0..self.state.owned_slots.word_count() {
            let word = self.state.owned_slots.word(w);
            for slot in crate::space::slots::slots_in_word(w, word) {
                if walk.has_visited(slot) {
                    continue;
                }
                // Inspect kind. IndexNode orphans go unconditionally;
                // Superblocks are judged against the horizon and take their
                // Commit chunk with them; DataBatch chunks belong to
                // `vacuum_data_batches` and are left alone here.
                let pt = match self.read_owned_chunk(slot) {
                    Ok(p) => p,
                    Err(Error::AuthFailed) => {
                        // Already scrubbed (or otherwise non-decryptable).
                        to_drop.insert(slot);
                        continue;
                    },
                    Err(other) => return Err(other),
                };
                if pt.kind == ChunkKind::Superblock {
                    // A superblock this build cannot decode is left where it
                    // is. `unreadable_newer_superblock` above already refuses
                    // the whole pass for a NEWER one; an older unreadable one
                    // is superseded history we still decline to destroy,
                    // because we cannot read which Commit chunk it holds and
                    // would orphan that chunk silently.
                    let Ok(sb) = Superblock::decode(&pt.payload) else {
                        continue;
                    };
                    if pt.seq >= threshold {
                        kept_roots.insert(sb.root_slot);
                        continue;
                    }
                    doomed_roots.insert(sb.root_slot);
                    self.file.scrub_slot(slot)?;
                    to_drop.insert(slot);
                    scrubbed += 1;
                    continue;
                }
                if pt.kind != ChunkKind::IndexNode {
                    continue;
                }
                self.file.scrub_slot(slot)?;
                to_drop.insert(slot);
                scrubbed += 1;
            }
        }
        // The Commit chunks the retired eras pointed at, minus any a KEPT era
        // still points at.
        //
        // A second phase rather than inline, because a Commit chunk can only
        // be judged once every superblock has been seen: an era below the
        // horizon is walked before the reader knows whether some era above it
        // shares the same root. They do not share by construction — each
        // commit writes its own — but the subtraction makes that a property of
        // the code rather than of a belief about it.
        for root in doomed_roots.iter() {
            if kept_roots.contains(root) || to_drop.contains(root) {
                continue;
            }
            match self.read_owned_chunk(root) {
                Ok(pt) if pt.kind == ChunkKind::Commit => {
                    self.file.scrub_slot(root)?;
                    to_drop.insert(root);
                    scrubbed += 1;
                },
                // Not ours, not a Commit, or already gone. A superblock whose
                // root does not read back as a Commit chunk is a shape this
                // writer never produced; leaving it is the safe half.
                _ => {},
            }
        }
        // fsync only when bytes actually changed, but drop the slots whenever
        // there are any to drop. A slot reaches `to_drop` through the
        // `AuthFailed` arm when an earlier pass already scrubbed it: gating the
        // retain on `scrubbed > 0` left those in `owned_slots` forever, so
        // every later open re-read and re-failed on the same dead slots and the
        // checkpoint kept carrying them.
        if scrubbed > 0 {
            self.file.fsync()?;
        }
        if !to_drop.is_empty() {
            self.state.owned_slots.retain(|s| !to_drop.contains(s));
            // Retired, therefore reusable AND churnable (DESIGN §9.1). This
            // is the ONLY way a slot that once held real data enters the
            // pool, and it enters carrying vacuum's own proof: unreachable
            // from the current era, under the `PublishUncertain` /
            // `UnreadableNewerState` guards this method already applies.
            // The `AuthFailed` arm above feeds it too — a slot in
            // `owned_slots` that no longer decrypts is one an earlier pass
            // scrubbed, which is the same retirement by a different route.
            for slot in to_drop.iter() {
                self.state.pool.insert(slot);
            }
            // The anchor list is DERIVED from the owned superblocks at open,
            // so a retired era has to leave it here too. Without this, this
            // session keeps answering `commit_history()` with anchors that no
            // longer exist on disk while the next open answers differently —
            // and a host comparing the two reads a fork where there is none.
            if threshold > 0 {
                self.state.commit_history.retain(|seq| *seq >= threshold);
                self.state.commit_eras.retain(|(seq, _)| *seq >= threshold);
            }
        }
        Ok(scrubbed)
    }

    /// Run the post-open scrub that a constant-time open deliberately
    /// left undone. Returns the number of chunks scrubbed.
    ///
    /// [`Container::open_space_constant_time`][crate::Container::open_space_constant_time]
    /// and its parallel / mmap companions equalize the discovery scan so
    /// the unlock's duration cannot say whether a password matched — and
    /// then used to vacuum inline, doing work whose duration and disk
    /// writes scale with the space's history, on the success path only.
    /// The measurement the equalized scan removes was handed back by the
    /// maintenance that followed it (audit HV-01). This is that
    /// maintenance, as its own operation.
    ///
    /// **When to call it.** Not immediately after the open: the same
    /// milliseconds a few milliseconds later are still the unlock's
    /// milliseconds, and an observer watching the process at the moment a
    /// password is typed reads the same answer. Call it at a moment the
    /// unlock did not cause — after a randomised delay, when the screen
    /// goes off, or on the first user-initiated write.
    ///
    /// **The scrub is still owed until this runs.** Nothing else performs
    /// it on the constant-time path, and until it does, the `IndexNode`
    /// chunks holding previous versions of deleted or overwritten values
    /// stay valid AEAD: whoever later obtains the password and an old
    /// snapshot of the file can read them back. This is the honest cost of
    /// the split, and the reason a host that opens constant-time must wire
    /// this somewhere rather than treat it as optional.
    ///
    /// Idempotent and cheap when there is nothing to reclaim.
    ///
    /// On a read-only handle it returns `Ok(0)` having done nothing,
    /// rather than the [`Error::ReadOnly`] that [`Self::vacuum_orphans`]
    /// answers — the same choice
    /// [`MultiSpace::vacuum_hosted`][crate::MultiSpace::vacuum_hosted]
    /// makes, and for the same reason: a host calls this unconditionally
    /// after every open, and failing on a container someone mounted
    /// read-only would break that host for no gain. `Ok` here therefore
    /// means "nothing is owed, or nothing could be done", not "the scrub
    /// ran"; forward secrecy is, intentionally, a writer-only property.
    /// Reach for [`Self::vacuum_orphans`] when the caller wants the strict
    /// answer.
    pub fn vacuum_after_open(&mut self) -> Result<usize> {
        if !self.file.lock_mode.allows_writes() {
            return Ok(0);
        }
        self.vacuum_orphans()
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
        // Same refusal as `vacuum_orphans`, and it was missing here (report9
        // HV-09). A superblock NEWER than the one we settled on decrypted under
        // our key and could not be parsed: something we do not understand
        // published state after us. This pass scrubs every owned DataBatch not
        // referenced from OUR namespaces — and the batches that writer's
        // entries point at are exactly the ones our tree does not reference.
        if self.state.unreadable_newer_superblock.is_some() {
            return Err(Error::UnreadableNewerState);
        }
        if !self.file.lock_mode.allows_writes() {
            return Err(Error::ReadOnly);
        }
        // A publish that got a replica onto the disk and then failed leaves
        // this handle a full era behind what a reopen would select. Walking
        // THIS tree and erasing the rest would erase that era's chunks, and
        // the reopen then lands on a Superblock pointing at nothing
        // (audit HV-01). Reopen first; the open scan settles which era landed.
        if self.state.attempted_seq > self.state.superblock.seq {
            return Err(Error::PublishUncertain("vacuuming"));
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
        // One bit per slot, not a `HashSet<u64>` — see [`DenseSlotSet`]
        // (audit HV-03).
        let mut referenced = DenseSlotSet::with_capacity(self.file.slot_count());
        for root in &prior_roots {
            if root.kind != crate::tx::NamespaceKind::Log {
                continue;
            }
            // Paged, not `collect_leaves` (audit HV-03): only the
            // 8-byte values are wanted, and materialising every
            // `(log_id_key, batch_slot)` pair of every log namespace
            // first meant the peak was the sum over all of them. A page
            // is dropped before the next is read, so it is now one
            // page.
            let mut cursor: Option<Vec<u8>> = None;
            loop {
                let page =
                    self.list_after(root.namespace, cursor.as_deref(), BATCH_POINTER_PAGE)?;
                let Some((last_key, _)) = page.last() else {
                    break;
                };
                cursor = Some(last_key.clone());
                for (_key, value) in &page {
                    if let Ok(bytes) = <[u8; 8]>::try_from(value.as_slice()) {
                        // A value that names no real slot is dropped by
                        // `insert` and cannot match an owned slot
                        // anyway — a false negative at worst, never a
                        // wrongful scrub.
                        referenced.insert(u64::from_le_bytes(bytes));
                    }
                }
            }
        }

        // 2. Walk owned slots; scrub each DataBatch not in `referenced`.
        //    Indexed rather than cloned — the loop body never touches
        //    `owned_slots` (audit HV-03).
        let mut scrubbed = 0;
        // A second `DenseSlotSet`, so the `retain` below stays O(N) rather
        // than the O(N²) a `Vec::contains` would make it. Audit F1
        // (2026-05-03): matters for heavy-history containers (100K
        // owned + 1K to-scrub = 100M comparisons with Vec::contains).
        let mut to_drop = DenseSlotSet::with_capacity(self.file.slot_count());
        // Word-wise for the same reason as `vacuum_orphans` above: the body
        // needs `&mut self`, and a whole-list copy is what audit HV-03 removed.
        for w in 0..self.state.owned_slots.word_count() {
            let word = self.state.owned_slots.word(w);
            for slot in crate::space::slots::slots_in_word(w, word) {
                if referenced.contains(slot) {
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
        }
        // fsync only when bytes actually changed, but drop the slots whenever
        // there are any to drop. A slot reaches `to_drop` through the
        // `AuthFailed` arm when an earlier pass already scrubbed it: gating the
        // retain on `scrubbed > 0` left those in `owned_slots` forever, so
        // every later open re-read and re-failed on the same dead slots and the
        // checkpoint kept carrying them.
        if scrubbed > 0 {
            self.file.fsync()?;
        }
        if !to_drop.is_empty() {
            self.state.owned_slots.retain(|s| !to_drop.contains(s));
            // Retired, therefore reusable AND churnable (DESIGN §9.1). This
            // is the ONLY way a slot that once held real data enters the
            // pool, and it enters carrying vacuum's own proof: unreachable
            // from the current era, under the `PublishUncertain` /
            // `UnreadableNewerState` guards this method already applies.
            // The `AuthFailed` arm above feeds it too — a slot in
            // `owned_slots` that no longer decrypts is one an earlier pass
            // scrubbed, which is the same retirement by a different route.
            for slot in to_drop.iter() {
                self.state.pool.insert(slot);
            }
        }
        Ok(scrubbed)
    }

    /// Walk the tree rooted at `slot`, admitting every IndexNode chunk
    /// (Leaves and Internal nodes) into `walk`. Used at vacuum time,
    /// where `walk`'s visited set IS the answer — see the caller.
    ///
    /// Guarded by `walk` (visited set + traversal budget + the depth
    /// that budget can hold) against cyclic, DAG-shaped or
    /// unboundedly-deep IndexNode chains — writer-bug regression or
    /// adversarial key-holder. Note that the guard is what makes a DAG
    /// terminate rather than cost `fanout^depth` reads for a handful of
    /// distinct slots; see [`super::walk`].
    ///
    /// The caller shares one `walk` across every namespace root, since
    /// no two roots legitimately reach the same chunk.
    fn walk_tree_chunks(&mut self, slot: u64, walk: &mut TreeWalk) -> Result<()> {
        self.walk_tree_chunks_at(slot, 0, walk)
    }

    fn walk_tree_chunks_at(&mut self, slot: u64, depth: u8, walk: &mut TreeWalk) -> Result<()> {
        walk.admit(slot, depth)?;
        let node = self.read_index_node_at(slot)?;
        if let IndexNode::Internal(i) = node {
            for c in i.children {
                self.walk_tree_chunks_at(c.child_slot, depth + 1, walk)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod newer_state_guard_tests {
    use crate::space::index::Namespace;
    use crate::{Container, Error};

    fn container() -> (std::path::PathBuf, Container) {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_owned();
        drop(tmp);
        let c = Container::create(&path, crate::crypto::kdf::Argon2Params::MIN).unwrap();
        (path, c)
    }

    /// With a newer superblock we could not read, the space stays READABLE but
    /// refuses everything that would act on the stale view.
    ///
    /// Readable matters as much as refusing: a corrupt or forged superblock
    /// must not be able to brick a container, which is why the open still falls
    /// back to the newest era it understands.
    #[test]
    fn an_unreadable_newer_superblock_blocks_destruction_but_not_reads() {
        let (_path, mut c) = container();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();

        // Someone newer published an era we cannot parse.
        s.state.unreadable_newer_superblock = Some(s.state.superblock.seq + 1);

        assert!(
            matches!(s.get(Namespace::SETTINGS, b"k"), Ok(Some(_))),
            "reads must keep working — the data is still there"
        );
        assert!(
            matches!(s.vacuum_orphans(), Err(Error::UnreadableNewerState)),
            "vacuum would delete exactly the newer writer's chunks"
        );
        // The batch pass had the publish-uncertain and read-only refusals and
        // not this one (report9 HV-09), and it is the pass that scrubs by
        // "not referenced from OUR namespaces" — which is precisely what the
        // newer writer's batches are.
        assert!(
            matches!(s.vacuum_data_batches(), Err(Error::UnreadableNewerState)),
            "the batch pass scrubs exactly the batches the newer era points at"
        );

        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k2", b"v2").unwrap();
        assert!(
            matches!(tx.commit(), Err(Error::UnreadableNewerState)),
            "committing on a superseded root forks the space"
        );
    }

    /// Clearing the flag restores normal operation — the guard is about the
    /// observed state, not a permanent brand on the container.
    #[test]
    fn a_space_without_newer_state_is_unaffected() {
        let (_path, mut c) = container();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
        assert!(s.state.unreadable_newer_superblock.is_none());
        assert!(s.vacuum_orphans().is_ok());
        assert!(s.vacuum_data_batches().is_ok());
    }
}

#[cfg(test)]
mod hv01_tests {
    use crate::container::Container;
    use crate::crypto::kdf::Argon2Params;
    use crate::space::index::Namespace;

    fn scratch() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "hv01-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    /// A vacuum on a handle whose last publish may have landed must refuse.
    ///
    /// `commit_tx` writes N Superblock replicas and adopts the new one only
    /// after the final fsync. ENOSPC on the second replica leaves replica 1 of
    /// seq N+1 ON DISK while this handle still names N. Vacuuming then walks
    /// N's tree and erases everything else — including N+1's chunks — and the
    /// next open picks N+1 by seq and finds it pointing at nothing. The
    /// documented recovery advice was to vacuum, which is how this became a
    /// way to destroy an already-published commit (audit HV-01).
    ///
    /// The partial publish needs an I/O fault to induce, so this drives the
    /// state it leaves behind — `attempted_seq` ahead of `superblock.seq`,
    /// exactly what `commit_tx` sets before its first replica append.
    #[test]
    fn a_vacuum_on_an_uncertain_publish_is_refused_until_reopen() {
        let path = scratch();
        let _cleanup = Cleanup(path.clone());

        let mut c = Container::create(&path, Argon2Params::MIN).unwrap();
        let mut s = c.create_space(b"pw").unwrap();
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k", b"v").unwrap();
        tx.commit().unwrap();
        tx = s.begin_tx();
        tx.delete(Namespace::SETTINGS, b"k").unwrap();
        tx.commit().unwrap();

        // Control: with the publish settled, both vacuums run.
        assert!(s.vacuum_orphans().is_ok());
        assert!(s.vacuum_data_batches().is_ok());

        // A publish of the next seq reached the disk and then failed.
        s.state.attempted_seq = s.commit_seq() + 1;

        assert!(
            matches!(s.vacuum_orphans(), Err(crate::Error::PublishUncertain(_))),
            "vacuum_orphans must refuse rather than erase an era it cannot see"
        );
        assert!(
            matches!(
                s.vacuum_data_batches(),
                Err(crate::Error::PublishUncertain(_))
            ),
            "vacuum_data_batches must refuse for the same reason"
        );

        // Committing is deliberately still allowed: it skips the burnt seq
        // rather than writing a second payload under it, so blocking it would
        // wedge the space for no gain.
        let mut tx = s.begin_tx();
        tx.put(Namespace::SETTINGS, b"k2", b"v2").unwrap();
        assert!(tx.commit().is_ok(), "commit must remain available");
    }

    struct Cleanup(std::path::PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}
