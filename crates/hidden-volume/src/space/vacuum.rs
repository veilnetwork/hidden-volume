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

/// Membership over chunk slot indices, one bit per slot.
///
/// Every set a vacuum builds — reachable, referenced, to-drop — is
/// keyed on a slot index, and slot indices are dense and bounded by the
/// file's own [`ContainerFile::slot_count`][crate::container::file::ContainerFile::slot_count].
/// A `HashSet<u64>` over that costs on the order of 32-48 bytes per
/// member plus its load-factor slack, and a vacuum built three of them
/// at once on top of a clone of `owned_slots`: for the container sizes
/// this format now permits (audit HV-15 removed the per-namespace index
/// cap; [`crate::MAX_OPEN_SCAN_CHUNKS`] is all that is left) that is
/// hundreds of MiB where one bit per slot is 2 MiB at the very ceiling
/// (audit HV-03).
///
/// This matters more than an ordinary allocation win because
/// `vacuum_orphans` runs automatically on every writable open: a
/// container that has grown to where the vacuum cannot allocate stops
/// opening at all, and the person who filled it has locked themselves
/// out with no adversary involved.
struct SlotSet {
    words: Vec<u64>,
    capacity: u64,
    len: usize,
}

impl SlotSet {
    /// Room for slots `0..capacity`. `capacity` is the file's slot
    /// count, so `Vec` allocates `capacity / 8` bytes.
    fn with_capacity(capacity: u64) -> Self {
        Self {
            words: vec![0u64; capacity.div_ceil(64) as usize],
            capacity,
            len: 0,
        }
    }

    /// Record `slot`; returns whether it was in range and therefore
    /// recorded.
    ///
    /// Out-of-range is not an error for every caller: the batch-pointer
    /// scan feeds this arbitrary 8-byte KV values, which need not name
    /// a real slot. Such a value can never match an owned slot either,
    /// so dropping it changes no answer. Callers for whom a dropped
    /// slot WOULD change an answer — anything feeding the reachable set,
    /// where a miss means scrubbing live data — must check the result.
    fn insert(&mut self, slot: u64) -> bool {
        if slot >= self.capacity {
            return false;
        }
        let word = &mut self.words[(slot / 64) as usize];
        let bit = 1u64 << (slot % 64);
        if *word & bit == 0 {
            *word |= bit;
            self.len += 1;
        }
        true
    }

    fn contains(&self, slot: u64) -> bool {
        slot < self.capacity && self.words[(slot / 64) as usize] & (1u64 << (slot % 64)) != 0
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

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
        // A second `SlotSet`, so the `retain` below stays O(N) rather
        // than the O(N²) a `Vec::contains` would make it. Audit F1
        // (2026-05-03): matters for heavy-history containers (100K
        // owned + 1K to-scrub = 100M comparisons with Vec::contains).
        let mut to_drop = SlotSet::with_capacity(self.file.slot_count());
        for i in 0..self.state.owned_slots.len() {
            let slot = self.state.owned_slots[i];
            if walk.has_visited(slot) {
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
            self.state.owned_slots.retain(|s| !to_drop.contains(*s));
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
        // One bit per slot, not a `HashSet<u64>` — see [`SlotSet`]
        // (audit HV-03).
        let mut referenced = SlotSet::with_capacity(self.file.slot_count());
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
        // A second `SlotSet`, so the `retain` below stays O(N) rather
        // than the O(N²) a `Vec::contains` would make it. Audit F1
        // (2026-05-03): matters for heavy-history containers (100K
        // owned + 1K to-scrub = 100M comparisons with Vec::contains).
        let mut to_drop = SlotSet::with_capacity(self.file.slot_count());
        for i in 0..self.state.owned_slots.len() {
            let slot = self.state.owned_slots[i];
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
            self.state.owned_slots.retain(|s| !to_drop.contains(*s));
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
