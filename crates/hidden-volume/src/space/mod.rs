//! Per-space state and public API. See DESIGN §4–§7, §12.

pub mod index;
pub mod log;
pub mod superblock;

// Audit pass 8 (E7): subtree-specific implementations
// extracted from this file. Each contains an
// `impl<'f> Space<'f>` block with the methods listed.
mod commit;
mod integrity;
mod log_iter;
mod vacuum;

use zeroize::Zeroizing;

use crate::cancel::CancelToken;
use crate::chunk::ChunkKind;
use crate::chunk::format::Plaintext;
use crate::container::ContainerFile;
use crate::crypto::aead::{ChunkAead, make_aad};
use crate::crypto::derive::{SpaceKeys, derive_chunk_key};
use crate::open::{scan_and_recover, scan_and_recover_with_cancel};
use crate::tx::Tx;
use crate::tx::commit::{CommitPayload, IndexRoot};
use crate::{CHUNK_SIZE, Error, NONCE_LEN, Result};

use self::index::{IndexNode, Namespace};
use self::superblock::{NO_RECORD, Superblock};

/// Aggregate statistics for a [`Space`] — the structured form host-apps
/// typically render in a "Storage" / "About this profile" UI page.
///
/// Cheap to compute: walks the per-namespace KV-index trees once
/// (same cost as calling [`Space::count`] for every namespace).
/// Does NOT walk DataBatch chunks or verify integrity — for that use
/// [`Space::verify_integrity`].
///
/// Marked `#[non_exhaustive]` — host-apps construct nothing; the
/// library may add fields (e.g. `total_log_entries`, `bytes_owned`)
/// in future minor releases without bumping major.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SpaceStats {
    /// Current monotonic commit counter (same as [`Space::commit_seq`]).
    pub commit_seq: u64,
    /// Number of distinct seqs in [`Space::commit_history`] —
    /// recoverable Superblocks still on disk.
    pub commit_history_len: usize,
    /// Number of chunks owned by this space (decryptable under its
    /// key). Includes Superblock replicas, Commit chunks, IndexNode
    /// chunks, and DataBatch chunks.
    pub owned_chunk_count: usize,
    /// Total slot count of the underlying container file (excluding
    /// the cleartext header chunk). The host-app uses this together
    /// with [`Self::owned_chunk_count`] to decide when to call
    /// [`crate::Container::compact_known`] — see
    /// [`Self::utilization_ratio`] for the convenience accessor.
    /// Audit pass 17: surfaced so the "is the file too sparse?"
    /// trigger does not require a separate `Container::file_chunks()`
    /// call after dropping the `Space` handle.
    pub total_slot_count: u64,
    /// Per-namespace `(namespace, entry_count)` pairs in ascending
    /// `Namespace.0` order. For KV namespaces `entry_count` is the
    /// KV pair count; for log namespaces it is the log-entry count
    /// (which equals the KV-index entry count, since each log
    /// record is one KV pointer).
    pub namespace_counts: Vec<(Namespace, usize)>,
}

impl SpaceStats {
    /// Total entries across all namespaces (sum of `namespace_counts`
    /// values). Useful for a single "items in this profile" headline
    /// number in a UI.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.namespace_counts.iter().map(|(_, n)| *n).sum()
    }

    /// Fraction of the container file's slot grid that is owned by
    /// **this space**, in `[0.0, 1.0]`. A multi-space container will
    /// have ratios that sum to less than 1.0 (the rest is garbage
    /// padding + foreign hidden spaces); a single-space container
    /// approaches 1.0 minus padding overhead.
    ///
    /// **Use as a `compact_known` trigger.** The append-only write
    /// invariant (DESIGN §9) means scrubbed slots are NOT reused —
    /// they remain on disk as uniform-random bytes. Over the lifetime
    /// of a heavy-delete workload (e.g. a messenger that erases
    /// expired conversations), the file's high-water mark drifts
    /// upward while the "live" content shrinks. When this ratio drops
    /// below a host-app-chosen threshold (e.g. `0.5`), it's time to
    /// call [`crate::Container::compact_known`] to physically reclaim
    /// the disk space and rotate the `container_id`. See
    /// `docs/en/guide/operations.md` §3 "Reclaiming disk space".
    ///
    /// Returns `0.0` for an empty container (no slots), avoiding
    /// division by zero.
    #[must_use]
    pub fn utilization_ratio(&self) -> f64 {
        if self.total_slot_count == 0 {
            0.0
        } else {
            self.owned_chunk_count as f64 / self.total_slot_count as f64
        }
    }
}

/// Result of a successful [`Space::verify_integrity`] walk.
///
/// All counts are over chunks reachable from the current Superblock;
/// older Superblock or Commit chunks (kept on disk as crash-recovery
/// fallbacks) are excluded. Since the M2 audit fix (2026-05-10)
/// `DataBatch` chunks of log namespaces ARE covered — see
/// [`Self::data_batches_verified`].
///
/// Marked `#[non_exhaustive]` — only the library constructs this;
/// future fields (e.g. integrity walk duration, branch factor stats)
/// may be added in minor releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct IntegrityReport {
    /// Number of namespaces whose Merkle subtree was verified end-to-end.
    pub namespaces_verified: usize,
    /// Total IndexNode + Commit chunks read and hash-matched against
    /// their parent's recorded hash.
    pub chunks_verified: usize,
    /// Maximum tree depth observed across all namespaces. 0 = empty
    /// space, 1 = single-leaf namespace, 2 = leaf-and-internal split.
    /// Bounded by the format's B+ tree max-depth (see DESIGN §11.4).
    pub max_depth: u8,
    /// Total `DataBatch` chunks visited while walking log namespaces.
    /// AEAD-decrypted and `decode_batch`-validated; counts each batch
    /// slot once even if multiple log entries point at the same batch.
    /// Closes the M2 audit gap (2026-05-10): prior versions of this
    /// walker stopped at Leaf nodes, which left payload-bearing
    /// `DataBatch` chunks unverified.
    pub data_batches_verified: usize,
}

/// In-memory state of an opened space. Not part of the public API — the
/// public surface is [`Space`].
#[derive(Debug)]
pub(crate) struct SpaceState {
    pub keys: SpaceKeys,
    pub container_id: [u8; 32],
    pub superblock: Superblock,
    pub owned_slots: Vec<u64>,
    /// Sorted-ascending, deduplicated `seq` values of every Superblock
    /// chunk that AEAD-decrypted under this space's key during the open
    /// scan. Updated on every successful `commit_tx` by appending the
    /// new seq. Exposed via [`Space::commit_history`] for host-app
    /// rollback / multi-device anchor logic.
    pub commit_history: Vec<u64>,
    /// Audit M1 (2026-05-10). Last error encountered in the post-
    /// commit padding step (DESIGN §8). Does NOT affect durability of
    /// the commit itself — see [`commit_tx`](crate::space::Space::commit_tx)
    /// docs. Exposed read-only via [`Space::last_padding_error`] so
    /// host-apps can surface a privacy-hardening warning without
    /// confusing it with a commit failure.
    pub last_padding_error: Option<crate::Error>,
    /// Per-`seq` cache of the decrypted `Commit`-chunk payload bytes (the
    /// `CommitPayload` wire bytes living at `superblock.root_slot`), so the
    /// read-hot [`Space::load_prior_roots`] does not re-read + re-AEAD-decrypt
    /// the same Commit chunk on every namespace lookup — a 50-namespace read
    /// sweep was 50 redundant XChaCha20-Poly1305 opens of one chunk.
    ///
    /// `(seq, bytes)`: served ONLY while `seq == superblock.seq`. A successful
    /// `commit_tx` advances `superblock.seq` and clears this, and the `seq`
    /// equality check is a backstop, so a stale era can never be served (`seq`
    /// is strictly monotonic per space — DESIGN §6 Inv-W3). The bytes are
    /// decrypted plaintext, held in [`Zeroizing`] and scrubbed on drop / replace
    /// so they never outlive their commit era in cleartext.
    pub roots_payload_cache: Option<(u64, Zeroizing<Vec<u8>>)>,
}

impl SpaceState {
    pub(crate) fn fresh(keys: SpaceKeys, container_id: [u8; 32]) -> Self {
        Self {
            keys,
            container_id,
            superblock: Superblock {
                seq: 0,
                root_slot: NO_RECORD,
                root_hash: [0u8; 32],
                checkpoint_slot: NO_RECORD,
            },
            owned_slots: Vec::new(),
            commit_history: Vec::new(),
            last_padding_error: None,
            roots_payload_cache: None,
        }
    }
}

/// An opened space inside a container.
///
/// Holds an exclusive `&mut` borrow on the underlying file for the
/// duration of the borrow — drop the `Space` to release. Lifetime `'f`
/// ties the space to the file handle that opened it; this statically
/// prevents using a stale `Space` after the container is closed or
/// reopened.
#[derive(Debug)]
pub struct Space<'f> {
    file: &'f mut ContainerFile,
    state: SpaceState,
}

impl<'f> Space<'f> {
    /// Open an existing space identified by `keys`. Performs the
    /// trial-decrypt scan (DESIGN §5) and returns the recovered
    /// state. `cancel` polls at periodic checkpoints inside the scan
    /// loop; pass `None` for non-cancellable behaviour. Audit pass 8
    /// (D10): the previous `open(file, keys)` and `open_with_cancel(...)`
    /// pair is consolidated into this single method.
    pub(crate) fn open_with_cancel(
        file: &'f mut ContainerFile,
        keys: SpaceKeys,
        cancel: Option<&CancelToken>,
    ) -> Result<Self> {
        let state = scan_and_recover_with_cancel(file, keys, cancel)?;
        Ok(Self { file, state })
    }

    /// Parallel variant of [`Self::open`] (feature `parallel-scan`,
    /// Unix only). Uses rayon's work-stealing pool to parallelize
    /// AEAD-decrypts across slots.
    #[cfg(all(feature = "parallel-scan", unix))]
    pub(crate) fn open_parallel(file: &'f mut ContainerFile, keys: SpaceKeys) -> Result<Self> {
        let state = crate::open::scan_and_recover_parallel(file, keys)?;
        Ok(Self { file, state })
    }

    /// Constant-time companion to [`Self::open_parallel`] — closes
    /// the dominant component of the TM1 timing oracle on the
    /// parallel scan path. See [`crate::open::scan_and_recover_parallel_constant_time`].
    #[cfg(all(feature = "parallel-scan", unix))]
    pub(crate) fn open_parallel_constant_time(
        file: &'f mut ContainerFile,
        keys: SpaceKeys,
    ) -> Result<Self> {
        let state = crate::open::scan_and_recover_parallel_constant_time(file, keys)?;
        Ok(Self { file, state })
    }

    /// Memory-mapped variant of [`Self::open`] (feature `mmap`,
    /// Unix only). Maps the entire file once and slices each chunk
    /// out of the mapping for AEAD-decryption — zero allocation per
    /// chunk on the read path.
    #[cfg(all(feature = "mmap", unix))]
    pub(crate) fn open_mmap(file: &'f mut ContainerFile, keys: SpaceKeys) -> Result<Self> {
        let state = crate::open::scan_and_recover_mmap(file, keys)?;
        Ok(Self { file, state })
    }

    /// Constant-time companion to [`Self::open_mmap`] — closes the
    /// dominant component of the TM1 timing oracle on the mmap scan
    /// path. See [`crate::open::scan_and_recover_mmap_constant_time`].
    #[cfg(all(feature = "mmap", unix))]
    pub(crate) fn open_mmap_constant_time(
        file: &'f mut ContainerFile,
        keys: SpaceKeys,
    ) -> Result<Self> {
        let state = crate::open::scan_and_recover_mmap_constant_time(file, keys)?;
        Ok(Self { file, state })
    }

    /// Constant-time-scan variant of [`Self::open_with_cancel`] —
    /// closes the TM1 timing oracle for the sequential path by
    /// running a ChaCha20 timing-equalizer on every MAC-fail. See
    /// [`crate::Container::open_space_constant_time`] for the
    /// public entry point + threat-model §4.4 F-TM1.
    pub(crate) fn open_constant_time(file: &'f mut ContainerFile, keys: SpaceKeys) -> Result<Self> {
        let state = crate::open::scan_and_recover_constant_time(file, keys)?;
        Ok(Self { file, state })
    }

    /// Bootstrap a new space with `keys`: scans first to refuse collision,
    /// then writes an initial superblock chunk so future `open` finds it.
    pub(crate) fn create(file: &'f mut ContainerFile, keys: SpaceKeys) -> Result<Self> {
        match scan_and_recover(file, keys.clone()) {
            Ok(_) => return Err(Error::SpaceAlreadyExists),
            Err(Error::AuthFailed) => {},
            Err(other) => return Err(other),
        }

        // v3: container_id is derived per-space inside SpaceKeys::from_master,
        // no longer stored in the cleartext header.
        let container_id = keys.container_id;
        let mut space = Self {
            file,
            state: SpaceState::fresh(keys, container_id),
        };

        // Initial Superblock with seq=1, no namespaces yet (root_slot
        // = NO_RECORD; future Tx commits link in a Commit chunk).
        // Multiple replicas for resilience (DESIGN §7).
        let initial = Superblock {
            seq: 1,
            root_slot: NO_RECORD,
            root_hash: [0u8; 32],
            checkpoint_slot: NO_RECORD,
        };
        let replicas = space.file.superblock_replicas.max(1);
        for _ in 0..replicas {
            space.append_superblock(&initial)?;
        }
        space.file.fsync()?;
        space.state.superblock = initial;
        space.state.commit_history.push(1);
        Ok(space)
    }

    /// Re-attach a previously [detached](Self::into_state) [`SpaceState`] to a
    /// container file, yielding a usable `Space` again. The seam that lets a
    /// host hold MANY spaces' states at once (each detached) and bind one to the
    /// file per operation — see [`crate::MultiSpace`]. The `'f` borrow is only
    /// held for the duration of the bound operation, so the single file (and its
    /// exclusive lock) is shared serially across all hosted spaces.
    pub(crate) fn from_state(file: &'f mut ContainerFile, state: SpaceState) -> Self {
        Self { file, state }
    }

    /// Detach this space's [`SpaceState`], dropping the file borrow so the file
    /// is free for another hosted space. Companion to [`Self::from_state`].
    pub(crate) fn into_state(self) -> SpaceState {
        self.state
    }

    /// Per-space monotonic commit counter. Exposed for host-app rollback
    /// detection (DESIGN §11.2): host-app stores this value externally
    /// after a successful commit, then on the next open compares the
    /// stored value to whatever this returns. If the new value is lower,
    /// the file has been rolled back.
    ///
    /// **Privacy contract.** Do NOT anchor decoy/duress spaces — anchoring
    /// presence reveals presence. Anchoring is host-app policy.
    #[must_use]
    pub fn commit_seq(&self) -> u64 {
        self.state.superblock.seq
    }

    /// This space's [`SpaceKeys`] — the per-space decryption root, derived at
    /// open time from the password (Argon2id + version-bind). Returns a clone so
    /// a host-app can persist it for keys-only reopen via
    /// [`crate::Container::open_space_with_keys`] (the documented external-keyring
    /// / master-space workflow; see [`crate::Container::derive_space_keys`]).
    ///
    /// **Sensitive.** These bytes bypass Argon2 on reopen, so storing them
    /// outside the process forfeits the brute-force protection of the password.
    /// Keep them only inside another deniable space (e.g. a master roster);
    /// never log or persist them in the clear. Do NOT expose for decoy/duress
    /// spaces whose presence must stay hidden.
    #[must_use]
    pub fn space_keys(&self) -> SpaceKeys {
        self.state.keys.clone()
    }

    /// All recoverable commit-anchor seq numbers for this space, sorted
    /// ascending. Each entry is a `seq` whose Superblock chunk is still
    /// present on disk (one or more replicas) and decrypts under this
    /// space's key.
    ///
    /// Use cases (host-app, see `docs/en/guide/multi-device.md`):
    /// - **Rollback verification.** After reopening, the host-app's
    ///   externally-stored anchor `seq_a` should appear in this list. If
    ///   `commit_seq() < seq_a`, the file was rolled back. If
    ///   `commit_seq() >= seq_a` but `seq_a` is absent, the file was
    ///   forked (different timeline) — treat as adversarial.
    /// - **P2P sync state.** Devices that share a container can compare
    ///   histories to detect divergent timelines and decide reconciliation
    ///   strategy at the host-app layer (the library does not perform
    ///   sync — see `docs/en/guide/multi-device.md`).
    ///
    /// **What is in the list.** Every Superblock chunk that AEAD-decrypts
    /// under this space's key contributes one seq, deduplicated across
    /// replicas. The initial Superblock (`seq = 1`, written at
    /// [`Container::create_space`](crate::Container::create_space) time)
    /// counts.
    ///
    /// **What is NOT in the list.** Seqs whose Superblock replicas have
    /// all been physically removed from disk — most importantly, after
    /// [`Container::compact_known`](crate::Container::compact_known) /
    /// [`compact_known`](crate::Container::compact_known) the destination
    /// container is fresh and its history starts at `[1]` regardless of
    /// the source's history. Hosts must re-anchor after compaction.
    ///
    /// **Privacy contract.** Same as [`Space::commit_seq`]: do NOT
    /// publish the history of a decoy/duress space. The shape of the
    /// list (length, gaps if any) is metadata about activity that an
    /// adversary with side-channel access to the host-app could exploit.
    #[must_use]
    pub fn commit_history(&self) -> &[u64] {
        &self.state.commit_history
    }

    /// Set the post-commit padding policy on the underlying
    /// container. Equivalent to calling
    /// [`crate::Container::set_padding_policy`] before opening this
    /// space — the policy is held by `ContainerFile` and shared
    /// between Container and any active Space. Audit pass 7 (S1):
    /// added so FFI / async wrappers can configure padding without
    /// dropping the open handle.
    ///
    /// Returns [`Error::ReadOnly`] when called on a handle that was
    /// opened via [`crate::Container::open_readonly`] (`LOCK_SH`).
    /// Audit pass 10 (M1): closes a strict-RO contract violation —
    /// previously this method silently mutated `padding_policy` on
    /// RO handles, contradicting `Container::set_padding_policy`'s
    /// `Err(ReadOnly)` behaviour and breaking the asymmetry that
    /// async / FFI wrappers depend on (they route through
    /// `with_space_mut()`).
    pub fn set_padding_policy(&mut self, policy: crate::padding::PaddingPolicy) -> Result<()> {
        if self.file.lock_mode == crate::container::file::LockMode::Shared {
            return Err(Error::ReadOnly);
        }
        self.file.padding_policy = policy;
        Ok(())
    }

    /// Current post-commit padding policy. See
    /// [`Self::set_padding_policy`].
    #[must_use]
    pub fn padding_policy(&self) -> crate::padding::PaddingPolicy {
        self.file.padding_policy
    }

    /// Last error from the post-commit padding step, if any. Audit M1
    /// (2026-05-10): padding failures DO NOT downgrade a durable
    /// commit — `Tx::commit` returns `Ok(seq)` even if this field is
    /// `Some(_)`. Host-apps may surface this as a privacy-hardening
    /// warning (the affected commit's size is observable to a
    /// multi-snapshot adversary) without confusing it with a commit
    /// failure. Cleared on every successful padding round.
    #[must_use]
    pub fn last_padding_error(&self) -> Option<&crate::Error> {
        self.state.last_padding_error.as_ref()
    }

    /// Number of chunks owned by this space — chunks that AEAD-decrypt
    /// under our key. Useful for verifying scrub behavior in tests
    /// (after delete + commit, this should not grow indefinitely).
    /// Production callers usually don't need this.
    #[must_use]
    pub fn audit_owned_chunk_count(&self) -> usize {
        self.state.owned_slots.len()
    }

    /// Aggregate statistics for this space — the structured form most
    /// host-app UIs render in a "Storage" / "About this profile"
    /// section. Returns commit-seq, history length, owned-chunk count,
    /// and per-namespace entry counts in one call.
    ///
    /// **Cost.** Walks the KV-index tree of every active namespace
    /// once (same cost as [`Self::count`] per namespace summed). Does
    /// NOT walk DataBatch chunks and does NOT verify integrity — for
    /// that use [`Self::verify_integrity`].
    ///
    /// **Read-only safe.** No writes occur; this method works on a
    /// handle returned by [`crate::Container::open_readonly`].
    pub fn stats(&mut self) -> Result<SpaceStats> {
        let namespaces = self.list_namespaces()?;
        let mut namespace_counts = Vec::with_capacity(namespaces.len());
        for ns in namespaces {
            let count = self.count(ns)?;
            namespace_counts.push((ns, count));
        }
        Ok(SpaceStats {
            commit_seq: self.commit_seq(),
            commit_history_len: self.commit_history().len(),
            owned_chunk_count: self.audit_owned_chunk_count(),
            total_slot_count: self.file.slot_count(),
            namespace_counts,
        })
    }

    /// Open a new transaction. Single concurrent tx per space; the tx
    /// borrows the space mutably until committed or dropped.
    pub fn begin_tx<'s>(&'s mut self) -> Tx<'s, 'f> {
        Tx::new(self)
    }

    /// Read a single value from `namespace` by `key`. `Ok(None)` if the
    /// key is absent or the namespace has never been written to.
    ///
    /// Errors with [`Error::Malformed`] if the B+ tree depth exceeds
    /// the internal `MAX_TREE_DEPTH` (currently 3) — defense-in-depth
    /// against a writer-bug regression or adversarial-key-holder cycle
    /// in the IndexNode chain. See
    /// [`docs/en/security/audits/adversarial-stance.md` F-A5](../../../docs/en/security/audits/adversarial-stance.md).
    pub fn get(&mut self, namespace: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let root_slot = match self.find_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(None),
        };
        // Walk down to the leaf containing `key`. `depth` caps a
        // pathological cyclic Internal→Internal chain that would
        // otherwise loop forever; the writer-side invariant
        // guarantees depth ≤ 2. The check is performed on *entry* to
        // each node — BEFORE matching Leaf vs Internal — so that a
        // forged tree presenting a `Leaf` at depth > MAX is rejected
        // identically to `collect_leaves_at` / `count_leaves_at`
        // (audit pass 20: the prior placement inside the `Internal`
        // arm let `get` accept a Leaf one level deeper than every
        // other walker, contradicting the `index::MAX_TREE_DEPTH`
        // "identical across read paths" invariant).
        // `read_index_node_at_expected` additionally gates
        // `IndexNode.namespace == namespace` (audit pass 19 round 6
        // root-relabel closure).
        let mut depth: u8 = 0;
        let mut slot = root_slot;
        loop {
            if depth > index::MAX_TREE_DEPTH {
                return Err(Error::Malformed("tree depth exceeded MAX_TREE_DEPTH"));
            }
            match self.read_index_node_at_expected(slot, namespace)? {
                IndexNode::Leaf(l) => return Ok(l.get(key).map(|v| v.to_vec())),
                IndexNode::Internal(i) => {
                    let idx = i.child_index_for(key);
                    slot = i.children[idx].child_slot;
                    depth += 1;
                },
            }
        }
    }

    /// List all `(key, value)` pairs in `namespace`, sorted by key.
    /// Empty Vec for namespaces that have never been written to.
    pub fn list(&mut self, namespace: Namespace) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let root_slot = match self.find_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        self.collect_leaves(root_slot, namespace, &mut out)?;
        Ok(out)
    }

    /// Number of entries in `namespace`. Walks all leaves of the tree
    /// — O(N) but only chunk reads, no decode of values. There is no
    /// count cache: `count` is rarely on a UI hot path.
    pub fn count(&mut self, namespace: Namespace) -> Result<usize> {
        let root_slot = match self.find_root_slot(namespace)? {
            Some(s) => s,
            None => return Ok(0),
        };
        self.count_leaves(root_slot, namespace)
    }

    /// Erase **every** entry in `namespace` in a single transaction.
    /// Returns the number of entries removed.
    ///
    /// Use case (messenger): "Clear chat history" or "Wipe contacts" —
    /// the user wants to drop a whole namespace's worth of data with
    /// one click. Doing this via per-key `Tx::delete` requires the
    /// host-app to enumerate keys first, which is awkward and easy to
    /// get wrong; this method does the right thing in one call.
    ///
    /// ## Mechanics
    ///
    /// 1. Enumerate all `(key, _)` pairs in the namespace via [`Self::list`].
    /// 2. Open a single `Tx`, issue a `delete` for each key, commit.
    /// 3. The new commit omits this namespace from its `IndexRoot` set
    ///    (since the rebuilt tree is empty). Old IndexNode chunks
    ///    become orphans.
    /// 4. The next `Container::open_space` (or an explicit
    ///    [`Self::vacuum_orphans`] call now) scrubs those orphan
    ///    IndexNode chunks → forward-secrecy for the keys themselves.
    ///
    /// ## Forward-secrecy caveat for log namespaces
    ///
    /// `vacuum_orphans` does NOT scrub `DataBatch` chunks (a single
    /// batch may still contain live entries from other log_ids; safe
    /// scrub requires repacking). For log namespaces, calling
    /// `erase_namespace` followed by an immediate
    /// [`crate::Container::compact_known`] is the recipe that
    /// physically eliminates message bytes. Until compaction, an
    /// adversary with the password can still recover erased messages
    /// from their (no-longer-pointed-to but still-AEAD-decryptable)
    /// `DataBatch` chunks.
    ///
    /// ## Cost
    ///
    /// One Tx → 3-fsync barrier. Pending state: `O(N)` in-memory
    /// `Delete { key }` ops where `N` is the namespace's entry count.
    /// For a 10 K-entry namespace this is ~300 KiB of pending state —
    /// fine for any device class.
    ///
    /// ## Idempotence
    ///
    /// Erasing an already-empty namespace is a no-op (returns `0`)
    /// and does NOT produce a commit (the underlying `Tx` is dropped
    /// without commit when there is nothing to do).
    pub fn erase_namespace(&mut self, namespace: Namespace) -> Result<usize> {
        // R-NSKIND: works on both Kv AND Log namespaces. Internally
        // we walk the KV index via `list` (which returns the raw
        // `(key, value)` shape regardless of the namespace's kind —
        // for Log namespaces that's `(log_id_key_be, batch_slot_le)`
        // pointers) and queue Delete ops via the kind-bypassing
        // internal helper. `commit_tx` permits pure-Delete op sets
        // against a Log namespace because they cannot introduce
        // mixed-kind state.
        let entries = self.list(namespace)?;
        if entries.is_empty() {
            return Ok(0);
        }
        let count = entries.len();
        let mut tx = self.begin_tx();
        for (key, _value) in &entries {
            tx.delete_internal(namespace, key)?;
        }
        tx.commit()?;
        Ok(count)
    }

    /// List all namespaces with data in the latest commit. Useful for
    /// inspection / compaction tooling. Returned in ascending namespace
    /// order (matches the on-disk Commit roots layout).
    pub fn list_namespaces(&mut self) -> Result<Vec<Namespace>> {
        let prior_roots = self.load_prior_roots()?;
        Ok(prior_roots.into_iter().map(|r| r.namespace).collect())
    }

    /// List all namespaces with their data shape
    /// ([`crate::tx::NamespaceKind`]). R-NSKIND: each `IndexRoot`
    /// carries an explicit `kind` byte (format v2); this method
    /// surfaces the persisted classification so external tools
    /// (`Container::repack`, host-app introspection) can route by
    /// kind without re-running the v1 content-shape heuristic.
    /// Returns pairs in ascending namespace order.
    pub fn list_namespaces_with_kind(
        &mut self,
    ) -> Result<Vec<(Namespace, crate::tx::NamespaceKind)>> {
        let prior_roots = self.load_prior_roots()?;
        Ok(prior_roots
            .into_iter()
            .map(|r| (r.namespace, r.kind))
            .collect())
    }

    // --- tree walks ---
    //
    // Cross-submodule helpers below are `pub(super)` so the
    // `commit.rs` / `vacuum.rs` / `log_iter.rs` / `integrity.rs`
    // submodules (each contains an `impl<'f> Space<'f>` block) can
    // share the canonical implementation. Audit pass 8 (E7) split
    // factored these out of a single 1578-LOC file. Keep contracts
    // documented here.

    /// Recursively flatten every IndexNode subtree rooted at `slot`
    /// into a flat `(key, value)` Vec. Used by `Space::list` and the
    /// `commit.rs` flatten-and-rebuild path.
    ///
    /// **Errors:** propagates AEAD failure or `Malformed` from
    /// [`Self::read_index_node_at`]; returns `Malformed` if depth
    /// exceeds [`index::MAX_TREE_DEPTH`].
    pub(super) fn collect_leaves(
        &mut self,
        slot: u64,
        namespace: Namespace,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        self.collect_leaves_at(slot, namespace, 0, out)
    }

    fn collect_leaves_at(
        &mut self,
        slot: u64,
        namespace: Namespace,
        depth: u8,
        out: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<()> {
        if depth > index::MAX_TREE_DEPTH {
            return Err(Error::Malformed("tree depth exceeded MAX_TREE_DEPTH"));
        }
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => {
                out.extend(l.entries);
                Ok(())
            },
            IndexNode::Internal(i) => {
                for c in i.children {
                    self.collect_leaves_at(c.child_slot, namespace, depth + 1, out)?;
                }
                Ok(())
            },
        }
    }

    fn count_leaves(&mut self, slot: u64, namespace: Namespace) -> Result<usize> {
        self.count_leaves_at(slot, namespace, 0)
    }

    fn count_leaves_at(&mut self, slot: u64, namespace: Namespace, depth: u8) -> Result<usize> {
        if depth > index::MAX_TREE_DEPTH {
            return Err(Error::Malformed("tree depth exceeded MAX_TREE_DEPTH"));
        }
        let node = self.read_index_node_at_expected(slot, namespace)?;
        match node {
            IndexNode::Leaf(l) => Ok(l.entries.len()),
            IndexNode::Internal(i) => {
                let mut total = 0;
                for c in i.children {
                    total += self.count_leaves_at(c.child_slot, namespace, depth + 1)?;
                }
                Ok(total)
            },
        }
    }

    /// Locate the root IndexNode slot for `namespace` at the
    /// **current** commit. Returns `Ok(None)` if the namespace does
    /// not appear in the current `CommitPayload` (i.e. has never
    /// been written to OR was fully erased). `Ok(Some(slot))`
    /// otherwise. Used by reads (`Space::get`, `list`, `count`,
    /// `iter_log_*`, `read_log`).
    pub(super) fn find_root_slot(&mut self, namespace: Namespace) -> Result<Option<u64>> {
        let prior_roots = self.load_prior_roots()?;
        Ok(prior_roots
            .iter()
            .find(|r| r.namespace == namespace)
            .map(|r| r.index_slot))
    }

    /// Like [`Self::find_root_slot`] but returns the whole
    /// [`crate::tx::commit::IndexRoot`] — in particular its persisted
    /// [`crate::tx::NamespaceKind`] byte. The log read paths
    /// (`iter_log_*`, `read_log`) use this to enforce the kind
    /// contract from the persisted byte instead of inferring "this is
    /// a log namespace" from the 8-byte-key / DataBatch-pointer shape
    /// downstream (audit pass 20: R-NSKIND parity — vacuum/repack were
    /// already kind-driven; the read iterators still relied on the
    /// shape heuristic, giving an unpredictable error taxonomy when a
    /// KV namespace happened to hold 8-byte keys *and* values).
    pub(super) fn find_root(
        &mut self,
        namespace: Namespace,
    ) -> Result<Option<crate::tx::commit::IndexRoot>> {
        let prior_roots = self.load_prior_roots()?;
        Ok(prior_roots.into_iter().find(|r| r.namespace == namespace))
    }

    // --- internals ---

    /// Decode the current commit's `CommitPayload` and return its
    /// per-namespace root list. `Ok(vec![])` if the space has no
    /// commits yet (`superblock.root_slot == NO_RECORD`).
    ///
    /// **Errors:** AEAD failure on the Commit chunk → `AuthFailed`;
    /// `Malformed` if the chunk's kind is wrong or `CommitPayload::decode`
    /// fails. Used by `find_root_slot`, `commit_tx`, and vacuum paths.
    pub(super) fn load_prior_roots(&mut self) -> Result<Vec<IndexRoot>> {
        if self.state.superblock.root_slot == NO_RECORD {
            return Ok(Vec::new());
        }
        let seq = self.state.superblock.seq;
        // Warm cache: decode straight from the cached payload bytes for this
        // commit era, skipping the disk read + AEAD open. Decoding is pure
        // parsing (no crypto), so the AEAD — the dominant per-read cost — is paid
        // once per commit instead of once per namespace lookup. The `seq`
        // equality gate means a stale era can never be served.
        if let Some((cached_seq, bytes)) = &self.state.roots_payload_cache
            && *cached_seq == seq
        {
            return Ok(CommitPayload::decode(bytes)?.roots);
        }
        let pt = self.read_owned_chunk(self.state.superblock.root_slot)?;
        if pt.kind != ChunkKind::Commit {
            return Err(Error::Malformed(
                "superblock root_slot is not a Commit chunk",
            ));
        }
        let cp = CommitPayload::decode(&pt.payload)?;
        // Cache the verified, AEAD-decrypted payload bytes (Zeroizing) keyed by
        // the current seq for subsequent lookups in the same commit era.
        self.state.roots_payload_cache = Some((seq, Zeroizing::new(pt.payload)));
        Ok(cp.roots)
    }

    /// Read the IndexNode at `slot` (assumed owned by this space).
    /// Wraps [`Self::read_owned_chunk`] with a kind check + decode.
    ///
    /// **Errors:** `AuthFailed` if the slot is foreign; `Malformed`
    /// if the kind is not `IndexNode` or `IndexNode::decode` fails.
    /// Used by reachability sweeps (vacuum / orphan collection)
    /// that don't carry a namespace context; namespace-aware
    /// read paths use [`Self::read_index_node_at_expected`].
    pub(super) fn read_index_node_at(&mut self, slot: u64) -> Result<IndexNode> {
        let pt = self.read_owned_chunk(slot)?;
        if pt.kind != ChunkKind::IndexNode {
            return Err(Error::Malformed("commit root pointer not an IndexNode"));
        }
        IndexNode::decode(&pt.payload)
    }

    /// Namespace-checked variant of [`Self::read_index_node_at`]:
    /// reads + decodes the chunk, then verifies the decoded node's
    /// `namespace` byte matches `expected`. Closes the root-relabel
    /// surface (audit pass 19 round 6 user-report 2026-05-28): a
    /// key-holder / buggy writer could otherwise have an
    /// `IndexRoot` declare `namespace = A` while the actual tree's
    /// nodes carry `namespace = B`, and the regular read path
    /// would silently traverse foreign-namespace data. Used by
    /// `Space::get` / `list` / `count` and the log-iter walkers —
    /// every path with a `namespace: Namespace` parameter.
    pub(super) fn read_index_node_at_expected(
        &mut self,
        slot: u64,
        expected: Namespace,
    ) -> Result<IndexNode> {
        let node = self.read_index_node_at(slot)?;
        let node_ns = match &node {
            IndexNode::Leaf(l) => l.namespace,
            IndexNode::Internal(i) => i.namespace,
        };
        if node_ns != expected {
            return Err(Error::Malformed(
                "IndexNode.namespace != expected (relabel attempt or writer bug)",
            ));
        }
        Ok(node)
    }

    /// Encode + append a Superblock chunk. Thin wrapper over
    /// [`Self::append_chunk`] with the right `ChunkKind` and seq.
    /// Used by `commit_tx` (writes one or more replicas per commit).
    pub(super) fn append_superblock(&mut self, sb: &Superblock) -> Result<u64> {
        self.append_chunk(ChunkKind::Superblock, sb.seq, &sb.encode())
    }

    /// AEAD-seal `payload` at the next free slot with the given kind
    /// and seq, append the ciphertext chunk, and record the slot in
    /// `state.owned_slots`. Returns the new slot index.
    ///
    /// **Errors:** Any I/O error from `file.append_slot`; AEAD seal
    /// failure (effectively impossible — XChaCha20-Poly1305 with
    /// random nonce never errors on input).
    ///
    /// **Side effects:** appends to `state.owned_slots`. On caller
    /// error mid-`commit_tx`, `state.owned_slots` may include slots
    /// that aren't yet reachable from any committed Superblock —
    /// the next `vacuum_orphans` reclaims them.
    pub(super) fn append_chunk(
        &mut self,
        kind: ChunkKind,
        seq: u64,
        payload: &[u8],
    ) -> Result<u64> {
        let slot = self.file.slot_count();
        let key = derive_chunk_key(&self.state.keys.aead_root, &self.state.container_id, slot);
        let aead = ChunkAead::new(&key);
        let pt = Plaintext {
            kind,
            seq,
            payload: payload.to_vec(),
        };
        // Encoded plaintext sits on the stack as a 4040-byte array; wrap
        // in Zeroizing so that when this stack slot is reclaimed at end
        // of function, the plaintext bytes are scrubbed before the slot
        // can be reused for unrelated data.
        let pt_bytes: Zeroizing<[u8; crate::PLAINTEXT_LEN]> = Zeroizing::new(pt.encode()?);
        let aad = make_aad(&self.state.container_id, slot);
        let (nonce, ct) = aead.seal(&pt_bytes[..], aad)?;
        let mut chunk = [0u8; CHUNK_SIZE];
        chunk[..NONCE_LEN].copy_from_slice(&nonce);
        chunk[NONCE_LEN..].copy_from_slice(&ct);
        self.file.append_slot(&chunk)?;
        self.state.owned_slots.push(slot);
        Ok(slot)
    }

    /// Read + AEAD-decrypt the chunk at `slot` under this space's
    /// per-slot key. Used by every read path (integrity walk, log
    /// iteration, vacuum classification, find_root_slot).
    ///
    /// **Errors:**
    ///
    /// | Error | Meaning |
    /// |---|---|
    /// | `Io(...)` | Filesystem I/O failed reading the slot |
    /// | `AuthFailed` | The slot is NOT owned by this space (AEAD-decrypt failed under our per-slot key) |
    /// | `Malformed(...)` | AEAD passed but `Plaintext::decode` rejected the bytes (writer-bug regression or bit-flip past AEAD) |
    ///
    /// **Caller-side mapping note (audit pass 8 E7):** `integrity.rs`
    /// translates `AuthFailed` here into `IntegrityFailure` (the
    /// integrity walk's contract is "AEAD-fail on a chunk we expected
    /// to own = corruption"); `commit.rs` / `log_iter.rs` /
    /// `vacuum.rs` propagate as-is.
    pub(super) fn read_owned_chunk(&mut self, slot: u64) -> Result<Plaintext> {
        let chunk = self.file.read_slot(slot)?;
        let key = derive_chunk_key(&self.state.keys.aead_root, &self.state.container_id, slot);
        let aead = ChunkAead::new(&key);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&chunk[..NONCE_LEN]);
        let ct = &chunk[NONCE_LEN..];
        let aad = make_aad(&self.state.container_id, slot);
        // `aead.open` returns Zeroizing<Vec<u8>> — the AEAD-decrypted
        // bytes are scrubbed on drop. `Plaintext::decode` borrows
        // immutably; the wrapper drops at end of this function,
        // scrubbing the heap region.
        let pt_bytes = aead.open(&nonce, ct, aad)?;
        Plaintext::decode(&pt_bytes)
    }
}
